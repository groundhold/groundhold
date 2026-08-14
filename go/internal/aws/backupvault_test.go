package aws

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func bkvAttrs() map[string]any {
	return map[string]any{
		"location.region":    "eu-central-1",
		"retention.minimum":  "2160h", // 90 days
		"retention.lockMode": "compliance",
		"service.managed":    true,
	}
}

func TestBuildBackupVaultHonors(t *testing.T) {
	p, err := BuildBackupVault("prod", "archive", bkvAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !backupVaultNameOK.MatchString(p.Name) || !strings.HasPrefix(p.Name, "pv-archive-prod-") {
		t.Fatalf("name = %q", p.Name)
	}
	if p.MinRetentionDays != 90 || p.LockMode != "compliance" {
		t.Fatalf("plan = %+v", p)
	}
	lb := p.lockBody()
	if lb["MinRetentionDays"] != 90 {
		t.Fatalf("lock body = %+v", lb)
	}
	// D724: this assertion used to read `if has { t.Fatal(...) }` — it required a
	// COMPLIANCE lock to OMIT ChangeableForDays, which is the vendor contract exactly
	// backwards, and so it locked the defect in place. AWS, verbatim:
	//   "Before the lock date, you can delete Vault Lock ... On and after the lock
	//    date, the Vault Lock becomes immutable and cannot be changed or deleted."
	//   "If this parameter is not specified, you can delete Vault Lock from the vault
	//    ... at any time."
	// So ChangeableForDays is what MAKES a lock immutable. Superseded, not edited: the
	// name stays and the expectation is inverted to the contract it was measured against.
	if lb["ChangeableForDays"] != 3 {
		t.Fatalf("a compliance (WORM) lock becomes immutable only via ChangeableForDays "+
			"— omitting it leaves the lock deletable at any time; got %+v", lb)
	}
}

// TestBuildBackupVaultGovernanceStaysChangeable supersedes
// TestBuildBackupVaultGovernanceGrace (D724), which asserted that a GOVERNANCE lock
// carries ChangeableForDays. It is the reverse: ChangeableForDays sets a lock DATE,
// after which the lock can never be removed by anyone, including the account root.
// A contract asking for the changeable mode was getting the irreversible one.
func TestBuildBackupVaultGovernanceStaysChangeable(t *testing.T) {
	a := bkvAttrs()
	a["retention.lockMode"] = "governance"
	p, err := BuildBackupVault("prod", "archive", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := p.lockBody()["ChangeableForDays"]; has {
		t.Fatalf("a governance lock must stay deletable at any time, so it must NOT set "+
			"a lock date — with one, it becomes immutable and unrecoverable; got %+v",
			p.lockBody())
	}
}

func TestBuildBackupVaultRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-lockmode":     {"retention.lockMode": "worm-forever"},
		"lock-without-min": {"retention.minimum": nil, "retention.lockMode": "compliance"},
		"bad-retention":    {"retention.minimum": "nope"},
		"unmanaged":        {"service.managed": false},
		"unknown-attr":     {"backup.schedule": "daily"},
		"bad-region":       {"location.region": "nope"},
	}
	for name, extra := range cases {
		a := bkvAttrs()
		for k, v := range extra {
			if v == nil {
				delete(a, k)
			} else {
				a[k] = v
			}
		}
		if _, err := BuildBackupVault("prod", "archive", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestBuildBackupVaultCMKRequiresArn(t *testing.T) {
	a := bkvAttrs()
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildBackupVault("prod", "archive", a, nil, 1); err == nil {
		t.Fatal("cmk without impl.kms_key_arn must refuse")
	}
	p, err := BuildBackupVault("prod", "archive", a, map[string]any{"kms_key_arn": "arn:aws:kms:eu-central-1:0:key/k"}, 1)
	if err != nil || p.KmsKeyArn == "" {
		t.Fatalf("cmk: %+v err=%v", p, err)
	}
}

// bkvServer is a happy AWS Backup REST double. GET Describe reflects lock+retention;
// GET /tags reflects owner tags.
// bkvServer serves a vault. lockDate is the Unix instant the lock becomes immutable;
// 0 means none was set, which per the AWS contract is a GOVERNANCE lock (D724).
func bkvServer(t *testing.T, capLabel string, locked bool, minDays int, lockDate int64) *httptest.Server {
	t.Helper()
	lockedStr := "false"
	if locked {
		lockedStr = "true"
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/vault-lock"):
				_, _ = w.Write([]byte(`{}`))
			case r.Method == "PUT":
				_, _ = w.Write([]byte(`{"BackupVaultName":"v","BackupVaultArn":"arn:aws:backup:eu-central-1:000000000000:backup-vault:v"}`))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/tags/"):
				_, _ = w.Write([]byte(`{"Tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"}}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"BackupVaultArn":"arn:aws:backup:eu-central-1:000000000000:backup-vault:v",` +
					`"Locked":` + lockedStr + `,"LockDate":` + strconv.FormatInt(lockDate, 10) +
					`,"MinRetentionDays":` + strconv.Itoa(minDays) + `,"EncryptionKeyArn":"aws/backup"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func bkvDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.BackupBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteBackupVault(t *testing.T) {
	srv := bkvServer(t, "archive", true, 90, 0)
	defer srv.Close()
	d := bkvDriver(t, srv)
	res := d.Create("backupvault", "archive", "prod", bkvAttrs(), nil, "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "bkv:eu-central-1:000000000000:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeBackupVault("archive", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	// D724: this asserted `compliance` from a fixture that set `Locked: true` and no
	// lock date — which is the exact estate AWS documents as deletable at any time. The
	// expectation is corrected to what that response means, and the compliance side is
	// asserted in TestBackupVaultLockModeComesFromTheLockDate against a vault that has
	// one.
	if got["retention.minimum"] != "2160h" || got["retention.lockMode"] != "governance" ||
		got["location.region"] != "eu-central-1" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("backupvault", "archive", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteBackupVaultForeignRefused(t *testing.T) {
	srv := bkvServer(t, "someone-else", true, 90, 0)
	defer srv.Close()
	d := bkvDriver(t, srv)
	pid := bkvProviderID("eu-central-1", "000000000000", BackupVaultName("prod", "archive", 1))
	res := d.Delete("backupvault", "archive", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign vault must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessBackupVault(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := bkvProviderID("eu-central-1", "000000000000", BackupVaultName("prod", "archive", 1))
	p := &certifynet.Probe{
		Name:            "aws/backupvault",
		AssertTransient: true,        // D237: create/delete route through provider.MutationResult
		Classify:        restXMLRole, // REST: GET read, PUT/DELETE opaque (name deterministic)
		OwnerTagValue:   "archive",
		DeterministicID: true, // the vault name is chosen
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("backupvault", "archive", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return bkvServer(t, "archive", true, 90, 0) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("backupvault", "archive", "prod", bkvAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return bkvServer(t, "archive", true, 90, 0) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("backupvault", "archive", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func bkvRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingBackupVault enrols backupvault in the D391 gate. A vault holds
// recovery points: standing one up twice does not just cost money, it SPLITS the backup
// estate, so the second vault looks empty while the real one is unmanaged. The name is
// the address and the tags are the ownership check.
// bkvAdoptSrv builds a 409-adopt fixture: our vault already standing, with the given
// EncryptionKeyArn (D1062). "aws/backup" reads as the AWS-managed key (cmek false),
// a KMS key arn reads as a customer key (cmek true).
func bkvAdoptSrv(encKeyArn string) func() *httptest.Server {
	return func() *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/vault-lock"):
				_, _ = w.Write([]byte(`{}`))
			case r.Method == "PUT":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"AlreadyExistsException","Message":"AlreadyExists"}`))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/tags/"):
				_, _ = w.Write([]byte(`{"Tags":{"groundhold-capability":"vault","groundhold-environment":"prod"}}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"BackupVaultArn":"arn:aws:backup:eu-central-1:000000000000:backup-vault:v",` +
					`"Locked":true,"MinRetentionDays":90,"EncryptionKeyArn":"` + encKeyArn + `"}`))
			default:
				w.WriteHeader(400)
			}
		}))
	}
}

func TestAdoptsExistingBackupVault(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/backupvault",
		Classify:       bkvRole,
		ExistingServer: bkvAdoptSrv("aws/backup"), // AWS-managed key = cmek false, not required by bkvAttrs
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.BackupBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("backupvault", "vault", "prod", bkvAttrs(), nil, "vault", 1)
		},
		AllowedMutations: 2, // the refused PUT + the retention lock
		// D1062: the customer key is fixed at create — its absence fails the adopt.
		AdoptControls: bkvAdoptControls,
		MissingControl: []certifynet.ControlCase{
			{Path: "encryption.customerManagedKeys", Server: bkvAdoptSrv("aws/backup"), // AWS-managed = not customer
				WantStatus: "failed", WantMutations: 2,
				Create: func(pr provider.Provider) provider.CreateResult {
					a := bkvAttrs()
					a["encryption.customerManagedKeys"] = true
					return pr.Create("backupvault", "vault", "prod", a,
						map[string]any{"kms_key_arn": "arn:aws:kms:eu-central-1:000000000000:key/abc"}, "vault", 1)
				}},
		},
		MoreSecure: bkvAdoptSrv("arn:aws:kms:eu-central-1:000000000000:key/customer"), // customer key though not declared
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D724. `Locked` is true for BOTH vault-lock modes — AWS: "A Boolean that indicates
// whether AWS Backup Vault Lock is currently protecting the backup vault." The driver
// read it as COMPLIANCE, so a vault any administrator could unlock at any moment was
// reported as immutable WORM, and a contract demanding `compliance` was satisfied by a
// vault that gives none of it.
//
// LockDate is the field that separates them and it was in the same response:
// "If you applied Vault Lock to your vault without specifying a lock date, you can
// change any of your Vault Lock settings, or delete Vault Lock from the vault entirely,
// at any time."
func TestBackupVaultLockModeComesFromTheLockDate(t *testing.T) {
	const now = 1800000000 // the driver's clock for this test
	cases := []struct {
		name     string
		lockDate int64
		want     any // nil => the attribute must be WITHHELD
	}{
		{"no lock date is deletable at any time", 0, "governance"},
		{"a lock date in the past is immutable", now - 3600, "compliance"},
		{"still inside the cooling-off window", now + 3600, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := bkvServer(t, "archive", true, 90, c.lockDate)
			defer srv.Close()
			d := bkvDriver(t, srv)
			d.Now = func() time.Time { return time.Unix(now, 0) }

			obs, diags, err := d.observeBackupVault("archive",
				"bkv:eu-central-1:000000000000:pv-archive-prod-jvaldlkf")
			if err != nil {
				t.Fatal(err)
			}
			var got any
			for _, o := range obs {
				if o.Path == "retention.lockMode" {
					got = o.Value
				}
			}
			if c.want == nil {
				if got != nil {
					t.Fatalf("a lock that is not yet immutable must not be reported as "+
						"%v — the WORM guarantee is not in force until the lock date", got)
				}
				if len(diags) == 0 {
					t.Fatal("withholding the value without saying why is the silence this " +
						"project treats as a defect of its own")
				}
				return
			}
			if got != c.want {
				t.Fatalf("lockMode = %v, want %v", got, c.want)
			}
		})
	}
}
