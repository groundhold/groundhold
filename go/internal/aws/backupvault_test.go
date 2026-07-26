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
	if _, has := lb["ChangeableForDays"]; has {
		t.Fatal("compliance lock must be immutable (no ChangeableForDays)")
	}
}

func TestBuildBackupVaultGovernanceGrace(t *testing.T) {
	a := bkvAttrs()
	a["retention.lockMode"] = "governance"
	p, err := BuildBackupVault("prod", "archive", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.lockBody()["ChangeableForDays"] != 3 {
		t.Fatalf("governance lock must carry a grace window, got %+v", p.lockBody())
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
func bkvServer(t *testing.T, capLabel string, locked bool, minDays int) *httptest.Server {
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
					`"Locked":` + lockedStr + `,"MinRetentionDays":` + strconv.Itoa(minDays) + `,"EncryptionKeyArn":"aws/backup"}`))
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
	srv := bkvServer(t, "archive", true, 90)
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
	if got["retention.minimum"] != "2160h" || got["retention.lockMode"] != "compliance" ||
		got["location.region"] != "eu-central-1" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("backupvault", "archive", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteBackupVaultForeignRefused(t *testing.T) {
	srv := bkvServer(t, "someone-else", true, 90)
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
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "aws/backupvault",
		AssertTransient: true,        // D237: create/delete route through provider.MutationResult
		Classify:        restXMLRole, // REST: GET read, PUT/DELETE opaque (name deterministic)
		OwnerTagValue:   "archive",
		DeterministicID: true, // the vault name is chosen
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return bkvServer(t, "archive", true, 90) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("backupvault", "archive", "prod", bkvAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return bkvServer(t, "archive", true, 90) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("backupvault", "archive", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}
