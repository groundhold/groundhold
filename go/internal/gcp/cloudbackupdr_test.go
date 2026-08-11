package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func bkdrAttrs() map[string]any {
	return map[string]any{
		"location.region":   "europe-west1",
		"retention.minimum": "2160h", // 90 days
		// D752: governance is what this driver BUILDS — it sends no effectiveTime, so
		// the vault it creates is patchable and its data deletable. compliance was the
		// declaration here, and it was a promise the driver could not keep.
		"retention.lockMode": "governance",
		"service.managed":    true,
	}
}

func TestBuildBackupDRHonors(t *testing.T) {
	p, err := BuildBackupDRVault("acme-prod", "prod", "archive", bkdrAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !gcpName.MatchString(p.VaultID) || p.RetentionSeconds != "7776000s" {
		t.Fatalf("plan = %+v", p)
	}
	if p.Labels["groundhold-capability"] != "archive" {
		t.Fatalf("labels = %+v", p.Labels)
	}
}

func TestBuildBackupDRRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		// D752 SUPERSEDES `governance-refused`. It pinned the belief that GCP has no
		// admin-changeable mode; the provider's own contract, and this driver's own
		// createBody, say the opposite. compliance is the refusal now — the driver
		// cannot lock a vault, so promising WORM would be false.
		"compliance-refused": {"retention.lockMode": "compliance"},
		"cmk-refused":        {"encryption.customerManagedKeys": true},
		"bad-lockmode":       {"retention.lockMode": "worm"},
		"no-retention":       {"retention.minimum": nil},
		"no-location":        {"location.region": nil},
		"unmanaged":          {"service.managed": false},
		"unknown-attr":       {"backup.plan": "daily"},
	}
	for name, extra := range cases {
		a := bkdrAttrs()
		for k, v := range extra {
			if v == nil {
				delete(a, k)
			} else {
				a[k] = v
			}
		}
		if _, err := BuildBackupDRVault("acme-prod", "prod", "archive", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// bkdrServer is a happy Backup and DR LRO double. Create/Delete return an op; the op
// polls done; GET reflects labels + retention.
// gcpVaultEffectiveTime is the lock time the fake serves, as a JSON fragment. It served
// NONE, so the driver's read of the field that decides the lock could not be exercised
// end to end — the same blind-spot fixture as preflightFake (D750) and iamRoleXML (D751).
var gcpVaultEffectiveTime = ""

func bkdrServer(t *testing.T, capLabel, retention string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "POST" && strings.Contains(r.URL.Path, "/backupVaults"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-create"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/operations/op-delete"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"labels":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"backupMinimumEnforcedRetentionDuration":"` + retention + `"` +
					gcpVaultEffectiveTime + `}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func bkdrDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.BackupDRBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteBackupDR(t *testing.T) {
	srv := bkdrServer(t, "archive", "7776000s")
	defer srv.Close()
	d := bkdrDriver(t, srv)
	res := d.Create("backupvault", "archive", "prod", bkdrAttrs(), nil, "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gbkv:acme-prod:europe-west1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeBackupDR("archive", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["retention.minimum"] != "7776000s" || got["retention.lockMode"] != "governance" ||
		got["location.region"] != "europe-west1" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("backupvault", "archive", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteBackupDRForeignRefused(t *testing.T) {
	srv := bkdrServer(t, "someone-else", "7776000s")
	defer srv.Close()
	d := bkdrDriver(t, srv)
	pid := backupDRProviderID("acme-prod", "europe-west1", resourceName("acme-prod", "prod", "archive", 1, 63))
	res := d.Delete("backupvault", "archive", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign vault must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessBackupDR(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := backupDRProviderID("acme-prod", "europe-west1", resourceName("acme-prod", "prod", "archive", 1, 63))
	p := &certifynet.Probe{
		Name:            "gcp/backupvault",
		AssertTransient: true,      // D237 sweep
		Classify:        gcpOpRole, // LRO create/delete parse the operation name
		OwnerTagValue:   "archive",
		DeterministicID: true, // the vault id is a chosen slug+hash
		// F-LC3 (D519): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("backupvault", "archive", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return bkdrServer(t, "archive", "7776000s") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("backupvault", "archive", "prod", bkdrAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return bkdrServer(t, "archive", "7776000s") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("backupvault", "archive", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// D752. `retention.lockMode` was the CONSTANT "compliance" — an attribute whose whole
// meaning is which lock is in force, computed from nothing. Google's public discovery
// document names the field that decides it: effectiveTime, "Time after which the
// BackupVault resource is locked", and it is OPTIONAL. Until it passes, `patch` updates
// the vault's settings and `delete force=true` removes it "and any data source from this
// backup vault".
//
// Driven through observeBackupDR, not through the branch expression (D726).
func TestGCPVaultLockModeComesFromTheLockTime(t *testing.T) {
	cases := []struct {
		name      string
		effective string // JSON fragment the fake appends
		want      any    // nil => withheld, with a diagnostic
		diagWant  string
	}{
		{"no lock time — patchable and deletable with its data", "", "governance", ""},
		{"locked in the past", `,"effectiveTime":"2020-01-01T00:00:00Z"`, "compliance", ""},
		{"configured to lock, not locked yet", `,"effectiveTime":"2999-01-01T00:00:00Z"`,
			nil, "locks only at 2999-01-01T00:00:00Z"},
		{"a lock time we cannot read", `,"effectiveTime":"whenever"`,
			nil, "not a timestamp this driver can read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := gcpVaultEffectiveTime
			gcpVaultEffectiveTime = c.effective
			defer func() { gcpVaultEffectiveTime = old }()

			srv := bkdrServer(t, "archive", "7776000s")
			defer srv.Close()
			d := bkdrDriver(t, srv)

			obs, diags, err := d.observeBackupDR("archive",
				"gbkv:acme-prod:europe-west1:archive-prod-2bcec2b5")
			if err != nil {
				t.Fatal(err)
			}
			var got any
			for _, o := range obs {
				if o.Path == "retention.lockMode" {
					got = o.Value
				}
			}
			if got != c.want {
				t.Fatalf("retention.lockMode = %v, want %v — a vault nobody has locked is "+
					"not WORM, and reporting it as WORM satisfies a contract that asked "+
					"for immutability (D752)", got, c.want)
			}
			if c.diagWant != "" {
				found := false
				for _, dg := range diags {
					if strings.Contains(dg, c.diagWant) {
						found = true
					}
				}
				if !found {
					t.Fatalf("withheld the value and said nothing useful: %v", diags)
				}
			}
		})
	}
}

// The builder half: the truth must be declarable, and the promise this driver cannot
// keep must be refused with somewhere to go (D749's lesson, and the routing rule).
func TestGCPVaultBuilderDeclarations(t *testing.T) {
	a := bkdrAttrs()
	a["retention.lockMode"] = "governance"
	if _, err := BuildBackupDRVault("acme-prod", "prod", "archive", a, nil, 1); err != nil {
		t.Fatalf("governance is what this driver builds and it must be declarable: %v", err)
	}
	a["retention.lockMode"] = "compliance"
	_, err := BuildBackupDRVault("acme-prod", "prod", "archive", a, nil, 1)
	if err == nil {
		t.Fatal("compliance must refuse: this driver sends no effectiveTime, so it builds " +
			"a vault it would then have to report as WORM without one")
	}
	for _, want := range []string{"governance", "effectiveTime", "ADOPT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q — a refusal that routes at nothing leaves "+
				"the reader with a blocked plan and no next step", want)
		}
	}
}
