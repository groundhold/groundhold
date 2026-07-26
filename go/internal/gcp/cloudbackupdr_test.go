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
		"location.region":    "europe-west1",
		"retention.minimum":  "2160h", // 90 days
		"retention.lockMode": "compliance",
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
		"governance-refused": {"retention.lockMode": "governance"}, // honest gap
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
					`"backupMinimumEnforcedRetentionDuration":"` + retention + `"}`))
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
	if got["retention.minimum"] != "7776000s" || got["retention.lockMode"] != "compliance" ||
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
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "gcp/backupvault",
		AssertTransient: true,      // D237 sweep
		Classify:        gcpOpRole, // LRO create/delete parse the operation name
		OwnerTagValue:   "archive",
		DeterministicID: true, // the vault id is a chosen slug+hash
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
