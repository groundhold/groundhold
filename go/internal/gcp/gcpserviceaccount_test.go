package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func readBodyMap(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func gsaAttrs() map[string]any {
	return map[string]any{
		"display.name":    "batch-runner",
		"key.exportable":  false,
		"service.managed": true,
	}
}

func TestBuildGServiceAccountHonors(t *testing.T) {
	p, err := BuildGServiceAccount("acme-prod", "prod", "runner", gsaAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.DisplayName != "batch-runner" || !gsaAccountIDOK.MatchString(p.AccountID) {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("runner", "prod")
	sa := body["serviceAccount"].(map[string]any)
	if !strings.Contains(sa["description"].(string), "capability=runner") {
		t.Fatalf("marker missing: %+v", sa)
	}
}

func TestBuildGServiceAccountRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"exportable-key-refused": {"key.exportable": true}, // D53 — no downloadable key
		"unmanaged":              {"service.managed": false},
		"unknown-attr":           {"identity.tier": "x"},
	}
	for name, extra := range cases {
		a := gsaAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildGServiceAccount("acme-prod", "prod", "runner", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func gsaServer(t *testing.T, capLabel, displayName string) *httptest.Server {
	t.Helper()
	marker := "groundhold:capability=" + capLabel + ";environment=prod"
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/serviceAccounts"):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/serviceAccounts/x","email":"x@acme-prod.iam.gserviceaccount.com",` +
					`"displayName":"` + displayName + `","description":"` + marker + `"}`))
			case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/keys"):
				_, _ = w.Write([]byte(`{"keys":[]}`)) // keyless: no user-managed key
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/serviceAccounts/x","email":"x@acme-prod.iam.gserviceaccount.com",` +
					`"displayName":"` + displayName + `","description":"` + marker + `"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func gsaDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.IAMBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteGServiceAccount(t *testing.T) {
	srv := gsaServer(t, "runner", "batch-runner")
	defer srv.Close()
	d := gsaDriver(t, srv)
	res := d.createGServiceAccount("prod", "runner", gsaAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gsa:acme-prod:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeGServiceAccount("runner", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["display.name"] != "batch-runner" || got["key.exportable"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteGServiceAccount("runner", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// gsaKeysServer serves the SA doc plus a keys.list response the caller supplies.
func gsaKeysServer(keysStatus int, keysBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/keys") {
			if keysStatus != 0 && keysStatus != 200 {
				w.WriteHeader(keysStatus)
			}
			_, _ = w.Write([]byte(keysBody))
			return
		}
		_, _ = w.Write([]byte(`{"email":"runner@acme-prod.iam.gserviceaccount.com","displayName":"R",` +
			`"description":"groundhold:capability=runner;environment=prod"}`))
	}))
}

// THE MUTANT-DEFECT TEST: a discovered/adopted SA carrying a USER_MANAGED key must read
// key.exportable=true (measured) — the downloadable long-lived secret this control
// forbids. The old code hardcoded false and read a key-bearing account as keyless: a
// false-green on discover/posture and a hard `equals false` that could not see the key.
// SYSTEM_MANAGED keys (on every account) must NOT count.
func TestObserveGSA_UserManagedKeyIsExportable(t *testing.T) {
	srv := gsaKeysServer(200, `{"keys":[{"keyType":"SYSTEM_MANAGED"},{"keyType":"USER_MANAGED"}]}`)
	defer srv.Close()
	d := gsaDriver(t, srv)
	obs, _, err := d.observeGServiceAccount("runner", gsaProviderID("acme-prod", "runner-prod-x"))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["key.exportable"] != true {
		t.Fatalf("a USER_MANAGED key must read key.exportable=true (measured), got %v", got["key.exportable"])
	}
}

// SYSTEM_MANAGED-only keys are keyless: key.exportable=false (measured).
func TestObserveGSA_SystemManagedOnlyIsKeyless(t *testing.T) {
	srv := gsaKeysServer(200, `{"keys":[{"keyType":"SYSTEM_MANAGED"}]}`)
	defer srv.Close()
	d := gsaDriver(t, srv)
	obs, _, err := d.observeGServiceAccount("runner", gsaProviderID("acme-prod", "runner-prod-x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "key.exportable" && o.Value != false {
			t.Fatalf("SYSTEM_MANAGED-only must read keyless (false), got %v", o.Value)
		}
	}
}

// An unreadable key list WITHHOLDS key.exportable — never fabricate keyless (the security
// floor then blocks a hard constraint as unknown rather than passing it vacuously).
func TestObserveGSA_UnreadableKeysWithholds(t *testing.T) {
	srv := gsaKeysServer(403, `{"error":{"code":403,"message":"denied"}}`)
	defer srv.Close()
	d := gsaDriver(t, srv)
	obs, diags, err := d.observeGServiceAccount("runner", gsaProviderID("acme-prod", "runner-prod-x"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "key.exportable" {
			t.Fatalf("an unreadable key list must WITHHOLD key.exportable, got %v", o.Value)
		}
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "key.exportable not observed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a withheld key.exportable must diag why, got %v", diags)
	}
}

func TestDeleteGServiceAccountForeignRefused(t *testing.T) {
	srv := gsaServer(t, "someone-else", "batch-runner")
	defer srv.Close()
	d := gsaDriver(t, srv)
	pid := gsaProviderID("acme-prod", GServiceAccountID("acme-prod", "prod", "runner", 1))
	res := d.deleteGServiceAccount("runner", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign account must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.identity.serviceaccount on GCP. A STATEFUL fake records the display name
// the create writes and reflects it on the account read.
func TestMetamorphicGServiceAccountRoundTrip(t *testing.T) {
	for _, name := range []string{"batch-runner", "sync-worker"} {
		t.Run(name, func(t *testing.T) {
			var display string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/serviceAccounts"):
						body := readBodyMap(r)
						sa, _ := body["serviceAccount"].(map[string]any)
						display, _ = sa["displayName"].(string)
						_, _ = w.Write([]byte(`{"displayName":"` + display + `","description":"groundhold:capability=runner;environment=prod"}`))
					case r.Method == "GET":
						_, _ = w.Write([]byte(`{"displayName":"` + display + `","description":"groundhold:capability=runner;environment=prod"}`))
					default:
						_, _ = w.Write([]byte(`{}`))
					}
				}))
			defer srv.Close()
			d := gsaDriver(t, srv)
			a := gsaAttrs()
			a["display.name"] = name
			res := d.createGServiceAccount("prod", "runner", a, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeGServiceAccount("runner", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["display.name"] != name {
				t.Errorf("display name round-trip: want %q got %v", name, got["display.name"])
			}
		})
	}
}
