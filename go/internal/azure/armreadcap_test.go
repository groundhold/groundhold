package azure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRoleDefinitionsListSurvivesTheBuiltInRoles is D872, and it is a FIELD defect: run
// against our own subscription, `discover --provider azure` returned
// "roleDefinitions.list: HTTP 200 but the body did not parse".
//
// The cause was the read cap, not the estate. roleDefinitions.list returns EVERY built-in
// Azure role in one body — 1.14 MB across ~922 roles on a real subscription — with no
// nextLink. The old 1<<20 (1 MB) cap truncated it mid-JSON, so the parse failed on every
// real subscription and capability.authorization.role could never be enumerated. The D803
// truncation disclosure never fired: there was no continuation to note, the loss was
// entirely client-side, and a failed sweep becomes a diagnostic rather than an incomplete
// scope (so posture would count 0 custom roles as EXACT — the D803/D650 shape).
//
// This test stands a roleDefinitions.list body just over the OLD cap and asserts the
// driver reads it whole.
func TestRoleDefinitionsListSurvivesTheBuiltInRoles(t *testing.T) {
	// One built-in role, padded so the whole array clears 1 MB the way ~922 real roles do.
	pad := strings.Repeat("x", 4096)
	var items []string
	for i := 0; len(strings.Join(items, ",")) < (1<<20)+512*1024; i++ {
		items = append(items, fmt.Sprintf(
			`{"name":"role-%d","properties":{"type":"BuiltInRole","description":%q}}`, i, pad))
	}
	// The one custom role we must actually surface, at the END — past the old cap, so a
	// driver that stopped at 1 MB would miss exactly the thing discovery is for.
	items = append(items, `{"name":"11111111-1111-1111-1111-111111111111",`+
		`"properties":{"type":"CustomRole","roleName":"our-role"}}`)
	body := `{"value":[` + strings.Join(items, ",") + `]}`
	if len(body) <= 1<<20 {
		t.Fatalf("test body is %d bytes, not over the old 1MB cap — it would not reproduce", len(body))
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "roleDefinitions") {
			w.WriteHeader(404)
			return
		}
		// The reverse-map re-reads the single custom role (roleDefinitions/<guid>) for its
		// permission set — serve that, so the LIST body is what this test is about.
		if strings.Contains(r.URL.Path, "11111111-1111-1111-1111-111111111111") {
			_, _ = w.Write([]byte(`{"name":"11111111-1111-1111-1111-111111111111",` +
				`"properties":{"type":"CustomRole","roleName":"our-role",` +
				`"permissions":[{"actions":["Microsoft.Storage/*/read"],"notActions":[]}]}}`))
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "t"

	found, diags, err := d.discoverCustomRoles("westeurope")
	if err != nil {
		t.Fatalf("discoverCustomRoles errored on a %d-byte body: %v\ndiags: %v", len(body), err, diags)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.authorization.role" {
		t.Fatalf("expected the one custom role past the old cap, got %d: %v", len(found), found)
	}
	if !strings.Contains(found[0].ProviderID, "11111111-1111-1111-1111-111111111111") {
		t.Fatalf("wrong role surfaced: %s", found[0].ProviderID)
	}
}

// TestAnOverCapARMBodyIsAnErrorNotATruncatedParse: raising the cap must not re-introduce
// the silent truncation it removed. A body PAST the (raised) cap is refused as an error —
// a truncated list handed to a decision-gating parse is the D87 hazard, and a bigger cap
// only moves the cliff unless the cliff itself is made loud.
func TestAnOverCapARMBodyIsAnErrorNotATruncatedParse(t *testing.T) {
	huge := strings.Repeat("a", maxARMResponseBytes+4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"value":"` + huge + `"}`))
	}))
	defer srv.Close()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "t"

	st, body, err := d.doARM("GET", srv.URL+"/x", nil)
	if err == nil {
		t.Fatalf("a body past the %d-byte cap returned no error (status %d, %d bytes) — it "+
			"would be parsed as if complete", maxARMResponseBytes, st, len(body))
	}
	if !strings.Contains(err.Error(), "read cap") {
		t.Fatalf("the error should name the read cap, got: %v", err)
	}
	if body != nil {
		t.Fatalf("an over-cap read must return no body, got %d bytes", len(body))
	}
}
