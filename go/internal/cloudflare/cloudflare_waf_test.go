package cloudflare

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

// wafServer serves the two WAF endpoints. entrypoint controls the managed-ruleset rules;
// bot is the raw bot_management result body ("" => 404, "403" => forbidden).
func wafServer(t *testing.T, entrypoint, bot string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/rulesets/phases/http_request_firewall_managed/entrypoint"):
			if entrypoint == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(entrypoint))
		case strings.HasSuffix(r.URL.Path, "/bot_management"):
			switch bot {
			case "":
				w.WriteHeader(http.StatusNotFound)
			case "403":
				w.WriteHeader(http.StatusForbidden)
			default:
				_, _ = w.Write([]byte(bot))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func wafObs(t *testing.T, entrypoint, bot string) (map[string]any, []string) {
	t.Helper()
	srv := wafServer(t, entrypoint, bot)
	defer srv.Close()
	d := &Driver{Token: "test-token", BaseURL: srv.URL, HTTP: srv.Client(), Now: time.Now}
	obs, diags := d.mapZoneWAF("zoneX")
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	return m, diags
}

const managedRulesetEntrypoint = `{"success":true,"result":{"id":"e1","phase":"http_request_firewall_managed","rules":[` +
	`{"action":"execute","enabled":true,"action_parameters":{"id":"efb7b8c949ac4650a09736fc376e9aee"}}]}}`

// TestWAFManagedRulesetInPreventionWithBotFight is the happy path: a Cloudflare managed
// ruleset deployed with no override (blocks) and Bot Fight Mode on.
func TestWAFManagedRulesetInPreventionWithBotFight(t *testing.T) {
	m, diags := wafObs(t, managedRulesetEntrypoint, `{"success":true,"result":{"fight_mode":true}}`)
	if m["managed.ruleset"] != true {
		t.Fatalf("managed.ruleset = %v, want true (a Cloudflare managed ruleset executes)", m["managed.ruleset"])
	}
	if m["policy.mode"] != "prevention" {
		t.Fatalf("policy.mode = %v, want prevention (no log override)", m["policy.mode"])
	}
	if m["bot.protection"] != true {
		t.Fatalf("bot.protection = %v, want true (fight_mode on)", m["bot.protection"])
	}
	if len(diags) != 0 {
		t.Fatalf("no read failed, so no diagnostics expected: %v", diags)
	}
}

// TestWAFLogOverrideIsDetection: the SAME managed ruleset with an override action of "log"
// is detection, not prevention — the axis a compliance contract constrains.
func TestWAFLogOverrideIsDetection(t *testing.T) {
	ep := `{"success":true,"result":{"rules":[{"action":"execute","enabled":true,` +
		`"action_parameters":{"id":"efb7b8c949ac4650a09736fc376e9aee","overrides":{"action":"log"}}}]}}`
	m, _ := wafObs(t, ep, `{"success":true,"result":{"fight_mode":false}}`)
	if m["managed.ruleset"] != true || m["policy.mode"] != "detection" {
		t.Fatalf("a log-override managed ruleset must be detection: managed=%v mode=%v",
			m["managed.ruleset"], m["policy.mode"])
	}
	if m["bot.protection"] != false {
		t.Fatalf("bot.protection = %v, want false (fight_mode off, nothing else)", m["bot.protection"])
	}
}

// TestWAFCustomRulesAreNotAManagedRuleset: a rule that executes a NON-managed ruleset (a
// customer's own) must not read as a deployed managed WAF — the distinction the ID table
// draws.
func TestWAFCustomRulesAreNotAManagedRuleset(t *testing.T) {
	ep := `{"success":true,"result":{"rules":[{"action":"execute","enabled":true,` +
		`"action_parameters":{"id":"00000000000000000000000000000000"}}]}}`
	m, _ := wafObs(t, ep, `{"success":true,"result":{}}`)
	if m["managed.ruleset"] != false {
		t.Fatalf("a custom ruleset is not a managed one: managed.ruleset = %v", m["managed.ruleset"])
	}
	if _, ok := m["policy.mode"]; ok {
		t.Fatalf("policy.mode must be absent when no managed ruleset is deployed, got %v", m["policy.mode"])
	}
}

// TestWAFDisabledRuleDoesNotCount: a managed ruleset rule that is DISABLED is not a
// deployed WAF — reporting it on would overstate protection.
func TestWAFDisabledRuleDoesNotCount(t *testing.T) {
	ep := `{"success":true,"result":{"rules":[{"action":"execute","enabled":false,` +
		`"action_parameters":{"id":"efb7b8c949ac4650a09736fc376e9aee"}}]}}`
	m, _ := wafObs(t, ep, `{"success":true,"result":{}}`)
	if m["managed.ruleset"] != false {
		t.Fatalf("a disabled managed-ruleset rule must read as not deployed: %v", m["managed.ruleset"])
	}
}

// TestWAFNoFirewallPhaseIsAuthoritativeAbsence: a 404 on the entrypoint (a free-tier zone
// with no managed phase) is managed.ruleset=false MEASURED, not an error — but it is a
// different thing from a 403, which stays unknown.
func TestWAFNoFirewallPhaseIsAuthoritativeAbsence(t *testing.T) {
	m, diags := wafObs(t, "", `{"success":true,"result":{"fight_mode":false}}`)
	if m["managed.ruleset"] != false {
		t.Fatalf("a 404 entrypoint is authoritative absence -> managed.ruleset=false, got %v", m["managed.ruleset"])
	}
	for _, dg := range diags {
		if strings.Contains(dg, "managed.ruleset") {
			t.Fatalf("an authoritative absence must not be a diagnostic: %v", dg)
		}
	}
}

// TestWAFBotManagement403IsUnknownNotOff: a 403 on bot_management (a token or plan without
// bot read) is UNKNOWN — bot.protection is OMITTED with a diagnostic, never a fabricated
// "off" that would tell an operator they have no bot exposure when the truth is unread.
func TestWAFBotManagement403IsUnknownNotOff(t *testing.T) {
	m, diags := wafObs(t, managedRulesetEntrypoint, "403")
	if _, ok := m["bot.protection"]; ok {
		t.Fatalf("a 403 bot_management read must OMIT bot.protection, not report %v", m["bot.protection"])
	}
	var told bool
	for _, dg := range diags {
		if strings.Contains(dg, "bot.protection not observed") {
			told = true
		}
	}
	if !told {
		t.Fatalf("the unread bot posture must be disclosed: %v", diags)
	}
}

// TestWAFSuperBotFightModeCounts: a Super Bot Fight Mode action that is not "allow" is
// protection on, even with fight_mode false — the Pro/Business tier signal.
func TestWAFSuperBotFightModeCounts(t *testing.T) {
	m, _ := wafObs(t, managedRulesetEntrypoint,
		`{"success":true,"result":{"fight_mode":false,"sbfm_definitely_automated":"block"}}`)
	if m["bot.protection"] != true {
		t.Fatalf("an sbfm block action is bot protection on: %v", m["bot.protection"])
	}
}

// TestWAFObserveRoutesByProviderID: cfwaf:<zoneId> reaches the WAF map, dns:… the record
// map — the dispatch the ledger relies on to re-observe a bound WAF posture.
func TestWAFObserveRoutesByProviderID(t *testing.T) {
	srv := wafServer(t, managedRulesetEntrypoint, `{"success":true,"result":{"fight_mode":true}}`)
	defer srv.Close()
	d := &Driver{Token: "test-token", BaseURL: srv.URL, HTTP: srv.Client(), Now: time.Now}
	obs, _, err := d.Observe("", "capability.security.waf", "cfwaf:zoneX")
	if err != nil {
		t.Fatalf("observe waf: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["managed.ruleset"] != true || got["bot.protection"] != true {
		t.Fatalf("observe via cfwaf: providerId must return the WAF posture: %v", got)
	}
	if _, _, err := d.Observe("", "", "cfwaf:"); err == nil {
		t.Fatal("a malformed cfwaf providerId must refuse, not silently map an empty zone")
	}
	var _ provider.Observation
}

// TestWAFEmittedEvenWhenDNSFails is D874b, a FIELD-caught defect: a token with zone-list
// but no dns_records read (a real Cloudflare scope) made List `continue` past the WAF
// emission on the DNS failure, so every zone's WAF posture went invisible. DNS records and
// the WAF posture are independent reads; a failure of one must not hide the other.
func TestWAFEmittedEvenWhenDNSFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/zones":
			_, _ = w.Write([]byte(`{"success":true,"result":[{"id":"z1","name":"ex.com","status":"active"}],` +
				`"result_info":{"page":1,"total_pages":1}}`))
		case strings.HasSuffix(r.URL.Path, "/dns_records"):
			w.WriteHeader(http.StatusForbidden) // token cannot read DNS records
		case strings.HasSuffix(r.URL.Path, "/entrypoint"):
			w.WriteHeader(http.StatusNotFound) // authoritative: no managed WAF
		case strings.HasSuffix(r.URL.Path, "/bot_management"):
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	d := &Driver{Token: "test-token", BaseURL: srv.URL, HTTP: srv.Client(), Now: time.Now}

	found, diags, err := d.List("")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var waf *provider.Discovered
	for i := range found {
		if found[i].ResourceType == "capability.security.waf" {
			waf = &found[i]
		}
	}
	if waf == nil {
		t.Fatalf("the WAF posture went invisible because DNS records could not be read — the "+
			"two are independent reads (D874b). Found: %+v, diags: %v", found, diags)
	}
	got := map[string]any{}
	for _, o := range waf.Observations {
		got[o.Path] = o.Value
	}
	if got["managed.ruleset"] != false {
		t.Fatalf("the WAF read (a real 404) must still produce managed.ruleset=false: %v", got)
	}
}
