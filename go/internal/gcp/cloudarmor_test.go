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

func armorAttrs() map[string]any {
	return map[string]any{
		"policy.mode":     "prevention",
		"managed.ruleset": true,
		"bot.protection":  true,
		"service.managed": true,
	}
}

func TestBuildArmorHonors(t *testing.T) {
	p, err := BuildArmor("acme-prod", "prod", "edge", armorAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Prevention || !p.ManagedRuleset || !p.BotProtection {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("edge", "prod")
	if !strings.Contains(body["description"].(string), "capability=edge") {
		t.Fatalf("marker missing: %+v", body["description"])
	}
	if body["adaptiveProtectionConfig"] == nil {
		t.Fatalf("bot protection missing: %+v", body)
	}
	// prevention => the managed rule is enforced (preview=false).
	rules := body["rules"].([]any)
	if rules[0].(map[string]any)["preview"] != false {
		t.Fatalf("prevention must not preview: %+v", rules[0])
	}
}

func TestBuildArmorRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-mode":     {"policy.mode": "paranoid"},
		"unmanaged":    {"service.managed": false},
		"unknown-attr": {"waf.tier": "x"},
	}
	for name, extra := range cases {
		a := armorAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildArmor("acme-prod", "prod", "edge", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := armorAttrs()
	delete(a, "policy.mode")
	if _, err := BuildArmor("acme-prod", "prod", "edge", a, nil, 1); err == nil {
		t.Error("missing policy.mode must refuse")
	}
}

func armorServer(t *testing.T, capLabel string, prevention, managed, bot bool) *httptest.Server {
	t.Helper()
	marker := "groundhold:capability=" + capLabel + ";environment=prod"
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/securityPolicies"):
				_, _ = w.Write([]byte(`{"name":"op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"status":"DONE"}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"opdel"}`))
			case r.Method == "GET":
				rules := `{"priority":2147483647,"action":"allow"}`
				if managed {
					rules = `{"priority":1000,"action":"deny(403)","preview":` + boolStr(!prevention) +
						`,"match":{"expr":{"expression":"evaluatePreconfiguredWaf('sqli-v33-stable')"}}},` + rules
				}
				adaptive := ""
				if bot {
					adaptive = `,"adaptiveProtectionConfig":{"layer7DdosDefenseConfig":{"enable":true}}`
				}
				_, _ = w.Write([]byte(`{"name":"x","description":"` + marker + `","rules":[` + rules + `]` + adaptive + `}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func armorDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.ComputeBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteArmor(t *testing.T) {
	srv := armorServer(t, "edge", true, true, true)
	defer srv.Close()
	d := armorDriver(t, srv)
	res := d.createArmor("prod", "edge", armorAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "armor:acme-prod:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeArmor("edge", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["policy.mode"] != "prevention" || got["managed.ruleset"] != true || got["bot.protection"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteArmor("edge", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteArmorForeignRefused(t *testing.T) {
	srv := armorServer(t, "someone-else", true, false, false)
	defer srv.Close()
	d := armorDriver(t, srv)
	pid := armorProviderID("acme-prod", ArmorPolicyName("acme-prod", "prod", "edge", 1))
	res := d.deleteArmor("edge", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign policy must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.security.waf on GCP Cloud Armor. A STATEFUL fake records the mode
// (preview), managed rule and adaptive protection the create writes and reflects
// them on the get read.
func TestMetamorphicArmorRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		managed  bool
		bot      bool
		wantMode string
	}{
		{"prevention-full", "prevention", true, true, "prevention"},
		{"detection-owasp", "detection", true, false, "detection"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var preview, managed, bot bool
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/securityPolicies"):
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							Rules []struct {
								Preview bool `json:"preview"`
								Match   struct {
									Expr struct {
										Expression string `json:"expression"`
									} `json:"expr"`
								} `json:"match"`
							} `json:"rules"`
							AdaptiveProtectionConfig *struct{} `json:"adaptiveProtectionConfig"`
						}
						_ = json.Unmarshal(body, &doc)
						bot = doc.AdaptiveProtectionConfig != nil
						for _, ru := range doc.Rules {
							if ru.Match.Expr.Expression != "" {
								managed = true
								preview = ru.Preview
							}
						}
						_, _ = w.Write([]byte(`{"name":"op1"}`))
					case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
						_, _ = w.Write([]byte(`{"status":"DONE"}`))
					case r.Method == "GET":
						rules := `{"priority":2147483647,"action":"allow"}`
						if managed {
							rules = `{"action":"deny(403)","preview":` + boolStr(preview) +
								`,"match":{"expr":{"expression":"evaluatePreconfiguredWaf('sqli-v33-stable')"}}},` + rules
						}
						adaptive := ""
						if bot {
							adaptive = `,"adaptiveProtectionConfig":{"layer7DdosDefenseConfig":{"enable":true}}`
						}
						_, _ = w.Write([]byte(`{"description":"groundhold:capability=edge;environment=prod","rules":[` + rules + `]` + adaptive + `}`))
					default:
						w.WriteHeader(404)
					}
				}))
			defer srv.Close()
			d := armorDriver(t, srv)
			a := armorAttrs()
			a["policy.mode"] = c.mode
			a["managed.ruleset"] = c.managed
			a["bot.protection"] = c.bot
			res := d.createArmor("prod", "edge", a, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeArmor("edge", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["policy.mode"] != c.wantMode {
				t.Errorf("mode round-trip: want %q got %v", c.wantMode, got["policy.mode"])
			}
			if got["managed.ruleset"] != c.managed || got["bot.protection"] != c.bot {
				t.Errorf("ruleset round-trip: managed want %v got %v, bot want %v got %v",
					c.managed, got["managed.ruleset"], c.bot, got["bot.protection"])
			}
		})
	}
}
