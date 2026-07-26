package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func wafAttrs() map[string]any {
	return map[string]any{
		"policy.mode":     "prevention",
		"managed.ruleset": true,
		"bot.protection":  true,
		"service.managed": true,
	}
}

func TestBuildWAFHonors(t *testing.T) {
	p, err := BuildWAF("prod", "edge", wafAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Prevention || !p.ManagedRuleset || !p.BotProtection {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("edge", "prod")
	rules := body["Rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("rules = %+v", rules)
	}
	// prevention => OverrideAction None (block)
	r0 := rules[0].(map[string]any)
	if _, none := r0["OverrideAction"].(map[string]any)["None"]; !none {
		t.Fatalf("prevention must use None override: %+v", r0)
	}
}

func TestBuildWAFDetectionCounts(t *testing.T) {
	a := wafAttrs()
	a["policy.mode"] = "detection"
	p, err := BuildWAF("prod", "edge", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	body := p.createBody("edge", "prod")
	r0 := body["Rules"].([]any)[0].(map[string]any)
	if _, count := r0["OverrideAction"].(map[string]any)["Count"]; !count {
		t.Fatalf("detection must use Count override: %+v", r0)
	}
}

func TestBuildWAFRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-mode":     {"policy.mode": "paranoid"},
		"unmanaged":    {"service.managed": false},
		"unknown-attr": {"waf.tier": "x"},
	}
	for name, extra := range cases {
		a := wafAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildWAF("prod", "edge", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := wafAttrs()
	delete(a, "policy.mode")
	if _, err := BuildWAF("prod", "edge", a, nil, 1); err == nil {
		t.Error("missing policy.mode must refuse")
	}
}

func wafTarget2(r *http.Request) string {
	full := r.Header.Get("X-Amz-Target")
	return full[strings.LastIndex(full, ".")+1:]
}

func wafServer(t *testing.T, capLabel string, prevention, managed, bot bool) *httptest.Server {
	t.Helper()
	const arn = "arn:aws:wafv2:us-east-1:000000000000:global/webacl/pv/id-1"
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch wafTarget2(r) {
			case "CreateWebACL":
				_, _ = w.Write([]byte(`{"Summary":{"Id":"id-1","ARN":"` + arn + `","LockToken":"lt-1"}}`))
			case "ListWebACLs":
				_, _ = w.Write([]byte(`{"WebACLs":[{"Name":"` + wafListedName(t) + `","Id":"id-1","ARN":"` + arn + `","LockToken":"lt-1"}]}`))
			case "GetWebACL":
				override := `{"None":{}}`
				if !prevention {
					override = `{"Count":{}}`
				}
				rules := ""
				if managed {
					rules += `{"Statement":{"ManagedRuleGroupStatement":{"Name":"AWSManagedRulesCommonRuleSet"}},"OverrideAction":` + override + `}`
				}
				if bot {
					if rules != "" {
						rules += ","
					}
					rules += `{"Statement":{"ManagedRuleGroupStatement":{"Name":"AWSManagedRulesBotControlRuleSet"}},"OverrideAction":` + override + `}`
				}
				_, _ = w.Write([]byte(`{"WebACL":{"DefaultAction":{"Allow":{}},"Rules":[` + rules + `]}}`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"TagInfoForResource":{"TagList":[{"Key":"groundhold-capability","Value":"` + capLabel + `"},{"Key":"groundhold-environment","Value":"prod"}]}}`))
			case "DeleteWebACL":
				w.WriteHeader(200)
			default:
				w.WriteHeader(400)
			}
		}))
}

// wafListedName is the deterministic name the create/observe/delete flow uses, so
// the ListWebACLs stub returns a matching entry.
func wafListedName(t *testing.T) string {
	t.Helper()
	return WAFACLName("prod", "edge", 1)
}

func readJSON3(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func wafDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("us-east-1")
	d.Account = "000000000000"
	d.WAFBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteWAF(t *testing.T) {
	srv := wafServer(t, "edge", true, true, true)
	defer srv.Close()
	d := wafDriver(t, srv)
	res := d.createWAF("000000000000", "prod", "edge", wafAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "waf:000000000000:pv-") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeWAF("edge", res.ProviderID)
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
	if del := d.deleteWAF("edge", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteWAFForeignRefused(t *testing.T) {
	srv := wafServer(t, "someone-else", true, false, false)
	defer srv.Close()
	d := wafDriver(t, srv)
	pid := wafProviderID("000000000000", WAFACLName("prod", "edge", 1))
	res := d.deleteWAF("edge", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign WebACL must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.security.waf on AWS WAFv2. A STATEFUL fake records the mode + managed
// rule groups the create writes and reflects them on the get read.
func TestMetamorphicWAFRoundTrip(t *testing.T) {
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
			const arn = "arn:aws:wafv2:us-east-1:000000000000:global/webacl/pv/id-1"
			var prevention, managed, bot bool
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch wafTarget2(r) {
					case "CreateWebACL":
						body := readJSON3(r)
						rules, _ := body["Rules"].([]any)
						for _, ra := range rules {
							rm := ra.(map[string]any)
							nm := rm["Statement"].(map[string]any)["ManagedRuleGroupStatement"].(map[string]any)["Name"].(string)
							if nm == "AWSManagedRulesCommonRuleSet" {
								managed = true
							}
							if nm == "AWSManagedRulesBotControlRuleSet" {
								bot = true
							}
							if _, none := rm["OverrideAction"].(map[string]any)["None"]; none {
								prevention = true
							}
						}
						_, _ = w.Write([]byte(`{"Summary":{"Id":"id-1","ARN":"` + arn + `","LockToken":"lt-1"}}`))
					case "ListWebACLs":
						_, _ = w.Write([]byte(`{"WebACLs":[{"Name":"` + WAFACLName("prod", "edge", 1) + `","Id":"id-1","ARN":"` + arn + `","LockToken":"lt-1"}]}`))
					case "GetWebACL":
						override := `{"Count":{}}`
						if prevention {
							override = `{"None":{}}`
						}
						parts := []string{}
						if managed {
							parts = append(parts, `{"Statement":{"ManagedRuleGroupStatement":{"Name":"AWSManagedRulesCommonRuleSet"}},"OverrideAction":`+override+`}`)
						}
						if bot {
							parts = append(parts, `{"Statement":{"ManagedRuleGroupStatement":{"Name":"AWSManagedRulesBotControlRuleSet"}},"OverrideAction":`+override+`}`)
						}
						_, _ = w.Write([]byte(`{"WebACL":{"DefaultAction":{"Allow":{}},"Rules":[` + strings.Join(parts, ",") + `]}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := wafDriver(t, srv)
			a := wafAttrs()
			a["policy.mode"] = c.mode
			a["managed.ruleset"] = c.managed
			a["bot.protection"] = c.bot
			res := d.createWAF("000000000000", "prod", "edge", a, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeWAF("edge", res.ProviderID)
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
			if got["managed.ruleset"] != c.managed {
				t.Errorf("managed round-trip: want %v got %v", c.managed, got["managed.ruleset"])
			}
			if got["bot.protection"] != c.bot {
				t.Errorf("bot round-trip: want %v got %v", c.bot, got["bot.protection"])
			}
		})
	}
}
