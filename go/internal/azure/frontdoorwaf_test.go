package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func fdWafAttrs() map[string]any {
	return map[string]any{
		"policy.mode":     "prevention",
		"managed.ruleset": true,
		"bot.protection":  true,
		"service.managed": true,
	}
}

func fdWafImpl() map[string]any { return map[string]any{"resource_group": "rg1"} }

func TestBuildFrontDoorWAFHonors(t *testing.T) {
	p, err := BuildFrontDoorWAF("prod", "edge", fdWafAttrs(), fdWafImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Prevention || !p.ManagedRuleset || !p.BotProtection || !fdWAFNameOK.MatchString(p.Name) {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody(map[string]any{})
	props := body["properties"].(map[string]any)
	if props["policySettings"].(map[string]any)["mode"] != "Prevention" {
		t.Fatalf("body = %+v", props)
	}
	if len(props["managedRules"].(map[string]any)["managedRuleSets"].([]any)) != 2 {
		t.Fatalf("rulesets = %+v", props["managedRules"])
	}
}

func TestBuildFrontDoorWAFRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"bad-mode":     {"policy.mode": "paranoid"},
		"unmanaged":    {"service.managed": false},
		"unknown-attr": {"waf.tier": "x"},
	}
	for name, extra := range cases {
		a := fdWafAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildFrontDoorWAF("prod", "edge", a, fdWafImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := fdWafAttrs()
	delete(a, "policy.mode")
	if _, err := BuildFrontDoorWAF("prod", "edge", a, fdWafImpl(), 1); err == nil {
		t.Error("missing policy.mode must refuse")
	}
}

func fdWafServer(t *testing.T, capLabel, mode string, managed, bot bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				sets := []string{}
				if managed {
					sets = append(sets, `{"ruleSetType":"Microsoft_DefaultRuleSet"}`)
				}
				if bot {
					sets = append(sets, `{"ruleSetType":"Microsoft_BotManagerRuleSet"}`)
				}
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","policySettings":{"mode":"` + mode + `"},` +
					`"managedRules":{"managedRuleSets":[` + strings.Join(sets, ",") + `]}}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func fdWafDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteFrontDoorWAF(t *testing.T) {
	srv := fdWafServer(t, "edge", "Prevention", true, true)
	defer srv.Close()
	d := fdWafDriver(t, srv)
	res := d.createFrontDoorWAF("prod", "edge", fdWafAttrs(), fdWafImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "fdwaf:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeFrontDoorWAF("edge", res.ProviderID)
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
	if del := d.deleteFrontDoorWAF("edge", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteFrontDoorWAFForeignRefused(t *testing.T) {
	srv := fdWafServer(t, "someone-else", "Detection", false, false)
	defer srv.Close()
	d := fdWafDriver(t, srv)
	pid := frontDoorWAFProviderID(testSub, "rg1", frontDoorWAFName("prod", "edge", 1))
	res := d.deleteFrontDoorWAF("edge", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign policy must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessFrontDoorWAF(t *testing.T) {
	pid := frontDoorWAFProviderID(testSub, "rg1", frontDoorWAFName("prod", "edge", 1))
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "azure/frontdoorwaf",
		Classify:        armRole,
		OwnerTagValue:   "edge",
		AssertTransient: true, // D237
		DeterministicID: true,
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.BaseURL = happyURL
			d.HTTP = &http.Client{Transport: rt}
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return fdWafServer(t, "edge", "Prevention", true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("frontdoorwaf", "edge", "prod", fdWafAttrs(), fdWafImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return fdWafServer(t, "edge", "Prevention", true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("frontdoorwaf", "edge", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.security.waf on Azure Front Door WAF.
func TestMetamorphicFrontDoorWAFRoundTrip(t *testing.T) {
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
			var mode string
			var managed, bot bool
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "PUT":
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							Properties struct {
								PolicySettings struct {
									Mode string `json:"mode"`
								} `json:"policySettings"`
								ManagedRules struct {
									ManagedRuleSets []struct {
										RuleSetType string `json:"ruleSetType"`
									} `json:"managedRuleSets"`
								} `json:"managedRules"`
							} `json:"properties"`
						}
						_ = json.Unmarshal(body, &doc)
						mode = doc.Properties.PolicySettings.Mode
						for _, rs := range doc.Properties.ManagedRules.ManagedRuleSets {
							if rs.RuleSetType == "Microsoft_DefaultRuleSet" {
								managed = true
							}
							if rs.RuleSetType == "Microsoft_BotManagerRuleSet" {
								bot = true
							}
						}
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
					case "GET":
						sets := []string{}
						if managed {
							sets = append(sets, `{"ruleSetType":"Microsoft_DefaultRuleSet"}`)
						}
						if bot {
							sets = append(sets, `{"ruleSetType":"Microsoft_BotManagerRuleSet"}`)
						}
						_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"edge","groundhold-environment":"prod"},` +
							`"properties":{"provisioningState":"Succeeded","policySettings":{"mode":"` + mode + `"},` +
							`"managedRules":{"managedRuleSets":[` + strings.Join(sets, ",") + `]}}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := fdWafDriver(t, srv)
			a := fdWafAttrs()
			a["policy.mode"] = c.mode
			a["managed.ruleset"] = c.managed
			a["bot.protection"] = c.bot
			res := d.createFrontDoorWAF("prod", "edge", a, fdWafImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeFrontDoorWAF("edge", res.ProviderID)
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
