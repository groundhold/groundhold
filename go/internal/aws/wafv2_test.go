package aws

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

// wafAssociated controls whether the fake's distribution names this WebACL (D765).
var wafAssociated = true

func wafDistributions(arn string) string {
	if !wafAssociated {
		return `<DistributionSummary><Id>E1</Id><WebACLId></WebACLId></DistributionSummary>`
	}
	return `<DistributionSummary><Id>E1</Id><WebACLId>` + arn + `</WebACLId></DistributionSummary>`
}

func wafServer(t *testing.T, capLabel string, prevention, managed, bot bool) *httptest.Server {
	t.Helper()
	const arn = "arn:aws:wafv2:us-east-1:000000000000:global/webacl/pv/id-1"
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// D765: the CloudFront distribution listing, which is the ONLY place a
			// CLOUDFRONT-scope WebACL's associations are visible. The fake answered no
			// such path, so "does this firewall protect anything" could not be asked in
			// any test — and the field found a live firewall protecting nothing.
			if r.Method == "GET" && strings.Contains(r.URL.Path, "/distribution") {
				_, _ = w.Write([]byte(`<DistributionList><Items>` + wafDistributions(arn) +
					`</Items></DistributionList>`))
				return
			}
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
	// D765: the same fake answers the distribution listing, which is where a
	// CLOUDFRONT-scope WebACL's associations are visible.
	d.CloudFrontBaseURL = srv.URL
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
					// D765: this stateful fake reflects what the create wrote; the association
					// lives on the distribution, so it answers that path too.
					if r.Method == "GET" && strings.Contains(r.URL.Path, "/distribution") {
						_, _ = w.Write([]byte(`<DistributionList><Items>` +
							wafDistributions(arn) +
							`</Items></DistributionList>`))
						return
					}
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

func wafRole(req *http.Request, _ []byte) certifynet.Role {
	switch wafTarget2(req) {
	case "ListWebACLs", "GetWebACL", "ListTagsForResource":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingWAF enrols waf in the D391 gate. Unlike apigateway (D410), this
// driver was already sound: CreateWebACL answers WAFDuplicateItem, the driver resolves
// by name and checks the tags before binding. The gate turns that from a code path into
// an asserted property.
func TestAdoptsExistingWAF(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	const arn = "arn:aws:wafv2:eu-central-1:000000000000:regional/webacl/w/id-1"
	p := &certifynet.ExistingProbe{
		Name:     "aws/waf",
		Classify: wafRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch wafTarget2(r) {
					case "CreateWebACL":
						w.WriteHeader(400)
						_, _ = w.Write([]byte(`{"__type":"WAFDuplicateItem","message":"exists"}`))
					case "ListWebACLs":
						_, _ = w.Write([]byte(`{"WebACLs":[{"Name":"` + wafListedName(t) +
							`","Id":"id-1","ARN":"` + arn + `","LockToken":"lt-1"}]}`))
					case "ListTagsForResource":
						_, _ = w.Write([]byte(`{"TagInfoForResource":{"TagList":[` +
							`{"Key":"groundhold-capability","Value":"edge"},` +
							`{"Key":"groundhold-environment","Value":"prod"}]}}`))
					default:
						w.WriteHeader(400)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.WAFBaseURL = happyURL
			d.CloudFrontBaseURL = happyURL
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("waf", "edge", "prod", wafAttrs(), nil, "edge", 1)
		},
		AllowedMutations: 1, // the refused CreateWebACL — the detection itself
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D765, from the field, measured on a live production estate: a WebACL with sensible
// rules — common, bad-inputs, IP reputation, RATE LIMIT — the WRONG SCOPE, and
// `ResourceArns: []`. It protected nothing, and in the console, in the code and in the
// contract it was indistinguishable from one that worked.
//
// The reporter's stake makes the direction concrete: for them a rate limit is not a
// performance control but a defence against enumeration and location triangulation, so a
// firewall that silently guards nothing has a physical consequence.
//
// The vocabulary decides which attribute moves. `bot.protection` says "is managed bot
// mitigation ON" — a statement about the rules, true of an unattached ACL.
// `managed.ruleset` says "am I PROTECTED by the managed baseline" — a statement about
// protection, false when nothing is behind it.
func TestWAFManagedRulesetIsFalseWhenItGuardsNothing(t *testing.T) {
	for _, c := range []struct {
		name       string
		associated bool
		want       any
		diag       string
	}{
		{"a distribution names this ACL", true, true, ""},
		{"no distribution names it — it protects nothing", false, false, "protects nothing"},
	} {
		t.Run(c.name, func(t *testing.T) {
			old := wafAssociated
			wafAssociated = c.associated
			defer func() { wafAssociated = old }()

			srv := wafServer(t, "edge", true, true, true)
			defer srv.Close()
			d := wafDriver(t, srv)

			obs, diags, err := d.observeWAF("edge", "waf:000000000000:"+wafListedName(t))
			if err != nil {
				t.Fatal(err)
			}
			var managed, bot any
			for _, o := range obs {
				switch o.Path {
				case "managed.ruleset":
					managed = o.Value
				case "bot.protection":
					bot = o.Value
				}
			}
			if managed != c.want {
				t.Fatalf("managed.ruleset = %v, want %v — the vocabulary's own words are "+
					"\"am I protected by the managed baseline\" (D765)", managed, c.want)
			}
			if bot != true {
				t.Fatalf("bot.protection = %v, want true in both cases: it says whether the "+
					"bot rules are ON, which an unattached ACL still answers truthfully", bot)
			}
			if c.diag != "" {
				found := false
				for _, dg := range diags {
					if strings.Contains(dg, c.diag) {
						found = true
					}
				}
				if !found {
					t.Fatalf("a bare false teaches nothing; say why: %v", diags)
				}
			}
		})
	}
}

// An unread listing is not an empty one: a denied or failed ListDistributions must leave
// the attribute unobserved, never claim the firewall guards nothing.
func TestWAFProtectionUnknownWhenTheListingCannotBeRead(t *testing.T) {
	srv := wafServer(t, "edge", true, true, true)
	defer srv.Close()
	d := wafDriver(t, srv)
	d.CloudFrontBaseURL = "http://127.0.0.1:1" // nothing answers

	obs, diags, err := d.observeWAF("edge", "waf:000000000000:"+wafListedName(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "managed.ruleset" {
			t.Fatalf("managed.ruleset = %v from a listing that never answered — an "+
				"unattached firewall and an unread one are not the same answer", o.Value)
		}
	}
	found := false
	for _, dg := range diags {
		if strings.Contains(dg, "not observed") {
			found = true
		}
	}
	if !found {
		t.Fatalf("withheld the value and said nothing: %v", diags)
	}
}
