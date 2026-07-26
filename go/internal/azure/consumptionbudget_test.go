package azure

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func consBudgetAttrs() map[string]any {
	return map[string]any{
		"budget.limit":    "700 EUR",
		"budget.period":   "monthly",
		"alert.threshold": 80,
		"service.managed": true,
	}
}

func consBudgetImpl() map[string]any {
	return map[string]any{
		"billingCurrency": "EUR",
		"contactEmails":   []any{"ops@example.com"},
	}
}

func TestBuildConsumptionBudgetHonors(t *testing.T) {
	p, err := BuildConsumptionBudget("prod", "spend-guard", consBudgetAttrs(), consBudgetImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Amount != 700 || p.Currency != "EUR" || p.TimeGrain != "Monthly" || p.Threshold != 80 {
		t.Fatalf("plan = %+v", p)
	}
	if p.ResourceGroup != "" {
		t.Fatalf("default scope must be subscription (empty rg), got %q", p.ResourceGroup)
	}
	if !consBudgetOurs(p.Name, "prod", "spend-guard") {
		t.Fatalf("name %q must carry ownership marker", p.Name)
	}
	body := p.createBody("2026-07-01T00:00:00Z")
	props := body["properties"].(map[string]any)
	if props["timeGrain"] != "Monthly" || props["amount"] != float64(700) {
		t.Fatalf("body props = %+v", props)
	}
	notif := props["notifications"].(map[string]any)["pv-actual-threshold"].(map[string]any)
	if notif["operator"] != "GreaterThan" || notif["threshold"] != float64(80) || notif["thresholdType"] != "Actual" {
		t.Fatalf("notification = %+v", notif)
	}
}

func TestBuildConsumptionBudgetRGScope(t *testing.T) {
	impl := consBudgetImpl()
	impl["resource_group"] = "rg1"
	p, err := BuildConsumptionBudget("prod", "spend-guard", consBudgetAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.ResourceGroup != "rg1" {
		t.Fatalf("rg scope not honored: %+v", p)
	}
}

func TestBuildConsumptionBudgetActionGroupSink(t *testing.T) {
	impl := map[string]any{
		"billingCurrency": "EUR",
		"actionGroups":    []any{"/subscriptions/x/resourceGroups/rg/providers/Microsoft.Insights/actionGroups/ag"},
	}
	if _, err := BuildConsumptionBudget("prod", "spend-guard", consBudgetAttrs(), impl, 1); err != nil {
		t.Fatalf("action-group sink alone must be accepted: %v", err)
	}
}

func TestBuildConsumptionBudgetRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"daily-refused":     {mergeCB(consBudgetAttrs(), map[string]any{"budget.period": "daily"}), consBudgetImpl()},
		"currency-mismatch": {consBudgetAttrs(), map[string]any{"billingCurrency": "USD", "contactEmails": []any{"a@b.com"}}},
		"no-billing-cur":    {consBudgetAttrs(), map[string]any{"contactEmails": []any{"a@b.com"}}},
		"no-sink":           {consBudgetAttrs(), map[string]any{"billingCurrency": "EUR"}},
		"unmanaged":         {mergeCB(consBudgetAttrs(), map[string]any{"service.managed": false}), consBudgetImpl()},
		"unknown-attr":      {mergeCB(consBudgetAttrs(), map[string]any{"budget.tier": "x"}), consBudgetImpl()},
		"bad-threshold":     {mergeCB(consBudgetAttrs(), map[string]any{"alert.threshold": 150}), consBudgetImpl()},
		"limit-not-money":   {mergeCB(consBudgetAttrs(), map[string]any{"budget.limit": 700}), consBudgetImpl()},
		"bad-email":         {consBudgetAttrs(), map[string]any{"billingCurrency": "EUR", "contactEmails": []any{"not-an-email"}}},
		"bad-actiongroup":   {consBudgetAttrs(), map[string]any{"billingCurrency": "EUR", "actionGroups": []any{"just-a-name"}}},
	}
	for name, c := range cases {
		if _, err := BuildConsumptionBudget("prod", "spend-guard", c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing required attributes each refuse.
	for _, drop := range []string{"budget.limit", "budget.period", "alert.threshold"} {
		a := consBudgetAttrs()
		delete(a, drop)
		if _, err := BuildConsumptionBudget("prod", "spend-guard", a, consBudgetImpl(), 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func TestConsumptionBudgetClassifyChange(t *testing.T) {
	for _, p := range []string{"budget.limit", "alert.threshold", "budget.period"} {
		if kind, _ := classifyConsumptionBudgetChange(p); kind != "mutable" {
			t.Errorf("%s should be mutable, got %q", p, kind)
		}
	}
	if kind, _ := classifyConsumptionBudgetChange("service.managed"); kind != "unsupported" {
		t.Errorf("service.managed should be unsupported, got %q", kind)
	}
}

func TestConsumptionBudgetNameGenerations(t *testing.T) {
	g1 := ConsumptionBudgetName("prod", "spend-guard", 1)
	g2 := ConsumptionBudgetName("prod", "spend-guard", 2)
	if g1 == g2 {
		t.Fatal("generation must discriminate the name")
	}
	// owner token is generation-independent — both are still ours.
	if !consBudgetOurs(g1, "prod", "spend-guard") || !consBudgetOurs(g2, "prod", "spend-guard") {
		t.Fatal("both generations must carry the ownership marker")
	}
	if consBudgetOurs(g1, "prod", "other-cap") {
		t.Fatal("a different capability must not match ownership")
	}
}

func consBudgetDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = func() time.Time { return time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC) }
	return d
}

// consBudgetServer serves a Consumption budget with the given name back on GET.
func consBudgetServer(t *testing.T, name string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"name":"` + name + `"}`))
		case "GET":
			doc := map[string]any{
				"name": name,
				"properties": map[string]any{
					"category":     "Cost",
					"amount":       700,
					"timeGrain":    "Monthly",
					"timePeriod":   map[string]any{"startDate": "2026-06-01T00:00:00Z"},
					"currentSpend": map[string]any{"amount": 12.5, "unit": "EUR"},
					"notifications": map[string]any{
						"pv-actual-threshold": map[string]any{
							"enabled": true, "operator": "GreaterThan", "threshold": 80, "thresholdType": "Actual",
							"contactEmails": []string{"ops@example.com"},
						},
					},
				},
			}
			b, _ := json.Marshal(doc)
			_, _ = w.Write(b)
		case "DELETE":
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestCreateObserveUpdateDeleteConsumptionBudget(t *testing.T) {
	name := ConsumptionBudgetName("prod", "spend-guard", 1)
	srv := consBudgetServer(t, name)
	defer srv.Close()
	d := consBudgetDriver(t, srv)

	res := d.createConsumptionBudget("prod", "spend-guard", consBudgetAttrs(), consBudgetImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID != consBudgetProviderID(testSub, "", name) {
		t.Fatalf("create: %+v", res)
	}

	obs, _, err := d.observeConsumptionBudget("spend-guard", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	lim, ok := got["budget.limit"].(map[string]any)
	if !ok || lim["currency"] != "EUR" || lim["amount"] != float64(700) {
		t.Fatalf("observe budget.limit = %+v", got["budget.limit"])
	}
	if got["budget.period"] != "monthly" || got["alert.threshold"] != float64(80) {
		t.Fatalf("observe = %+v", got)
	}

	upd := d.updateConsumptionBudget("spend-guard", "prod", res.ProviderID, consBudgetAttrs(), consBudgetImpl(), []string{"alert.threshold"})
	if upd.Status != "succeeded" {
		t.Fatalf("update: %+v", upd)
	}

	del := d.deleteConsumptionBudget("spend-guard", "prod", res.ProviderID)
	if del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteConsumptionBudgetForeignRefused(t *testing.T) {
	// a name that does not carry our owner token must be refused before any call.
	srv := consBudgetServer(t, "someone-elses-budget")
	defer srv.Close()
	d := consBudgetDriver(t, srv)
	pid := consBudgetProviderID(testSub, "", "someone-elses-budget")
	res := d.deleteConsumptionBudget("spend-guard", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign budget must refuse delete, got %+v", res)
	}
}

func TestDiscoverConsumptionBudget(t *testing.T) {
	name := ConsumptionBudgetName("prod", "spend-guard", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := map[string]any{
			"value": []any{map[string]any{
				"name": name,
				"properties": map[string]any{
					"amount": 700, "timeGrain": "Monthly",
					"currentSpend": map[string]any{"unit": "EUR"},
				},
			}},
		}
		b, _ := json.Marshal(doc)
		_, _ = w.Write(b)
	}))
	defer srv.Close()
	d := consBudgetDriver(t, srv)
	found, _, err := d.discoverConsumptionBudget("eastus")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.cost.budget" {
		t.Fatalf("discover = %+v", found)
	}
	if found[0].ProviderID != consBudgetProviderID(testSub, "", name) {
		t.Fatalf("discover providerId = %q", found[0].ProviderID)
	}
}

func mergeCB(base, over map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		out[k] = v
	}
	return out
}
