package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testBillingAccount = "012345-6789AB-CDEF01"

func budgetAttrs() map[string]any {
	return map[string]any{
		"budget.limit":    "700 EUR",
		"budget.period":   "monthly",
		"alert.threshold": float64(90),
		"service.managed": true,
	}
}

func budgetImpl() map[string]any {
	return map[string]any{
		"billingAccountId": testBillingAccount,
		"pubsubTopic":      "projects/acme-prod/topics/budget-alerts",
	}
}

func TestBuildBillingBudgetHonors(t *testing.T) {
	p, err := BuildBillingBudget("acme-prod", "prod", "cost", budgetAttrs(), budgetImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.CalendarPeriod != "MONTH" {
		t.Fatalf("calendarPeriod = %q", p.CalendarPeriod)
	}
	if p.Units != 700 || p.Nanos != 0 || p.Currency != "EUR" {
		t.Fatalf("limit = %d units, %d nanos, %s", p.Units, p.Nanos, p.Currency)
	}
	// vocab percentage 90 -> API fraction 0.9
	if p.ThresholdPercent != 0.9 {
		t.Fatalf("thresholdPercent = %v (want 0.9)", p.ThresholdPercent)
	}
	if p.BillingAccountID != testBillingAccount {
		t.Fatalf("billingAccountId = %q", p.BillingAccountID)
	}
	body := p.createBody()
	sa := body["amount"].(map[string]any)["specifiedAmount"].(map[string]any)
	if sa["units"] != "700" || sa["currencyCode"] != "EUR" {
		t.Fatalf("specifiedAmount = %+v", sa)
	}
	rule := body["thresholdRules"].([]any)[0].(map[string]any)
	if rule["thresholdPercent"] != 0.9 {
		t.Fatalf("thresholdRules = %+v", rule)
	}
	if _, ok := body["notificationsRule"]; !ok {
		t.Fatalf("pubsubTopic must produce a notificationsRule")
	}
}

func TestBuildBillingBudgetFractionalLimit(t *testing.T) {
	a := budgetAttrs()
	a["budget.limit"] = "99.99 USD"
	p, err := BuildBillingBudget("acme-prod", "prod", "cost", a, budgetImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Units != 99 || p.Nanos != 990000000 {
		t.Fatalf("99.99 -> %d units, %d nanos", p.Units, p.Nanos)
	}
}

func TestBuildBillingBudgetOptionalSink(t *testing.T) {
	impl := map[string]any{"billingAccountId": testBillingAccount} // no sink
	p, err := BuildBillingBudget("acme-prod", "prod", "cost", budgetAttrs(), impl, 1)
	if err != nil {
		t.Fatalf("a budget with no explicit sink must still build (GCP alerts default recipients): %v", err)
	}
	if p.notificationsRule() != nil {
		t.Fatalf("no sink -> no notificationsRule")
	}
}

func TestBuildBillingBudgetRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"daily-unsupported": {map[string]any{"budget.period": "daily"}, budgetImpl()},
		"bad-period":        {map[string]any{"budget.period": "hourly"}, budgetImpl()},
		"unmanaged":         {map[string]any{"service.managed": false}, budgetImpl()},
		"threshold-hi":      {map[string]any{"alert.threshold": float64(150)}, budgetImpl()},
		"threshold-nan":     {map[string]any{"alert.threshold": "lots"}, budgetImpl()},
		"limit-not-money":   {map[string]any{"budget.limit": "700"}, budgetImpl()},
		"limit-neg":         {map[string]any{"budget.limit": "-5 EUR"}, budgetImpl()},
		"unknown-attr":      {map[string]any{"budget.rollover": true}, budgetImpl()},
		"no-account":        {nil, map[string]any{}},
		"bad-account":       {nil, map[string]any{"billingAccountId": "not-an-account"}},
		"bad-topic":         {nil, map[string]any{"billingAccountId": testBillingAccount, "pubsubTopic": "not-a-topic"}},
	}
	for name, c := range cases {
		a := budgetAttrs()
		for k, v := range c.attrs {
			a[k] = v
		}
		if _, err := BuildBillingBudget("acme-prod", "prod", "cost", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing each required attribute
	for _, drop := range []string{"budget.limit", "budget.period", "alert.threshold"} {
		a := budgetAttrs()
		delete(a, drop)
		if _, err := BuildBillingBudget("acme-prod", "prod", "cost", a, budgetImpl(), 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
}

func TestBillingBudgetDisplayNameAndOwnership(t *testing.T) {
	n1 := BillingBudgetDisplayName("prod", "cost", 1)
	n1b := BillingBudgetDisplayName("prod", "cost", 1)
	if n1 != n1b {
		t.Fatalf("display name not deterministic: %q vs %q", n1, n1b)
	}
	if len(n1) > 60 || !strings.HasPrefix(n1, "groundhold-") {
		t.Fatalf("display name shape: %q (len %d)", n1, len(n1))
	}
	// generation salts the name but the ownership token is generation-INDEPENDENT
	n2 := BillingBudgetDisplayName("prod", "cost", 2)
	if n1 == n2 {
		t.Fatalf("g2 must differ from g1")
	}
	if !billingBudgetOurs(n1, "prod", "cost") || !billingBudgetOurs(n2, "prod", "cost") {
		t.Fatalf("both generations must be recognized as ours")
	}
	// a different (env, cap) is NOT ours; a foreign name is NOT ours
	if billingBudgetOurs(n1, "staging", "cost") || billingBudgetOurs("someones-budget", "prod", "cost") {
		t.Fatalf("foreign display names must not be recognized as ours")
	}
}

func TestClassifyBillingBudgetChange(t *testing.T) {
	for _, p := range []string{"budget.limit", "alert.threshold", "budget.period"} {
		if m, _ := classifyBillingBudgetChange(p); m != "mutable" {
			t.Errorf("%s should be mutable, got %q", p, m)
		}
	}
	for _, p := range []string{"service.managed", "cost.monthly", "budget.rollover"} {
		if m, _ := classifyBillingBudgetChange(p); m != "unsupported" {
			t.Errorf("%s should be unsupported, got %q", p, m)
		}
	}
}

// budgetServer is a STATEFUL fake covering list/create/get/patch/delete plus the
// project billingInfo lookup discovery uses.
func budgetServer(t *testing.T) *httptest.Server {
	t.Helper()
	stored := map[string]map[string]any{} // budgetId -> resource
	nextID := "budget-abc123"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/billingInfo") && r.Method == "GET":
			_, _ = w.Write([]byte(`{"billingAccountName":"billingAccounts/` + testBillingAccount + `","billingEnabled":true}`))
		case strings.HasSuffix(path, "/budgets") && r.Method == "POST":
			body, _ := io.ReadAll(r.Body)
			var doc map[string]any
			_ = json.Unmarshal(body, &doc)
			doc["name"] = "billingAccounts/" + testBillingAccount + "/budgets/" + nextID
			stored[nextID] = doc
			b, _ := json.Marshal(doc)
			_, _ = w.Write(b)
		case strings.HasSuffix(path, "/budgets") && r.Method == "GET":
			list := []map[string]any{}
			for _, v := range stored {
				list = append(list, v)
			}
			b, _ := json.Marshal(map[string]any{"budgets": list})
			_, _ = w.Write(b)
		case r.Method == "GET":
			id := path[strings.LastIndex(path, "/")+1:]
			if v, ok := stored[id]; ok {
				b, _ := json.Marshal(v)
				_, _ = w.Write(b)
				return
			}
			w.WriteHeader(404)
		case r.Method == "PATCH":
			id := path[strings.LastIndex(path, "/")+1:]
			body, _ := io.ReadAll(r.Body)
			var patch map[string]any
			_ = json.Unmarshal(body, &patch)
			if v, ok := stored[id]; ok {
				for k, val := range patch {
					v[k] = val
				}
				b, _ := json.Marshal(v)
				_, _ = w.Write(b)
				return
			}
			w.WriteHeader(404)
		case r.Method == "DELETE":
			id := path[strings.LastIndex(path, "/")+1:]
			delete(stored, id)
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}

func budgetDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	billingBudgetsBaseURLOverride = srv.URL
	cloudBillingBaseURLOverride = srv.URL
	t.Cleanup(func() {
		billingBudgetsBaseURLOverride = ""
		cloudBillingBaseURLOverride = ""
	})
	return NewDriver("acme-prod")
}

func TestCreateObserveUpdateDeleteBillingBudget(t *testing.T) {
	srv := budgetServer(t)
	defer srv.Close()
	d := budgetDriver(t, srv)

	res := d.createBillingBudget("cost", "prod", budgetAttrs(), budgetImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	wantPID := billingBudgetProviderID(testBillingAccount, "budget-abc123")
	if res.ProviderID != wantPID {
		t.Fatalf("providerId = %q, want %q", res.ProviderID, wantPID)
	}

	obs, _, err := d.observeBillingBudget("cost", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["budget.period"] != "monthly" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if got["alert.threshold"] != float64(90) {
		t.Fatalf("observe threshold (want 90 percent): %+v", got["alert.threshold"])
	}
	money, ok := got["budget.limit"].(map[string]any)
	if !ok || money["currency"] != "EUR" || money["amount"] != float64(700) {
		t.Fatalf("observe limit: %+v", got["budget.limit"])
	}

	// update limit + threshold in place
	up := budgetAttrs()
	up["budget.limit"] = "1000 EUR"
	up["alert.threshold"] = float64(75)
	ur := d.updateBillingBudget("cost", "prod", res.ProviderID, up, budgetImpl(), []string{"budget.limit", "alert.threshold"})
	if ur.Status != "succeeded" {
		t.Fatalf("update: %+v", ur)
	}
	obs2, _, _ := d.observeBillingBudget("cost", res.ProviderID)
	got2 := map[string]any{}
	for _, o := range obs2 {
		got2[o.Path] = o.Value
	}
	if m := got2["budget.limit"].(map[string]any); m["amount"] != float64(1000) {
		t.Fatalf("post-update limit: %+v", got2["budget.limit"])
	}
	if got2["alert.threshold"] != float64(75) {
		t.Fatalf("post-update threshold: %+v", got2["alert.threshold"])
	}

	if del := d.deleteBillingBudget("cost", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	// idempotent second delete
	if del := d.deleteBillingBudget("cost", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("idempotent delete: %+v", del)
	}
}

func TestCreateBillingBudgetIdempotent(t *testing.T) {
	srv := budgetServer(t)
	defer srv.Close()
	d := budgetDriver(t, srv)

	r1 := d.createBillingBudget("cost", "prod", budgetAttrs(), budgetImpl(), 1)
	if r1.Status != "succeeded" {
		t.Fatalf("first create: %+v", r1)
	}
	// a second create must NOT duplicate — it finds our display name and returns it.
	r2 := d.createBillingBudget("cost", "prod", budgetAttrs(), budgetImpl(), 1)
	if r2.Status != "succeeded" || r2.ProviderID != r1.ProviderID {
		t.Fatalf("second create must be idempotent: %+v (want %s)", r2, r1.ProviderID)
	}
}

func TestDeleteBillingBudgetForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"name":"billingAccounts/` + testBillingAccount + `/budgets/budget-abc123","displayName":"someones-hand-made-budget"}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := billingBudgetProviderID(testBillingAccount, "budget-abc123")
	res := d.deleteBillingBudget("cost", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign budget must refuse delete, got %+v", res)
	}
	// update must refuse it too
	ur := d.updateBillingBudget("cost", "prod", pid, budgetAttrs(), budgetImpl(), []string{"budget.limit"})
	if ur.Status != "failed" || !strings.Contains(ur.Reason, "not ours") {
		t.Fatalf("foreign budget must refuse update, got %+v", ur)
	}
}

func TestDiscoverBillingBudget(t *testing.T) {
	srv := budgetServer(t)
	defer srv.Close()
	d := budgetDriver(t, srv)
	if r := d.createBillingBudget("cost", "prod", budgetAttrs(), budgetImpl(), 1); r.Status != "succeeded" {
		t.Fatalf("seed create: %+v", r)
	}
	found, _, err := d.discoverBillingBudget("")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.cost.budget" {
		t.Fatalf("discover: %+v", found)
	}
	if found[0].ProviderID != billingBudgetProviderID(testBillingAccount, "budget-abc123") {
		t.Fatalf("discover providerId: %q", found[0].ProviderID)
	}
}

func TestSplitBillingBudgetProviderIDRejectsUnsafe(t *testing.T) {
	bad := []string{
		"gcp-billingbudget:012345-6789AB-CDEF01:../etc",
		"gcp-billingbudget:012345-6789AB-CDEF01:a/b",
		"gcp-billingbudget:not-an-account:budget-1",
		"galert:acme:1",
	}
	for _, pid := range bad {
		if _, _, err := splitBillingBudgetProviderID(pid); err == nil {
			t.Errorf("%q must be rejected", pid)
		}
	}
	acct, id, err := splitBillingBudgetProviderID("gcp-billingbudget:012345-6789AB-CDEF01:budget-abc123")
	if err != nil || acct != testBillingAccount || id != "budget-abc123" {
		t.Fatalf("valid providerId parse: %q %q %v", acct, id, err)
	}
}
