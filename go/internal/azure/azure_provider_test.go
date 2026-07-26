package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// azValidServiceFixtures pairs EVERY wired azure service token (the keys of
// azureServices) with a real, ACCEPTED attrs/impl combination borrowed from that
// service's own "Honors" test elsewhere in this package. TestValidateDispatch
// below runs every one of them through the driver-level Validate dispatch (not
// the bare BuildXxx call the sibling test already exercises) — proving the
// SWITCH in azure_provider.go routes each token to the RIGHT builder, not just
// that the builder itself works.
func azValidServiceFixtures() map[string]struct{ attrs, impl map[string]any } {
	aksAttrs, aksImpl := aksCandidate()
	return map[string]struct{ attrs, impl map[string]any }{
		"vnet":             {vnetAttrs(), map[string]any{"resource_group": "rg1"}},
		"azvm":             {azVMAttrs(), azVMImpl()},
		"blob":             {blobAttrs(), map[string]any{"resource_group": "rg1"}},
		"containerapps":    {acaAttrs(), acaImpl()},
		"flexpostgres":     {flexAttrs(), flexImpl()},
		"servicebusqueue":  {sbQueueAttrs(), nil},
		"servicebustopic":  {map[string]any{"location.region": "eastus", "encryption.atRest": true, "service.managed": true}, nil},
		"keyvault":         {kvAttrs(), kvImpl()},
		"rediscache":       {redisAzAttrs(), redisAzImpl()},
		"dnszone":          {azDNSAttrs(), nil},
		"dnsrecord":        {azDNSRecordAttrs(), azDNSRecordImpl()},
		"roleassignment":   {azRoleAttrs(), nil},
		"customroledef":    {azRoleDefAttrs(), nil},
		"metricalert":      {azAlertAttrs(), azAlertImpl()},
		"portaldash":       {azDashAttrs(), azDashImpl()},
		"webtest":          {azWebtestAttrs(), azWebtestImpl()},
		"scheduledquery":   {azSQAttrs(), azSQImpl()},
		"acr":              {acrAttrs(), acrImpl()},
		"azurefiles":       {azfilesAttrs(), azfilesImpl()},
		"cosmos":           {cosmosAttrs(), cosmosImpl()},
		"aisearch":         {aiSearchAttrs(), aiSearchImpl()},
		"eventhubs":        {ehAttrs(), ehImpl()},
		"azkafka":          {azKafkaAttrs(), azKafkaImpl()},
		"frontdoorwaf":     {fdWafAttrs(), fdWafImpl()},
		"azurecdn":         {azCDNAttrs(), azCDNImpl()},
		"apim":             {apimAttrs(), apimImpl()},
		"containerappsjob": {cajAttrs(), cajImpl()},
		"managedidentity":  {uamiAttrs(), uamiImpl()},
		"keyvaultkey":      {azKeyAttrs(), azKeyImpl()},
		"changefeed":       {changeFeedAttrs(), nil},
		"loadbalancer": {
			map[string]any{"location.region": "eastus", "network.publicExposure": true},
			map[string]any{
				"resource_group": "rg1",
				"subnetId":       "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/virtualNetworks/vn/subnets/agw",
				"publicIpId":     "/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Network/publicIPAddresses/pip",
			},
		},
		"consumptionbudget":    {consBudgetAttrs(), consBudgetImpl()},
		"loganalytics":         {laAttrs(), laImpl()},
		"activitylog":          {activityLogAttrs(), activityLogImpl()},
		"defender":             {defenderAttrs(true, true, true), nil},
		"azureopenai":          {aoiAttrs(), map[string]any{"resource_group": "rg1", "deployment_model": "gpt-4o", "deployment_sku": "Standard"}},
		"aks":                  {aksAttrs, aksImpl},
		"aks-addon":            {aksAddonAttrs(), aksAddonImpl()},
		"aks-workloadidentity": {aksWIAttrs(), aksWIImpl()},
		"backuppolicy":         {backupPolicyAttrs(), backupPolicyImpl()},
		"backupvault":          {bvAttrs(), bvImpl()},
		"acsemail":             {acsEmailAttrs(), acsEmailImpl()},
	}
}

// TestValidateDispatchAllWiredServices proves EVERY wired service's Validate case
// routes to its OWN builder and accepts a real, valid candidate — not just that
// the builder in isolation works (already pinned per-service), but that the
// azure_provider.go switch wires the RIGHT one to the RIGHT token. A copy-paste
// mistake in the switch (e.g. two tokens routed to the same builder) would show
// up here as a spurious refusal.
func TestValidateDispatchAllWiredServices(t *testing.T) {
	fixtures := azValidServiceFixtures()
	for svc := range azureServices {
		fx, ok := fixtures[svc]
		if !ok {
			t.Errorf("service %q has no fixture in azValidServiceFixtures — add one so Validate dispatch is exercised", svc)
			continue
		}
		t.Run(svc, func(t *testing.T) {
			d := NewDriver(testSub)
			if err := d.Validate(svc, "cap", "prod", fx.attrs, fx.impl, 1); err != nil {
				t.Fatalf("Validate(%q) with a known-good candidate must succeed, got: %v", svc, err)
			}
		})
	}
}

// TestValidateUnknownServiceFailsClosed: dispatch is fail-closed (D76) — an
// unrecognized token is refused before any builder runs.
func TestValidateUnknownServiceFailsClosed(t *testing.T) {
	d := NewDriver(testSub)
	err := d.Validate("__not_a_service__", "cap", "prod", nil, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "unknown service") {
		t.Fatalf("an unknown service must be refused, got: %v", err)
	}
}

// TestValidateBadSubscriptionFailsClosed: requireService also bounds the pinned
// subscription — a non-GUID subscription refuses before any per-service work,
// for every entry point that shares requireService (Validate/Create/Delete/Update).
func TestValidateBadSubscriptionFailsClosed(t *testing.T) {
	d := NewDriver("not-a-guid")
	if err := d.Validate("vnet", "cap", "prod", vnetAttrs(), map[string]any{"resource_group": "rg1"}, 1); err == nil ||
		!strings.Contains(err.Error(), "not a valid GUID") {
		t.Fatalf("a malformed subscription must refuse, got: %v", err)
	}
	res := d.Create("vnet", "cap", "prod", vnetAttrs(), map[string]any{"resource_group": "rg1"}, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not a valid GUID") {
		t.Fatalf("Create must refuse the same way, got: %+v", res)
	}
	del := d.Delete("vnet", "cap", "prod", "vnet:x:y:z", "k")
	if del.Status != "failed" || !strings.Contains(del.Reason, "not a valid GUID") {
		t.Fatalf("Delete must refuse the same way, got: %+v", del)
	}
	upd := d.Update("consumptionbudget", "cap", "prod", "x", nil, nil, nil, "k")
	if upd.Status != "failed" || !strings.Contains(upd.Reason, "not a valid GUID") {
		t.Fatalf("Update must refuse the same way, got: %+v", upd)
	}
}

// notFoundServer answers every request with a plain 404 — the generic double
// used below to exercise DISPATCH (routing a service token to its own per-service
// function) without needing a realistic response shape for all ~41 services.
func notFoundServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
}

func fastDispatchDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 50 * time.Millisecond
	d.AKSLROTimeout = 50 * time.Millisecond
	return d
}

// TestCreateObserveDeleteDispatchRouteEveryWiredService is the symmetric sibling
// of TestClassifyChangeCompleteness/TestObserveCompleteness (completeness_test.go),
// but exercised at RUNTIME rather than by parsing source: for every service
// azureServices declares wired, Create/Observe/Delete must route to that
// service's OWN handler — never fall through to the generic "is not wired yet"
// default, which is the only place that exact phrase is produced. The
// candidate/providerId inputs are deliberately minimal (empty attrs, a
// syntactically-plausible-but-fake providerId): this test's job is proving
// DISPATCH is complete, not re-proving each service's business logic (already
// pinned in that service's own _test.go). Iterating the live azureServices map
// (rather than a hand-maintained list here) means a newly wired service with a
// forgotten case is caught automatically, the same self-updating discipline the
// other completeness tests use.
func TestCreateObserveDeleteDispatchRouteEveryWiredService(t *testing.T) {
	srv := notFoundServer()
	defer srv.Close()

	for svc := range azureServices {
		t.Run(svc, func(t *testing.T) {
			d := fastDispatchDriver(t, srv)

			cr := d.Create(svc, "cap", "prod", map[string]any{}, map[string]any{}, "key", 1)
			if strings.Contains(cr.Reason, "not wired yet") {
				t.Errorf("Create(%q) fell through to the default case — missing dispatch", svc)
			}

			if _, _, err := d.Observe(svc, "cap", svc+":dummy:pid"); err != nil &&
				strings.Contains(err.Error(), "not wired yet") {
				t.Errorf("Observe(%q) fell through to the default case — missing dispatch", svc)
			}

			del := d.Delete(svc, "cap", "prod", svc+":dummy:pid", "key")
			if strings.Contains(del.Reason, "not wired yet") {
				t.Errorf("Delete(%q) fell through to the default case — missing dispatch", svc)
			}
		})
	}
}

// TestCreateDeleteUnknownServiceFailsClosed / no-token gate: mirrors
// TestValidateUnknownServiceFailsClosed for the mutation entry points, and pins
// the refuse-before-mutate token gate shared by Create/Delete/Update (D29/D87 —
// never attempt a mutation the driver cannot even authenticate).
func TestCreateDeleteNoTokenRefusesBeforeMutating(t *testing.T) {
	d := NewDriver(testSub)
	d.token = ""
	if res := d.Create("blob", "cap", "prod", nil, nil, "k", 1); res.Status != "failed" ||
		!strings.Contains(res.Reason, "no Azure access token") {
		t.Fatalf("Create with no token must refuse, got %+v", res)
	}
	if res := d.Delete("blob", "cap", "prod", "blob:x", "k"); res.Status != "failed" ||
		!strings.Contains(res.Reason, "no Azure access token") {
		t.Fatalf("Delete with no token must refuse, got %+v", res)
	}
	if res := d.Update("consumptionbudget", "cap", "prod", "x", nil, nil, nil, "k"); res.Status != "failed" ||
		!strings.Contains(res.Reason, "no Azure access token") {
		t.Fatalf("Update with no token must refuse, got %+v", res)
	}
}

func TestCreateDeleteUnknownServiceFailsClosed(t *testing.T) {
	d := NewDriver(testSub)
	d.token = "test-token"
	if res := d.Create("__nope__", "cap", "prod", nil, nil, "k", 1); res.Status != "failed" ||
		!strings.Contains(res.Reason, "unknown service") {
		t.Fatalf("Create of an unknown service must refuse, got %+v", res)
	}
	if res := d.Delete("__nope__", "cap", "prod", "x", "k"); res.Status != "failed" ||
		!strings.Contains(res.Reason, "unknown service") {
		t.Fatalf("Delete of an unknown service must refuse, got %+v", res)
	}
	if _, _, err := d.Observe("__nope__", "cap", "x"); err == nil || !strings.Contains(err.Error(), "unknown service") {
		t.Fatalf("Observe of an unknown service must refuse, got err=%v", err)
	}
}

// aksWIFixture / azClassifyWiredServices: the services with an EXPLICIT
// ClassifyChange case. Each one's own classify function has a DIFFERENT default
// message than the D215 generic one below, so a nonsense path proves dispatch.
var azClassifyWiredServices = []string{
	"acr", "blob", "servicebusqueue", "loadbalancer", "consumptionbudget",
	"loganalytics", "activitylog", "defender", "azureopenai", "aks", "aks-addon",
	"aks-workloadidentity", "backuppolicy", "acsemail", "dnsrecord",
}

// TestClassifyChangeDispatchWiredServices proves every service with a
// ClassifyChange case routes to ITS OWN classifier rather than the generic D215
// fallback ("has no in-place update path"), by feeding a path none of them
// recognize and checking the per-service "unsupported" wording appears instead.
func TestClassifyChangeDispatchWiredServices(t *testing.T) {
	d := NewDriver(testSub)
	const genericD215 = "has no in-place update path"
	for _, svc := range azClassifyWiredServices {
		t.Run(svc, func(t *testing.T) {
			verb, reason := d.ClassifyChange(svc, "__nonsense.path__", nil, nil, nil)
			if strings.Contains(reason, genericD215) {
				t.Errorf("ClassifyChange(%q, ...) fell through to the generic D215 default "+
					"instead of its own classifier: verb=%q reason=%q", svc, verb, reason)
			}
		})
	}
}

// TestClassifyChangeDefaultForUnwiredService pins the D215 default itself: a
// create-capable service with NO ClassifyChange case (e.g. vnet, allowlisted in
// completeness_test.go) always classifies any path as an honest replacement.
func TestClassifyChangeDefaultForUnwiredService(t *testing.T) {
	d := NewDriver(testSub)
	verb, reason := d.ClassifyChange("vnet", "location.region", nil, nil, nil)
	if verb != "immutable" || !strings.Contains(reason, "has no in-place update path") {
		t.Fatalf("unwired service must hit the D215 default, got verb=%q reason=%q", verb, reason)
	}
}

// azUpdateWiredServices: the services with an explicit Update case (D46).
var azUpdateWiredServices = []string{
	"consumptionbudget", "loganalytics", "activitylog", "defender",
	"servicebusqueue", "aks", "aks-addon", "backuppolicy", "acsemail", "dnsrecord",
}

// TestUpdateDispatchWiredServices: mirrors the create/observe/delete dispatch
// test for the (smaller) set of in-place-update-capable services — each must
// route to its own updater, never the "in-place update is not wired yet" default.
func TestUpdateDispatchWiredServices(t *testing.T) {
	srv := notFoundServer()
	defer srv.Close()
	for _, svc := range azUpdateWiredServices {
		t.Run(svc, func(t *testing.T) {
			d := fastDispatchDriver(t, srv)
			res := d.Update(svc, "cap", "prod", svc+":dummy:pid", map[string]any{}, map[string]any{}, []string{"__nonsense.path__"}, "key")
			if strings.Contains(res.Reason, "in-place update is not wired yet") {
				t.Errorf("Update(%q) fell through to the default case — missing dispatch", svc)
			}
		})
	}
}

// TestUpdateDefaultForUnwiredService pins the Update default: a service with no
// updater case is an honest, clean refusal — never a silent no-op.
func TestUpdateDefaultForUnwiredService(t *testing.T) {
	srv := notFoundServer()
	defer srv.Close()
	d := fastDispatchDriver(t, srv)
	res := d.Update("vnet", "cap", "prod", "vnet:x:y:z", nil, nil, nil, "key")
	if res.Status != "failed" || !strings.Contains(res.Reason, "in-place update is not wired yet") {
		t.Fatalf("an unwired update must refuse cleanly, got %+v", res)
	}
}

// TestSubFromProviderID pins the pure helper Observe uses to lift the
// subscription out of an unpinned driver's providerId (D294): a well-formed id
// yields its subscription; anything short or with a malformed second component
// is rejected rather than guessed.
func TestSubFromProviderID(t *testing.T) {
	cases := []struct {
		pid     string
		wantSub string
		wantOK  bool
	}{
		{"blob:" + testSub + ":rg1:acct:container", testSub, true},
		{"vnet:" + testSub + ":rg1:name", testSub, true},
		{"too:short", "", false},
		{"kind:not-a-guid:rg1:name", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		sub, ok := subFromProviderID(c.pid)
		if sub != c.wantSub || ok != c.wantOK {
			t.Errorf("subFromProviderID(%q) = (%q, %v), want (%q, %v)", c.pid, sub, ok, c.wantSub, c.wantOK)
		}
	}
}

// TestObserveUsesProviderIDSubscriptionWhenUnpinned pins the D294 behavior
// itself (not just the helper): a driver created WITHOUT a pinned subscription
// (as `observe` deliberately builds one, since the ledger may span several)
// still resolves the request using the subscription embedded in the providerId,
// rather than failing the armURL guard on an empty subscription.
func TestObserveUsesProviderIDSubscriptionWhenUnpinned(t *testing.T) {
	var sawSub string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/subscriptions/") {
			parts := strings.SplitN(r.URL.Path, "/subscriptions/", 2)
			sawSub = strings.SplitN(parts[1], "/", 2)[0]
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	d := NewDriver("") // no pinned subscription — exactly how observe builds one
	d.BaseURL = srv.URL
	d.token = "test-token"

	pid := blobProviderID(testSub, "rg1", "acct0000000000000000", "container")
	if _, _, err := d.Observe("blob", "cap", pid); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sawSub != testSub {
		t.Fatalf("Observe with an unpinned driver must scope the request using the "+
			"providerId's subscription, got %q want %q", sawSub, testSub)
	}
}
