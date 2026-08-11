package azure

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

const aoiCap = "capability.ai.inference"

// ---- PURE: BuildAzureOpenAI ------------------------------------------------

func aoiAttrs() map[string]any {
	return map[string]any{
		"location.region": "swedencentral",
		"service.managed": true,
		"model.provider":  "openai",
	}
}

func TestBuildAzureOpenAIHappy(t *testing.T) {
	impl := map[string]any{
		"resource_group":   "rg1",
		"deployment_model": "gpt-4o",
		"deployment_sku":   "Standard",
	}
	p, err := BuildAzureOpenAI("prod", "inference", aoiAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "swedencentral" || p.NeedsAccess || p.DeploymentModel != "gpt-4o" ||
		p.DeploymentSku != "Standard" || p.DeploymentName == "" || !aoiAccountNameOK.MatchString(p.Account) {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildAzureOpenAIAccountOnly(t *testing.T) {
	p, err := BuildAzureOpenAI("prod", "inference", aoiAttrs(), map[string]any{"resource_group": "rg1"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.DeploymentModel != "" || p.DeploymentName != "" {
		t.Fatalf("account-only plan should carry no deployment: %+v", p)
	}
}

func TestBuildAzureOpenAIRefusals(t *testing.T) {
	base := map[string]any{"resource_group": "rg1"}
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"unmapped attribute":    {map[string]any{"location.region": "swedencentral", "bogus.attr": true}, base},
		"service.managed=false": {map[string]any{"location.region": "swedencentral", "service.managed": false}, base},
		"missing region":        {map[string]any{"service.managed": true}, base},
		"bad account_name":      {aoiAttrs(), map[string]any{"resource_group": "rg1", "account_name": "Bad_Name!"}},
		"bad deployment_model":  {aoiAttrs(), map[string]any{"resource_group": "rg1", "deployment_model": "bad/model"}},
	}
	for name, c := range cases {
		if _, err := BuildAzureOpenAI("prod", "inference", c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// model.access=true must be captured as NeedsAccess (never honored at build).
func TestBuildAzureOpenAIModelAccessNeedsGate(t *testing.T) {
	attrs := aoiAttrs()
	attrs["model.access"] = true
	p, err := BuildAzureOpenAI("prod", "inference", attrs, map[string]any{"resource_group": "rg1"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.NeedsAccess {
		t.Fatal("model.access=true must set NeedsAccess")
	}
}

func TestAzureOpenAIClassifyChange(t *testing.T) {
	cases := map[string]string{
		// D828: both follow the DEPLOYMENT, a child resource with its own PUT — the account
		// is untouched, so the old expectations pinned replacing it for nothing.
		"inference.destinationRegions": "unsupported",
		"location.region":              "immutable",
		"model.provider":               "unsupported",
		"model.access":                 "unsupported",
		"service.managed":              "unsupported",
		"cost.monthly":                 "unsupported",
		"whatever.else":                "unsupported",
	}
	for path, want := range cases {
		got, reason := classifyAzureOpenAIChange(path)
		if got != want {
			t.Errorf("%s: got %q want %q", path, got, want)
		}
		if reason == "" {
			t.Errorf("%s: empty reason", path)
		}
	}
}

func TestAzureOpenAIProviderIDRoundTrip(t *testing.T) {
	acct := aoiAccountName("prod", "inference", 1)
	pid := aoiProviderID(testSub, "rg1", acct)
	sub, rg, a, err := splitAzureOpenAIProviderID(pid)
	if err != nil || sub != testSub || rg != "rg1" || a != acct {
		t.Fatalf("round trip failed: %v %q %q %q", err, sub, rg, a)
	}
	bad := []string{
		"cosmos:" + testSub + ":rg1:" + acct,         // wrong service token
		"azureopenai:" + testSub + ":rg1:Bad!",       // invalid account
		"azureopenai:not-a-guid:rg1:" + acct,         // invalid sub
		"azureopenai:" + testSub + ":../etc:" + acct, // rg traversal
	}
	for _, b := range bad {
		if _, _, _, err := splitAzureOpenAIProviderID(b); err == nil {
			t.Errorf("%q should be rejected", b)
		}
	}
}

// The RESIDENCY measurement, PURE: a regional sku yields [account region]; a Global sku
// the ["global"] sentinel; a DataZone sku the ["datazone-<zone>"] sentinel.
func TestAzureOpenAIDestinationRegions(t *testing.T) {
	if got := destinationRegionsForScaleType("Standard", "swedencentral"); !reflect.DeepEqual(got, []string{"swedencentral"}) {
		t.Errorf("regional: %v", got)
	}
	if got := destinationRegionsForScaleType("GlobalStandard", "swedencentral"); !reflect.DeepEqual(got, []string{"global"}) {
		t.Errorf("global: %v", got)
	}
	if got := destinationRegionsForScaleType("DataZoneStandard", "swedencentral"); !reflect.DeepEqual(got, []string{"datazone-eu"}) {
		t.Errorf("datazone-eu: %v", got)
	}
	if got := destinationRegionsForScaleType("DataZoneStandard", "eastus"); !reflect.DeepEqual(got, []string{"datazone-us"}) {
		t.Errorf("datazone-us: %v", got)
	}
	// empty account -> the account's own region (regional by default)
	if got := destinationRegionsFromDeployments(nil, "francecentral"); !reflect.DeepEqual(got, []string{"francecentral"}) {
		t.Errorf("no deployments: %v", got)
	}
	// mixed: a regional + a global deployment -> the union carries global (the trap wins)
	got := destinationRegionsFromDeployments([]string{"Standard", "GlobalStandard"}, "swedencentral")
	if !reflect.DeepEqual(got, []string{"global", "swedencentral"}) {
		t.Errorf("mixed union: %v", got)
	}
}

// ---- NET: fake ARM control plane -------------------------------------------

type fakeAOI struct {
	location       string
	tags           map[string]string
	deployments    []map[string]any // {name, sku:{name}, properties:{model:{format,name}}}
	notFound       bool             // 404 on account GET
	unreadableDeps bool             // 500 on deployments list
	// D869: ARM pages this listing. A second page proves the reduction reads past the
	// first; an endless chain proves an unfinished read is not reported as a surface.
	deploymentsPage2 []map[string]any
	endlessDeps      bool
}

func aoiDeployment(name, sku, format, model string) map[string]any {
	return map[string]any{
		"name":       name,
		"sku":        map[string]any{"name": sku},
		"properties": map[string]any{"model": map[string]any{"format": format, "name": model}},
	}
}

func (f *fakeAOI) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "GET" && strings.HasSuffix(p, "/deployments"):
			if f.unreadableDeps {
				w.WriteHeader(500)
				return
			}
			next := "http://" + r.Host + p + "?api-version=x&$skiptoken=2"
			switch {
			case f.endlessDeps:
				_ = json.NewEncoder(w).Encode(map[string]any{"value": f.deployments, "nextLink": next})
			case f.deploymentsPage2 == nil:
				_ = json.NewEncoder(w).Encode(map[string]any{"value": f.deployments})
			case strings.Contains(r.URL.RawQuery, "skiptoken"):
				_ = json.NewEncoder(w).Encode(map[string]any{"value": f.deploymentsPage2})
			default:
				_ = json.NewEncoder(w).Encode(map[string]any{"value": f.deployments, "nextLink": next})
			}
		case strings.Contains(p, "/deployments/"): // single deployment PUT + poll GET
			_ = json.NewEncoder(w).Encode(map[string]any{"properties": map[string]any{"provisioningState": "Succeeded"}})
		case r.Method == "PUT" && strings.Contains(p, "/accounts/"): // account create
			_ = json.NewEncoder(w).Encode(map[string]any{"properties": map[string]any{"provisioningState": "Succeeded"}})
		case r.Method == "GET" && strings.HasSuffix(p, "/accounts"): // sub-level list (discover)
			_ = json.NewEncoder(w).Encode(map[string]any{"value": []map[string]any{{
				"id":       "/subscriptions/" + testSub + "/resourceGroups/rg1/providers/Microsoft.CognitiveServices/accounts/" + aoiAccountName("prod", "inference", 1),
				"name":     aoiAccountName("prod", "inference", 1),
				"kind":     "OpenAI",
				"location": f.location,
			}}})
		case r.Method == "GET" && strings.Contains(p, "/accounts/"): // account GET (poll + observe + pre-delete)
			if f.notFound {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"location":   f.location,
				"kind":       "OpenAI",
				"tags":       f.tags,
				"properties": map[string]any{"provisioningState": "Succeeded"},
			})
		case r.Method == "DELETE" && strings.Contains(p, "/accounts/"):
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}
}

func aoiDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func aoiTags(cap string) map[string]string {
	return map[string]string{
		"groundhold-capability":  sanitizeAzTag(cap),
		"groundhold-environment": sanitizeAzTag("prod"),
	}
}

func TestAzureOpenAICreateWithDeployment(t *testing.T) {
	srv := httptest.NewServer((&fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap)}).handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	impl := map[string]any{"resource_group": "rg1", "deployment_model": "gpt-4o", "deployment_sku": "Standard"}
	res := d.createAzureOpenAI("prod", aoiCap, aoiAttrs(), impl, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "azureopenai:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
}

// The MANUAL-GATE crux: model.access=true must HONEST-REFUSE, never fake a grant, never
// touch the API.
func TestAzureOpenAICreateRefusesModelAccessManualGate(t *testing.T) {
	touched := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		touched = true
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := aoiDriver(t, srv)
	attrs := aoiAttrs()
	attrs["model.access"] = true
	res := d.createAzureOpenAI("prod", aoiCap, attrs, map[string]any{"resource_group": "rg1"}, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "manual gate") {
		t.Fatalf("got %+v, want failed manual-gate refusal", res)
	}
	if touched {
		t.Fatal("manual-gate refusal must not touch the API")
	}
}

// RESIDENCY measured: a regional deployment yields destinationRegions = [account region].
func TestAzureOpenAIObserveEUResidencyMeasured(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap),
		deployments: []map[string]any{aoiDeployment("d1", "Standard", "OpenAI", "gpt-4o")}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	obs, diags, err := d.observeAzureOpenAI(aoiCap, pid)
	if err != nil {
		t.Fatal(err)
	}
	got := obsMap(t, obs)
	if dr, ok := got["inference.destinationRegions"].([]string); !ok || !reflect.DeepEqual(dr, []string{"swedencentral"}) {
		t.Fatalf("destinationRegions = %v", got["inference.destinationRegions"])
	}
	if got["model.provider"] != "openai" {
		t.Fatalf("model.provider = %v", got["model.provider"])
	}
	if got["model.access"] != true {
		t.Fatalf("model.access should be observed true (a model is deployed): %v", got["model.access"])
	}
	if !aoiHasDiag(diags, "manual-gate") {
		t.Fatalf("expected a manual-gate diagnostic, got %v", diags)
	}
}

// The TRAP: a Global-sku deployment reduces to ["global"], NOT an EU region.
func TestAzureOpenAIObserveGlobalTrap(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap),
		deployments: []map[string]any{aoiDeployment("d1", "GlobalStandard", "OpenAI", "gpt-4o")}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	obs, diags, err := d.observeAzureOpenAI(aoiCap, pid)
	if err != nil {
		t.Fatal(err)
	}
	got := obsMap(t, obs)
	if dr, ok := got["inference.destinationRegions"].([]string); !ok || !reflect.DeepEqual(dr, []string{"global"}) {
		t.Fatalf("global destinationRegions = %v", got["inference.destinationRegions"])
	}
	if !aoiHasDiag(diags, "global") {
		t.Fatalf("expected a global-trap diagnostic, got %v", diags)
	}
}

// A DataZone-sku deployment routes across a multi-region zone -> ["datazone-eu"].
func TestAzureOpenAIObserveDataZone(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap),
		deployments: []map[string]any{aoiDeployment("d1", "DataZoneStandard", "OpenAI", "gpt-4o")}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	obs, diags, err := d.observeAzureOpenAI(aoiCap, pid)
	if err != nil {
		t.Fatal(err)
	}
	got := obsMap(t, obs)
	if dr, ok := got["inference.destinationRegions"].([]string); !ok || !reflect.DeepEqual(dr, []string{"datazone-eu"}) {
		t.Fatalf("datazone destinationRegions = %v", got["inference.destinationRegions"])
	}
	if !aoiHasDiag(diags, "data-zone") {
		t.Fatalf("expected a data-zone diagnostic, got %v", diags)
	}
}

// No deployments -> a bare regional account, destinationRegions = [account region],
// model.access observed false.
func TestAzureOpenAIObserveNoDeployments(t *testing.T) {
	f := &fakeAOI{location: "francecentral", tags: aoiTags(aoiCap)}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	obs, _, err := d.observeAzureOpenAI(aoiCap, pid)
	if err != nil {
		t.Fatal(err)
	}
	got := obsMap(t, obs)
	if dr, _ := got["inference.destinationRegions"].([]string); !reflect.DeepEqual(dr, []string{"francecentral"}) {
		t.Fatalf("destinationRegions = %v", got["inference.destinationRegions"])
	}
	if got["model.access"] != false {
		t.Fatalf("model.access should be false with no deployments: %v", got["model.access"])
	}
}

func TestAzureOpenAIObserveNotFound(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", notFound: true}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	obs, diags, err := d.observeAzureOpenAI(aoiCap, pid)
	// Corrected with D518: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if err != nil || !absentMarked(obs) || !aoiHasDiag(diags, "bound resource is gone") {
		t.Fatalf("not-found must mark the resource absent: obs=%v diags=%v err=%v", obs, diags, err)
	}
}

// An unreadable deployment list must be an ERROR, never a fabricated absence that would
// understate the residency surface.
func TestAzureOpenAIObserveUnreadableDeploymentsIsError(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap), unreadableDeps: true}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	if _, _, err := d.observeAzureOpenAI(aoiCap, pid); err == nil {
		t.Fatal("unreadable deployments must be an error, never a fabricated absence")
	}
}

func TestAzureOpenAIObserveCrossSubRefused(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap)}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	other := "00000000-0000-0000-0000-0000000000ff"
	pid := aoiProviderID(other, "rg1", aoiAccountName("prod", "inference", 1))
	if _, _, err := d.observeAzureOpenAI(aoiCap, pid); err == nil {
		t.Fatal("cross-subscription observe must be refused")
	}
}

func TestAzureOpenAIDeleteOwned(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap)}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	if res := d.deleteAzureOpenAI(aoiCap, "prod", pid); res.Status != "succeeded" {
		t.Fatalf("owned delete: %+v", res)
	}
}

func TestAzureOpenAIDeleteForeignRefused(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags("someone-else")}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	res := d.deleteAzureOpenAI(aoiCap, "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign account must refuse delete, got %+v", res)
	}
}

func TestAzureOpenAIDeleteIdempotent(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", notFound: true}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	if res := d.deleteAzureOpenAI(aoiCap, "prod", pid); res.Status != "succeeded" {
		t.Fatalf("already-gone delete must be idempotent success: %+v", res)
	}
}

func TestAzureOpenAIDiscover(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap),
		deployments: []map[string]any{aoiDeployment("d1", "GlobalStandard", "OpenAI", "gpt-4o")}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	found, diags, err := d.discoverAzureOpenAI("swedencentral")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.ai.inference" {
		t.Fatalf("discover found = %+v", found)
	}
	if !aoiHasDiag(diags, "global") {
		t.Fatalf("discover should surface the global-trap diagnostic, got %v", diags)
	}
}

// Weapon 1 (D86 honesty harness): four-valued create/delete under fault injection,
// ownership refusal on a foreign pre-delete tag. Account-only (no deployment) keeps the
// happy trace a single mutation + poll, the parity twin of the Cosmos honesty test. This
// exercises the driver methods directly (the service is not yet in the shared dispatch
// switch — see the reported azure_provider.go snippet).
func TestHonestyHarnessAzureOpenAI(t *testing.T) {
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	happy := func() *httptest.Server {
		return httptest.NewServer((&fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap)}).handler(t))
	}
	newDriver := func(happyURL string, rt http.RoundTripper) provider.Provider {
		d := NewDriver(testSub)
		d.BaseURL = happyURL
		d.HTTP = &http.Client{Transport: rt}
		d.token = "test-token"
		d.Now = time.Now
		d.PollInterval = time.Millisecond
		d.PollTimeout = 2 * time.Second
		return d
	}
	p := &certifynet.Probe{
		Name:            "azure/azureopenai",
		Classify:        armRole,
		OwnerTagValue:   sanitizeAzTag(aoiCap),
		AssertTransient: true, // D237
		DeterministicID: true,
		New:             newDriver,
		// F-LC3 (D523): hand-wired — this probe declares New as a value rather
		// than a literal, so the sweep could not find its anchor.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("azureopenai", aoiCap,
				aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1)))
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: happy,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.(*Driver).createAzureOpenAI("prod", aoiCap, aoiAttrs(), map[string]any{"resource_group": "rg1"}, 1)
				},
			},
			{
				Name:  "delete",
				Happy: happy,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.(*Driver).deleteAzureOpenAI(aoiCap, "prod", pid)
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func aoiHasDiag(diags []string, sub string) bool {
	for _, d := range diags {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}
