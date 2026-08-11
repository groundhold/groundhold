package gcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

const (
	vtxCap    = "capability.ai.inference"
	vtxProj   = "acme-prod"
	vtxRegion = "europe-west4"
	vtxID     = "123"
)

func vtxEndpointName(loc, id string) string {
	return "projects/" + vtxProj + "/locations/" + loc + "/endpoints/" + id
}

// fakeVertex is a stateful fake Vertex AI endpoint control plane. It serves
// endpoints.create (-> operation), operations.get (-> done + response.name),
// endpoints.get, endpoints.delete (-> operation) and endpoints.list.
type fakeVertex struct {
	loc        string
	labels     map[string]string
	models     []map[string]any // deployedModels
	etag       string
	notFound   bool // 404 on endpoints.get
	unreadable bool // 500 on endpoints.get
	createBody string
	order      []string
}

func (f *fakeVertex) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, "/operations/"):
			f.order = append(f.order, "op")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"done":     true,
				"response": map[string]any{"name": vtxEndpointName(f.loc, vtxID)},
			})
		case r.Method == "POST" && strings.HasSuffix(p, "/endpoints"):
			f.order = append(f.order, "create")
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			raw, _ := json.Marshal(b)
			f.createBody = string(raw)
			_, _ = w.Write([]byte(`{"name":"` + "projects/" + vtxProj + "/locations/" + f.loc + "/operations/opc" + `"}`))
		case r.Method == "DELETE" && strings.Contains(p, "/endpoints/"):
			// D995: the real Vertex endpoints.delete has no etag parameter and 400s any
			// `?etag=` ("Unknown name 'etag': Cannot bind query parameter"). The fake
			// mirrors that, so a delete that appends an etag fails exactly as in the field.
			if r.URL.Query().Has("etag") {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":{"message":"Invalid JSON payload received. Unknown name \"etag\": Cannot bind query parameter."}}`))
				return
			}
			f.order = append(f.order, "delete")
			_, _ = w.Write([]byte(`{"name":"` + "projects/" + vtxProj + "/locations/" + f.loc + "/operations/opd" + `"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/endpoints"):
			f.order = append(f.order, "list")
			// D424: the real endpoints.list returns displayName and labels, and the
			// create-adoption scan reads both. Serving only the name made the fake
			// unable to describe a standing endpoint at all.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"endpoints": []map[string]any{{
					"name":        vtxEndpointName(f.loc, vtxID),
					"displayName": "claude-eu",
					"labels":      f.labels,
				}},
			})
		case r.Method == "GET" && strings.Contains(p, "/endpoints/"):
			f.order = append(f.order, "get")
			if f.unreadable {
				w.WriteHeader(500)
				return
			}
			if f.notFound {
				w.WriteHeader(404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name":           vtxEndpointName(f.loc, vtxID),
				"displayName":    "claude-eu",
				"labels":         f.labels,
				"deployedModels": f.models,
				"etag":           f.etag,
			})
		default:
			w.WriteHeader(500)
		}
	}
}

func vtxDriver(t *testing.T, f *fakeVertex) (*Driver, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	vertexAIBaseURLOverride = srv.URL
	t.Cleanup(func() { vertexAIBaseURLOverride = "" })
	d := NewDriver(vtxProj)
	d.PollInterval = 0
	return d, srv
}

func groundholdLabels() map[string]string {
	return map[string]string{
		"groundhold-capability":  sanitizeLabel(vtxCap),
		"groundhold-environment": sanitizeLabel("prod"),
	}
}

// ---- PURE: BuildVertexAI ---------------------------------------------------

func TestVertexAIBuildPlanHappy(t *testing.T) {
	attrs := map[string]any{
		"location.region":              vtxRegion,
		"service.managed":              true,
		"model.provider":               "anthropic",
		"inference.destinationRegions": []any{vtxRegion}, // observed/inherited, accepted
	}
	impl := map[string]any{
		"displayName":    "claude-eu",
		"publisherModel": "publishers/anthropic/models/claude-3-5-sonnet-v2@20241022",
	}
	p, err := BuildVertexAI(vtxProj, "prod", vtxCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Region != vtxRegion || p.DisplayName != "claude-eu" || p.NeedsAccess {
		t.Fatalf("bad plan: %+v", p)
	}
}

func TestVertexAIBuildRefusals(t *testing.T) {
	base := map[string]any{"location.region": vtxRegion, "service.managed": true}
	impl := map[string]any{"displayName": "d", "publisherModel": "publishers/anthropic/models/claude"}

	cases := []struct {
		name  string
		attrs map[string]any
		impl  map[string]any
	}{
		{"unmapped attribute", map[string]any{"location.region": vtxRegion, "bogus.attr": true}, impl},
		{"service.managed=false", map[string]any{"location.region": vtxRegion, "service.managed": false}, impl},
		{"missing region", map[string]any{"service.managed": true}, impl},
		{"missing displayName", base, map[string]any{"publisherModel": "publishers/anthropic/models/claude"}},
		{"missing publisherModel", base, map[string]any{"displayName": "d"}},
		{"bad publisherModel", base, map[string]any{"displayName": "d", "publisherModel": "arn:aws:bedrock:x"}},
	}
	for _, c := range cases {
		if _, err := BuildVertexAI(vtxProj, "prod", vtxCap, c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got nil", c.name)
		}
	}
}

// model.access=true must be captured as NeedsAccess (never honored at build).
func TestVertexAIBuildModelAccessNeedsGate(t *testing.T) {
	attrs := map[string]any{"location.region": vtxRegion, "service.managed": true, "model.access": true}
	impl := map[string]any{"displayName": "d", "publisherModel": "publishers/anthropic/models/claude"}
	p, err := BuildVertexAI(vtxProj, "prod", vtxCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !p.NeedsAccess {
		t.Fatal("model.access=true must set NeedsAccess")
	}
}

func TestVertexAIClassifyChange(t *testing.T) {
	cases := map[string]string{
		"inference.destinationRegions": "immutable",
		"location.region":              "immutable",
		// D828: Vertex swaps a model ON the endpoint (undeployModel then deployModel), so
		// the old expectation pinned replacing an endpoint every caller holds by id.
		"model.provider":  "unsupported",
		"model.access":    "unsupported",
		"service.managed": "unsupported",
		"cost.monthly":    "unsupported",
		"whatever.else":   "unsupported",
	}
	for path, want := range cases {
		got, reason := classifyVertexChange(path)
		if got != want {
			t.Errorf("%s: got %q want %q", path, got, want)
		}
		if reason == "" {
			t.Errorf("%s: empty reason", path)
		}
	}
}

func TestVertexProviderIDRoundTrip(t *testing.T) {
	pid := vertexProviderID(vtxProj, vtxRegion, vtxID)
	pr, loc, id, err := splitVertexProviderID(pid)
	if err != nil || pr != vtxProj || loc != vtxRegion || id != vtxID {
		t.Fatalf("round trip failed: %v %q %q %q", err, pr, loc, id)
	}
	// global location is valid (the trap surface must round-trip).
	if _, _, _, err := splitVertexProviderID(vertexProviderID(vtxProj, "global", vtxID)); err != nil {
		t.Fatalf("global location should be valid: %v", err)
	}
	bad := []string{
		"cloudrun:acme-prod:europe-west4:123",       // wrong service token
		"vertexai:acme-prod:europe-west4:abc",       // non-numeric id
		"vertexai:acme-prod:europe-west4:123:extra", // too many parts
		"vertexai:acme-prod:../etc/passwd:123",      // path traversal in location
	}
	for _, b := range bad {
		if _, _, _, err := splitVertexProviderID(b); err == nil {
			t.Errorf("%q should be rejected", b)
		}
	}
}

func TestVertexPureHelpers(t *testing.T) {
	if got := locationFromEndpointName(vtxEndpointName("europe-west4", "9")); got != "europe-west4" {
		t.Errorf("location parse: %q", got)
	}
	if got := endpointIDFromName(vtxEndpointName("europe-west4", "9")); got != "9" {
		t.Errorf("id parse: %q", got)
	}
	if got := providerFromPublisherModel("publishers/anthropic/models/claude-3-5"); got != "anthropic" {
		t.Errorf("provider parse: %q", got)
	}
	if got := providerFromPublisherModel("projects/p/locations/l/models/custom"); got != "" {
		t.Errorf("custom model has no publisher provider: %q", got)
	}
	if got := destinationRegionsFromLocation("global"); !reflect.DeepEqual(got, []string{"global"}) {
		t.Errorf("global dest: %v", got)
	}
}

// ---- NET: create / observe / delete / discover -----------------------------

func TestVertexAICreateSucceeds(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion}
	d, _ := vtxDriver(t, f)
	attrs := map[string]any{"location.region": vtxRegion, "service.managed": true}
	impl := map[string]any{"displayName": "claude-eu", "publisherModel": "publishers/anthropic/models/claude"}
	res := d.createVertexAI(vtxCap, "prod", attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("got %+v, want succeeded", res)
	}
	if res.ProviderID != vertexProviderID(vtxProj, vtxRegion, vtxID) {
		t.Fatalf("providerID %q", res.ProviderID)
	}
	if !strings.Contains(f.createBody, "groundhold-capability") {
		t.Fatalf("create body missing ownership labels: %s", f.createBody)
	}
}

// The MANUAL-GATE crux: model.access=true must HONEST-REFUSE, never fake a grant,
// and never touch the API.
func TestVertexAICreateRefusesModelAccessManualGate(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion}
	d, _ := vtxDriver(t, f)
	attrs := map[string]any{"location.region": vtxRegion, "service.managed": true, "model.access": true}
	impl := map[string]any{"displayName": "claude-eu", "publisherModel": "publishers/anthropic/models/claude"}
	res := d.createVertexAI(vtxCap, "prod", attrs, impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "manual gate") {
		t.Fatalf("got %+v, want failed manual-gate refusal", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("manual-gate refusal must not touch the API, saw: %v", f.order)
	}
}

// The RESIDENCY measurement: a regional endpoint yields destinationRegions =
// [region], MEASURED from the server-returned name (not the providerId claim).
func TestVertexAIObserveEUResidencyMeasured(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion, labels: groundholdLabels(),
		models: []map[string]any{{"id": "m1", "model": "publishers/anthropic/models/claude-3-5"}}}
	d, _ := vtxDriver(t, f)
	obs, diags, err := d.observeVertexAI(vtxCap, vertexProviderID(vtxProj, vtxRegion, vtxID))
	if err != nil {
		t.Fatalf("observe error: %v", err)
	}
	got := obsMap(obs)
	if dr, ok := got["inference.destinationRegions"].([]string); !ok || !reflect.DeepEqual(dr, []string{vtxRegion}) {
		t.Fatalf("destinationRegions = %v (want [%s])", got["inference.destinationRegions"], vtxRegion)
	}
	if got["model.provider"] != "anthropic" {
		t.Fatalf("model.provider = %v", got["model.provider"])
	}
	if got["model.access"] != true {
		t.Fatalf("model.access should be observed true (a model is deployed): %v", got["model.access"])
	}
	if !anyContains(diags, "manual-gate") {
		t.Fatalf("expected a manual-gate diagnostic, got %v", diags)
	}
}

// The TRAP: a "global" endpoint reduces to ["global"], NOT an EU region — a
// residency subset-of an EU allowlist will fail deterministically.
func TestVertexAIObserveGlobalTrap(t *testing.T) {
	f := &fakeVertex{loc: "global", labels: groundholdLabels()}
	d, _ := vtxDriver(t, f)
	obs, diags, err := d.observeVertexAI(vtxCap, vertexProviderID(vtxProj, "global", vtxID))
	if err != nil {
		t.Fatalf("observe error: %v", err)
	}
	got := obsMap(obs)
	if dr, ok := got["inference.destinationRegions"].([]string); !ok || !reflect.DeepEqual(dr, []string{"global"}) {
		t.Fatalf("global destinationRegions = %v", got["inference.destinationRegions"])
	}
	if !anyContains(diags, "global") {
		t.Fatalf("expected a global-trap diagnostic, got %v", diags)
	}
}

func TestVertexAIObserveNotFound(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion, notFound: true}
	d, _ := vtxDriver(t, f)
	obs, diags, err := d.observeVertexAI(vtxCap, vertexProviderID(vtxProj, vtxRegion, vtxID))
	// Corrected with D519: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if err != nil || !absentMarked(obs) || !anyContains(diags, "bound resource is gone") {
		t.Fatalf("not-found must mark the resource absent: obs=%v diags=%v err=%v", obs, diags, err)
	}
}

func TestVertexAIObserveUnreadableIsError(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion, unreadable: true}
	d, _ := vtxDriver(t, f)
	if _, _, err := d.observeVertexAI(vtxCap, vertexProviderID(vtxProj, vtxRegion, vtxID)); err == nil {
		t.Fatal("unreadable endpoint must be an error, never a fabricated absence")
	}
}

func TestVertexAIDeleteOwned(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion, labels: groundholdLabels(), etag: "e1"}
	d, _ := vtxDriver(t, f)
	res := d.deleteVertexAI(vtxCap, "prod", vertexProviderID(vtxProj, vtxRegion, vtxID))
	if res.Status != "succeeded" {
		t.Fatalf("owned delete: got %+v", res)
	}
}

// TestVertexAIDeleteSendsNoEtag (D995): a present endpoint always carries an etag,
// but Vertex endpoints.delete rejects an `?etag=` param. The delete must NOT append
// one — the ownership pre-read is the guard — so it succeeds against the faithful fake
// (which 400s an etag query, exactly like the real API). Before the fix every delete
// of a present endpoint 400'd, so the retire could never complete.
func TestVertexAIDeleteSendsNoEtag(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion, labels: groundholdLabels(), etag: "etag-abc123"}
	d, _ := vtxDriver(t, f)
	res := d.deleteVertexAI(vtxCap, "prod", vertexProviderID(vtxProj, vtxRegion, vtxID))
	if res.Status != "succeeded" {
		t.Fatalf("delete must succeed without appending an etag param, got %+v", res)
	}
}

func TestVertexAIDeleteForeignRefused(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion, labels: map[string]string{"groundhold-capability": "other"}, etag: "e1"}
	d, _ := vtxDriver(t, f)
	res := d.deleteVertexAI(vtxCap, "prod", vertexProviderID(vtxProj, vtxRegion, vtxID))
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign delete must refuse: got %+v", res)
	}
}

func TestVertexAIDeleteIdempotent(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion, notFound: true}
	d, _ := vtxDriver(t, f)
	res := d.deleteVertexAI(vtxCap, "prod", vertexProviderID(vtxProj, vtxRegion, vtxID))
	if res.Status != "succeeded" {
		t.Fatalf("already-gone delete must be idempotent success: got %+v", res)
	}
}

// A forged cross-project binding must be refused (confused-deputy boundary).
func TestVertexAIObserveCrossProjectRefused(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion, labels: groundholdLabels()}
	d, _ := vtxDriver(t, f)
	if _, _, err := d.observeVertexAI(vtxCap, vertexProviderID("other-proj-x", vtxRegion, vtxID)); err == nil {
		t.Fatal("cross-project observe must be refused")
	}
}

func TestVertexAIDiscover(t *testing.T) {
	f := &fakeVertex{loc: vtxRegion, labels: groundholdLabels(),
		models: []map[string]any{{"id": "m1", "model": "publishers/anthropic/models/claude"}}}
	d, _ := vtxDriver(t, f)
	found, _, err := d.discoverVertexAI(vtxRegion)
	if err != nil {
		t.Fatalf("discover error: %v", err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.ai.inference" {
		t.Fatalf("discover found = %+v", found)
	}
	if found[0].ProviderID != vertexProviderID(vtxProj, vtxRegion, vtxID) {
		t.Fatalf("discover providerID = %q", found[0].ProviderID)
	}
}

// ---- helpers ---------------------------------------------------------------

func anyContains(diags []string, sub string) bool {
	for _, d := range diags {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}
