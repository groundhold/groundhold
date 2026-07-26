package discover

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// fakeDisc is a controllable Discoverer. It embeds *provider.Fake to
// satisfy the wide provider.Provider interface, and shadows List/Name so
// each test drives exactly what discovery enumerates.
type fakeDisc struct {
	*provider.Fake
	name      string
	resources []provider.Discovered
	diags     []string
	err       error
}

func (f *fakeDisc) List(region string) ([]provider.Discovered, []string, error) {
	return f.resources, f.diags, f.err
}

func (f *fakeDisc) Name() string {
	if f.name != "" {
		return f.name
	}
	return "fake"
}

func newFakeDisc(res []provider.Discovered, diags []string, err error) *fakeDisc {
	return &fakeDisc{Fake: &provider.Fake{}, resources: res, diags: diags, err: err}
}

// nonDiscoverer implements provider.Provider WITHOUT a List method, so the
// type-assertion in Run fails and discovery must refuse.
type nonDiscoverer struct{}

func (nonDiscoverer) Name() string { return "no-disc" }
func (nonDiscoverer) Validate(service, capability, environment string,
	attrs, impl map[string]any, generation int) error {
	return nil
}
func (nonDiscoverer) Create(service, capability, environment string,
	attrs, impl map[string]any, key string, generation int) provider.CreateResult {
	return provider.CreateResult{}
}
func (nonDiscoverer) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	return nil, nil, nil
}
func (nonDiscoverer) ClassifyChange(service, path string, current, desired any,
	impl map[string]any) (string, string) {
	return "", ""
}
func (nonDiscoverer) Update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string, key string) provider.CreateResult {
	return provider.CreateResult{}
}
func (nonDiscoverer) Delete(service, capability, environment, providerID, key string) provider.CreateResult {
	return provider.CreateResult{}
}

// compile-time guards: the stubs are exactly what the tests assume.
var (
	_ provider.Provider   = nonDiscoverer{}
	_ provider.Provider   = (*fakeDisc)(nil)
	_ provider.Discoverer = (*fakeDisc)(nil)
)

func TestRunRefusesNonDiscoverer(t *testing.T) {
	res, err := Run(nonDiscoverer{}, "proj", "us", "2026-07-24T00:00:00Z")
	if err == nil {
		t.Fatalf("expected refusal for a provider without discovery, got result %+v", res)
	}
	if res != nil {
		t.Fatalf("refusal must return a nil result, got %+v", res)
	}
	if !strings.Contains(err.Error(), "does not support discovery") {
		t.Fatalf("error should name the missing capability, got %q", err.Error())
	}
	// The provider name must be surfaced so the caller knows which driver.
	if !strings.Contains(err.Error(), "no-disc") {
		t.Fatalf("error should name the provider, got %q", err.Error())
	}
}

func TestRunPropagatesListError(t *testing.T) {
	boom := fmt.Errorf("cloud is on fire")
	res, err := Run(newFakeDisc(nil, nil, boom), "proj", "us", "2026-07-24T00:00:00Z")
	if err != boom {
		t.Fatalf("List error must propagate verbatim, got %v", err)
	}
	if res != nil {
		t.Fatalf("error path must return a nil result, got %+v", res)
	}
}

func TestRunEmptyEnumeration(t *testing.T) {
	res, err := Run(newFakeDisc(nil, nil, nil), "proj", "eu", "2026-07-24T00:00:00Z")
	if err != nil {
		t.Fatalf("empty enumeration is not an error: %v", err)
	}
	// Resources must be a non-nil empty slice — a discovery that SAW
	// nothing renders `[]`, distinct from a null.
	if res.Discovery.Resources == nil {
		t.Fatalf("Resources must be an empty slice, not nil")
	}
	if len(res.Discovery.Resources) != 0 {
		t.Fatalf("expected zero resources, got %d", len(res.Discovery.Resources))
	}
	if !strings.HasPrefix(res.DiscoveryHash, "sha256:") {
		t.Fatalf("empty discovery still gets a hash, got %q", res.DiscoveryHash)
	}
}

func TestRunPropagatesDiagnostics(t *testing.T) {
	diags := []string{"skipped: region eu-x lists nothing", "partial"}
	res, err := Run(newFakeDisc(nil, diags, nil), "proj", "eu", "2026-07-24T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Diagnostics, diags) {
		t.Fatalf("diagnostics must pass through verbatim, got %v", res.Diagnostics)
	}
}

func TestRunShaping(t *testing.T) {
	at := "2026-07-24T00:00:00Z"
	tests := []struct {
		name     string
		in       []provider.Discovered
		wantIDs  []string   // expected ProviderID order after shaping
		wantObs  [][]string // per-resource observation Path order after shaping
		wantAttr []map[string]any
	}{
		{
			name: "resources sorted by providerId",
			in: []provider.Discovered{
				{ProviderID: "z-db", ResourceType: "capability.database.relational"},
				{ProviderID: "a-db", ResourceType: "capability.database.relational"},
				{ProviderID: "m-db", ResourceType: "capability.database.relational"},
			},
			wantIDs:  []string{"a-db", "m-db", "z-db"},
			wantObs:  [][]string{{}, {}, {}},
			wantAttr: []map[string]any{{}, {}, {}},
		},
		{
			name: "observations sorted by path; skeleton mirrors them",
			in: []provider.Discovered{
				{
					ProviderID:   "db-1",
					ResourceType: "capability.database.relational",
					Observations: []provider.Observation{
						{Path: "service.version", Value: "8.0", Derivation: "measured"},
						{Path: "residency.region", Value: "eu-central", Derivation: "config-intent"},
						{Path: "exposure.public", Value: false, Derivation: "measured"},
					},
				},
			},
			wantIDs: []string{"db-1"},
			wantObs: [][]string{{"exposure.public", "residency.region", "service.version"}},
			wantAttr: []map[string]any{{
				"service.version":  "8.0",
				"residency.region": "eu-central",
				"exposure.public":  false,
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Run(newFakeDisc(tc.in, nil, nil), "proj", "eu", at)
			if err != nil {
				t.Fatal(err)
			}
			got := res.Discovery.Resources
			if len(got) != len(tc.wantIDs) {
				t.Fatalf("resource count: got %d want %d", len(got), len(tc.wantIDs))
			}
			for i, r := range got {
				if r.ProviderID != tc.wantIDs[i] {
					t.Fatalf("resource[%d] id: got %q want %q", i, r.ProviderID, tc.wantIDs[i])
				}
				var paths []string
				for _, o := range r.Observations {
					paths = append(paths, o.Path)
				}
				wantPaths := tc.wantObs[i]
				if len(paths) == 0 && len(wantPaths) == 0 {
					// both empty — ok
				} else if !reflect.DeepEqual(paths, wantPaths) {
					t.Fatalf("resource[%d] obs paths: got %v want %v", i, paths, wantPaths)
				}
				skel, ok := r.CandidateSkeleton["attributes"].(map[string]any)
				if !ok {
					t.Fatalf("resource[%d] skeleton must nest an attributes map, got %#v", i, r.CandidateSkeleton)
				}
				if !reflect.DeepEqual(skel, tc.wantAttr[i]) {
					t.Fatalf("resource[%d] skeleton attrs: got %v want %v", i, skel, tc.wantAttr[i])
				}
			}
		})
	}
}

// The skeleton is the exact set of observed paths and nothing more: Run
// synthesizes no attribute of its own. This is the structural guarantee
// the onboarding path leans on — anything a driver deliberately withheld
// (secrets, credentials) never appears here, because Run only ever mirrors
// what List surfaced. Pin that Run adds no keys.
func TestRunSkeletonMirrorsObservationsExactly(t *testing.T) {
	in := []provider.Discovered{{
		ProviderID:   "db-secretless",
		ResourceType: "capability.database.relational",
		Observations: []provider.Observation{
			{Path: "service.managed", Value: true, Derivation: "measured"},
			{Path: "service.engine", Value: "mysql", Derivation: "measured"},
		},
	}}
	res, err := Run(newFakeDisc(in, nil, nil), "proj", "eu", "2026-07-24T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	skel := res.Discovery.Resources[0].CandidateSkeleton["attributes"].(map[string]any)
	want := map[string]any{"service.managed": true, "service.engine": "mysql"}
	if !reflect.DeepEqual(skel, want) {
		t.Fatalf("skeleton must equal the observation set exactly, got %v", skel)
	}
	// A driver that withholds a secret path simply never emits it. Prove the
	// exclusion is structural: an observation set with no secret produces a
	// skeleton with no secret key — Run cannot invent one.
	if _, leaked := skel["password"]; leaked {
		t.Fatalf("skeleton must not contain paths the driver never observed")
	}
	// CandidateSkeleton carries ONLY the attributes bag, nothing else.
	if len(res.Discovery.Resources[0].CandidateSkeleton) != 1 {
		t.Fatalf("skeleton must hold exactly one key (attributes), got %v",
			res.Discovery.Resources[0].CandidateSkeleton)
	}
}

// Value fidelity: observation values flow into both the observation list and
// the skeleton verbatim, across scalar/collection kinds (no coercion — an
// invariant the whole system rests on).
func TestRunPreservesObservationValues(t *testing.T) {
	in := []provider.Discovered{{
		ProviderID:   "res",
		ResourceType: "capability.object.storage",
		Observations: []provider.Observation{
			{Path: "b", Value: true, Derivation: "measured"},
			{Path: "n", Value: 42, Derivation: "measured"},
			{Path: "s", Value: "text", Derivation: "config-intent"},
			{Path: "list", Value: []any{"x", "y"}, Derivation: "measured"},
			{Path: "nil", Value: nil, Derivation: "measured"},
		},
	}}
	res, err := Run(newFakeDisc(in, nil, nil), "p", "r", "2026-07-24T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	r := res.Discovery.Resources[0]
	// derivation survives on each observation
	byPath := map[string]provider.Observation{}
	for _, o := range r.Observations {
		byPath[o.Path] = provider.Observation(o)
	}
	if byPath["s"].Derivation != "config-intent" {
		t.Fatalf("derivation must survive, got %q", byPath["s"].Derivation)
	}
	skel := r.CandidateSkeleton["attributes"].(map[string]any)
	want := map[string]any{"b": true, "n": 42, "s": "text", "list": []any{"x", "y"}, "nil": nil}
	if !reflect.DeepEqual(skel, want) {
		t.Fatalf("values must be mirrored without coercion, got %v", skel)
	}
}

// Determinism: the discovery hash is invariant under the input ORDER of both
// resources and observations, because Run sorts before hashing. Two shuffled
// enumerations of the same reality must produce the identical DiscoveryHash.
func TestRunHashIgnoresInputOrder(t *testing.T) {
	a := []provider.Discovered{
		{ProviderID: "b", ResourceType: "t", Observations: []provider.Observation{
			{Path: "y", Value: 2, Derivation: "measured"},
			{Path: "x", Value: 1, Derivation: "measured"},
		}},
		{ProviderID: "a", ResourceType: "t"},
	}
	b := []provider.Discovered{
		{ProviderID: "a", ResourceType: "t"},
		{ProviderID: "b", ResourceType: "t", Observations: []provider.Observation{
			{Path: "x", Value: 1, Derivation: "measured"},
			{Path: "y", Value: 2, Derivation: "measured"},
		}},
	}
	at := "2026-07-24T00:00:00Z"
	r1, err := Run(newFakeDisc(a, nil, nil), "proj", "eu", at)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Run(newFakeDisc(b, nil, nil), "proj", "eu", at)
	if err != nil {
		t.Fatal(err)
	}
	if r1.DiscoveryHash != r2.DiscoveryHash {
		t.Fatalf("hash must be order-independent: %q vs %q", r1.DiscoveryHash, r2.DiscoveryHash)
	}
	// And the resources themselves are canonically ordered.
	if r1.Discovery.Resources[0].ProviderID != "a" || r1.Discovery.Resources[1].ProviderID != "b" {
		t.Fatalf("resources must be sorted by providerId, got %+v", r1.Discovery.Resources)
	}
}

// The hash changes when reality changes — a different value under the same
// path must not collide (guards against a hasher that drops values).
func TestRunHashDistinguishesValues(t *testing.T) {
	mk := func(v any) *Result {
		r, err := Run(newFakeDisc([]provider.Discovered{{
			ProviderID: "db", ResourceType: "t",
			Observations: []provider.Observation{{Path: "region", Value: v, Derivation: "measured"}},
		}}, nil, nil), "proj", "eu", "2026-07-24T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if mk("eu").DiscoveryHash == mk("us").DiscoveryHash {
		t.Fatalf("different observed values must yield different hashes")
	}
}

// Duplicate observation paths: the skeleton is a map, so the last value in
// ORIGINAL input order wins (the attrs loop runs before the sort). The
// observation LIST keeps both entries. Pin ACTUAL behavior.
func TestRunDuplicatePathLastWriteWins(t *testing.T) {
	in := []provider.Discovered{{
		ProviderID:   "db",
		ResourceType: "t",
		Observations: []provider.Observation{
			{Path: "dup", Value: "first", Derivation: "measured"},
			{Path: "dup", Value: "second", Derivation: "measured"},
		},
	}}
	res, err := Run(newFakeDisc(in, nil, nil), "p", "r", "2026-07-24T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	r := res.Discovery.Resources[0]
	if len(r.Observations) != 2 {
		t.Fatalf("observation list must keep both duplicate entries, got %d", len(r.Observations))
	}
	skel := r.CandidateSkeleton["attributes"].(map[string]any)
	if skel["dup"] != "second" {
		t.Fatalf("skeleton map keeps last-in-input value, got %v", skel["dup"])
	}
}

func TestDocumentTree(t *testing.T) {
	tests := []struct {
		name        string
		doc         Document
		wantHasProj bool
		wantHasReg  bool
	}{
		{
			name:        "project and region present when set",
			doc:         Document{Provider: "gcp", Project: "p1", Region: "eu", At: "t", Resources: []Resource{}},
			wantHasProj: true,
			wantHasReg:  true,
		},
		{
			name:        "empty project and region are omitted",
			doc:         Document{Provider: "gcp", At: "t", Resources: []Resource{}},
			wantHasProj: false,
			wantHasReg:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := tc.doc.tree()
			if tr["apiVersion"] != "discovery/v0" {
				t.Fatalf("apiVersion: got %v", tr["apiVersion"])
			}
			if tr["kind"] != "DiscoveryDocument" {
				t.Fatalf("kind: got %v", tr["kind"])
			}
			if _, ok := tr["project"]; ok != tc.wantHasProj {
				t.Fatalf("project presence: got %v want %v", ok, tc.wantHasProj)
			}
			if _, ok := tr["region"]; ok != tc.wantHasReg {
				t.Fatalf("region presence: got %v want %v", ok, tc.wantHasReg)
			}
			// resources is always present (even if empty).
			if _, ok := tr["resources"]; !ok {
				t.Fatalf("resources key must always be present")
			}
		})
	}
}

// tree() renders observations as path/value/derivation maps and nests the
// candidate skeleton — this is the exact shape the canonical hasher sees.
func TestDocumentTreeObservationShape(t *testing.T) {
	doc := Document{
		Provider: "gcp", At: "t",
		Resources: []Resource{{
			ProviderID:   "db",
			ResourceType: "capability.database.relational",
			Observations: []Observation{{Path: "p", Value: "v", Derivation: "measured"}},
			CandidateSkeleton: map[string]any{
				"attributes": map[string]any{"p": "v"},
			},
		}},
	}
	tr := doc.tree()
	resources := tr["resources"].([]any)
	if len(resources) != 1 {
		t.Fatalf("expected one resource, got %d", len(resources))
	}
	r := resources[0].(map[string]any)
	obs := r["observations"].([]any)
	o := obs[0].(map[string]any)
	if o["path"] != "p" || o["value"] != "v" || o["derivation"] != "measured" {
		t.Fatalf("observation shape wrong: %v", o)
	}
	if r["providerId"] != "db" || r["resourceType"] != "capability.database.relational" {
		t.Fatalf("resource identity fields wrong: %v", r)
	}
	if _, ok := r["candidateSkeleton"]; !ok {
		t.Fatalf("candidateSkeleton must be rendered")
	}
}

// Run must reflect the caller's provider name / project / region / at into
// the document header — these are the provenance coordinates a draft cites.
func TestRunPopulatesHeader(t *testing.T) {
	res, err := Run(newFakeDisc(nil, nil, nil), "my-project", "europe-west1", "2026-07-24T12:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	d := res.Discovery
	if d.Provider != "fake" || d.Project != "my-project" || d.Region != "europe-west1" || d.At != "2026-07-24T12:00:00Z" {
		t.Fatalf("header not populated from arguments: %+v", d)
	}
}
