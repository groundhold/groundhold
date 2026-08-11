package suggest

import (
	"reflect"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/scalars"
	"groundhold/internal/vocab"
)

// vocs builds a minimal vocabulary set with one relational-db attribute carrying
// a `recommended` marker, parameterized so each test can shape the marker.
func vocs(rec map[string]any) map[string]vocab.Vocabulary {
	attr := map[string]any{"kind": "bool"}
	if rec != nil {
		attr["recommended"] = rec
	}
	return map[string]vocab.Vocabulary{
		"capability.database.relational": {
			Capability: "capability.database.relational",
			Attributes: map[string]map[string]any{
				"encryption.inTransit": attr,
			},
		},
	}
}

func dbContract(env string, cons ...contract.Constraint) *contract.Contract {
	return &contract.Contract{
		ID:          "c1",
		Environment: env,
		Capabilities: map[string]map[string]any{
			"db": {"id": "db", "type": "capability.database.relational"},
		},
		Constraints: cons,
	}
}

func baseRec(scope string) map[string]any {
	return map[string]any{
		"op": "equals", "value": true, "scope": scope,
		"rationale": "Force TLS.", "ruleId": "PV_TEST",
		"controls": map[string]any{"FSBP": []any{"RDS.16"}},
	}
}

func TestScopeFilter(t *testing.T) {
	// prod-scoped rec must NOT fire in a test/dev environment.
	r := Compute(dbContract("test"), vocs(baseRec("prod")), nil)
	if len(r.Suggestions) != 0 {
		t.Fatalf("prod-scoped rec fired in test env: %+v", r.Suggestions)
	}
	// all-scoped rec fires everywhere.
	r = Compute(dbContract("test"), vocs(baseRec("all")), nil)
	if len(r.Suggestions) != 1 {
		t.Fatalf("all-scoped rec did not fire: %+v", r.Suggestions)
	}
	// prod-scoped rec fires in prod (and production normalizes to prod).
	if len(Compute(dbContract("prod"), vocs(baseRec("prod")), nil).Suggestions) != 1 {
		t.Fatal("prod-scoped rec did not fire in prod")
	}
	if len(Compute(dbContract("production"), vocs(baseRec("prod")), nil).Suggestions) != 1 {
		t.Fatal("prod-scoped rec did not fire in production")
	}
}

func TestWhenGuard(t *testing.T) {
	rec := baseRec("all")
	rec["when"] = map[string]any{"path": "network.publicExposure", "op": "equals", "value": true}
	// guard not satisfied -> no suggestion
	if got := Compute(dbContract("test"), vocs(rec), nil).Suggestions; len(got) != 0 {
		t.Fatalf("when guard held with no matching value: %+v", got)
	}
	// guard satisfied by a contract constraint
	c := dbContract("test", contract.Constraint{
		ID: "x", Subject: "db", Path: "network.publicExposure", Op: "equals", Value: true,
	})
	if got := Compute(c, vocs(rec), nil).Suggestions; len(got) != 1 {
		t.Fatalf("when guard did not hold on matching contract constraint: %+v", got)
	}
	// guard satisfied by a candidate attribute value
	cand := &contract.Candidate{Capabilities: map[string]map[string]contract.Provenanced{
		"db": {"network.publicExposure": {Scalar: &scalars.Scalar{Kind: "bool", Value: true}, Status: "declared"}},
	}}
	if got := Compute(dbContract("test"), vocs(rec), cand).Suggestions; len(got) != 1 {
		t.Fatalf("when guard did not hold on matching candidate value: %+v", got)
	}
}

func TestSkipAlreadyConstrained(t *testing.T) {
	c := dbContract("test", contract.Constraint{
		ID: "c-tls", Subject: "db", Path: "encryption.inTransit", Op: "equals", Value: true,
	})
	r := Compute(c, vocs(baseRec("all")), nil)
	if len(r.Suggestions) != 0 {
		t.Fatalf("suggested an already-constrained (subject,path): %+v", r.Suggestions)
	}
	if r.AlreadyEnforced != 1 {
		t.Fatalf("alreadyEnforced: want 1, got %d", r.AlreadyEnforced)
	}
}

func TestDeterministicSort(t *testing.T) {
	// two capabilities of the same type -> suggestions sorted by capability id.
	c := &contract.Contract{
		ID: "c1", Environment: "test",
		Capabilities: map[string]map[string]any{
			"zeta":  {"type": "capability.database.relational"},
			"alpha": {"type": "capability.database.relational"},
		},
	}
	r := Compute(c, vocs(baseRec("all")), nil)
	if len(r.Suggestions) != 2 {
		t.Fatalf("want 2 suggestions, got %d", len(r.Suggestions))
	}
	if r.Suggestions[0].Capability != "alpha" || r.Suggestions[1].Capability != "zeta" {
		t.Fatalf("suggestions not sorted by capability: %v, %v",
			r.Suggestions[0].Capability, r.Suggestions[1].Capability)
	}
	// determinism: repeated runs are byte-identical.
	if !reflect.DeepEqual(r, Compute(c, vocs(baseRec("all")), nil)) {
		t.Fatal("Compute is not deterministic across runs")
	}
}

func TestSnippetGolden(t *testing.T) {
	r := Compute(dbContract("test"), vocs(baseRec("all")), nil)
	want := "- id: rec-db-encryption.inTransit\n" +
		"  subject: db\n" +
		"  path: encryption.inTransit\n" +
		"  op: equals\n" +
		"  value: true\n" +
		"  verify: { method: provider-api }"
	if got := r.Suggestions[0].Snippet; got != want {
		t.Fatalf("snippet golden mismatch:\n got: %q\nwant: %q", got, want)
	}
	if src := r.Suggestions[0].Source(); src != "FSBP RDS.16" {
		t.Fatalf("source label: want FSBP RDS.16, got %q", src)
	}
}

func TestListValueSnippet(t *testing.T) {
	rec := map[string]any{
		"op": "in", "value": []any{"private", "mixed"}, "scope": "all",
		"rationale": "x", "ruleId": "PV_L", "controls": map[string]any{"CIS-EKS": []any{"5.4.1"}},
	}
	v := map[string]vocab.Vocabulary{
		"capability.database.relational": {Capability: "capability.database.relational",
			Attributes: map[string]map[string]any{"network.apiExposure": {"kind": "string", "recommended": rec}}},
	}
	r := Compute(dbContract("test"), v, nil)
	if len(r.Suggestions) != 1 || r.Suggestions[0].Snippet == "" {
		t.Fatalf("list-value suggestion missing: %+v", r.Suggestions)
	}
	if want := "  value: [private, mixed]\n"; !contains(r.Suggestions[0].Snippet, want) {
		t.Fatalf("list value not rendered: %q", r.Suggestions[0].Snippet)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// D773. The advisor recommends HARDENING — encryption, exposure, flow logs, rotation —
// and baked `verify: {method: static}` into every snippet, which is the bar the author's
// own declaration meets. Paste the tool's advice, declare the value it told you to
// declare, and the control is green from the assertion.
//
// The bar is now DERIVED from what the vocabulary says is reachable, not chosen. The test
// asserts the derivation rather than the three strings, so a fourth evidence class fails
// here instead of silently taking the default.
func TestTheRecommendedBarIsDerivedFromWhatCanBeRead(t *testing.T) {
	for _, c := range []struct {
		evidence string
		want     string
		why      string
	}{
		{"resource", "provider-api",
			"ordinary resource state can be READ; recommending a bar the declaration meets " +
				"turns a hardening control into a restatement"},
		{"probe", "probe", "an outcome needs a measurement, not a config read"},
		{"projection", "static",
			"no reading will ever exist (D311); static is the only reachable bar and the " +
				"compile-time advisory says so"},
		{"", "provider-api", "an unmarked attribute is ordinary resource state"},
	} {
		if got := snippetMethod(c.evidence); got != c.want {
			t.Errorf("evidence %q -> %q, want %q — %s", c.evidence, got, c.want, c.why)
		}
	}
}
