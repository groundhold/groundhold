package posture

import "testing"

// TestPostureExitCode pins D958: the unattended exit code (the only alert, D649) is
// non-zero for shadow/drift AND for unknown (unverifiable compliance) AND for an incomplete
// sweep (shadowLowerBound), but 0 for a clean or merely-decayed estate. Reporting 0 for
// unknown or incomplete scope would read "all clear" over an estate posture could not judge.
func TestPostureExitCode(t *testing.T) {
	cases := []struct {
		name string
		s    Summary
		want int
	}{
		{"clean", Summary{ManagedOK: 3}, 0},
		{"decayed alone renews, not fails", Summary{Decayed: 2}, 0},
		{"shadow", Summary{Shadow: 1}, 2},
		{"drift", Summary{Drifted: 1}, 2},
		{"unknown is not clean", Summary{Unknown: 1}, 2},
		{"incomplete sweep is not clean", Summary{ShadowLowerBound: true}, 2},
	}
	for _, c := range cases {
		if got := c.s.ExitCode(); got != c.want {
			t.Errorf("%s: ExitCode()=%d, want %d", c.name, got, c.want)
		}
	}
}

func classOf(doc *Document, pid string) string {
	for _, r := range doc.Rows {
		if r.ProviderID == pid {
			return r.Class
		}
	}
	return ""
}

// TestFiveClasses pins each class against one deterministic input.
func TestFiveClasses(t *testing.T) {
	in := Input{
		At: "2026-07-18T00:00:00Z",
		Discovered: []Discovered{
			{ProviderID: "fake:managed", Scope: "s", ScopeComplete: true},
			{ProviderID: "fake:drifted", Scope: "s", ScopeComplete: true},
			{ProviderID: "fake:decayed", Scope: "s", ScopeComplete: true},
			{ProviderID: "fake:shadow", Scope: "s", ScopeComplete: true}, // no binding
		},
		// D650: the sweep's completeness travels per SCOPE now; this fixture
		// always meant "one scope, listed completely" — it just used to say so
		// once per resource.
		Scopes: []Scope{{Provider: "fake", Scope: "s", Complete: true}},
		Bindings: map[string]string{
			"ok-cap":    "fake:managed",
			"drift-cap": "fake:drifted",
			"decay-cap": "fake:decayed",
			"unver-cap": "fake:unver",
		},
		Verdict: map[string]string{
			"ok-cap":    "satisfied",
			"drift-cap": "violated",
			"decay-cap": "satisfied", // satisfied but its proof decayed
			"unver-cap": "unverifiable",
		},
		Decayed: map[string]bool{"decay-cap": true},
	}
	doc := Classify(in)

	want := map[string]string{
		"fake:managed": "managed-ok",
		"fake:drifted": "drifted",
		"fake:decayed": "decayed",
		"fake:shadow":  "shadow",
		"fake:unver":   "unknown",
	}
	for pid, cls := range want {
		if got := classOf(doc, pid); got != cls {
			t.Fatalf("%s classified %q, want %q", pid, got, cls)
		}
	}
	s := doc.Summary
	if s.ManagedOK != 1 || s.Drifted != 1 || s.Decayed != 1 || s.Shadow != 1 || s.Unknown != 1 {
		t.Fatalf("summary counts wrong: %+v", s)
	}
	if s.ShadowLowerBound {
		t.Fatal("all scopes complete — shadow count must be exact, not a lower bound")
	}
	if doc.PostureHash == "" {
		t.Fatal("missing content hash")
	}
}

func TestDriftOutranksDecay(t *testing.T) {
	// a capability both violated AND stale is DRIFTED (a fresh violation wins)
	doc := Classify(Input{At: "2026-07-18T00:00:00Z",
		Bindings: map[string]string{"c": "fake:x"},
		Verdict:  map[string]string{"c": "violated"},
		Decayed:  map[string]bool{"c": true}})
	if classOf(doc, "fake:x") != "drifted" {
		t.Fatalf("violated+stale must be drifted, got %q", classOf(doc, "fake:x"))
	}
}

func TestIncompleteScopeMakesShadowALowerBound(t *testing.T) {
	doc := Classify(Input{At: "2026-07-18T00:00:00Z",
		Discovered: []Discovered{{ProviderID: "fake:s", Scope: "s", ScopeComplete: false}}})
	if !doc.Summary.ShadowLowerBound {
		t.Fatal("an incomplete scope must demote the shadow count to a lower bound")
	}
	if classOf(doc, "fake:s") != "shadow" {
		t.Fatal("an unbound discovered id is still shadow even from an incomplete scope (presence, not absence)")
	}
}

func TestShadowCarriesAdoptThenRetireRecipe(t *testing.T) {
	doc := Classify(Input{At: "2026-07-18T00:00:00Z",
		Discovered: []Discovered{{ProviderID: "s3:rogue", ScopeComplete: true}}})
	var rem Remediation
	for _, r := range doc.Rows {
		if r.ProviderID == "s3:rogue" {
			rem = r.Remediation
		}
	}
	if rem.Action != "adopt" || len(rem.Steps) == 0 {
		t.Fatalf("shadow must carry an adopt recipe: %+v", rem)
	}
	// the delete path is honestly adopt-then-retire, never a raw provider delete
	if rem.Note == "" || !contains(rem.Note, "retired") {
		t.Fatalf("shadow delete must be the adopt-then-retire path: %q", rem.Note)
	}
}

// TestHashIsClassificationOnly proves identity ignores the --at and prose: two runs
// that reach the same classification hash identically even at different times.
func TestHashIsClassificationOnly(t *testing.T) {
	mk := func(at string) *Document {
		return Classify(Input{At: at,
			Bindings: map[string]string{"c": "fake:x"},
			Verdict:  map[string]string{"c": "satisfied"}})
	}
	a := mk("2026-07-18T00:00:00Z")
	b := mk("2027-01-01T12:00:00Z")
	if a.PostureHash != b.PostureHash {
		t.Fatalf("same classification must hash identically regardless of --at:\n %s\n %s", a.PostureHash, b.PostureHash)
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
