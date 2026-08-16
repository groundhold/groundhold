package k8s

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1118. spec/mapping.md publishes the mapping engine's operator set and calls it
// CLOSED, with a rule attached: "Growing the set is a spec change with a conformance
// case and a DESIGN entry — never an ad-hoc addition." No test read that file.
//
// The set was written down three times. The spec listed three ops. `closedOps` held
// four. The refusal message recited its own copy of the four names. `resolve-ref` — a
// real operator, used by a shipped mapping — had earned its DESIGN entry and never
// reached the spec, so half the rule was honoured and the published half was not.
//
// The third copy is gone: the refusal now renders the registry rather than restating
// it, because a message that names its own set will eventually tell an author their op
// is missing from a set that no longer exists.
func TestClosedOperatorSetMatchesTheSpec(t *testing.T) {
	want := map[string]bool{
		"copy": true, "const": true, "quantity-int": true, "resolve-ref": true,
	}

	diffOps(t, "the engine's closed operator set", closedOps, want)

	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "mapping.md"))
	if err != nil {
		t.Skipf("no mapping spec here: %v", err)
	}
	block := regexp.MustCompile(`(?s)applies a CLOSED operator set(.*?)Growing the set`).
		FindStringSubmatch(string(raw))
	if block == nil {
		t.Fatal("spec/mapping.md no longer publishes the closed operator set in the form " +
			"this gate reads — the published copy is unguarded again")
	}
	published := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z][a-z-]*)`").FindAllStringSubmatch(block[1], -1) {
		published[m[1]] = true
	}
	diffOps(t, "spec/mapping.md's published operator set", published, want)

	// The refusal must RECITE the registry rather than carry a copy of it — checked by
	// driving the real refusal, not by asking the helper. The first version of this
	// assertion inspected closedOpNames() and passed while the message itself carried
	// a hand-written list: a check aimed at the wrong witness.
	_, err = loadMapping([]byte(`mapping: v0.1
fieldpath: groundhold/fieldpath/v1
service: test
provider: k8s
capability: capability.test
resource: {group: "", version: v1, kind: Test, scope: Namespaced}
schema: {source: test, digest: "sha256:0"}
attributes:
  test.path:
    op: no-such-op
    field: spec.x
`))
	if err == nil {
		t.Fatal("a mapping declaring an op outside the closed set loaded without " +
			"complaint — the closed set is not closed")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no-such-op") {
		t.Errorf("the refusal does not name the offending op: %s\n"+
			"spec/mapping.md promises the engine refuses BY NAME, never guesses.", msg)
	}
	for op := range want {
		if !strings.Contains(msg, op) {
			t.Errorf("the refusal does not recite %q from the registry:\n  %s\n\n"+
				"The message must render the registry, not restate it — a restated "+
				"list eventually tells an author their op is missing from a set that "+
				"no longer exists.", op, msg)
		}
	}
}

func diffOps(t *testing.T, what string, got, want map[string]bool) {
	t.Helper()
	var missing, extra []string
	for v := range want {
		if !got[v] {
			missing = append(missing, v)
		}
	}
	for v := range got {
		if !want[v] {
			extra = append(extra, v)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%s is missing: %s", what, strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.Errorf("%s carries unexpected: %s — a new op is a spec change with a "+
			"conformance case and a DESIGN entry, and this gate is where the spec half "+
			"gets noticed", what, strings.Join(extra, ", "))
	}
}
