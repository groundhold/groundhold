package progress

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1114. spec/progress.md publishes the action-state enum under the heading "Closed
// action-state enum" and says it is "closed twice, in code and in the suite". It is
// closed in a THIRD place — that document — and nothing read it. No test in the tree
// opened spec/progress.md at all.
//
// The names were never the interesting part. The table publishes two RELATIONS beside
// them, and one of those is a claim about liveness: motion is a pure function of state,
// and "the only motion states are `running` and `provider-wait`". A renderer animates
// what the runtime calls motion, and a human reads animation as "it is working". If the
// motion set ever grew to include `stalled` or `blocked-consent`, a wedged action would
// keep moving on screen while the document still promised it could not — the failure
// would be invisible to every test, because nothing compares the two.
//
// The expected table is written HERE rather than derived from either side. A gate that
// parses the spec and checks what it finds narrows itself when the spec loses a row
// (D1113 was exactly that, verified by deleting one), and a gate that reads the code
// and checks the code proves nothing at all.
func TestActionStateTableMatchesTheSpec(t *testing.T) {
	type row struct {
		terminal bool
		motion   bool
	}
	want := map[string]row{
		"pending":         {terminal: false, motion: false},
		"ready":           {terminal: false, motion: false},
		"running":         {terminal: false, motion: true},
		"provider-wait":   {terminal: false, motion: true},
		"stalled":         {terminal: false, motion: false},
		"blocked-consent": {terminal: false, motion: false},
		"done":            {terminal: true, motion: false},
		"failed":          {terminal: true, motion: false},
		"skipped":         {terminal: true, motion: false},
		"indeterminate":   {terminal: true, motion: false},
	}

	// --- the runtime's answers ---
	for name, w := range want {
		s := ActionState(name)
		if got := IsTerminal(s); got != w.terminal {
			t.Errorf("runtime: IsTerminal(%s) = %v, the published table says %v", name, got, w.terminal)
		}
		if got := IsMotion(s); got != w.motion {
			t.Errorf("runtime: IsMotion(%s) = %v, the published table says %v.\n"+
				"Motion is read by a human as \"it is working\"; a state that animates "+
				"without the table granting it says a wedged action is alive.", name, got, w.motion)
		}
	}
	// A state the table does not name must not be motion or terminal by accident —
	// the maps are keyed, so an unknown key answers false, and this asserts that
	// rather than assuming it.
	for _, unknown := range []string{"blocked-input", "waiting", ""} {
		if IsMotion(ActionState(unknown)) || IsTerminal(ActionState(unknown)) {
			t.Errorf("runtime treats the unpublished state %q as motion or terminal", unknown)
		}
	}

	// --- the document's answers ---
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "spec", "progress.md"))
	if err != nil {
		t.Skipf("no progress spec here: %v", err)
	}
	table := regexp.MustCompile(`(?s)## Closed action-state enum(.*?)\n\n- \*\*Motion`).
		FindStringSubmatch(string(raw))
	if table == nil {
		t.Fatal("spec/progress.md no longer carries the closed action-state table in the " +
			"form this gate reads — the published copy is unguarded again")
	}

	published := map[string]row{}
	for _, line := range strings.Split(table[1], "\n") {
		m := regexp.MustCompile("^\\| `([a-z-]+)` \\|(.*)\\|\\s*(yes\\*?|no)\\s*\\|$").FindStringSubmatch(line)
		if m == nil {
			continue
		}
		published[m[1]] = row{
			terminal: strings.Contains(m[2], "terminal"),
			motion:   strings.HasPrefix(m[3], "yes"),
		}
	}

	var missing, extra []string
	for name := range want {
		if _, ok := published[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name, got := range published {
		w, ok := want[name]
		if !ok {
			extra = append(extra, name)
			continue
		}
		if got != w {
			t.Errorf("spec/progress.md publishes %s as {terminal:%v motion:%v}; this gate "+
				"and the runtime say {terminal:%v motion:%v}", name, got.terminal, got.motion,
				w.terminal, w.motion)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("the published table no longer lists: %s — if a state was genuinely "+
			"removed, remove it here and from the runtime in the same commit",
			strings.Join(missing, ", "))
	}
	if len(extra) > 0 {
		t.Errorf("the published table lists states this gate does not know about: %s — "+
			"a new state arrives through a conformance case first, then here",
			strings.Join(extra, ", "))
	}
}
