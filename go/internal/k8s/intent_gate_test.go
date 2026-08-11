package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D584. D550 found that a READ was gated on a write-safety predicate, and fixed the
// three call sites a failing command walked through. D574 found the fourth, because a
// fix derived from a trace covers the trace. Nine dispatch points each choose
// `mappingFor` (any mapped service) or `genericMapping` (mapped AND write-safe) on
// their own, and the choice is invisible at the call site — `genericMapping` does not
// say "write" anywhere in its name.
//
// So the convention is still a convention, and D583's test applies: does the next
// author have to REMEMBER it? Yes. Then it is not fixed.
//
// This is the mechanism. `serviceMapping(service, intent)` is the one place read and
// write semantics live, the caller must state which it wants, and the refusal is
// worded for that intent. `genericMapping` may then have exactly one caller — this
// gate — so write-safety cannot be consulted by accident, and a tenth verb cannot
// repeat D550 by forgetting which helper to use.
func TestWriteSafetyIsConsultedInExactlyOnePlace(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	callers := map[string]int{}
	scanned := 0
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(".", n))
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		for _, line := range strings.Split(string(raw), "\n") {
			// the DISPATCH question — "may this verb write here?" — is
			// writeSafe(). Two callers are legitimate: the witness predicate the
			// compiler registers (a different question: is it authored at all?)
			// and serviceMapping. A third is a verb deciding for itself again.
			if strings.Contains(line, ".writeSafe()") && !strings.HasPrefix(strings.TrimSpace(line), "//") &&
				!strings.Contains(line, "func (m *Mapping) writeSafe") {
				callers[n]++
			}
		}
	}
	if scanned < 10 {
		t.Fatalf("scanned %d driver files — the probe broke and this gate would pass "+
			"on anything", scanned)
	}
	total := 0
	for _, n := range callers {
		total += n
	}
	if total > 2 { // the witness predicate and serviceMapping, nothing else
		t.Errorf("write-safety is consulted in %d places across %v — the third and "+
			"beyond is a verb deciding read-vs-write for itself, which is how D550 "+
			"and D574 happened. Route it through serviceMapping(service, intent).",
			total, callers)
	}
}
