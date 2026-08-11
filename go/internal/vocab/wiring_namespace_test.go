// External test package: the namespace constant lives in internal/ledger,
// which (transitively) imports vocab — so the gate cannot sit inside package
// vocab without an import cycle. One definition of the prefix, still shared.
package vocab_test

import (
	"strings"
	"testing"

	"groundhold/internal/ledger"
	"groundhold/internal/vocab"
)

// TestReservedWiringNamespaceIsFree pins D286's namespace reservation: no
// vocabulary may declare an attribute under "outputs.", because the ledger
// replay routes that prefix into the WIRING projection. A vocabulary that
// claimed the prefix would have its attribute silently routed away from the
// semantic observations the verifier and reconcile read — a value that looks
// declared but can never be observed. The reservation is enforced here rather
// than trusted, so a future vocabulary author is stopped by CI, not by a
// field bug.
func TestReservedWiringNamespaceIsFree(t *testing.T) {
	v, err := vocab.Embedded()
	if err != nil {
		t.Fatalf("vocab.Embedded(): %v", err)
	}
	// D579: a gate that scans a set must prove it HAD one. An empty embedded
	// vocabulary passes this loop silently, and D565 showed that copy can drift from
	// its source without anything noticing — so "no reserved attribute found" and
	// "no attribute found at all" must not read the same.
	if len(v) < 20 {
		t.Fatalf("only %d embedded vocabularies — this gate would pass on an empty "+
			"vocabulary set, which is exactly the state it must not bless", len(v))
	}
	attrs := 0
	for _, voc := range v {
		attrs += len(voc.Attributes)
	}
	if attrs < 100 {
		t.Fatalf("the embedded vocabularies declare %d attributes in total — too few "+
			"to be the real set, so this scan proves nothing", attrs)
	}
	for capType, voc := range v {
		for path := range voc.Attributes {
			if strings.HasPrefix(path, ledger.WiringPrefix) {
				t.Errorf("%s declares %q — the %q namespace is RESERVED for typed "+
					"outputs (D286); a vocabulary attribute there would be routed to "+
					"the wiring projection and never verified",
					capType, path, ledger.WiringPrefix)
			}
		}
	}
}
