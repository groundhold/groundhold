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
