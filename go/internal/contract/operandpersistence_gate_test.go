package contract_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheOperandBlockSaysItIsRecordedVerbatim (D851).
//
// Reported from the field: an EventBridge Scheduler payload is the ONLY channel a
// scheduled invocation has — a direct Lambda call carries no headers — so a team that
// wants the job to prove its identity to the target has nowhere to put the proof except
// an operand, and nothing told them that operands are written into the ledger and stay
// there. The D364 scan says exactly that, but only for a value whose SHAPE it recognises;
// a random secret is invisible to it by design, and the reporter's was.
//
// So the statement has to live where a person looks BEFORE writing the value, which is the
// published description of the block itself. This gate keeps it there: a sentence that
// matters only when someone reads it first is a sentence that can be dropped without any
// test noticing.
func TestTheOperandBlockSaysItIsRecordedVerbatim(t *testing.T) {
	// internal/contract sits two levels under go/, and the spec is a sibling of go/.
	blob, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "candidate.schema.json"))
	if err != nil {
		t.Fatalf("read candidate schema: %v", err)
	}
	var doc struct {
		Properties struct {
			Capabilities struct {
				AdditionalProperties struct {
					Properties struct {
						Implementation struct {
							Description string `json:"description"`
						} `json:"implementation"`
					} `json:"properties"`
				} `json:"additionalProperties"`
			} `json:"capabilities"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("parse candidate schema: %v", err)
	}
	desc := doc.Properties.Capabilities.AdditionalProperties.Properties.Implementation.Description
	if len(desc) < 200 {
		t.Fatalf("the implementation block's description is %d chars — too short to be the "+
			"real one; this gate would pass over nothing (D328)", len(desc))
	}

	// The claim itself, and the caveat that makes it useful. Without the second half a
	// reader can take the scan's silence for a clearance, which is what the field did.
	for _, want := range []string{"LEDGER VERBATIM", "silence is not a clearance"} {
		if !strings.Contains(desc, want) {
			t.Errorf("the implementation block's description no longer says %q.\n\n"+
				"Operand values are persisted and travel in capsules and exports. The "+
				"shape-based warning (D364) cannot see an arbitrary secret, so this "+
				"sentence is the only thing standing between a reader and a credential "+
				"in a ledger (D851).", want)
		}
	}
}
