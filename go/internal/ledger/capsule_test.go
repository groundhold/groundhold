package ledger

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestVerifyCapsuleAfterJSONRoundTrip pins the receiver contract (D103): a
// capsule is verified straight off json.Unmarshal, which decodes every number
// as float64. A capsule whose subchain carries a lease/binding event (i.e. a
// fencingToken — the common case for real infrastructure history) must still
// verify. Before the fix VerifyCapsule ran ValidateEvent on the float64 doc,
// whose int assertion on fencingToken failed, so an AUTHENTIC proof spuriously
// refused. Fail-safe, but it breaks "the receiver verifies with no ledger".
func TestVerifyCapsuleAfterJSONRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/l.jsonl"
	// builds lease.acquired + binding.updated(fencingToken) + lease.released
	writeHonestLedger(t, path, 0)

	cap, err := EmitCapsule(path, "db")
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	// sanity: the subchain really carries a fencingToken (else the test is vacuous)
	hasToken := false
	for _, doc := range cap.Events {
		ev, _ := doc["event"].(map[string]any)
		if _, ok := ev["fencingToken"]; ok {
			hasToken = true
		}
	}
	if !hasToken {
		t.Fatal("precondition: the db subchain must include a fencingToken event")
	}

	// the receiver path: marshal to JSON and decode back — numbers become float64
	raw, err := json.Marshal(cap)
	if err != nil {
		t.Fatal(err)
	}
	var received Capsule
	if err := json.Unmarshal(raw, &received); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCapsule(&received, nil); err != nil {
		t.Fatalf("a JSON-round-tripped capsule with a fencingToken must verify, got: %v", err)
	}

	// and a genuinely tampered capsule must still refuse (the fix must not
	// weaken verification — only accept the honest float64 shape)
	received.Head = "sha256:" + strings.Repeat("0", 64)
	if _, err := VerifyCapsule(&received, nil); err == nil {
		t.Fatal("a capsule whose claimed head was altered must still refuse")
	}
}
