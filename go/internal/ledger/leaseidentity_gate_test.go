package ledger

import (
	"strings"
	"testing"
)

// D644. D633 requires ONE lease to cover the whole affected set of a mutation, so a
// writer holding {a,b} cannot mutate {b,c} the moment an unrelated worker acquires
// {c} and is handed the same token number. The check compared each capability's
// lease `seq` against a running value that started at 0 — and 0 is also a lease
// seq, so the comparison was skipped for it and the verdict depended on the ORDER
// of the affected list:
//
//	a.seq=0 c.seq=1, both token 1:  caps=[a c] -> accepted
//	                                caps=[c a] -> refused
//
// Seq 0 reaches a fold exactly one way: a snapshot written before D633 carries no
// `seq` field, `omitempty` makes it absent, and every seeded lease reads back as 0.
// So any ledger that has ever been compacted by an older binary silently relaxed to
// the per-capability check the rule replaced.
func TestTheCoveringLeaseCheckIsNotOrderDependent(t *testing.T) {
	build := func(order []string) (string, bool) {
		led := New()
		led.Clock = 100
		led.leases["a"] = &lease{token: 1, expiry: 1000, ttl: 900, seq: 0}
		led.leases["c"] = &lease{token: 1, expiry: 1000, ttl: 900, seq: 1}
		ev := map[string]any{"type": "binding.updated", "fencingToken": 1,
			"capabilities": order,
			"body":         map[string]any{"providerId": "fake:x"}}
		reason, _, _ := led.checkRules(ev, order)
		return reason, reason == ""
	}
	forward, okF := build([]string{"a", "c"})
	reverse, okR := build([]string{"c", "a"})

	if okF != okR {
		t.Errorf("the same mutation was accepted in one order and refused in the "+
			"other — the covering-lease rule is decided by list order, which no "+
			"caller controls meaningfully.\n  [a c] -> accepted=%v %q\n  [c a] -> "+
			"accepted=%v %q", okF, forward, okR, reverse)
	}
	if okF || okR {
		t.Errorf("two capabilities under DIFFERENT leases carrying the same token "+
			"number were accepted as one mutation — this is the writer-mutating-into-"+
			"another-holder's-lease that D633 exists to stop: %q / %q", forward, reverse)
	}
}

// A snapshot written before lease identity existed cannot prove that two
// capabilities were held by ONE lease. Seeding must not answer that question with
// silence: the seq-less leases become distinct, and a multi-capability mutation
// over them is refused for the reason that is actually true.
func TestASnapshotWithoutLeaseIdentityDoesNotDisableTheRule(t *testing.T) {
	// The pre-D633 shape: leases with a token and a TTL and no seq at all.
	s := &Snapshot{
		APIVersion: "snapshot/v0.1",
		Kind:       "LedgerSnapshot",
		BaseEvents: 12,
		BaseHead:   "sha256:aaaa",
		Clock:      100,
		Leases: map[string]SnapLease{
			"a": {Token: 1, Expiry: 1000, TTL: 900},
			"b": {Token: 1, Expiry: 1000, TTL: 900},
		},
	}
	led, err := SeedLedger(s)
	if err != nil {
		t.Fatal(err)
	}
	led.Clock = 100

	if led.leases["a"].seq == led.leases["b"].seq {
		t.Errorf("both seeded leases carry seq %d — the snapshot never said they "+
			"were the same lease, and reading them as one makes the covering check "+
			"vacuous for every ledger an older binary compacted", led.leases["a"].seq)
	}
	ev := map[string]any{"type": "binding.updated", "fencingToken": 1,
		"capabilities": []string{"a", "b"},
		"body":         map[string]any{"providerId": "fake:x"}}
	reason, _, _ := led.checkRules(ev, []string{"a", "b"})
	if reason == "" {
		t.Fatal("a cross-capability mutation was accepted over a snapshot that " +
			"cannot say whether one lease covered both")
	}
	if !strings.Contains(reason, "snapshot") {
		t.Errorf("the refusal blames the wrong thing — the operator must be told "+
			"the snapshot predates lease identity and to re-acquire the lease, not "+
			"that two leases differ (which this snapshot cannot establish): %q", reason)
	}

	// The control: a single-capability mutation is trivially covered by one lease
	// and must still work, or an old snapshot would freeze the ledger entirely.
	if reason, _, _ := led.checkRules(map[string]any{
		"type": "binding.updated", "fencingToken": 1,
		"capabilities": []string{"a"},
		"body":         map[string]any{"providerId": "fake:x"},
	}, []string{"a"}); reason != "" {
		t.Errorf("a one-capability mutation must still be accepted: %q", reason)
	}
}
