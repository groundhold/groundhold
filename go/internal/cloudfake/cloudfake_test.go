package cloudfake

import (
	"strings"
	"testing"
)

func ours(tags map[string]string) bool { return tags["owner"] == "us" }

// A create is READ-DRIVEN: it becomes Available only after settleAfter describes — a
// driver that concludes "ready" on the first read is caught.
func TestReadDrivenReady(t *testing.T) {
	w := New(2)
	w.Create("db1", "instance", map[string]string{"owner": "us"})

	if st, _, _ := w.Describe("db1"); st != Creating {
		t.Fatalf("read 1: state=%s, want creating (not ready yet)", st)
	}
	if st, _, _ := w.Describe("db1"); st != Available {
		t.Fatalf("read 2: state=%s, want available", st)
	}
	if st, _, found := w.Describe("db1"); !found || st != Available {
		t.Fatalf("read 3: state=%s found=%v, want available", st, found)
	}
}

// settleAfter==0 means immediate availability (a sync resource).
func TestImmediateReady(t *testing.T) {
	w := New(0)
	w.Create("s1", "secret", nil)
	if st, _, _ := w.Describe("s1"); st != Available {
		t.Fatalf("sync resource must be available on first read, got %s", st)
	}
}

// A stuck resource NEVER becomes ready — the adversarial "never provisions" case.
func TestStuckNeverReady(t *testing.T) {
	w := New(1)
	w.Create("db1", "instance", nil)
	w.SetStuck("db1", Observed)
	for i := 0; i < 10; i++ {
		if st, _, _ := w.Describe("db1"); st != Creating {
			t.Fatalf("a stuck resource must stay creating, got %s at read %d", st, i)
		}
	}
}

// Delete is async and read-driven the same way.
func TestAsyncDelete(t *testing.T) {
	w := New(2)
	w.Seed(&Resource{ID: "db1", Type: "instance", State: Available})
	if err := w.Delete("db1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if st, _, _ := w.Describe("db1"); st != Deleting {
		t.Fatalf("read 1 after delete: state=%s, want deleting", st)
	}
	if _, _, found := w.Describe("db1"); found {
		t.Fatalf("read 2 after delete: still found, want gone")
	}
}

// The Aurora rule: a cluster refuses deletion while a member still exists; once the
// member is gone the cluster deletes. This is the exact constraint AWS bit us with.
func TestParentRefusesDeleteWhileChild(t *testing.T) {
	w := New(1)
	w.AddConstraint(Constraint{
		Name: "cluster-has-member", Prov: Observed,
		Blocks: func(w *World, id string) string {
			if w.TypeOf(id) == "cluster" && w.ChildPresent(id, "member") {
				return "cluster still has a member"
			}
			return ""
		},
	})
	w.Seed(&Resource{ID: "cl1", Type: "cluster", State: Available})
	w.Seed(&Resource{ID: "cl1-member", Type: "member", State: Available})

	if err := w.Delete("cl1"); err == nil {
		t.Fatal("deleting a cluster with a live member must be refused")
	}
	// tear the member down first, let it settle, THEN the cluster deletes.
	if err := w.Delete("cl1-member"); err != nil {
		t.Fatalf("member delete: %v", err)
	}
	w.Describe("cl1-member") // settle -> Absent (settleAfter=1)
	if err := w.Delete("cl1"); err != nil {
		t.Fatalf("cluster delete after member gone must succeed, got %v", err)
	}
}

// LeakCheck is the universal postcondition: an owned resource left non-terminal is a
// leak; a deleted/absent one is not. This catches the Aurora-class bug generically.
func TestLeakCheck(t *testing.T) {
	w := New(0)
	w.Seed(&Resource{ID: "kept", Type: "cluster", State: Available, Tags: map[string]string{"owner": "us"}})
	w.Seed(&Resource{ID: "gone", Type: "cluster", State: Absent, Tags: map[string]string{"owner": "us"}})
	w.Seed(&Resource{ID: "foreign", Type: "cluster", State: Available, Tags: map[string]string{"owner": "them"}})

	leaked := w.LeakCheck(ours)
	if len(leaked) != 1 || !strings.Contains(leaked[0], "kept") {
		t.Fatalf("leak check = %v, want exactly [kept] (absent=clean, foreign=not ours)", leaked)
	}
}

// A test whose green result rode an Assumed transition or constraint is surfaced, not
// silently trusted — the anti-recursion audit.
func TestProvenanceAudit(t *testing.T) {
	w := New(1)
	w.Create("db1", "instance", nil)
	w.SetStuck("db1", Assumed) // pretend "never ready" is a guess
	w.Describe("db1")          // stuck, no transition fires yet
	if len(w.UsedAssumed()) != 0 {
		t.Fatalf("no transition completed yet: %v", w.UsedAssumed())
	}

	w2 := New(1)
	w2.AddConstraint(Constraint{
		Name: "guessed-rule", Prov: Assumed,
		Blocks: func(w *World, id string) string { return "assumed refusal" },
	})
	w2.Seed(&Resource{ID: "x", State: Available})
	_ = w2.Delete("x")
	if got := w2.UsedAssumed(); len(got) != 1 || got[0] != "constraint:guessed-rule" {
		t.Fatalf("an exercised Assumed constraint must be flagged, got %v", got)
	}
}

// TestLeakDetectorCatchesAuroraClass is the payoff demonstration: the leak-detector
// postcondition catches the real Aurora bug GENERICALLY, with no bug-specific
// assertion. Two teardown sequences run against the same modelled world (cluster +
// member, the cluster refusing delete while the member exists). The BUGGY sequence
// (delete member, immediately delete cluster — the exact shipped bug) leaves the
// cluster standing; LeakCheck flags it. The CORRECT sequence (wait for the member to
// be gone, then delete) leaves nothing. This is the assertion a per-service probe test
// gets for free once its fake is a World.
func TestLeakDetectorCatchesAuroraClass(t *testing.T) {
	newWorld := func() *World {
		w := New(2)
		w.AddConstraint(Constraint{
			Name: "cluster-has-member", Prov: Observed,
			Blocks: func(w *World, id string) string {
				if w.TypeOf(id) == "cluster" && w.ChildPresent(id, "member") {
					return "InvalidDBClusterStateFault: cluster still has a member"
				}
				return ""
			},
		})
		w.Seed(&Resource{ID: "cl", Type: "cluster", State: Available, Tags: map[string]string{"owner": "us"}})
		w.Seed(&Resource{ID: "cl-member", Type: "member", State: Available, Tags: map[string]string{"owner": "us"}})
		return w
	}

	// BUGGY teardown: delete member, then immediately the cluster (no wait).
	buggy := newWorld()
	_ = buggy.Delete("cl-member")
	_ = buggy.Delete("cl") // refused by the constraint — the member is still deleting
	if leaked := buggy.LeakCheck(ours); len(leaked) == 0 {
		t.Fatal("the buggy teardown MUST leak the cluster — the leak detector failed to catch the Aurora class")
	}

	// CORRECT teardown: delete member, drain it to gone, then the cluster.
	fixed := newWorld()
	_ = fixed.Delete("cl-member")
	for i := 0; i < 5; i++ { // poll the member to gone (waitInstanceGone)
		if _, _, found := fixed.Describe("cl-member"); !found {
			break
		}
	}
	if err := fixed.Delete("cl"); err != nil {
		t.Fatalf("cluster delete after member gone must succeed: %v", err)
	}
	for i := 0; i < 5; i++ {
		fixed.Describe("cl")
	}
	if leaked := fixed.LeakCheck(ours); len(leaked) != 0 {
		t.Fatalf("the correct teardown must leave nothing, leaked: %v", leaked)
	}
}

// TestLedgerWorldDiff is the second universal postcondition: it catches a receipt for
// a resource never created (the D62 phantom-receipt class) and a wire mutation with no
// receipt (an orphan). The World records the actual wire mutations; the diff is against
// what the ledger claims.
func TestLedgerWorldDiff(t *testing.T) {
	w := New(0)
	w.Create("db-a", "instance", nil)
	w.Create("db-b", "instance", nil)

	// clean: every create has a receipt, every receipt a create.
	if p, u := LedgerWorldDiff(w.CreatedIDs(), []string{"db-a", "db-b"}); len(p) != 0 || len(u) != 0 {
		t.Fatalf("matched ledger/world must diff clean, got phantom=%v unrecorded=%v", p, u)
	}
	// phantom receipt: the ledger claims db-c, which was never created (D62).
	if p, _ := LedgerWorldDiff(w.CreatedIDs(), []string{"db-a", "db-b", "db-c"}); len(p) != 1 || p[0] != "db-c" {
		t.Fatalf("a receipt with no wire create must be flagged phantom, got %v", p)
	}
	// unrecorded mutation: db-b was created but the ledger has no receipt for it.
	if _, u := LedgerWorldDiff(w.CreatedIDs(), []string{"db-a"}); len(u) != 1 || u[0] != "db-b" {
		t.Fatalf("a wire create with no receipt must be flagged unrecorded, got %v", u)
	}
}
