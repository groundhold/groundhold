package observe

import (
	"os"
	"testing"

	"groundhold/internal/ledger"
	"groundhold/internal/provider"
)

// F16/F25 residual: a bound capability that reads CLEANLY but yields zero
// observable attributes must still be RECORDED, so a later compile can tell
// "observed but blind" (isolate) from "never observed" (re-observe). A read
// FAILURE is different — it stays Unreadable and records nothing (D242).
func TestObserveRecordsAReadableButEmptyCapability(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ledger.jsonl"
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(map[string]string{"db": "empty:db-1"}, &provider.Fake{},
		"2026-07-12T13:00:00Z", 0, led, path, true)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if res.Partial || len(res.Unreadable) != 0 {
		t.Fatalf("a clean empty read is NOT partial/unreadable, got %+v", res)
	}
	if len(res.Observations) != 0 {
		t.Fatalf("an empty capability yields no observations, got %+v", res.Observations)
	}
	after, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !after.ObservedCapabilities()["db"] {
		t.Fatal("observe must record a readable-but-empty capability as observed")
	}
	if len(after.Observations["db"]) != 0 {
		t.Fatalf("no observable attributes should be recorded, got %v", after.Observations["db"])
	}
}

// D242: a capability whose primary read fails does not abort the whole observe
// run — it is isolated (recorded as unreadable + a diagnostic, no observations),
// and every other capability is still observed. Absence of evidence for the
// failed cap is the signal; nothing is fabricated.
func TestObserveIsolatesUnreadableCapability(t *testing.T) {
	bindings := map[string]string{
		"cap.storage": "unreadable:HTTP 429", // primary read fails
		"cap.compute": "fake:vm-1",           // reads fine
	}
	res, err := Run(bindings, &provider.Fake{}, "2026-01-01T00:00:00Z", 0, nil, "", false)
	if err != nil {
		t.Fatalf("a per-capability read failure must NOT abort the run: %v", err)
	}
	if !res.Partial {
		t.Error("a run with an unreadable capability must be Partial")
	}
	readable := false
	for _, o := range res.Observations {
		if o.Capability == "cap.storage" {
			t.Errorf("the failed capability must yield NO observations (no fabrication), got %+v", o)
		}
		if o.Capability == "cap.compute" {
			readable = true
		}
	}
	if !readable {
		t.Error("the readable capability must still be observed despite the sibling's failure")
	}
	un := false
	for _, u := range res.Unreadable {
		if u.Capability == "cap.storage" {
			un = true
		}
	}
	if !un {
		t.Errorf("the failed capability must be recorded in Unreadable, got %+v", res.Unreadable)
	}
}

// Even when EVERY capability is unreadable, the run does not error — it reports an
// empty, Partial result (exit 0 at the verb); the downstream staleness gate turns
// the total evidence gap into observation-required, never a fabricated success.
func TestObserveAllUnreadableIsEmptyPartialNotError(t *testing.T) {
	bindings := map[string]string{
		"cap.a": "unreadable:down",
		"cap.b": "unreadable:down",
	}
	res, err := Run(bindings, &provider.Fake{}, "2026-01-01T00:00:00Z", 0, nil, "", false)
	if err != nil {
		t.Fatalf("all-unreadable must not error the run: %v", err)
	}
	if !res.Partial {
		t.Error("all-unreadable must be Partial")
	}
	if len(res.Observations) != 0 {
		t.Errorf("all-unreadable must produce zero observations, got %d", len(res.Observations))
	}
	if len(res.Unreadable) != 2 {
		t.Errorf("both capabilities must be recorded unreadable, got %+v", res.Unreadable)
	}
}
