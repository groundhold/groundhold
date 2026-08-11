package observe

import (
	"os"
	"strings"
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

// D774. One unreadable output discarded EVERY readable one: the driver had just adopted a
// function BY its ARN and then recorded no outputs at all, including that ARN, because a
// second declared output was absent. Every $ref to the function then refused and the plan
// blocked by a route with nothing to do with the missing value.
//
// And the absent one was `functionUrl` on a function declaring `network.publicExposure:
// false` — an output whose EXISTENCE would have broken the reporter's own security
// constraint. The registry described it as conditional in prose while the loop treated
// every declared output as mandatory.
//
// Driven through outputDocs, not re-computed beside it (D726).
type partialOutputProv struct {
	provider.Provider
	specs []provider.OutputSpec
	raw   map[string]any
}

func (p partialOutputProv) OutputsFor(string) []provider.OutputSpec { return p.specs }
func (p partialOutputProv) ReadOutputs(string, string) (map[string]any, error) {
	return p.raw, nil
}

func TestOutputsArePartialNotAllOrNothing(t *testing.T) {
	prov := partialOutputProv{
		Provider: &provider.Fake{},
		specs: []provider.OutputSpec{
			{Name: "functionArn", Kind: "string"},
			{Name: "functionName", Kind: "string"},
			{Name: "functionUrl", Kind: "string", Conditional: true},
			{Name: "missingOnPurpose", Kind: "string"},
		},
		raw: map[string]any{
			"functionArn":  "arn:aws:lambda:eu-central-1:000000000000:function:api",
			"functionName": "api",
		},
	}
	res := &Result{}
	docs := outputDocs(prov, "lambda", "api", "lambda:eu-central-1:000000000000:api",
		"2026-08-04T10:00:00Z", 0, res)

	var got []string
	for _, d := range docs {
		got = append(got, d.Path)
	}
	if len(got) != 2 || got[0] != "outputs.functionArn" {
		t.Fatalf("recorded %v — the readable outputs must survive an unreadable sibling; "+
			"the ARN was in the driver's hand, it had just adopted by it (D774)", got)
	}
	named, conditional := 0, 0
	for _, d := range res.Diagnostics {
		if strings.Contains(d, "missingOnPurpose") {
			named++
		}
		if strings.Contains(d, "functionUrl") {
			conditional++
		}
	}
	if named != 1 {
		t.Errorf("the genuinely missing output must be NAMED: %v", res.Diagnostics)
	}
	if conditional != 0 {
		t.Errorf("a CONDITIONAL absence is the contract being honoured, not a fault — "+
			"this function declares publicExposure:false and is supposed to have no URL: %v",
			res.Diagnostics)
	}
}
