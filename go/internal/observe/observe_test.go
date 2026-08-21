package observe

import (
	"errors"
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
	docs, _ := outputDocs(prov, "lambda", "api", "lambda:eu-central-1:000000000000:api",
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

// D1152. A failed READ used to live on stdout and nowhere else: `observe` printed
// "unreadable: …" and recorded nothing, so the ledger remembered only that the last
// good observation was getting older. `plan` then said "observation is stale —
// re-observe first", which is TRUE, USELESS, and a loop — re-observing is precisely
// what had just failed, and nothing in the ledger said so.
//
// The fix is the move D59 already made for probe.failed: a failed measurement is
// knowledge, and it is never an observation. It records the failure and NOTHING about
// the resource's state — absence of evidence stays the signal (D242).
//
// Reported from the field: a deployment runbook that starts with `export AWS_PROFILE=…`
// (the ordinary way to drive the AWS CLI) leaves the drivers without credentials, and
// the operator loops between observe and plan with both looking correct in isolation.
func TestAnUnreadableCapabilityIsRecordedAsAFailureNotForgotten(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ledger.jsonl"
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	bindings := map[string]string{
		"cap.storage": "unreadable:HTTP 403 (signature does not match)",
		"cap.compute": "fake:vm-1",
	}
	res, err := Run(bindings, &provider.Fake{}, "2026-01-01T00:00:00Z", 0, led, path, true)
	if err != nil {
		t.Fatalf("a per-capability read failure must NOT abort the run: %v", err)
	}
	if !res.Partial {
		t.Fatal("the run must still report Partial — this gate is about DURABILITY, " +
			"not about changing what the result says")
	}

	replayed, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatalf("the recorded failure must leave a REPLAYABLE ledger: %v", err)
	}
	fails := replayed.ReadFailures()
	got, ok := fails["cap.storage"]
	if !ok {
		t.Fatalf("the unreadable capability left no observation.failed in the ledger — "+
			"the failure is again visible only on stdout, which is what made `plan` "+
			"prescribe a re-observe that cannot work. Got: %+v", fails)
	}
	if !strings.Contains(got.Reason, "403") {
		t.Errorf("the recorded reason is not the driver's own sentence: %q — a reworded "+
			"reason cannot tell a credentials problem from a permissions one", got.Reason)
	}
	if got.AttemptedAt != "2026-01-01T00:00:00Z" {
		t.Errorf("attemptedAt = %q, want the observe clock: without it the operator "+
			"cannot tell a failure from this run from one a week old", got.AttemptedAt)
	}

	// The readable sibling is untouched, and the failure carries NO state.
	if _, ok := replayed.Observations["cap.storage"]; ok {
		t.Error("the failed capability must contribute NO observation — recording a " +
			"failure must never become recording a value")
	}
	if len(replayed.Observations["cap.compute"]) == 0 {
		t.Error("the readable sibling must still be observed (D242: one failure is " +
			"evidence about ONE capability)")
	}
}

// failingOutputProv reads its own state fine and cannot read its declared outputs —
// the shape a `$ref` consumer depends on and the one the field reported.
type failingOutputProv struct {
	provider.Provider
	specs []provider.OutputSpec
}

func (p failingOutputProv) OutputsFor(string) []provider.OutputSpec { return p.specs }
func (p failingOutputProv) ReadOutputs(string, string) (map[string]any, error) {
	return nil, errors.New("GetTopicAttributes: HTTP 403 (not authorized)")
}

// D1153. A failed OUTPUTS read was the one read failure that left no trace at all: a
// diagnostic on stdout, no observations, and — unlike a failed primary read — the run
// was not even marked Partial. So `observe` looked complete, the ledger kept no
// outputs.<name> for the producer, and every `$ref` to it refused with "no outputs.X
// observation — re-observe first". Re-observing fails identically, which is the loop
// D1152 closed for the primary read, one field over.
//
// Reported from the field as "the same candidate seals with a literal ARN and refuses
// through a $ref" — and noted there that it bites hardest on STABLE resources, which
// is exactly right: a producer created in this plan takes its outputs from the create
// result, so only a bound one depends on the read that was failing silently.
func TestAFailedOutputsReadIsPartialAndRecorded(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ledger.jsonl"
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	prov := failingOutputProv{
		Provider: &provider.Fake{},
		specs:    []provider.OutputSpec{{Name: "topicArn", Kind: "string"}},
	}
	res, err := Run(map[string]string{"temat": "fake:topic-1"}, prov,
		"2026-01-01T00:00:00Z", 0, led, path, true)
	if err != nil {
		t.Fatalf("an outputs failure must not abort the run: %v", err)
	}
	if !res.Partial {
		t.Error("a run whose outputs read FAILED must be Partial — it reported success " +
			"while the producer's outputs were unreadable, so nothing downstream could " +
			"tell this from a producer that simply has none")
	}
	found := false
	for _, u := range res.Unreadable {
		if u.Capability == "temat" && strings.Contains(u.Reason, "403") {
			found = true
		}
	}
	if !found {
		t.Errorf("the outputs failure is not in Unreadable: %+v", res.Unreadable)
	}

	replayed, rerr := ledger.ReplayFile(path)
	if rerr != nil {
		t.Fatalf("the recorded failure must leave a REPLAYABLE ledger: %v", rerr)
	}
	fails := replayed.ReadFailures()
	got, ok := fails["temat"]
	if !ok || !strings.Contains(got.Reason, "403") {
		t.Fatalf("the outputs failure left nothing in the ledger, so a $ref refusal "+
			"cannot name it and still says \"re-observe first\". Got: %+v", fails)
	}
	if !strings.HasPrefix(got.Reason, "outputs:") {
		t.Errorf("the recorded reason does not say it was the OUTPUTS read: %q — a "+
			"reader cannot tell it from a failure to read the resource itself", got.Reason)
	}
}
