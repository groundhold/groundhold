package converge

import (
	"strings"
	"testing"
)

// D379. A run that stopped part-way has already changed the world, and the
// refusal that stopped it says nothing about that.
//
// This is the shape of the field incident: a plan with two actions, one that
// deployed an image and one that could only ever be refused. The image went out.
// The run reported the refusal. Nothing in the status said production had been
// mutated, so the operator had no reason to look — and found the outage by hand
// several minutes later.
func TestAppliedSummaryLeadsWithWhatChanged(t *testing.T) {
	stdout := `{"status":"failed","code":"provider-refused",
"outcomes":{"a-update-api":"succeeded","a-create-ai-inference":"failed"},
"reasons":["action a-create-ai-inference failed: model access is a manual gate"]}`

	got := appliedSummary(stdout)
	if len(got) == 0 {
		t.Fatal("no summary — the operator learns nothing about what applied")
	}
	first := got[0]
	if !strings.Contains(first, "1 of 2 actions applied") {
		t.Errorf("first line = %q, want the applied count up front", first)
	}
	if !strings.Contains(first, "the world HAS changed") {
		t.Errorf("first line = %q, want it to say plainly that something was mutated", first)
	}
	if !strings.Contains(first, "a-update-api") {
		t.Errorf("first line = %q, want it to NAME the action that applied — the one "+
			"whose effect the operator has to go and check", first)
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "failed: a-create-ai-inference") {
		t.Errorf("summary %q does not name the failed action", joined)
	}
}

// The opposite case must read differently, or the line is noise: a run that
// refused before mutating anything has NOT changed the world, and saying so is
// the whole reason the distinction exists.
func TestAppliedSummarySaysWhenNothingChanged(t *testing.T) {
	got := appliedSummary(`{"outcomes":{"a-create-db":"failed","a-create-cache":"skipped"}}`)
	if len(got) == 0 {
		t.Fatal("no summary")
	}
	if !strings.Contains(got[0], "0 of 2 actions applied") ||
		!strings.Contains(got[0], "nothing was changed") {
		t.Errorf("first line = %q, want it to state plainly that nothing was mutated", got[0])
	}
	if strings.Contains(got[0], "HAS changed") {
		t.Errorf("first line = %q claims a change on a run that made none", got[0])
	}
}

// A clean run emits no `outcomes` at all (apply stays quiet when everything
// succeeded), and a summary invented for it would be noise on the happy path.
func TestAppliedSummaryQuietOnACleanRun(t *testing.T) {
	for _, stdout := range []string{
		`{"status":"applied"}`,
		`{"status":"applied","outcomes":{}}`,
		`not json at all`,
		``,
	} {
		if got := appliedSummary(stdout); len(got) != 0 {
			t.Errorf("stdout %q produced %v; a run with no per-action outcomes has "+
				"nothing to summarise", stdout, got)
		}
	}
}

// Deterministic output: two runs of the same outcome map must produce the same
// lines, or a scripted diff of converge output flaps on Go's map ordering.
func TestAppliedSummaryIsDeterministic(t *testing.T) {
	stdout := `{"outcomes":{"a-3":"succeeded","a-1":"succeeded","a-2":"failed","a-0":"unknown"}}`
	first := strings.Join(appliedSummary(stdout), "\n")
	for i := 0; i < 20; i++ {
		if got := strings.Join(appliedSummary(stdout), "\n"); got != first {
			t.Fatalf("ordering is not stable:\n%q\nvs\n%q", first, got)
		}
	}
	if !strings.Contains(first, "a-1, a-3") {
		t.Errorf("succeeded actions are not sorted: %q", first)
	}
}

// D529, from the field: a create whose outcome was UNKNOWN printed "0 of 1 actions
// applied — nothing was changed", and the Lambda had been created. The partner
// checked AWS by hand (a habit their own outage taught them), saw the function, and
// wrote: "'nothing was changed' is a stronger claim than the evidence the run had.
// If the outcome of the action is UNKNOWN then the number of applied actions is
// unknown too." Someone who reads it and retries blind gets a duplicate.
//
// Their framing is the invariant this project already holds everywhere else —
// three states, not two: applied / not applied / NOT KNOWN — and the third must
// not be dressed as the second. D29 says the same thing about a verdict; this is
// the summary line saying the opposite.
func TestAppliedSummaryDoesNotClaimNothingChangedWhenAnOutcomeIsUnknown(t *testing.T) {
	got := appliedSummary(`{"outcomes":{"a-create-pilot-raport":"unknown"}}`)
	if len(got) == 0 {
		t.Fatal("no summary")
	}
	if strings.Contains(got[0], "nothing was changed") {
		t.Errorf("first line = %q — the run does not KNOW whether the action landed, "+
			"so it may not report the world as untouched", got[0])
	}
	if !strings.Contains(got[0], "UNKNOWN") {
		t.Errorf("first line = %q — an unknown outcome must be named as unknown", got[0])
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "MAY have changed") {
		t.Errorf("summary = %q — it must say the world may have changed", joined)
	}
}

// The mixed case: something definitely landed AND something is unknown. Both
// facts have to survive; leading with the confirmed change must not swallow the
// uncertainty behind it.
func TestAppliedSummaryKeepsBothConfirmedAndUnknown(t *testing.T) {
	got := appliedSummary(`{"outcomes":{"a-create-db":"succeeded","a-create-fn":"unknown"}}`)
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "HAS changed") {
		t.Errorf("summary = %q — the confirmed apply is missing", joined)
	}
	if !strings.Contains(joined, "UNKNOWN") {
		t.Errorf("summary = %q — the unknown action is missing", joined)
	}
}
