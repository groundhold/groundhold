package verify

import (
	"encoding/json"
	"strings"
	"testing"

	"groundhold/internal/contract"
)

// D365: an agent reads the REPORT and never sees the terminal. A warning that
// lives only in stderr prose is one the agent is structurally unable to act on.
func TestAdvisoriesRideInTheReport(t *testing.T) {
	cand := &contract.Candidate{
		ContractID: "orders",
		Extras: map[string]map[string]any{
			"db": {"implementation": map[string]any{
				"environment": map[string]any{
					"SIGNING_KEY": "-----BEGIN PRIVATE KEY-----",
					"API_KEY":     "{{secret:acme/api-key}}",
				},
			}},
		},
	}
	got := advisoriesFor(cand)
	if len(got) != 2 {
		t.Fatalf("expected 2 advisories, got %d: %+v", len(got), got)
	}
	codes := map[string]bool{}
	for _, a := range got {
		codes[a.Code] = true
		if a.Pointer == "" || a.Detail == "" || a.Next == "" {
			t.Errorf("advisory %+v has an empty field — an agent routes on all of them", a)
		}
		// An advisory that quotes the secret defeats itself.
		if strings.Contains(a.Detail+a.Next, "BEGIN PRIVATE KEY") {
			t.Error("the advisory carries the offending value")
		}
	}
	for _, want := range []string{contract.CodePlaintextCredential, contract.CodeUnsubstitutedPlaceholder} {
		if !codes[want] {
			t.Errorf("missing advisory code %q — an agent cannot route on prose", want)
		}
	}
}

// An advisory is something NOTICED, never something proven: it must not change
// whether the candidate may execute.
func TestAdvisoriesDoNotAffectExecutability(t *testing.T) {
	if got := advisoriesFor(nil); got != nil {
		t.Errorf("nil candidate produced %+v", got)
	}
	// The field is omitted entirely when there is nothing to say, so a clean run
	// does not grow a noisy empty array.
	r := Report{Executable: true}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "advisories") {
		t.Error("an empty advisories array was emitted — a clean report should stay clean")
	}
}
