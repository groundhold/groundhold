package main

import (
	"bytes"
	"strings"
	"testing"

	"groundhold/internal/suggest"
)

// D594. `suggest` emits ready-to-paste constraints, and its header reads:
//
//	# Advisory only — never gates; paste what you want to adopt.
//
// True of the SUGGESTION and misleading about the PASTE. Measured end to end: a
// storage contract verifying PROVEN, with the three recommended constraints pasted
// as hard (the default), goes to BLOCKED — three `unknown`, because the candidate
// says nothing about `encryption.customerManagedKeys`, `network.publicExposure` or
// `versioning.enabled`, and unknown blocks by design.
//
// The blocking is correct; the four-valued verifier is working. What is missing is
// that the operator was told "never gates" one line before pasting something that
// gates. They read the result as a failure, with nothing connecting it to the advice
// — D566's shape and D568's, on the strongest form of advice in the system: text the
// tool hands you to put in your contract.
//
// The escape route exists and works: `--as soft` on the same suggestions verifies
// PROVEN with the three still unknown, which is adoption of the intent without the
// block. The advice never mentioned it.
func TestHardSuggestionsSayWhatPastingCosts(t *testing.T) {
	var b bytes.Buffer
	renderSuggestText(&b, "assets", sampleSuggestions(), "hard")
	out := b.String()
	if !strings.Contains(out, "--as soft") {
		t.Error("the hard form never mentions `--as soft`, which is the way to adopt " +
			"the intent without blocking on an attribute the candidate does not declare")
	}
	if !strings.Contains(strings.ToLower(out), "unknown") {
		t.Error("nothing warns that a hard constraint over an undeclared attribute " +
			"verifies UNKNOWN and blocks — the operator meets that one verb later")
	}
}

// In soft mode the warning cannot apply, and a caveat printed where it cannot apply
// is the noise D537 warns about.
func TestSoftSuggestionsCarryNoBlockingWarning(t *testing.T) {
	var b bytes.Buffer
	renderSuggestText(&b, "assets", sampleSuggestions(), "soft")
	if strings.Contains(b.String(), "--as soft") {
		t.Error("the soft form advertises `--as soft` to someone already using it")
	}
}

// An empty result must stay a single quiet line — no advice, no caveat about advice.
func TestNoSuggestionsStayQuiet(t *testing.T) {
	var b bytes.Buffer
	renderSuggestText(&b, "assets", suggest.Result{}, "hard")
	if strings.Contains(b.String(), "--as soft") {
		t.Error("a contract with nothing to suggest was warned about pasting")
	}
}

func sampleSuggestions() suggest.Result {
	return suggest.Result{
		Environment: "prod",
		Suggestions: []suggest.Suggestion{{
			Capability: "bucket", Type: "capability.storage.object",
			Path: "network.publicExposure", RuleID: "rec-bucket-network.publicExposure",
			Snippet: "    - id: rec-bucket-network.publicExposure\n",
		}},
	}
}
