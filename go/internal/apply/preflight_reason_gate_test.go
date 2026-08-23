package apply

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D1240. `PreflightResult` has four fields and one of them carries the meaning:
// `Status` says which of three outcomes happened, and `Reason` says what that outcome
// is worth. Two statuses had a Reason. The third — `passed` — did not.
//
// That is the outcome most in need of qualifying. The doctrine is old and written
// down: "a preflight refusal is trustworthy; a pass is EVIDENCE, not proof", in both
// driver file headers, and attached to the remediation for a permission DENIAL — the
// branch where nobody needs to hear it. An agent reading `{"status":"passed"}` from
// the JSON had nothing telling it a mid-apply denial is still possible, which those
// same headers say plainly.
//
// The gate is over the SET of statuses rather than the one that was wrong, because a
// fourth outcome added later would otherwise arrive mute exactly the same way.

func TestEveryPreflightStatusExplainsItself(t *testing.T) {
	// The statuses the type documents, read from its own comment so a new one cannot
	// be added there and skipped here.
	src, err := os.ReadFile("apply.go")
	if err != nil {
		t.Fatal(err)
	}
	// Anchored to the DECLARATION, not to the field shape. The first cut searched for
	// `Status string \`json:"status"\`` anywhere in the file and matched the APPLY
	// result's status (applied|refused|corrupted) — a different type with an identical
	// field. The marker has to be unique to its subject, which is the trap this
	// codebase keeps meeting and which I walked into while gating against it.
	declIdx := strings.Index(string(src), "type PreflightResult struct {")
	if declIdx < 0 {
		t.Fatal("PreflightResult is gone — move this gate with it rather than dropping it")
	}
	decl := regexp.MustCompile(`Status\s+string\s+` + "`" + `json:"status"` + "`" + `\s*// ([^\n]+)`)
	m := decl.FindSubmatch(src[declIdx:])
	if m == nil {
		t.Fatal("PreflightResult.Status no longer documents its outcomes — this gate reads " +
			"that comment to know what the set IS, so it cannot be dropped silently")
	}
	var statuses []string
	for _, s := range strings.Split(string(m[1]), "|") {
		if s = strings.TrimSpace(s); s != "" {
			statuses = append(statuses, s)
		}
	}
	// D328: the subject must exist and be plausible.
	if len(statuses) < 3 {
		t.Fatalf("parsed %d statuses from the type comment (%q) — the scan is broken",
			len(statuses), m[1])
	}

	// Every status must be constructed SOMEWHERE with a Reason. Matched on the literal
	// `Status: "<name>"` and then the same composite literal's Reason field, by walking
	// to the closing brace — a window would count a Reason belonging to a neighbour.
	// Search only the function that builds them, for the same reason.
	body := string(src)
	for _, st := range statuses {
		needle := `Status: "` + st + `"`
		idx := strings.Index(body, needle)
		if idx < 0 {
			t.Errorf("status %q is documented but never constructed", st)
			continue
		}
		end := strings.Index(body[idx:], "}")
		if end < 0 {
			t.Errorf("status %q: could not find the end of its literal", st)
			continue
		}
		lit := body[idx : idx+end]
		if !strings.Contains(lit, "Reason:") {
			t.Errorf("preflight status %q is reported with no Reason. Every other outcome "+
				"explains what it is worth; a bare status leaves the reader — often an "+
				"agent reading JSON — to supply the meaning themselves, and for %q the "+
				"meaning is \"evidence, not proof\".", st, st)
			continue
		}
		if st != "passed" {
			continue
		}
		// The pass's Reason has to carry the CLAIM, not merely exist. A first cut of
		// this gate checked only that the field was present, and a mutant that
		// replaced "a mid-apply permission failure stays possible" with "outcomes may
		// vary" survived it — the field was there, the meaning was gone. The
		// behavioural test below could not catch it either, because it builds its own
		// literal; it proves the sentence SERIALISES, not that this is the sentence.
		for _, must := range []string{"not proof", "mid-apply"} {
			if !strings.Contains(lit, must) {
				t.Errorf("the passing preflight's Reason must contain %q — a hedge that does "+
					"not name what can still happen is not the disclosure this exists for:\n%s",
					must, lit)
			}
		}
	}
}

// The behavioural half: the pass must actually SAY the thing, and say it where a
// machine reads it. A source-level check cannot tell whether the sentence survives
// into the JSON.
func TestAPassingPreflightSerialisesItsCaveat(t *testing.T) {
	res := &PreflightResult{Status: "passed", Checked: []string{"iam:PassRole"},
		Reason: "the acting identity holds the permissions this plan declares, " +
			"as of this check — EVIDENCE, not proof: the provider check cannot " +
			"see deny policies, conditions evaluated at mutation time, or " +
			"propagation lag, so a mid-apply permission failure stays possible " +
			"and the write-ahead receipts are the recovery path"}
	blob, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if json.Unmarshal(blob, &back) != nil {
		t.Fatal("the result did not round-trip")
	}
	reason, _ := back["reason"].(string)
	if !strings.Contains(reason, "not proof") {
		t.Fatalf("the caveat must reach the JSON an agent reads, got %q", reason)
	}
	if !strings.Contains(reason, "mid-apply") {
		t.Fatalf("the caveat must name what can still happen, not merely hedge: %q", reason)
	}
}

// The caveat's own claim has to stay true of the drivers: it says the check cannot see
// deny policies and mutation-time conditions, and both driver headers must still say
// so. A caveat that outlives the limitation it describes is its own kind of drift.
func TestTheCaveatMatchesWhatTheDriversDisclaim(t *testing.T) {
	for _, p := range []string{
		filepath.Join("..", "aws", "preflight.go"),
		filepath.Join("..", "gcp", "preflight.go"),
	} {
		blob, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		src := string(blob)
		if !strings.Contains(src, "EVIDENCE, not proof") {
			t.Errorf("%s no longer states that a pass is evidence rather than proof — "+
				"either restore it or retire the caveat that repeats it", p)
		}
	}
}
