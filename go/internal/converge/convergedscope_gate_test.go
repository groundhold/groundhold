package converge

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// D1242. `converge` is the porcelain — the verb a person or an agent actually runs —
// and `converged` is the answer they route on. Three sites report it.
//
// One of them said the honest thing, in the line printed for a HUMAN: "the world
// already matches on every attribute this run can compare". The other two said the
// stronger, unqualified "the world already matches the candidate". And none of the
// three put the qualification in the machine field, where an agent reads.
//
// This is not a false green — `witnessReality` already refuses a converged verdict
// that recorded reality does not witness, so hard constraints are guarded. It is the
// difference between "matches" and "matches on what was compared", stated at one of
// three exits and never to a machine.
//
// The gate is over the SET, so a fourth exit cannot arrive without the scope.

func TestEveryConvergedVerdictCarriesItsScope(t *testing.T) {
	src, err := os.ReadFile("converge.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)

	// Each construction of a converged result, found by the literal that builds it.
	sites := regexp.MustCompile(`result\{Status: "converged"[^}]*\}`).FindAllString(body, -1)
	// D328: the subject must exist. If converge stops reporting converged at all, this
	// gate is watching nothing and should be retired deliberately rather than passing.
	if len(sites) < 3 {
		t.Fatalf("found %d converged results — converge reports it at three exits; the scan "+
			"is broken or the verb changed shape", len(sites))
	}
	for i, site := range sites {
		if !strings.Contains(site, "convergedScope") {
			t.Errorf("converged exit %d builds its result without convergedScope:\n  %s\n\n"+
				"An agent routes on {\"status\":\"converged\"} and has only the strongest "+
				"reading available unless the machine field says what was compared.",
				i+1, strings.Join(strings.Fields(site), " "))
		}
	}
}

// The scope sentence must say the two things that make it useful: what WAS compared,
// and that a hard constraint unwitnessed by reality refuses the verdict rather than
// riding inside it. A hedge naming neither is the noise D1227 warns about.
func TestTheConvergedScopeSaysWhatItCovers(t *testing.T) {
	for _, must := range []string{"could compare", "witness", "no value in this run"} {
		if !strings.Contains(convergedScope, must) {
			t.Fatalf("the scope must contain %q — otherwise it hedges without telling the "+
				"reader which world they are in:\n%s", must, convergedScope)
		}
	}
}

// And the human line must not be WEAKER than the machine field: a person reading the
// terminal should not get a stronger claim than an agent reading the JSON. This is the
// asymmetry the entry started from — one exit told the human, none told the machine.
func TestTheHumanLineIsNotStrongerThanTheMachineField(t *testing.T) {
	src, err := os.ReadFile("converge.go")
	if err != nil {
		t.Fatal(err)
	}
	// The whole call, not the first literal: these banners are built by concatenation,
	// and a pattern stopping at the first closing quote reads only the first half —
	// the same quote-naive shape D1236 fixed in another gate. `(?s)` so the match can
	// cross the line break a concatenated string sits on.
	says := regexp.MustCompile(`(?s)o\.say\("  ✓ converged.*?\)`).FindAllString(string(src), -1)
	if len(says) < 4 {
		t.Fatalf("found %d converged banners, expected the three no-op exits plus the "+
			"verified one — the scan is broken or an exit stopped announcing itself", len(says))
	}
	for _, s := range says {
		// The VERIFIED banner is exempt, and the exemption is the point rather than a
		// hole. `convergence = "verified"` is set only when the post-apply re-plan
		// found NothingToChange against OBSERVED reality — and the branch beside it
		// says "inconclusive (observations do not cover every attribute)" when they do
		// not. So verified already means the observations covered it and matched;
		// attaching the no-op hedge there would weaken an earned claim and put a
		// sentence on every case, which distinguishes none (D1227).
		if strings.Contains(s, "verified against observed reality") {
			continue
		}
		if !strings.Contains(s, "this run can compare") {
			t.Errorf("a converged banner claims more than the run compared:\n  %s\n\n"+
				"Say the scope here too, or the terminal reads stronger than the JSON.", s)
		}
	}
	// ...and the exemption must not become a way to smuggle a bare banner in: the
	// verified one has to still be there, and still say what it verified against.
	var haveVerified bool
	for _, s := range says {
		if strings.Contains(s, "verified against observed reality") {
			haveVerified = true
		}
	}
	if !haveVerified {
		t.Fatal("the verified-convergence banner is gone — either restore it or remove the " +
			"exemption above, which exists only because that banner earns its stronger claim")
	}
}
