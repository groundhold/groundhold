package azure

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D471: the D470 property on azure. Scope is the FILE the observe lives in, not the
// function: several drivers assemble their observations in a helper (consBudgetObservations,
// and others), and a function-scoped check reported those as silent when they are not.
//
// An attribute the driver REALISES must be one its observe can either read back or
// say why it cannot.
//
// MATURITY has carried a gap for a long time — "several declared attributes cannot be
// read back, so a reconcile reports them unverifiable rather than checked" — with the
// note that the system is honest about it. Measuring rather than trusting that, the
// honesty turned out to be real and near-universal: every AZURE service that realises an
// attribute it cannot observe emits a diagnostic naming the cause (dynamodb's CMK, msk's
// CMK, and a long tail besides). One did not. `availability.class` on the VPC drives the
// private-subnet spread and appeared nowhere in its observe — not as a value, not as a
// reason — so a reconcile reported it unverifiable with nothing to say about why it
// would stay that way.
//
// The convention was 52 services out of 53, unwritten. Same shape as D466: a check
// everyone had, nothing named, one file outside it.

var (
	buildFn       = regexp.MustCompile(`func Build\w+\(`)
	observeFn     = regexp.MustCompile(`func \(d \*Driver\) (observe\w+)\(`)
	attrCase      = regexp.MustCompile(`case ((?:"[a-z][a-zA-Z]*\.[a-zA-Z][a-zA-Z0-9.]*",? ?)+):`)
	assignsToPlan = regexp.MustCompile(`\n\s*(?:p|plan)\.[A-Z]\w*\s*(?:=|\+=)`)
	nextArm       = regexp.MustCompile(`\n\t\tcase |\n\t\tdefault:`)
)

// realisedAttrs returns the attribute paths whose case body ASSIGNS something to the
// plan — a case that only returns an error is a refusal, and there is nothing to observe
// about an attribute the driver never honors.
func realisedAttrs(body string) map[string]bool {
	out := map[string]bool{}
	locs := attrCase.FindAllStringSubmatchIndex(body, -1)
	for i, loc := range locs {
		// The segment must end at the NEXT case arm of any shape — the next attribute
		// case, a non-attribute case, or `default:`. Slicing only to the next ATTRIBUTE
		// case let a later arm's assignment leak in, which turned three deliberately
		// accept-and-ignore attributes on GCP and Azure into phantom findings. A gate
		// that cries wolf is a gate someone eventually switches off (D470).
		end := len(body)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		if n := nextArm.FindStringIndex(body[loc[1]:end]); n != nil {
			end = loc[1] + n[0]
		}
		seg := body[loc[1]:end]
		if !assignsToPlan.MatchString(seg) {
			continue
		}
		for _, p := range regexp.MustCompile(`"([a-z][a-zA-Z]*\.[a-zA-Z][a-zA-Z0-9.]*)"`).
			FindAllStringSubmatch(body[loc[2]:loc[3]], -1) {
			out[p[1]] = true
		}
	}
	return out
}

// observeReach returns, for each observe* function, its own body PLUS the bodies of the
// same-package functions it CALLS. That is the honest unit, and getting it right took
// two corrections. Function scope alone reported three phantom findings, because several
// drivers assemble their observations in a helper (consBudgetObservations and friends).
// Whole-FILE scope fixed those and went too far the other way: a path mentioned by the
// CREATE code in the same file counted as "observed", which a teeth-check exposed by
// breaking a mention the gate then failed to notice. Callees are the set the observe can
// actually reach.
func observeReach(t *testing.T) map[string]string {
	t.Helper()
	all := funcBodies(t, regexp.MustCompile(`\nfunc (?:\(\w+ \*?\w+\) )?\w+\(`))
	obs := funcBodies(t, observeFn)
	callRE := regexp.MustCompile(`\b(?:d\.)?([a-zA-Z]\w*)\(`)
	out := map[string]string{}
	for name, body := range obs {
		key := strings.ToLower(strings.TrimPrefix(name, "observe"))
		reach := body
		for _, c := range callRE.FindAllStringSubmatch(body, -1) {
			if b, ok := all[c[1]]; ok && c[1] != name {
				reach += b
			}
		}
		out[key] += reach
	}
	return out
}

func funcBodies(t *testing.T, decl *regexp.Regexp) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	name := regexp.MustCompile(`func (?:\(d \*Driver\) )?(\w+)\(`)
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(n)
		if err != nil {
			continue
		}
		src := string(raw)
		locs := decl.FindAllStringIndex(src, -1)
		for i, loc := range locs {
			end := len(src)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			body := src[loc[0]:end]
			if m := name.FindStringSubmatch(body); m != nil {
				out[m[1]] = body
			}
		}
	}
	return out
}

func TestRealisedAttributesAreObservedOrExplained(t *testing.T) {
	builds := funcBodies(t, buildFn)
	observes := observeReach(t)
	if len(builds) < 20 || len(observes) < 20 {
		t.Fatalf("found %d builders and %d observers — the detector is under-counting "+
			"what it guards (D463)", len(builds), len(observes))
	}

	var compared int
	var silent []string
	for b, bb := range builds {
		key := strings.ToLower(strings.TrimPrefix(b, "Build"))
		ob := observes[key]
		if ob == "" {
			continue
		}
		compared++
		for p := range realisedAttrs(bb) {
			if !strings.Contains(ob, p) {
				silent = append(silent, key+": "+p)
			}
		}
	}
	if compared < 15 {
		t.Fatalf("only %d build/observe pairs matched — under-counting (D463)", compared)
	}
	sort.Strings(silent)
	if len(silent) > 0 {
		t.Errorf("attributes the driver REALISES that its observe never mentions — "+
			"neither as an observed path nor as a diagnostic naming why it cannot be "+
			"read: %v\nA reconcile reports these unverifiable with no explanation of why "+
			"they will stay that way. Observe it, or say what stops you (D306's rule, "+
			"applied to attributes rather than to reads).", silent)
	}
}

// D791. The twin of D784's AWS self-test. The sweep in this file cannot be mutated
// through its subject — no driver in this package realises an attribute its observe never
// mentions — so its detector is proved against a SYNTHETIC pair instead: a builder body
// realising two attributes, an observe body mentioning one.
//
// Each cloud carries its OWN copy of realisedAttrs and assignsToPlan, so proving one
// proves nothing about the others; that is why this is repeated rather than shared.
func TestTheVisibilityDetectorFindsAViolationWhenThereIsOneAzure(t *testing.T) {
	build := `
		switch path {
		case "encryption.atRest":
			p.Encrypted = raw == true
		case "retention.minimum":
			p.Retention = raw
		}`
	observe := `obs = append(obs, provider.Observation{Path: "encryption.atRest", Value: true})`

	realised := realisedAttrs(build)
	if !realised["encryption.atRest"] || !realised["retention.minimum"] {
		t.Fatalf("the detector missed a realised attribute: %v — a sweep that cannot SEE "+
			"a violation cannot report one (D791)", realised)
	}
	var silent []string
	for p := range realised {
		if !strings.Contains(observe, p) {
			silent = append(silent, p)
		}
	}
	if len(silent) != 1 || silent[0] != "retention.minimum" {
		t.Fatalf("silent = %v, want exactly the attribute the observer never mentions", silent)
	}
}
