package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// D1235 generalises D1234. That entry found ONE mapping that dropped an unmappable
// provider value in silence; a sweep of the same shape found eight more sites, six of
// them real. The shape:
//
//	if x := mapIt(raw); x != "" { obs = append(obs, ...) }
//
// A mapping that signals "I do not know this" by returning the empty string, guarded
// by a test for the empty string, with nothing on the other side. The attribute simply
// does not appear, which reads as "this resource has no such property" rather than
// "we could not map the property it has". Silence is the D513 class, and it lands here
// on `viewer.protocol`, `dns.target` and `engine.protocol` among others.
//
// This gate is a COMPLETENESS check over the class, and it says so plainly because the
// D1234 version of this idea overclaimed: reading source cannot tell a live branch
// from a dead one (`} else if false {` satisfies any structural test). What it can do
// — and what nothing else does — is notice the NINTH site the day it is written.
// Behaviour is witnessed in the driver packages, per attribute.
func TestNoObservationMappingDropsAnUnmappableValueInSilence(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	pkgs := []string{"aws", "gcp", "azure", "k8s", "cloudflare", "hetzner", "upstash"}

	// `if <v> := <fn>(...); <v> != "" {` — the guard that turns "unmapped" into a
	// branch nobody takes.
	guard := regexp.MustCompile(`if (\w+) := (\w+)\([^)]*\); (\w+) != "" \{`)

	var silent []string
	scanned := 0
	for _, pkg := range pkgs {
		dir := filepath.Join(root, pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // a provider this build does not carry
		}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			blob, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				t.Fatalf("read %s/%s: %v", pkg, n, err)
			}
			lines := strings.Split(string(blob), "\n")
			for i, ln := range lines {
				m := guard.FindStringSubmatch(ln)
				if m == nil || m[1] != m[3] {
					continue
				}
				// Only the guards that EMIT an observation are in this class, and the
				// test is the guard's OWN block — found by matching braces, not by a
				// fixed window. A window is what made the first cut of this gate report
				// two false positives: a `provider.Observation` on a line AFTER the
				// block counted as if it were inside it. A guard whose body appends a
				// diagnostic (empty meaning "nothing to warn about") is a different
				// thing and correctly has no else.
				end, ok := blockEnd(lines, i)
				if !ok {
					continue
				}
				block := strings.Join(lines[i+1:end], "\n")
				if !strings.Contains(block, "provider.Observation") {
					continue
				}
				scanned++
				if !regexp.MustCompile(`^\s*\}\s*else`).MatchString(lines[end]) {
					silent = append(silent, pkg+"/"+n+":"+strconv.Itoa(i+1)+" ("+m[2]+")")
				}
			}
		}
	}
	// D328: the scan must have a subject. A regex that stopped matching would report a
	// clean sweep over nothing, which is the failure mode this whole class is about.
	if scanned < 10 {
		t.Fatalf("only %d observation-emitting mappings found — the scan is broken, so this "+
			"gate is protecting nothing", scanned)
	}
	sort.Strings(silent)
	if len(silent) > 0 {
		t.Errorf("%d mapping(s) drop an unmappable provider value in SILENCE — no observation "+
			"and no diagnostic:\n  %s\n\nThe attribute simply does not appear, which reads as "+
			"\"this resource has no such property\" rather than \"we could not map the property "+
			"it has\". Add the else-branch AND a behavioural witness; this check reads source "+
			"and cannot tell a live branch from a dead one.",
			len(silent), strings.Join(silent, "\n  "))
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// blockEnd returns the index of the line closing the block opened on line start,
// by brace depth. Crude but exact enough for gofmt'd Go, and exact is the point:
// the window it replaces produced false positives in both directions.
func blockEnd(lines []string, start int) (int, bool) {
	depth := 0
	for i := start; i < len(lines); i++ {
		for _, c := range lines[i] {
			switch c {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return i, true
				}
			}
		}
	}
	return 0, false
}
