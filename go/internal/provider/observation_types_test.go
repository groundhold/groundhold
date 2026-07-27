package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/scalars"
)

// Every Go type a driver uses as an observation Value must be one the scalar
// parser accepts (D376).
//
// THE SEAM THIS EXISTS TO COVER: the conformance suite supplies observations as
// YAML, which decodes to `[]any`, `string`, `bool`, `float64`. A DRIVER produces
// Go values directly, and the natural Go type for a set of regions is
// `[]string`. Those two sets are not the same, and no test compared them — so a
// driver could emit a value that every driver test accepted and that `adopt`
// then refused as "observation unparseable". Six observations across four
// capability types were in exactly that state, reported from the field.
//
// The check is deliberately SOURCE-BASED rather than behavioural. Running every
// driver's observe against a fake would be better evidence, but it needs a
// per-service fixture registry that does not exist; this catches the same class
// with no per-driver work, which is what makes it likely to survive. It finds the
// declared type of each variable used as an observation Value and asserts the
// parser handles a sample of it.
func TestObservationValueTypesAreParseable(t *testing.T) {
	// samples: the Go types a driver may put in an Observation.Value, each with a
	// representative value. A type found in the source but missing here fails the
	// test — deliberately, so widening the drivers' vocabulary is a decision.
	samples := map[string]any{
		"[]string": []string{"eu-central-1"},
		"[]any":    []any{"eu-central-1"},
		"string":   "eu-central-1",
		"bool":     true,
		"int":      3,
		"float64":  1.5,
	}
	// []float64 is deliberately ABSENT: the parser does not accept it and no driver
	// emits it. Claiming it here would assert support that does not exist; leaving
	// it out means the second half of this test fails loudly the day a driver does.
	for typ, sample := range samples {
		if _, err := scalars.Parse(sample); err != nil {
			t.Errorf("scalars.Parse rejects %s, which a driver may emit: %v", typ, err)
		}
	}

	// Now find what the drivers ACTUALLY emit, and refuse anything not sampled above.
	valueVar := regexp.MustCompile(`\{Path:\s*"[^"]+",\s*Value:\s*([A-Za-z_][A-Za-z0-9_]*)\b`)
	found := map[string][]string{} // type -> where
	for _, pkg := range []string{"aws", "azure", "gcp", "k8s", "cloudflare", "hetzner", "upstash"} {
		dir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			src := string(raw)
			for _, m := range valueVar.FindAllStringSubmatch(src, -1) {
				v := m[1]
				// declared as a concrete slice? (the class that bit us)
				decl := regexp.MustCompile(`\b` + regexp.QuoteMeta(v) +
					`\s*:?=\s*(?:make\()?(\[\][a-z0-9]+)`)
				if d := decl.FindStringSubmatch(src); d != nil {
					found[d[1]] = append(found[d[1]], pkg+"/"+e.Name()+":"+v)
				}
			}
		}
	}
	if len(found) == 0 {
		t.Skip("no slice-typed observation values found — nothing for this gate to check here")
	}
	var unsampled []string
	for typ, where := range found {
		if _, ok := samples[typ]; !ok {
			sort.Strings(where)
			unsampled = append(unsampled, typ+" ("+where[0]+")")
		}
	}
	sort.Strings(unsampled)
	if len(unsampled) > 0 {
		t.Errorf("drivers emit observation values of types this gate has never parsed: %v\n"+
			"Add each to `samples` above. If scalars.Parse then refuses it, that is the "+
			"bug — a value every driver test accepts and `adopt` rejects as "+
			"\"observation unparseable\".", unsampled)
	}
}
