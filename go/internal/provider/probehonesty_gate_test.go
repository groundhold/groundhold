package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D775. A probe exists to measure an OUTCOME rather than trust a configuration — that is
// the whole reason the verb is separate from `observe`, and why a probe is allowed to be
// expensive and sometimes intrusive. So the `Method` on a measurement is not decoration:
// it says what was DONE to learn the value.
//
// Three probers stamped `tcp-connect` on a value obtained by reading a config flag and
// dialling nothing. It is the same lie D766 removed from verdicts one layer up — a field
// whose job is to say how we know, saying something we did not do.
//
// This gate holds the narrow, checkable half: a measurement whose evidence says nothing
// was dialled must not claim a method that dials.
func TestNoProbeClaimsAMethodItDidNotUse(t *testing.T) {
	root := repoRoot(t)
	files := []string{
		"go/internal/aws/probe.go",
		"go/internal/gcp/probe.go",
		"go/internal/azure/probe_azure.go",
	}
	// A measurement literal: Method and Evidence inside one ProbeMeasurement.
	block := regexp.MustCompile(`(?s)provider\.ProbeMeasurement\{(.{0,600}?)\}`)
	var bad []string
	checked := 0
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		for _, m := range block.FindAllStringSubmatch(string(raw), -1) {
			body := m[1]
			if !strings.Contains(body, "Method:") {
				continue
			}
			checked++
			dialClaimed := strings.Contains(body, `Method:   "tcp-connect"`) ||
				strings.Contains(body, `Method: "tcp-connect"`)
			saysNothingDialled := strings.Contains(body, "nothing was dialled") ||
				strings.Contains(body, "nothing dialled") ||
				strings.Contains(body, "no endpoint to reach")
			if dialClaimed && saysNothingDialled {
				bad = append(bad, rel+": "+strings.TrimSpace(strings.SplitN(body, "\n", 2)[0]))
			}
		}
	}
	if checked < 8 {
		t.Fatalf("only %d probe measurements found — the gate has lost its subject (D328)", checked)
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		t.Errorf("%d probe measurement(s) claim a method that dials while their own evidence "+
			"says nothing was dialled:\n  %s\n\nA probe's Method says what was DONE; a config "+
			"read is not a handshake (D775).", len(bad), strings.Join(bad, "\n  "))
	}
	t.Logf("%d probe measurements checked across %d probers", checked, len(files))
}
