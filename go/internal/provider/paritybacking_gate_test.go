package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var (
	parityEntry   = regexp.MustCompile(`"([a-z0-9-]+)":\s*"(capability\.[a-z.]+)"`)
	capabilityLit = regexp.MustCompile(`"(capability\.[a-z.]+)"`)
)

// TestEveryParityValueIsBackedByTheDriver (D844).
//
// Each driver publishes a parity map — one capability TYPE per certified service token —
// and `groundhold parity` prints the matrix built from all three. Every header says the
// values are "the exact capability string the service's Observe/discover stamps as
// ResourceType — ground truth, not a guess", and then names the handful of tokens that are
// the exception, because their type comes from the Build dispatch instead.
//
// The exception lists were prose, and all three had drifted the same way: AWS named
// `rolepolicy`, which IS stamped, and omitted `route53record`, which is not; GCP said "the
// one non-listable token" with two; Azure said "two" with three. One cause — the DNS-record
// driver is a sub-resource on every cloud and arrived after the headers were written.
//
// A prose list cannot be wrong for long if something reads it. This is that something: a
// value must appear as a capability literal somewhere in its own driver package, or be
// named here with the reason it cannot.
func TestEveryParityValueIsBackedByTheDriver(t *testing.T) {
	root := repoRoot(t)

	// The tokens whose TYPE comes from the Build dispatch rather than a discover stamp.
	// A stale entry fails: an exception nobody needs covers the next token that lands on it.
	exempt := map[string]string{
		"aws/changefeed":     "no top-level discover sweep — TYPE from the Build dispatch (changefeed.go)",
		"aws/cwlogfilter":    "a metric filter is a sub-resource of a log group, enumerated under it",
		"aws/route53record":  "a record set is a sub-resource of a hosted zone (NonListable)",
		"gcp/assetfeed":      "no top-level discover sweep — TYPE from the Build dispatch",
		"gcp/clouddnsrecord": "a record set is a sub-resource of a managed zone (NonListable)",
		"azure/changefeed":   "no top-level discover sweep — TYPE from the Build dispatch (azure_provider.go)",
		"azure/keyvaultkey":  "a key is a sub-resource of a vault, enumerated under it",
		"azure/dnsrecord":    "a record set is a sub-resource of a zone (NonListable)",
	}

	seen := map[string]bool{}
	var unbacked []string
	checked := 0

	for pkg, file := range map[string]string{
		"aws": "parity_aws.go", "gcp": "parity_gcp.go", "azure": "parity_azure.go",
	} {
		dir := filepath.Join(root, "go", "internal", pkg)
		blob, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		// Every capability literal the driver mentions ANYWHERE except in the map itself.
		// Azure threads the type through a shared sweep helper as an argument rather than
		// a ResourceType field, so looking only for `ResourceType: "..."` reads twenty of
		// its forty-five as unbacked — the scan has to match how each driver actually
		// names the type, not how one of them does.
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		lits := map[string]bool{}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || n == file {
				continue
			}
			src, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				t.Fatalf("read %s: %v", n, err)
			}
			for _, m := range capabilityLit.FindAllSubmatch(src, -1) {
				lits[string(m[1])] = true
			}
		}
		if len(lits) < 20 {
			t.Fatalf("%s driver mentions only %d capability types — the scan is broken", pkg, len(lits))
		}
		for _, m := range parityEntry.FindAllSubmatch(blob, -1) {
			token, typ := string(m[1]), string(m[2])
			key := pkg + "/" + token
			checked++
			if lits[typ] {
				continue
			}
			if _, ok := exempt[key]; ok {
				seen[key] = true
				continue
			}
			unbacked = append(unbacked, key+" -> "+typ)
		}
	}

	// D328: assert the subject before reporting on it.
	if checked < 100 {
		t.Fatalf("only %d parity entries scanned across three drivers — the pattern stopped "+
			"matching", checked)
	}
	sort.Strings(unbacked)

	if len(unbacked) > 0 {
		t.Errorf("%d parity value(s) name a capability their own driver never mentions:\n  %s\n\n"+
			"The map's header claims every value is the type the driver stamps. Either the "+
			"driver stamps it, or the token belongs in this test's exception table with the "+
			"reason (D844).", len(unbacked), strings.Join(unbacked, "\n  "))
	}
	for key, why := range exempt {
		if !seen[key] {
			t.Errorf("exception %q (%s) covers a token that is backed, or no longer exists — "+
				"drop it", key, why)
		}
	}
}
