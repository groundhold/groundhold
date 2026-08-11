package provider_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// unpagedGCPSweepCeiling and unpagedAzureSweepCeiling are how many discovery sweeps on
// each cloud still read one page. Both may only go DOWN.
//
// D814. A ceiling rather than a list, for the reason D807 gave: a list with no ceiling
// rots into permission, and a demand that all forty-five be done at once turns a ratchet
// into a blocked branch. Each of these sweeps reports an estate smaller than it is — D803
// makes the tool SAY so, which is honest and is not the same as being right.
const (
	unpagedGCPSweepCeiling   = 39
	unpagedAzureSweepCeiling = 39
	unpagedAWSSweepCeiling   = 34
)

// TestGCPSweepsThatStillReadOnePage counts the GCP discovery sweeps that do not use the
// shared paging loop, and holds that number to a ceiling.
//
// The check is deliberately crude — "does this function mention listAllPages" — because
// the precise question ("does it read every page") is not decidable by reading the source,
// and a crude check with a falling ceiling is worth more than a precise one nobody can
// implement. What it cannot do is confirm that a paginated sweep is CORRECT; that is what
// the per-sweep tests and the shared loop's own tests are for.
func TestGCPSweepsThatStillReadOnePage(t *testing.T) {
	unpagedSweeps(t, "gcp", []string{"listAllPages", "nextPageToken"}, unpagedGCPSweepCeiling)
}

// TestAzureSweepsThatStillReadOnePage is the same ratchet for ARM (D816).
func TestAzureSweepsThatStillReadOnePage(t *testing.T) {
	unpagedSweeps(t, "azure", []string{"listAllARMPages", "nextLink"}, unpagedAzureSweepCeiling)
}

// TestAWSSweepsThatStillReadOnePage is the same ratchet for AWS (D817).
//
// The marker list is longer here, and that is the finding rather than an inconvenience:
// AWS has no single paging shape. The Query-protocol services return a NextToken in the
// form response, the JSON ones a NextMarker with a Truncated flag, the REST ones a marker
// in the query string, and IsTruncated and Truncated are different fields on different
// services. Any of them appearing in a sweep is the evidence that the sweep knows about
// pages at all — which is all this ratchet claims to measure.
func TestAWSSweepsThatStillReadOnePage(t *testing.T) {
	unpagedSweeps(t, "aws", []string{
		"NextToken", "nextToken", "NextMarker", "IsTruncated", "Truncated",
		"Marker", "NextContinuationToken", "LastEvaluated", "ExclusiveStart",
		"HasMoreStreams",
	}, unpagedAWSSweepCeiling)
}

func unpagedSweeps(t *testing.T, pkg string, markers []string, ceiling int) {
	t.Helper()
	root := repoRoot(t)
	dir := filepath.Join(root, "go", "internal", pkg)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	var unpaged []string
	total := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !strings.HasPrefix(fn.Name.Name, "discover") {
				continue
			}
			total++
			body := string(src[fn.Pos()-1 : fn.End()-1])
			paged := false
			for _, m := range markers {
				if strings.Contains(body, m) {
					paged = true
				}
			}
			if paged {
				continue
			}
			unpaged = append(unpaged, name+": "+fn.Name.Name)
		}
	}

	// A gate with no subject reports a clean sweep over nothing (D328).
	if total < 30 {
		t.Fatalf("found %d %s sweeps — there are far more; the scan is broken", total, pkg)
	}
	sort.Strings(unpaged)

	if len(unpaged) > ceiling {
		t.Errorf("%d %s sweeps read one page, ceiling %d — the debt grew:\n  %s\n\n"+
			"Each of these reports an estate smaller than it is. Use the shared loop and "+
			"lower the ceiling (D814/D816).",
			len(unpaged), pkg, ceiling, strings.Join(unpaged, "\n  "))
	}
	if len(unpaged) < ceiling {
		t.Errorf("%d %s sweeps read one page but the ceiling still says %d. Lower it: a "+
			"ceiling that trails the work stops being a ratchet.", len(unpaged), pkg, ceiling)
	}
}
