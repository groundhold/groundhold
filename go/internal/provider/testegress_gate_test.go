package provider_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// productionRouteCeiling is how many recorded routes a driver's UNIT tests still send
// to a real cloud host. It may only go DOWN.
//
// D1232. A unit test that reaches a real provider API is not a unit test, and the GCP
// package was making 52 such requests per run across 20 production Google hosts. They
// were invisible for the reason D1230 named — the failure falls to the conservative
// branch. `List` sweeps every discoverer; a base URL the fixture did not pin sent its
// request to the real host; the request failed (no credentials, or no network); the
// sweep recorded the failure and carried on; and the assertion downstream counted only
// what the fixture served, so it passed either way.
//
// Worse than invisible, it was ENDORSED: the route recorder writes such a request into
// the checked-in baseline under a "-" marker (meaning "no override matched, this went
// to production"), where it reads as a legitimate route. The mechanism to detect this
// existed and its output was being filed as normal. This gate turns the marker from a
// record into a budget.
//
// Two things follow from a test that escapes, and the second is the sharper one. The
// suite's behaviour depends on network availability and on what an unauthenticated
// request to a real API returns — a 401 here, a dial error there — so the assertion is
// exercising an error branch while appearing to exercise the happy path. And on a
// machine that DOES hold cloud credentials, a unit test issues authenticated requests
// to a real project. Neither is acceptable, and neither announces itself.
//
// D1233 took it to ZERO, so this is no longer a budget — it is a prohibition, and the
// constant stays only because the shape of a ratchet is what stops one creeping back.
//
// The last eight needed a correction to D1232's own entry. That entry said two of them
// (serviceusage, securitycentermanagement) had NO override seam and could not be tested
// hermetically. Both have one — `suBaseOverride` and `sccBaseURLOverride` — and so do
// the other six. What they share is that the seam is a PACKAGE-LEVEL var rather than a
// Driver field, which is exactly what reflection over the struct cannot reach. The
// helper now pins those too, and a lint reads the package's sources and fails the build
// if a seam exists that it does not set.
const productionRouteCeiling = 0

// TestUnitTestsDoNotReachRealCloudHosts reads the recorded route baselines, which the
// per-package drift gates already force to match a fresh recording on every unfiltered
// run — so asserting on the file is asserting on what the suite actually does.
func TestUnitTestsDoNotReachRealCloudHosts(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	files := map[string]string{
		"aws":   filepath.Join(root, "aws", "testdata", "aws-routes.txt"),
		"gcp":   filepath.Join(root, "gcp", "testdata", "gcp-routes.txt"),
		"azure": filepath.Join(root, "azure", "testdata", "azure-routes.txt"),
	}
	var escapes []string
	lines := 0
	for pkg, path := range files {
		blob, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s routes: %v", pkg, err)
		}
		for _, ln := range strings.Split(string(blob), "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			lines++
			// The recorder writes "-\t<method>\t<absolute production URL>" when no
			// base-URL override matched the request.
			if strings.HasPrefix(ln, "-\t") {
				escapes = append(escapes, pkg+": "+strings.ReplaceAll(ln, "\t", " "))
			}
		}
	}
	// D328: assert the subject. A truncated or unwritten baseline would let this gate
	// report a clean run over nothing.
	if lines < 300 {
		t.Fatalf("the three route baselines hold only %d lines between them — too few to "+
			"be the real set, so this gate is measuring almost nothing", lines)
	}
	sort.Strings(escapes)
	if len(escapes) > productionRouteCeiling {
		t.Errorf("%d recorded unit-test requests go to a REAL cloud host, ceiling %d:\n  %s\n\n"+
			"A unit test that reaches a provider API exercises an error branch while looking "+
			"like it exercises the happy path, and on a machine holding cloud credentials it "+
			"issues authenticated requests to a real project. Pin the base URL in the test's "+
			"driver (internal/gcp: pinAllBaseURLs), or give the path an override seam if it "+
			"has none.",
			len(escapes), productionRouteCeiling, strings.Join(escapes, "\n  "))
	}
	// The two-sided half is retained for the shape, though at zero it can only fire if
	// the ceiling is raised — which is the edit this is here to make visible.
	if len(escapes) < productionRouteCeiling {
		t.Errorf("only %d escaping routes remain but the ceiling still says %d — lower it",
			len(escapes), productionRouteCeiling)
	}
}
