package provider_test

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
)

// D876. docs/COVERAGE.md is the maturity matrix at service granularity — every driver
// service, labelled `measured` (run against a real cloud, run cited) or `config-intent`
// (golden only). The launch plan's "eat your own epistemics" move only works if the table
// cannot lie in either direction, and a hand-maintained table can lie in three:
//
//   - it can OMIT a service (breadth silently overstated by absence),
//   - it can NAME a service the drivers do not have (a phantom row),
//   - it can call a service `measured` with NO evidence (overclaim, the cardinal sin).
//
// The service list is not the table's to assert — it comes from the drivers themselves
// (ServiceCapabilities, D317: ask the drivers, never scrape), so a driver that gains or
// drops a service forces the table to match or this fails. The evidence rule is what keeps
// `measured` honest: the column must carry a citation, or the claim does not stand.
func TestCoverageMatrixCannotOverclaimOrOmit(t *testing.T) {
	root := repoRoot(t)

	// The subject, asked of the drivers. constructor arg is irrelevant (parityCaps idiom).
	drivers := map[string]map[string]string{
		"aws":   aws.NewDriver("").ServiceCapabilities(),
		"gcp":   gcp.NewDriver("").ServiceCapabilities(),
		"azure": azure.NewDriver("").ServiceCapabilities(),
	}
	driverKey := map[string]bool{}
	total := 0
	for cloud, caps := range drivers {
		for tok := range caps {
			driverKey[cloud+"/"+tok] = true
			total++
		}
	}
	// D328: a subject that went empty would make every assertion below pass over nothing.
	if total < 100 {
		t.Fatalf("only %d driver services enumerated — the drivers went quiet, and this gate "+
			"would then certify a matrix against almost nothing", total)
	}

	raw, err := os.ReadFile(filepath.Join(root, "docs", "COVERAGE.md"))
	if err != nil {
		t.Fatalf("the coverage matrix is gone: %v — the honest breadth number cannot be missing", err)
	}

	// Parse the table rows: | cloud | service | capability | status | evidence |
	// D882: `exempt` joins measured/config-intent — a service that CANNOT be safely run on
	// this estate (an account-wide security posture on an account that also holds client
	// infra, a non-deletable resource, a singleton, an org-level control). Like measured, it
	// must carry a reason, so an exemption is a stated judgement, never a silent skip.
	rowRE := regexp.MustCompile(`^\|\s*(aws|gcp|azure)\s*\|\s*([a-z0-9-]+)\s*\|\s*([^|]+?)\s*\|\s*(measured|config-intent|exempt)\s*\|\s*([^|]*?)\s*\|$`)
	inMatrix := map[string]bool{}
	measured, exempt := 0, 0
	var overclaim, phantom, unreasoned []string
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		m := rowRE.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		cloud, tok, status, evidence := m[1], m[2], m[4], strings.TrimSpace(m[5])
		key := cloud + "/" + tok
		inMatrix[key] = true
		if !driverKey[key] {
			phantom = append(phantom, key)
		}
		if status == "measured" {
			measured++
			if evidence == "" {
				overclaim = append(overclaim, key)
			}
		}
		if status == "exempt" {
			exempt++
			if evidence == "" {
				unreasoned = append(unreasoned, key)
			}
		}
	}

	if len(phantom) > 0 {
		t.Errorf("the matrix names %d service(s) no driver has (phantom rows): %v — a service "+
			"that does not exist cannot have been tested", len(phantom), phantom)
	}
	if len(overclaim) > 0 {
		t.Errorf("%d service(s) are marked `measured` with an empty evidence column: %v — a "+
			"measured claim with no citation is exactly the overclaim this matrix exists to "+
			"forbid (D876)", len(overclaim), overclaim)
	}
	if len(unreasoned) > 0 {
		t.Errorf("%d service(s) are marked `exempt` with no reason: %v — an exemption without a "+
			"stated why is a silent skip wearing a label (D882)", len(unreasoned), unreasoned)
	}

	// Completeness: every driver service must have a row. A new service added to a driver
	// without a row here would be breadth counted by nobody — the absence that reads as
	// "covered" (D875's lesson, in the other direction).
	var missing []string
	for key := range driverKey {
		if !inMatrix[key] {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d driver service(s) have no row in the matrix: %v — add them (as "+
			"`config-intent` unless a real-cloud run is cited); a service the drivers "+
			"report and the matrix omits is breadth claimed by silence", len(missing), missing)
	}

	// The header's headline count must equal the table — a summary that drifts from its
	// own rows is the first thing a reader trusts and the first thing to rot. Both the
	// measured count AND the exempt count are asserted, so neither can quietly inflate.
	if !strings.Contains(string(raw), "Field-tested: "+strconv.Itoa(measured)+" of "+strconv.Itoa(total)) {
		t.Errorf("the header's field-tested count does not match the table (%d measured of %d "+
			"total counted from the rows) — regenerate the summary line", measured, total)
	}
	if exempt > 0 && !strings.Contains(string(raw), strconv.Itoa(exempt)+" exempt") {
		t.Errorf("the header does not state the exempt count (%d exempt counted from the rows) — "+
			"an exemption the summary hides reads as breadth still owed (D882)", exempt)
	}
}
