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

// TestMaturityFieldTestedCountMatchesCoverage links the two "authoritative" honesty
// docs so neither can go stale while the other moves. This session's honesty pass
// found MATURITY.md asserting "23 of 145 field-tested" while the gated COVERAGE.md
// said 144 — two source-of-truth documents with nothing between them, drifted by a
// factor of six because reality advanced and only one doc absorbed it. The arbiter is
// machine-derived: the `measured` rows COVERAGE carries (each already forced to cite a
// run by TestCoverageMatrixCannotOverclaimOrOmit, and the header already gated against
// those rows) and the service total the drivers themselves report (D317). MATURITY's
// headline count must equal both, or this fails and names the stale number.
func TestMaturityFieldTestedCountMatchesCoverage(t *testing.T) {
	root := repoRoot(t)

	// Denominator: ask the drivers, never a prose count (D317).
	total := 0
	for _, caps := range []map[string]string{
		aws.NewDriver("").ServiceCapabilities(),
		gcp.NewDriver("").ServiceCapabilities(),
		azure.NewDriver("").ServiceCapabilities(),
	} {
		total += len(caps)
	}
	if total < 100 {
		t.Fatalf("only %d driver services enumerated — the subject went quiet and this gate "+
			"would tie two docs to nothing (D328)", total)
	}

	// Numerator: the `measured` rows in COVERAGE. A counted row is a cited run, because the
	// sibling gate forbids a `measured` row with an empty evidence column.
	covRow := regexp.MustCompile(`^\|\s*(?:aws|gcp|azure)\s*\|\s*[a-z0-9-]+\s*\|\s*[^|]+?\s*\|\s*measured\s*\|`)
	covRaw, err := os.ReadFile(filepath.Join(root, "docs", "COVERAGE.md"))
	if err != nil {
		t.Fatalf("COVERAGE.md is gone: %v — the honest breadth number cannot be missing", err)
	}
	measured := 0
	for _, ln := range strings.Split(string(covRaw), "\n") {
		if covRow.MatchString(ln) {
			measured++
		}
	}
	if measured == 0 {
		t.Fatalf("parsed 0 `measured` rows from COVERAGE.md — the row shape changed and this " +
			"gate would compare MATURITY against nothing (D328)")
	}

	// The link that was missing: MATURITY's headline must equal the machine-derived reality.
	matRaw, err := os.ReadFile(filepath.Join(root, "docs", "MATURITY.md"))
	if err != nil {
		t.Fatalf("MATURITY.md is gone: %v", err)
	}
	m := regexp.MustCompile(`(\d+)\s+of\s+(\d+)\s+services field-tested`).FindStringSubmatch(string(matRaw))
	if m == nil {
		t.Fatalf("MATURITY.md states no \"N of M services field-tested\" count — the number the " +
			"launch narrative rests on must be present and checkable against COVERAGE")
	}
	matN, _ := strconv.Atoi(m[1])
	matM, _ := strconv.Atoi(m[2])
	if matN != measured || matM != total {
		t.Errorf("MATURITY.md says %d of %d services field-tested, but COVERAGE's rows + the "+
			"drivers say %d of %d — the two authoritative honesty docs have drifted (the 23-vs-144 "+
			"failure this gate exists to stop). Move the stale number behind the evidence, never "+
			"the evidence behind the number.", matN, matM, measured, total)
	}
}

// TestReadmeBreadthCountsMatchDrivers makes README's own claim true. The breadth
// bullet states "145 service mappings across AWS (54), GCP (46) and Azure (45),
// fulfilling 50/45/45 distinct capability TYPES ... Counts are read from the drivers'
// own certified ServiceCapabilities() maps, not from prose." They were prose that
// happened to match — nothing enforced the sentence's own promise. This does: every
// number in it is re-derived from ServiceCapabilities and must equal the prose, so the
// front-page breadth cannot drift from the drivers the way MATURITY's count once did.
func TestReadmeBreadthCountsMatchDrivers(t *testing.T) {
	root := repoRoot(t)

	caps := map[string]map[string]string{
		"aws":   aws.NewDriver("").ServiceCapabilities(),
		"gcp":   gcp.NewDriver("").ServiceCapabilities(),
		"azure": azure.NewDriver("").ServiceCapabilities(),
	}
	svc := map[string]int{}
	typ := map[string]int{}
	total := 0
	for cloud, m := range caps {
		svc[cloud] = len(m)
		total += len(m)
		distinct := map[string]bool{}
		for _, c := range m {
			distinct[c] = true
		}
		typ[cloud] = len(distinct)
	}
	if total < 100 {
		t.Fatalf("only %d driver services — the subject went quiet and this gate would "+
			"certify the front page against nothing (D328)", total)
	}

	raw, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	txt := string(raw)
	svcM := regexp.MustCompile(
		`(\d+) service mappings across AWS \((\d+)\), GCP \((\d+)\) and Azure \((\d+)\)`).
		FindStringSubmatch(txt)
	if svcM == nil {
		t.Fatalf("README has no \"N service mappings across AWS (a), GCP (b) and Azure (c)\" " +
			"line — the breadth it says is machine-derived must be present and parseable")
	}
	typM := regexp.MustCompile(`fulfilling (\d+)/(\d+)/(\d+) distinct capability TYPES`).
		FindStringSubmatch(txt)
	if typM == nil {
		t.Fatalf("README has no \"fulfilling a/b/c distinct capability TYPES\" line")
	}

	atoi := func(s string) int { n, _ := strconv.Atoi(s); return n }
	check := func(label string, got, want int) {
		if got != want {
			t.Errorf("README says %s = %d, but the drivers' ServiceCapabilities() say %d. The "+
				"README claims these counts are 'read from the drivers … not from prose' — this "+
				"gate is what makes that true. Move the prose behind the drivers.", label, got, want)
		}
	}
	check("total service mappings", atoi(svcM[1]), total)
	check("AWS services", atoi(svcM[2]), svc["aws"])
	check("GCP services", atoi(svcM[3]), svc["gcp"])
	check("Azure services", atoi(svcM[4]), svc["azure"])
	check("AWS capability types", atoi(typM[1]), typ["aws"])
	check("GCP capability types", atoi(typM[2]), typ["gcp"])
	check("Azure capability types", atoi(typM[3]), typ["azure"])
}
