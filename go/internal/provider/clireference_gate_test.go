package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1125. The published CLI reference opened with "The verbs, grouped below" and listed
// THIRTY-THREE of the binary's fifty-two. Nothing said it was a selection.
//
// The nineteen missing were not obscure: `posture` (the proactive classifier),
// `horizon` (when a verdict expires), `preflight` (the read-only permission pass before
// anything mutates), `backup` and `restore` (disaster recovery), `refresh`, `react`,
// `crawl`, `status`, `wait`, `runs`. Each was built deliberately and recorded in the
// design log; the page a reader consults to learn what the tool can do said none of
// them existed.
//
// This is D1123's shape one level up. There the harm was a driver author shipping a
// hole; here it is quieter and broader — a capability that is absent from the reference
// has, for that reader, not been built. Someone hits a permission failure mid-apply
// without knowing `preflight` would have said so first, or reaches for a backup during
// an incident and does not know the verb is there.
//
// `groundhold --help` was complete all along, which is the part worth noticing: the
// authoritative list existed, and the derived one drifted from it silently because
// nothing compared them.
func TestTheCLIReferenceListsEveryVerb(t *testing.T) {
	root := repoRoot(t)

	src, err := os.ReadFile(filepath.Join(root, "go", "cmd", "groundhold", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile("(?s)const usage = `(.*?)\n`").FindStringSubmatch(string(src))
	if block == nil {
		t.Fatal("cannot find the usage block — this gate has no authority to compare against")
	}
	binary := map[string]bool{}
	for _, line := range strings.Split(block[1], "\n") {
		// Two published forms: plain, and with a global flag before the verb.
		if m := regexp.MustCompile(`^  groundhold (?:\[[^\]]*\] )?([a-z][a-z-]*)(\s|$)`).
			FindStringSubmatch(line); m != nil {
			binary[m[1]] = true
		}
	}
	if len(binary) < 40 {
		t.Fatalf("parsed %d verbs from the usage block — the probe broke, and this gate "+
			"would pass over a reference missing almost everything (D328)", len(binary))
	}

	raw, err := os.ReadFile(filepath.Join(root, "website", "pages", "cli.md"))
	if err != nil {
		t.Skipf("no CLI reference here: %v", err)
	}
	page := string(raw)
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z][a-z-]*)").FindAllStringSubmatch(page, -1) {
		listed[m[1]] = true
	}
	// Rows that name two verbs at once, e.g. `pair` / `unpair`.
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z-]+)` / `([a-z-]+)`").FindAllStringSubmatch(page, -1) {
		listed[m[1]], listed[m[2]] = true, true
	}

	var missing, phantom []string
	for v := range binary {
		if !listed[v] {
			missing = append(missing, v)
		}
	}
	for v := range listed {
		if !binary[v] {
			phantom = append(phantom, v)
		}
	}
	sort.Strings(missing)
	sort.Strings(phantom)

	if len(missing) > 0 {
		t.Errorf("the binary accepts these verbs and the reference does not list them:\n  %s\n\n"+
			"A capability absent from the reference has, for that reader, not been built. "+
			"`--help` is the authority and was complete while this page drifted, because "+
			"nothing compared them.", strings.Join(missing, ", "))
	}
	if len(phantom) > 0 {
		t.Errorf("the reference lists verbs the binary does not accept:\n  %s\n\n"+
			"A reader would type them and get an operator error.", strings.Join(phantom, ", "))
	}
}

// The header must keep naming `--help` as the authority. A reference that claims to be
// the source of truth invites the drift this gate just closed; one that points at the
// generated list tells a reader where to go when the two disagree.
func TestTheCLIReferenceNamesItsAuthority(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "website", "pages", "cli.md"))
	if err != nil {
		t.Skipf("no CLI reference here: %v", err)
	}
	head := string(raw)
	if i := strings.Index(head, "## "); i > 0 {
		head = head[:i] // the intro only; the body is tables
	}
	if !strings.Contains(head, "--help") {
		t.Error("the CLI reference's intro no longer names `groundhold --help` as the " +
			"authority. The page is a derived list; saying so is what makes it safe to " +
			"read when the two ever disagree.")
	}
}
