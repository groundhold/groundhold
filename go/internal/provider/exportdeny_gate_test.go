package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D578. `scripts/export-public.sh` genericizes a client name and then audits the
// result against a DENY list that contains the same name. Read quickly, the DENY
// entry looks redundant — the sanitizer ran first, so what could be left?
//
// The casings. The sanitizer FINDS files case-insensitively (`grep -iE "acme"`) and
// REPLACES three exact spellings (`Acme`, `ACME`, `acme`). A mixed casing —
// `AcMe` — is found, not replaced, and reaches the export. Verified by putting one
// into an exported file: the run stops with `LEAK DETECTED in export — do not
// publish`, exit 1, with the offending file left in place to look at.
//
// So the DENY entry is not defence in depth against a hypothetical; it is the ONLY
// thing standing between an unexpected spelling and a publish. That is worth a test,
// because the next reader can reasonably conclude it is dead weight and delete it —
// and deleting it fails open, silently, on the one path that leaves the building.
//
// Deliberately NOT "fixed" by making the sed case-insensitive: silently rewriting an
// unexpected spelling hides that someone wrote the name in a form nobody anticipated.
// Stopping and making a human look is the safer behaviour, and matches how the rest
// of this system treats a surprise.
func TestExportDenyListStillNamesTheClients(t *testing.T) {
	skipIfExported(t, "the export script and its client list")
	root := repoRoot(t)
	// The export script is PRIVATE tooling and is deliberately not exported — it
	// carries the client list this gate is about, so shipping it would be the leak
	// it prevents. In the public tree there is nothing here to guard, and a hard
	// read is exactly the failure D340 describes: "a count gate that hard-read a
	// file the export omits". Reproduced verbatim by the first version of this test.
	path := filepath.Join(root, "scripts", "export-public.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)

	// every token the sanitizer genericizes must ALSO be in the deny audit
	sed := regexp.MustCompile(`s/([A-Za-z][A-Za-z0-9-]{2,})/[A-Za-z][A-Za-z0-9-]*/g`)
	var genericized []string
	for _, m := range sed.FindAllStringSubmatch(src, -1) {
		genericized = append(genericized, strings.ToLower(m[1]))
	}
	if len(genericized) == 0 {
		t.Fatal("no genericizing substitutions found in the export script — the probe " +
			"broke and this gate would pass on anything")
	}
	deny := denyBody(t, src)
	var unguarded []string
	for _, tok := range genericized {
		if !strings.Contains(strings.ToLower(deny), tok) {
			unguarded = append(unguarded, tok)
		}
	}
	if len(unguarded) > 0 {
		t.Errorf("the export genericizes %v but the DENY audit does not name them.\n"+
			"The substitution replaces EXACT casings; a spelling it did not anticipate "+
			"(AcMe) survives it, and the deny audit is then the only thing between "+
			"that spelling and a publish.", unguarded)
	}
}

// denyBody returns everything assigned to DENY, so the check reads the audit's real
// content rather than one line of it.
func denyBody(t *testing.T, src string) string {
	var b strings.Builder
	for _, line := range strings.Split(src, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "DENY=") {
			b.WriteString(line)
			b.WriteString("\n")
		}
	}
	if b.Len() == 0 {
		t.Fatal("no DENY assignment found — the export audit is gone or renamed")
	}
	return b.String()
}
