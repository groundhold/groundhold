package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// D580. The publication path has a thorough gate — `make export-check` copies the
// whitelist, sanitizes, audits against the deny list and runs a standalone `make
// check` on the result. It is not part of `make check`, because it costs minutes.
//
// So a leak ships green. Mine did: D578's entry and its test quoted a client name in
// a casing the sanitizer does not rewrite, `make check` passed, and the break was
// found only by running the export by hand afterwards. The gate that exists is the
// one nobody runs before committing.
//
// This is the cheap half, and it belongs in the gate everyone runs: grep the files
// the export actually ships for the tokens the export forbids, with no copy, no
// sanitize, no standalone build. It cannot replace export-check — it does not prove
// the public tree BUILDS — but it catches the class that has broken publication
// twice (D340, and this).
//
// It reads the deny list from the script rather than restating it, so a client added
// there is guarded here without anyone remembering to (D550).
func TestNoDeniedTokenInFilesTheExportShips(t *testing.T) {
	skipIfExported(t, "the export script and its client list")
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "export-public.sh")
	raw, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}

	tokens := clientTokens(t, string(raw))
	if len(tokens) < 3 {
		t.Fatalf("only %d client tokens parsed from the deny list — the probe broke and "+
			"this gate would pass on anything", len(tokens))
	}
	// The sanitizer rewrites three exact casings; anything else reaches the export,
	// so the search is case-insensitive exactly as the deny audit is.
	pattern := "(?i)(" + strings.Join(tokens, "|") + ")"
	re := regexp.MustCompile(pattern)

	// D603: a POSITIVE CONTROL, because this is an absence gate. Over a clean tree it
	// reports zero hits whether the scan runs or not, so disabling the scan entirely
	// was invisible — the mutation meter caught exactly that and called the mutant
	// SURVIVED. The control runs the same scanner over a synthetic line that MUST
	// match; nothing is written to disk, and the token is built from the deny list
	// itself so it cannot become a second hand-maintained copy (D580: the first
	// version of this gate carried the client's name in its own source).
	scan := func(rel, body string) []string {
		var out []string
		for i, line := range strings.Split(body, "\n") {
			if m := re.FindString(line); m != "" && !sanitizerRewrites(m) {
				out = append(out, rel+":"+strconv.Itoa(i+1)+" "+m)
			}
		}
		return out
	}
	// A casing the sanitizer does NOT rewrite: not all-lower, not all-upper, not
	// Capitalized — built here rather than written out, so the token never appears
	// literally in this file (D580).
	odd := tokens[0]
	odd = strings.ToUpper(odd[:1]) + strings.ToUpper(odd[1:2]) + strings.ToLower(odd[2:])
	if sanitizerRewrites(odd) {
		t.Fatalf("could not build a casing outside the sanitizer's three from %d "+
			"characters — the control cannot prove anything", len(tokens[0]))
	}
	control := "a line naming " + odd + " in a casing the sanitizer does not rewrite"
	if got := scan("<positive-control>", control); len(got) == 0 {
		t.Fatal("the deny-token scanner did not flag a synthetic line built from the " +
			"deny list itself — the scan is not running, and every green result it " +
			"produces over the real tree means nothing")
	}

	var hits []string
	for _, rel := range exportedTextFiles(t, root) {
		body, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue
		}
		hits = append(hits, scan(rel, string(body))...)
	}
	if len(hits) > 0 {
		t.Errorf("%d client-name occurrence(s) in files the export SHIPS, in a casing the "+
			"sanitizer does not rewrite:\n  %s\n`make export-check` would refuse to "+
			"publish; it is not in `make check`, so this would have shipped green.",
			len(hits), strings.Join(hits, "\n  "))
	}
}

// sanitizerRewrites reports whether the export's substitution handles this exact
// spelling. Those are safe: they become the generic name on the way out.
func sanitizerRewrites(s string) bool {
	return s == strings.ToLower(s) || s == strings.ToUpper(s) ||
		s == strings.ToUpper(s[:1])+strings.ToLower(s[1:])
}

// clientTokens pulls the client names out of the deny list's own client line.
func clientTokens(t *testing.T, src string) []string {
	for _, line := range strings.Split(src, "\n") {
		if !strings.Contains(line, "# clients") || !strings.HasPrefix(strings.TrimSpace(line), "DENY=") {
			continue
		}
		body := line[strings.Index(line, "\"")+1:]
		body = body[:strings.LastIndex(body, "\"")]
		body = strings.TrimPrefix(body, "$DENY|")
		var out []string
		for _, tok := range strings.Split(body, "|") {
			if tok = strings.TrimSpace(tok); tok != "" && regexp.MustCompile(`^[a-z-]+$`).MatchString(tok) {
				out = append(out, tok)
			}
		}
		return out
	}
	t.Fatal("no client line found in the deny list — it was renamed or removed")
	return nil
}

// exportedTextFiles lists the tracked text files the export whitelist ships.
func exportedTextFiles(t *testing.T, root string) []string {
	out, err := exec.Command("git", "-C", root, "ls-files",
		"docs/DESIGN.md", "docs/MATURITY.md", "docs/THREAT_MODEL.md", "docs/VOICE_TRACK.md",
		"README.md", "CHANGELOG.md", "spec", "go", "conformance", "examples", "ref").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	var files []string
	for _, f := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if f == "" {
			continue
		}
		switch filepath.Ext(f) {
		case ".go", ".md", ".yaml", ".yml", ".json", ".py", ".sh":
			files = append(files, f)
		}
	}
	if len(files) < 100 {
		t.Fatalf("only %d exported text files listed — the probe broke", len(files))
	}
	return files
}
