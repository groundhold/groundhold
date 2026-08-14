package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D1064. Every NUMBER a published document states is gated, and every VERB it invokes
// is gated — but the terminal output pasted underneath the command was not, and that
// is where the strongest claims live: a verdict line says what the tool concluded and
// on what evidence.
//
// D766 is the proof of what that costs. From the field, with money attached: `verify`
// rendered `observed <value>` whatever the provenance was, so a budget constraint
// compared a number the AUTHOR had written against a threshold the author had written
// and reported `observed 6 EUR` while the bill was 2.4x that. The runtime was fixed —
// nothing observes a declaration, so the sentence now follows the basis. The published
// examples were not: README and the quickstart went on showing `observed` over declared
// values, teaching a newcomer the exact sentence D766 had just called false, on the
// first page they read. The fix was invisible where it mattered most.
//
// So: a documented `verify` invocation over files this repository ships is RUN, and
// every line of the output block beneath it must be a line the tool actually prints.
// Not equality — the blocks are excerpts and legitimately drop the header — but no
// documented line may be absent from the real output.
func TestDocumentedVerifyOutputIsWhatTheToolPrints(t *testing.T) {
	root := repoRootFromCmd(t)

	docs := []string{"README.md", filepath.Join("website", "pages", "quickstart.md")}
	// Command, then the output block that follows it. `\s*` between the fences so a
	// prose sentence between them does not silently detach a block from its command
	// (it would, and the pair would go unchecked while looking checked).
	pair := regexp.MustCompile("(?s)```sh\\n(.*?)```\\s*```\\n(.*?)```")

	var checked int
	for _, rel := range docs {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			continue // a doc the export leaves behind is not this gate's business
		}
		for _, m := range pair.FindAllStringSubmatch(string(raw), -1) {
			cmd := strings.Join(strings.Fields(strings.ReplaceAll(m[1], "\\\n", " ")), " ")
			if !strings.Contains(cmd, " verify ") {
				continue
			}
			// Only the invocations whose operands this repository actually ships:
			// an inline example (the quickstart writes its documents into the page)
			// has no paths to resolve, and guessing at one would gate a fiction.
			var args []string
			for _, f := range strings.Fields(cmd) {
				if strings.HasSuffix(f, ".yaml") {
					if _, err := os.Stat(filepath.Join(root, f)); err != nil {
						args = nil
						break
					}
					args = append(args, filepath.Join(root, f))
				}
			}
			if len(args) != 2 {
				continue
			}

			got := captureStdout(t, func() { run(append([]string{"verify"}, args...)) })
			real := map[string]bool{}
			for _, line := range strings.Split(got, "\n") {
				real[strings.Join(strings.Fields(line), " ")] = true
			}
			for _, line := range strings.Split(m[2], "\n") {
				norm := strings.Join(strings.Fields(line), " ")
				if norm == "" {
					continue
				}
				if !real[norm] {
					t.Errorf("%s documents a line `verify` does not print:\n  documented: %s\n"+
						"  the command: %s\n"+
						"A pasted verdict is a claim about what the tool concluded and on what "+
						"evidence — D766 is what it costs when the runtime is corrected and the "+
						"published example is not.\n  actual output:\n%s",
						rel, norm, cmd, got)
				}
			}
			checked++
		}
	}

	// D328: an absence gate that matched nothing would pass forever. The pairs exist
	// today; if a rewrite drops them, this must say so rather than go quiet.
	if checked == 0 {
		t.Fatal("no documented verify invocation over shipped files was found — either " +
			"the docs stopped showing one (then this gate is watching nothing) or the " +
			"block shape changed and the parser walked past it")
	}
	t.Logf("checked %d documented verify output block(s)", checked)
}
