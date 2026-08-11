package perr

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// D619. `spec/errors.md` publishes a code AND an exit for every refusal, and callers
// are told to branch on them. The exit lived in exactly two places — that table, and a
// literal beside the code at each of 32 call sites — with nothing comparing them.
//
// Measured by an audit that provoked ~244 failures across 54 verbs:
//
//	structural-error   emitted at exits 1, 2 AND 3
//	stale-decision     emitted at exits 2 and 3
//	a stale plan       refused as `structural-error` on one path in apply.go and as
//	                   `stale-decision` on another, sixty lines apart
//	adopt              hardcoded exit 2 for EVERY code in one helper
//
// A caller cannot map code to exit in either direction, which is the entire purpose of
// publishing both. D330's registry gate reconciles the code NAMES across four
// artefacts; the exit column had no gate at all, which is precisely where the drift
// lived — the same lesson as D607, where a derivation that looked authoritative
// happened to exclude the most common case.
//
// `ExitFor` is now the single runtime source, and this gate holds it to the published
// table and to every call site.
func TestExitForMatchesThePublishedTable(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "errors.md"))
	if err != nil {
		t.Skipf("no published table here: %v", err)
	}
	// The cell may hold TWO exits ("3/4") for a code that legitimately carries both.
	// The first version of this gate matched only pure digits and silently dropped
	// three rows — and compared the result against a map built by the SAME parser, so
	// it passed while both sides were wrong together.
	rows := regexp.MustCompile("(?m)^\\|\\s*`([a-z-]+)`\\s*\\|\\s*([0-9/]+)\\s*\\|").
		FindAllStringSubmatch(string(raw), -1)
	if len(rows) < 20 {
		t.Fatalf("parsed %d rows from spec/errors.md — the probe broke and this gate "+
			"would pass on anything (D328)", len(rows))
	}
	if len(ExitsFor) == 0 {
		t.Fatal("ExitsFor is empty")
	}
	if len(ExitsFor) != len(rows) {
		t.Errorf("the runtime knows %d codes and the table publishes %d — a row the "+
			"parser drops disappears from BOTH sides of this comparison",
			len(ExitsFor), len(rows))
	}

	published := map[string][]int{}
	for _, r := range rows {
		var set []int
		for _, part := range strings.Split(r[2], "/") {
			n, err := strconv.Atoi(part)
			if err != nil {
				t.Fatalf("unreadable exit cell %q for %s", r[2], r[1])
			}
			set = append(set, n)
		}
		published[r[1]] = set
	}
	for code, exits := range ExitsFor {
		want, ok := published[string(code)]
		if !ok {
			t.Errorf("%s carries exits %v in the runtime and is absent from "+
				"spec/errors.md", code, exits)
			continue
		}
		if fmt.Sprint(want) != fmt.Sprint(exits) {
			t.Errorf("%s: runtime exits %v, the published table says %v",
				code, exits, want)
		}
	}
	for code := range published {
		if _, ok := ExitsFor[Code(code)]; !ok {
			t.Errorf("spec/errors.md publishes %s with an exit and the runtime has no "+
				"entry — a caller reading the table would branch on a number nothing "+
				"produces", code)
		}
	}
}

// Every call site that writes the exit beside the code must write the registry's exit.
func TestCallSitesUseTheRegistrysExit(t *testing.T) {
	root := repoRoot(t)
	pair := regexp.MustCompile(`perr\.([A-Z][A-Za-z]*),\s*(\d)\b`)
	seen := 0
	var bad []string

	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.Walk(filepath.Join(root, "go", dir),
			func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
					strings.HasSuffix(path, "_test.go") {
					return err
				}
				body, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(root, path)
				for _, m := range pair.FindAllStringSubmatch(string(body), -1) {
					allowed, ok := ExitsFor[codeByIdent(t, root, m[1])]
					if !ok {
						continue
					}
					seen++
					got, _ := strconv.Atoi(m[2])
					fine := false
					for _, a := range allowed {
						if a == got {
							fine = true
						}
					}
					if !fine {
						bad = append(bad, rel+": "+m[1]+" with exit "+m[2]+
							", the registry allows "+fmt.Sprint(allowed))
					}
				}
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
	}
	if seen == 0 {
		t.Fatal("no code/exit pairings found — the scan broke and this gate would " +
			"pass over anything (D328)")
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("call sites disagreeing with the registry:\n  %s\n"+
			"One code must mean one exit, or `spec/errors.md` is describing a tool "+
			"that does not exist.", strings.Join(bad, "\n  "))
	}
}

// codeByIdent resolves a Go identifier (StaleDecision) to its Code value, read from
// the source so the gate cannot drift from the constants it checks.
func codeByIdent(t *testing.T, root, ident string) Code {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "go", "internal", "perr", "perr.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(ident + `\s+Code = "([a-z-]+)"`).FindStringSubmatch(string(raw))
	if m == nil {
		return Code("")
	}
	return Code(m[1])
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "spec", "errors.md")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("no spec/errors.md above this directory")
	return ""
}
