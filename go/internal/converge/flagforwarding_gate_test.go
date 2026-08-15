package converge

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// D638. Three times now a flag has failed to reach converge's children, and each time
// the consequence was different and worse than the last: `--trust`/`--sign-key` left
// the security policy unenforced and permanently poisoned signed histories (D612);
// `--kubeconfig`/`--context` sent WRITES to the default cluster while the operator
// named another (measured on a live k3d cluster — a Role appeared with groundhold's
// ownership labels while the named endpoint was unreachable).
//
// converge runs plan, observe, forecast and apply as separate PROCESSES. A flag that
// is not on their argv does not exist for them. The pattern is not "remember to
// forward the important ones" — it is that EVERY global flag needs a decision, in
// writing, about whether it travels.
//
// This gate reads the CLI's global flag switch and requires every flag to appear in
// exactly one of the two sets below. Adding a flag to the CLI without classifying it
// fails here, which is the only way this stops recurring.
func TestEveryGlobalFlagIsClassifiedForForwarding(t *testing.T) {
	// Flags converge FORWARDS to its children, because they change what a child sees
	// or is allowed to do.
	forwarded := map[string]string{
		"--trust":      "the child enforces the trust policy or nothing does (D612)",
		"--trust-from": "the boundary the trust policy starts at (D612)",
		"--sign-key":   "an unsigned child event poisons a signed history forever (D612)",
		"--kubeconfig": "names WHICH cluster the child writes to (D638)",
		"--context":    "names WHICH cluster the child writes to (D638)",
		"--vocab":      "the vocabulary decides statefulness and therefore consent",
		"--no-vocab":   "the same decision, negated",
		"--ledger":     "the history the child reads and appends to",
		"--provider":   "the driver the child acts through",
		"--project":    "the provider scope the child acts in",
		"--at":         "the safety clock; a child with a different one judges differently",
		"--currency":   "the reporting currency of the child's cost estimate",
		// D638, found by this gate on its first run: these change what a child SEES
		// or DOES and were not travelling.
		"--region":            "the provider scope a child observes and writes in",
		"--bindings":          "the bindings the compiler reads",
		"--observations":      "the evidence the compiler judges against",
		"--ttl":               "how long the child's observation stays evidence",
		"--require-preflight": "apply must run the permission preflight, or not",
		"--budget":            "the ceiling the compiler refuses against",
		"--fail-key":          "fake-driver injection; converge's partial-apply path is unreachable without it",
		"--unknown-key":       "the same, for an unknown outcome",
		"--retryable-key":     "the same, for a retryable outcome",
	}
	// Flags that are converge's OWN and must not travel — each with the reason.
	local := map[string]string{
		"--json":            "converge renders; children always emit JSON",
		"--yes":             "consent is converge's to obtain, not the child's to skip",
		"--allow-data-loss": "the same consent, spent once by the porcelain",
		"--allow-exposure":  "the same consent for a provable exposure (D630)",
		"--detach":          "how converge itself runs",
		"--no-reachability": "converge runs its OWN probe phase and suppresses the child's",
		"--color":           "presentation, decided by the terminal converge owns",
		"--ascii":           "presentation",
		"--explain":         "presentation",
		"--progress":        "presentation",
		"--help":            "never reaches a verb",
		// Verb-specific: read by a verb converge never spawns. Forwarding them would
		// be noise at best and, for the destructive ones, a flag arriving where
		// nobody asked for it.
		"--actor":                  "publish's author",
		"--all":                    "deposed's scope",
		"--allow-intrusive":        "probe's consent, spent by the porcelain",
		"--allow-plaintext-secret": "a consent converge obtains once",
		"--as":                     "suggest's rendering",
		"--capability":             "capsule/unadopt target",
		"--check":                  "anchor/restore verification input",
		"--complete":               "crawl's completeness marker",
		"--contract":               "posture's contract input",
		"--crawl":                  "posture's sweep input",
		"--cred-ref":               "pair's credential reference",
		"--deposed":                "plan's retirement mode",
		"--discovery":              "adopt's provenance input",
		"--documents":              "backup/restore blob directory",
		"--event":                  "hash's document selector",
		"--fingerprint":            "repair's consent token",
		"--format":                 "export rendering",
		"--from":                   "export window start",
		"--heads":                  "scenario head pinning",
		"--live":                   "apiver's live check",
		"--map":                    "adopt's capability->providerId mapping",
		"--notify-cmd":             "converge's own doorbell",
		"--notify-url":             "converge's own doorbell",
		"--out":                    "where a verb writes its artefact",
		"--pairings":               "crawl's pairing registry",
		"--partial":                "restore's partial mode",
		"--poll":                   "wait's interval",
		"--print-config":           "mcp's config dump",
		"--quarantine":             "repair's destructive mode",
		"--record":                 "observe's write flag; converge passes it explicitly",
		"--scope":                  "crawl/pair scope",
		"--since":                  "runs' window",
		"--survey":                 "survey's output path",
		"--timeout":                "wait's bound",
		"--to":                     "export window end",
		"--type":                   "example's document kind",
		"--verify":                 "capsule verification input",
		"--verify-ref":             "capsule trust reference",
		"--version":                "answers before any verb",
		"--window":                 "forecast/report window",
		"--within":                 "horizon's projection window",
	}

	root := findRepoRoot(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, "go", "cmd", "groundhold",
		"main.go"), nil, 0)
	if err != nil {
		t.Skipf("cannot parse the CLI here: %v", err)
	}

	// The global switch lives in `run`; flags cased anywhere else belong to a verb's
	// own sub-parser (D602) and are not converge's business.
	global := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" {
			return true
		}
		ast.Inspect(fn, func(m ast.Node) bool {
			cc, ok := m.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				lit, ok := e.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, err := strconv.Unquote(lit.Value); err == nil &&
					strings.HasPrefix(v, "--") {
					global[v] = true
				}
			}
			return true
		})
		return true
	})
	if len(global) < 20 {
		t.Fatalf("found %d global flags — the parse broke and this gate would pass "+
			"over anything (D328)", len(global))
	}

	var unclassified []string
	for f := range global {
		_, fwd := forwarded[f]
		_, loc := local[f]
		switch {
		case fwd && loc:
			t.Errorf("%s is classified both forwarded and local", f)
		case !fwd && !loc:
			unclassified = append(unclassified, f)
		}
	}
	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("these global flags have no forwarding decision: %v\n"+
			"converge runs its children as separate PROCESSES — a flag not on their "+
			"argv does not exist for them. Add each to `forwarded` (with the reason a "+
			"child needs it) or to `local` (with the reason it is converge's own). "+
			"Three defects so far came from a flag nobody decided about.", unclassified)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go", "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("repo root not found")
	return ""
}
