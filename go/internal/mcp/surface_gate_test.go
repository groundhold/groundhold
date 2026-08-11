package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D614. The MCP surface is the one an autonomous caller drives with no human reading
// the argv, so its defaults and its schema ARE the safety boundary. Three defects, all
// measured by driving the server:
//
//  1. `provider` defaulted to "gcp" in four places, including the `observe` tool's own
//     description ("fake|gcp (default gcp)"). The CLI's published invariant is the
//     opposite: "the fake driver fabricates reality, so it is chosen deliberately,
//     never defaulted". An apply driven with a candidate declaring `provider: fake` and
//     no provider argument returned `target.provider: gcp` in the confirmation an agent
//     is told to show a human — a cloud nobody selected — and `observe` would have
//     contacted real GCP.
//
//  2. `inputSchema.required` omitted `at` on all four time-sensitive tools, so the
//     SCHEMA-CONFORMANT call could never succeed: plan, observe and forecast exit 1
//     with "requires an explicit --at", and apply burns its single-use confirmation
//     token before failing structurally.
//
//  3. `website/pages/mcp.md` said "the token proves a human saw THIS sealed decision"
//     while the package doc says it "does NOT authenticate a human" — a compliance
//     reader who reaches the page first draws the wrong conclusion about a control.
//
// This gate keeps the declared schema and the enforced arguments in one place, so a
// tool cannot declare a field required and then not require it (or vice versa).
func TestRequiredArgsMatchTheDeclaredSchema(t *testing.T) {
	// allowApply so groundhold_apply is declared: its schema is the one that matters
	// most here, since a missing argument costs the single-use confirmation token.
	s := &Server{allowApply: true}
	defs := s.toolDefs()
	if len(defs) == 0 {
		t.Fatal("no tools declared — the gate would be vacuous (D328)")
	}

	seen := map[string]bool{}
	for _, m := range defs {
		name, _ := m["name"].(string)
		schema, _ := m["inputSchema"].(map[string]any)
		var declared []string
		if raw, ok := schema["required"].([]string); ok {
			declared = raw
		}
		seen[name] = true

		enforced := requiredArgs[name]
		if len(enforced) == 0 {
			continue // tools with no CLI-refused arguments are not in the map
		}
		if strings.Join(declared, ",") != strings.Join(enforced, ",") {
			t.Errorf("%s declares required %v but enforces %v — a schema a caller "+
				"obeys must be the schema the server checks", name, declared, enforced)
		}
	}
	for name := range requiredArgs {
		if !seen[name] {
			t.Errorf("requiredArgs names %q, which is not a declared tool", name)
		}
	}
}

// No tool may pick a cloud for the caller.
func TestNoToolDefaultsToACloud(t *testing.T) {
	root := repoRootFromMCP(t)
	raw, err := os.ReadFile(filepath.Join(root, "go", "internal", "mcp", "mcp.go"))
	if err != nil {
		t.Skipf("source not readable here: %v", err)
	}
	src := string(raw)
	for _, cloud := range []string{"gcp", "aws", "azure", "k8s", "fake"} {
		needle := `str(a, "provider", "` + cloud + `")`
		if strings.Contains(src, needle) {
			t.Errorf("the MCP server defaults provider to %q (%s).\n"+
				"F4: a provider is chosen deliberately, never defaulted — the fake "+
				"driver fabricates reality and the real ones spend money.", cloud, needle)
		}
	}
	// Positive control: the detector must match the shape it looks for (D603).
	if !strings.Contains(`str(a, "provider", "gcp")`, `str(a, "provider", "`) {
		t.Fatal("the detector cannot match its own example — it is not running")
	}
}

// The published page and the package doc must agree about what the token proves.
func TestPublishedTokenClaimMatchesTheCode(t *testing.T) {
	root := repoRootFromMCP(t)
	page, err := os.ReadFile(filepath.Join(root, "website", "pages", "mcp.md"))
	if err != nil {
		t.Skipf("no published page here: %v", err)
	}
	text := string(page)
	if strings.Contains(text, "token proves a human") {
		t.Error("website/pages/mcp.md claims the confirmation token proves a human " +
			"saw the decision. The package doc says it does NOT authenticate a human — " +
			"it is delivered in-band to the same client, so an agent completes both " +
			"steps alone. A compliance reader must not be able to reach the stronger " +
			"claim from the docs.")
	}
	if !strings.Contains(text, "does **not** authenticate a human") {
		t.Error("the page no longer states the limit the code states — say it where " +
			"the reader is, not only in a source comment")
	}
}

func repoRootFromMCP(t *testing.T) string {
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

var _ = json.Marshal

// D704: every tool schema that takes a provider publishes the SAME set, and it is the
// set the runtime accepts.
//
// `groundhold_observe` named all five drivers; `groundhold_apply`, twenty lines below
// it in the same file, said "fake|gcp" — so an agent reading the schema for the verb
// that MUTATES believed AWS, Azure and Kubernetes were out of reach. Two copies of one
// closed set, one of them three drivers out of date, on the surface where the reader
// is a machine that cannot ask.
func TestEveryProviderSchemaPublishesTheSameDrivers(t *testing.T) {
	defs := (&Server{allowApply: true}).toolDefs()
	seen := 0
	for _, d := range defs {
		name, _ := d["name"].(string)
		sch, _ := d["inputSchema"].(map[string]any)
		props, _ := sch["properties"].(map[string]any)
		p, ok := props["provider"].(map[string]any)
		if !ok {
			continue
		}
		seen++
		desc, _ := p["description"].(string)
		for _, drv := range []string{"fake", "aws", "gcp", "azure", "k8s"} {
			if !strings.Contains(desc, drv) {
				t.Errorf("%s: the provider schema does not name %q — an agent reads this "+
					"as the closed set of drivers the verb accepts", name, drv)
			}
		}
	}
	if seen < 2 {
		t.Fatalf("only %d tool schema(s) take a provider — the scan broke and this gate "+
			"would pass over a stale one (D328)", seen)
	}
}

// D704: the status the server reports is the verb's own answer, never a guess from the
// exit code — and never the empty string.
func TestExecStatusPrefersTheVerbsOwnAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		code   int
		parsed any
		want   string
	}{
		{"a verb with its own status wins", 0,
			map[string]any{"status": "applied"}, "applied"},
		{"probe that measured nothing keeps its word", 2,
			map[string]any{"status": "unmeasured"}, "unmeasured"},
		{"verify not proven is a verdict, not a refusal", 2,
			map[string]any{"executable": false}, "not-proven"},
		{"verify proven", 0, map[string]any{"executable": true}, "proven"},
		{"a refusal with only a code", 2,
			map[string]any{"code": "consent-required"}, "refused"},
		{"no JSON at all falls back to the exit code", 3, nil, "stale-or-conflict"},
		{"an unrecognised exit code is never empty", 42, nil, "unrecognized-exit-42"},
	} {
		if got := execStatus(tc.code, tc.parsed); got != tc.want {
			t.Errorf("%s: execStatus(%d) = %q, want %q", tc.name, tc.code, got, tc.want)
		}
	}
}

// D705: every refusal this SERVER originates carries a machine code.
//
// `website/pages/mcp.md` promises "refusals pass through structurally, never
// summarized", and the project's machine contract is "route on the process exit code
// and the JSON `code` field, never on banner text". Both hold for refusals FORWARDED
// from the CLI — the verb's own result carries its code. Neither held for the five the
// server raises itself: apply disabled, unknown token, expired token, plan changed,
// target changed. An agent deciding between "ask for a fresh confirmation", "show the
// changed plan to a human" and "this server does not offer apply at all" had nothing
// but English prose to route on, on the one surface whose reader is a machine.
//
// The scan is over the source rather than a live run because two of the five need a
// server state a unit test cannot reach cheaply; the shape is uniform and small.
func TestEveryServerRefusalCarriesAMachineCode(t *testing.T) {
	root := repoRootFromMCP(t)
	raw, err := os.ReadFile(filepath.Join(root, "go", "internal", "mcp", "mcp.go"))
	if err != nil {
		t.Skipf("source not readable here: %v", err)
	}
	src := string(raw)

	const marker = `"status": "refused"`
	found, bare := 0, 0
	for i := 0; ; {
		j := strings.Index(src[i:], marker)
		if j < 0 {
			break
		}
		at := i + j
		found++
		// The composite literal continues to its closing brace; a code must appear
		// before the next `return` or the literal's end, whichever comes first.
		end := at + 400
		if end > len(src) {
			end = len(src)
		}
		window := src[at:end]
		if k := strings.Index(window, "\n\t\treturn "); k > 0 {
			window = window[:k]
		}
		if !strings.Contains(window, `"code":`) {
			bare++
			t.Errorf("a server-originated refusal near offset %d carries no `code` — an "+
				"agent can only route on its prose:\n%s", at, strings.TrimSpace(window))
		}
		i = at + len(marker)
	}
	if found < 4 {
		t.Fatalf("found %d server-originated refusals — the scan broke and this gate "+
			"would pass over a bare one (D328)", found)
	}
	// Positive control: the detector must be able to see a bare refusal.
	if strings.Contains(`{"status": "refused", "reasons": []string{"x"}}`, `"code":`) {
		t.Fatal("the detector matches a literal with no code — it is not running")
	}
	_ = bare
}

// D706: one failure vocabulary, and one payload shape.
//
// The server had twelve `status: "error"` sites covering three different things — a
// missing required argument, a path that escapes the workspace, an unknown tool, an
// empty draft, and two genuine local I/O failures — under a word that appears in no
// published set, half of them carrying `error: "<string>"` and half `reasons: [...]`.
// An agent cannot route on that, and D705's gate could not see any of it, because the
// gate looks for refusals and none of these called itself one.
//
// Refusals say `refused` and carry a code (D705 then holds them). The two things that
// are NOT refusals — the server could not write a draft, could not read entropy for a
// token — say `failed`, and carry no code deliberately: no registry code describes the
// tool's own environment failing, and inventing one to satisfy a gate would be the
// worse mistake.
func TestTheServerSpeaksOneFailureVocabulary(t *testing.T) {
	root := repoRootFromMCP(t)
	raw, err := os.ReadFile(filepath.Join(root, "go", "internal", "mcp", "mcp.go"))
	if err != nil {
		t.Skipf("source not readable here: %v", err)
	}
	src := string(raw)

	if n := strings.Count(src, `"status": "error"`); n > 0 {
		t.Errorf("%d site(s) still answer `status: \"error\"` — a word in no published "+
			"set, covering refusals and I/O failures alike", n)
	}
	// One payload shape: `reasons` is a list; `error` as a bare string is gone.
	if n := strings.Count(src, `"error":`); n > 0 {
		t.Errorf("%d site(s) still carry a bare `error` string — the surface says "+
			"`reasons: [...]` everywhere else, and two shapes for one thing is two "+
			"things to a machine reader", n)
	}
	// Non-vacuity: the vocabulary this gate describes must actually be in use.
	if strings.Count(src, `"status": "refused"`) < 4 {
		t.Fatal("fewer than four refusals in the server — the scan broke and this gate " +
			"would pass over a reintroduced `error` (D328)")
	}
	if !strings.Contains(src, `"status": "failed"`) {
		t.Error("no `failed` status remains — the two genuine I/O failures were folded " +
			"into refusals, which claims the server declined when it could not proceed")
	}
}
