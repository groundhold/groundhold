package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D615. `posture --crawl` decoded whatever JSON it was handed into `crawl.Document`.
// Every field there is optional to the decoder, so a `discover` output decoded CLEANLY
// into an empty crawl — no providers, no scopes — and posture reported
//
//	"shadow": 0, "shadowLowerBound": false      exit 0, banner OK
//
// over an estate it had never swept. `shadowLowerBound:false` is not silence: it is an
// affirmative claim that the sweep was complete.
//
// D567 closed exactly this trap on `--discovery`, in a message that names the reason
// (a crawl records per-scope completeness and `discover` does not) — and left it open
// on the flag next to it. That is worse than never having closed it: a refusal on one
// flag reads as diligence covering both. Posture's own shadow remediation tells the
// operator to run `discover`, so the wrong file is the one they are holding.
func TestPostureRefusesASweepItDidNotGet(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	ledger := write("l.jsonl", "")
	contract := write("c.yaml", `apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: p1, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - { id: c1, subject: db, path: service.managed, op: equals, value: true,
        verify: { method: static } }
`)
	discovery := write("disc.json", `{"apiVersion":"discovery/v0",
	  "kind":"DiscoveryDocument","at":"2026-02-01T00:00:00Z","provider":"fake",
	  "resources":[{"providerId":"fake:existing-db","resourceType":"db"}]}`)
	emptyCrawl := write("empty.json",
		`{"at":"2026-02-01T00:00:00Z","providers":[],"crawl":{},"contextHash":"sha256:x"}`)

	for _, tc := range []struct{ name, path, want string }{
		{"a discovery document", discovery, "DISCOVERY document"},
		{"a crawl that swept nothing", emptyCrawl, "names no providers"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stderr := captureStderr(t, func() {
				if code := run([]string{"posture", "--ledger", ledger,
					"--at", "2026-02-01T00:00:00Z", "--crawl", tc.path,
					"--contract", contract}); code == 0 {
					t.Errorf("posture accepted %s and reported a posture at exit 0 — "+
						"a shadow count over a sweep that did not happen is a claim "+
						"the tool has not earned", tc.name)
				}
			})
			if !strings.Contains(stderr, tc.want) {
				t.Errorf("the refusal does not say what is wrong with the file "+
					"(want %q):\n%s", tc.want, stderr)
			}
		})
	}
}
