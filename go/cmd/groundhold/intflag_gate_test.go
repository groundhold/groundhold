package main

import (
	"os"
	"path/filepath"
	"testing"
)

// D657. Four numeric flags were read with `_, _ = fmt.Sscanf(args[i+1], "%d", &x)`,
// discarding both return values. Measured:
//
//	observe … --ttl 1e9 --record   exit 0   ttlSeconds recorded = 1
//	observe … --ttl abc --record   exit 0   flag ignored (defaults used)
//	refresh … --window 1e9         exit 0   refreshed=[]  fresh=[assets,db]
//
// `--ttl 1e9 → 1` bakes a one-second freshness window into an append-only ledger,
// so every later audit blocks on evidence nobody could have kept fresh. `--window
// 1e9 → 1` is the same slip in the other direction: the unattended freshness agent
// reports success while doing nothing.
func TestUnreadableNumericFlagsAreRefused(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "l.jsonl")
	if err := os.WriteFile(ledgerPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(contract, []byte(`apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: p, owner: o@e.test, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
`), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ flag, value string }{
		{"--ttl", "1e9"}, {"--ttl", "abc"}, {"--ttl", "-5"},
		{"--ttl", "500x"}, {"--ttl", "99999999999999999999"},
		{"--window", "1e9"}, {"--budget", "abc"}, {"--since", "1e9"},
	} {
		t.Run(tc.flag+"="+tc.value, func(t *testing.T) {
			var code int
			captureStdout(t, func() {
				code = run([]string{"observe", contract, "--ledger", ledgerPath,
					"--provider", "fake", "--at", "2026-07-15T09:00:00Z",
					tc.flag, tc.value})
			})
			if code == 0 {
				t.Errorf("%s %s was accepted: a value the operator typed and the "+
					"tool could not read was silently replaced by a prefix of it or "+
					"by a default", tc.flag, tc.value)
			}
		})
	}

	// The control: a real number must still work, or every scheduled run breaks.
	t.Run("a whole number is accepted", func(t *testing.T) {
		var code int
		captureStdout(t, func() {
			code = run([]string{"observe", contract, "--ledger", ledgerPath,
				"--provider", "fake", "--at", "2026-07-15T09:00:00Z", "--ttl", "3600"})
		})
		if code != 0 {
			t.Errorf("--ttl 3600 was refused (exit %d)", code)
		}
	})
}
