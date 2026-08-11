package converge

import (
	"bytes"
	"sort"
	"strings"
	"testing"
)

// D612. converge executes plan, observe, forecast and apply as child PROCESSES.
// `--trust`, `--trust-from` and `--sign-key` are armed in the parent process and were
// never placed on the children's argv, so both halves of the security policy stopped
// at the porcelain boundary. Measured, on the same ledger and the same flag:
//
//	plan     --trust <foreign key>  exit 5   event signed by a FOREIGN key
//	export   --trust <foreign key>  exit 5
//	audit    --trust <foreign key>  exit 5
//	converge --trust <foreign key>  exit 0   ✓ converged  CONVERGED
//
// converge is the verb the README's walkthrough puts in front of operators, and under
// an armed trust policy it read AND WROTE a ledger the other three refused.
//
// The signing direction is worse, because it is not recoverable. A fully signed
// 13-event ledger, then one `converge --sign-key`:
//
//	before  attest: selfVerified 10, unsigned 12   export --trust exit 5 (forever)
//	after   attest: selfVerified 22, unsigned  0   export --trust exit 0
//
// The child observe wrote unsigned `observation.recorded` events into the middle of a
// signed history. History is append-only, so `export`, `backup`, `capsule` and `audit`
// under `--trust` refuse that ledger permanently — the operator armed signing and
// destroyed their own ability to verify.
//
// This gate reads the argv of every child, so a new child added later is covered by
// the same rule rather than by whoever remembers it.
func TestEveryLedgerChildCarriesTheRunPolicy(t *testing.T) {
	var calls [][]string
	run := func(args ...string) (int, string, string) {
		calls = append(calls, args)
		switch {
		case args[0] == "verify":
			return 0, `{"verdicts":[]}`, ""
		case args[0] == "plan":
			return 0, `{"plan":{"actions":[{"operation":"create","id":"a1"}]}}`, ""
		case args[0] == "forecast":
			return 0, `{"effects":[]}`, ""
		case args[0] == "apply":
			return 0, `{"status":"applied","outcomes":[]}`, ""
		}
		return 0, "", ""
	}

	var out bytes.Buffer
	Converge(Options{
		Contract: "c.yaml", Candidate: "k.yaml", Ledger: "l.jsonl",
		Provider: "fake", At: "2026-01-01T00:00:00Z",
		Yes: true, Run: run, Out: &out,
		Trust: []string{"aa11", "bb22"}, TrustFrom: "sha256:abc", SignKey: "k.key",
		Kubeconfig: "/tmp/other.kubeconfig", KubeContext: "other-cluster",
		Region: "eu-central-1", Bindings: "b.json", Observations: "o.json",
		TTL: "900", Budget: "50", RequirePreflight: true,
		FailKey: "k-fail", UnknownKey: "k-unknown", RetryableKey: "k-retry",
	})

	if len(calls) == 0 {
		t.Fatal("converge ran no children — the gate would be vacuous (D328)")
	}

	var offenders []string
	seen := map[string]bool{}
	for _, argv := range calls {
		line := strings.Join(argv, " ")
		// Only children that touch the LEDGER carry the policy; `verify` is a pure
		// document check and takes neither flag.
		if !strings.Contains(line, "--ledger") {
			continue
		}
		seen[argv[0]] = true
		for _, want := range []string{
			"--trust aa11", "--trust bb22", "--trust-from sha256:abc", "--sign-key k.key",
			// D638: the CLUSTER SELECTOR travels too. Without it, `converge
			// --kubeconfig <other> --context <other>` created objects on the DEFAULT
			// cluster — measured on a live k3d cluster: a Role appeared, carrying
			// groundhold's ownership labels, while the operator had named an
			// unreachable endpoint. Every other verb refuses an unknown context.
			"--kubeconfig /tmp/other.kubeconfig", "--context other-cluster",
			// D638, second pass: the flag-forwarding gate forced a decision on every
			// global flag and found nine more that change what a child sees or does
			// and were not travelling. The injection keys are why converge's own
			// partial-apply behaviour (D379, D387, D241) could not be exercised from
			// the command line at all — the surface a production incident lived on.
			"--region eu-central-1", "--bindings b.json", "--observations o.json",
			"--ttl 900", "--require-preflight",
			"--fail-key k-fail", "--unknown-key k-unknown", "--retryable-key k-retry",
		} {
			if !strings.Contains(line, want) {
				offenders = append(offenders, argv[0]+" is missing "+want)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no ledger-touching child was observed — either the flow changed or " +
			"the scan broke; both must fail loudly (D565)")
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("children run without the run's security policy:\n  %s\n"+
			"A child that does not carry --trust enforces nothing; one that does not "+
			"carry --sign-key writes UNSIGNED events into a signed history, which "+
			"append-only makes permanent.", strings.Join(offenders, "\n  "))
	}
}

// The other direction: with no policy armed, no child may invent one — an empty
// --trust would arm verification the operator did not ask for.
func TestNoPolicyMeansNoPolicyFlags(t *testing.T) {
	var calls [][]string
	run := func(args ...string) (int, string, string) {
		calls = append(calls, args)
		if args[0] == "verify" {
			return 0, `{"verdicts":[]}`, ""
		}
		if args[0] == "plan" {
			return 2, `{"code":"nothing-to-change"}`, ""
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	Converge(Options{Contract: "c.yaml", Candidate: "k.yaml", Ledger: "l.jsonl",
		Provider: "fake", At: "2026-01-01T00:00:00Z", Yes: true, Run: run, Out: &out})
	for _, argv := range calls {
		line := strings.Join(argv, " ")
		for _, forbidden := range []string{"--trust", "--sign-key",
			"--kubeconfig", "--context"} {
			if strings.Contains(line, forbidden) {
				t.Errorf("child %q carries %s with nothing armed: %s",
					argv[0], forbidden, line)
			}
		}
	}
}
