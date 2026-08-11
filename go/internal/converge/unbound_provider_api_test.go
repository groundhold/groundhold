package converge

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/ledger"
)

// D566. D290 wrote it down as "the natural mistake a first-time author makes with a
// four-valued verifier": hard constraints authored with `verify: {method:
// provider-api}` block the very first plan, because no observation can exist before
// the resource does. The system is right to block. What it says is
//
//	requires provider-api verification; not evaluable from the candidate alone
//
// and that one sentence covers two states whose remedies are OPPOSITE:
//
//	bound, not yet observed  -> run `observe --record`, and it will resolve
//	not created yet          -> observing will NEVER resolve it; the contract is
//	                            wrong for create time (state it static and let the
//	                            convergence check supply the measured half)
//
// An author who takes the natural reading runs `observe`, gets nothing, and is in the
// loop D290 describes. `verify` cannot tell the two apart — it is a pure function of
// the two documents, which is why it is dual-implemented and conformance-pinned, and
// changing its inputs to fix a message would be the wrong trade. `converge` HAS the
// ledger, is the verb an author actually runs, and says nothing.
//
// Reproduced against a live k3d cluster with a cert-manager Certificate contract
// written exactly the way D290 predicts a newcomer writes one.
func TestConvergeSaysWhyAnUnboundProviderAPIConstraintCannotResolve(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		if args[0] == "verify" {
			return 2, `{"executable":false,` +
				`"blockingReasons":["hard constraint not proven: c-domain (unknown)"],` +
				`"verdicts":[{"constraint":"c-domain","severity":"hard","verdict":"unknown",` +
				`"subject":"web","verifyMethod":"provider-api"}]}`, ""
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", Vocab: "v", Ledger: "l.ndjson",
		Provider: "k8s", At: "2026-01-01T00:00:00Z", Run: run, Out: &out, Yes: true}
	if exit := Converge(o); exit != 2 {
		t.Fatalf("a blocked verify must exit 2, got %d", exit)
	}
	got := out.String()
	if !strings.Contains(got, "no observation can exist before the resource does") {
		t.Errorf("converge blocked on a provider-api constraint over an UNBOUND capability "+
			"and did not say that observing can never resolve it.\noutput:\n%s\n"+
			"The author's next move is to run `observe`, which is the loop D290 "+
			"describes as the natural first-author mistake.", got)
	}
	if !strings.Contains(got, "web") {
		t.Errorf("the hint does not name the capability: %s", got)
	}
}

// A BOUND capability must not get that hint: there the remedy really is to observe,
// and telling an author their contract is wrong when it is merely unobserved sends
// them to rewrite a correct document.
func TestConvergeDoesNotBlameTheContractWhenTheCapabilityIsBound(t *testing.T) {
	run := func(args ...string) (int, string, string) {
		if args[0] == "verify" {
			return 2, `{"executable":false,` +
				`"blockingReasons":["hard constraint not proven: c-domain (unknown)"],` +
				`"verdicts":[{"constraint":"c-domain","severity":"hard","verdict":"unknown",` +
				`"subject":"web","verifyMethod":"provider-api"}]}`, ""
		}
		return 0, "", ""
	}
	var out bytes.Buffer
	o := Options{Contract: "c", Candidate: "k", Vocab: "v", Ledger: "l.ndjson",
		Provider: "k8s", At: "2026-01-01T00:00:00Z", Run: run, Out: &out, Yes: true}
	o.Ledger = boundLedger(t, "web", "cert-manager.io/v1/Certificate/default/web-cert")
	Converge(o)
	if strings.Contains(out.String(), "no observation can exist before the resource does") {
		t.Errorf("a BOUND capability was told its contract is wrong for create time:\n%s",
			out.String())
	}
}

// boundLedger writes a real ledger carrying one binding — converge must read the
// same file it reads in production, not a test-only flag.
func boundLedger(t *testing.T, capID, providerID string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.ndjson")
	w := &ledger.Writer{Path: path, Led: ledger.New(), Env: "prod",
		Clock: 1600000000, Actor: "t"}
	if err := w.Append("contract.published", []string{capID},
		map[string]any{"contract": "certs", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w2 := &ledger.Writer{Path: path, Led: led, Env: "prod", Clock: 1600000001, Actor: "t"}
	tok, err := w2.AppendLease([]string{capID}, map[string]any{"ttlSeconds": 300})
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if err := w2.Append("binding.updated", []string{capID}, map[string]any{
		"capability": capID, "environment": "prod",
		"provider":  map[string]any{"name": "k8s"},
		"resources": []any{map[string]any{"id": "primary", "providerId": providerID}},
	}, tok); err != nil {
		t.Fatalf("binding.updated rejected: %v", err)
	}
	if err := w2.Append("lease.released", []string{capID}, nil, tok); err != nil {
		t.Fatalf("release: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	return path
}
