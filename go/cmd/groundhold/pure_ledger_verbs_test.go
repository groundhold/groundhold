package main

import (
	"path/filepath"
	"testing"

	"groundhold/internal/ledger"
)

// D571. `providerVerbs` defines itself in its own comment: "the CLOSED set of verbs
// that OBSERVE or MUTATE real infrastructure through a provider driver". Two members
// do neither.
//
//	runAnchor(ledgerPath, checkPath)                         — no provider parameter
//	runRepair(ledgerPath, quarantine, fingerprint, explain)  — no provider parameter
//
// Neither body mentions a driver. Both demand `--provider` anyway, and both are
// DISASTER-RECOVERY verbs — the ones an operator reaches for with a damaged ledger,
// possibly not knowing or caring which cloud it describes. Found while checking that
// a restored ledger still verifies: `groundhold anchor --ledger <restored>` refused
// for want of a flag it cannot use.
//
// It fails CLOSED, so nothing unsafe happened. The cost is a lie about what the verb
// does: passing `--provider k8s` to an integrity check tells the reader the check
// contacts the cluster. It does not. This is D567's mirror — there a flag that meant
// nothing was accepted, here a flag that means nothing is required.
func TestPureLedgerVerbsNeedNoProvider(t *testing.T) {
	dir := t.TempDir()
	ledgerPath := filepath.Join(dir, "ledger.ndjson")
	w := &ledger.Writer{Path: ledgerPath, Led: ledger.New(), Env: "dev",
		Clock: 1752600000, Actor: "t"}
	if err := w.Append("contract.published", []string{"store"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	for _, verb := range []string{"anchor", "repair"} {
		if providerVerbs[verb] {
			t.Errorf("%q is in providerVerbs, whose comment says the set is verbs that "+
				"OBSERVE or MUTATE real infrastructure — its handler takes no provider "+
				"and its body names none. Requiring --provider on a recovery verb "+
				"claims it contacts a cloud it never touches.", verb)
		}
		if code := run([]string{verb, "--ledger", ledgerPath}); code != 0 {
			t.Errorf("%s on a healthy ledger, with no --provider, exited %d", verb, code)
		}
	}
}

// The set must keep every verb that DOES reach a driver: dropping one there is the
// fail-open regression its comment warns about (fake would become a silent default).
func TestRealProviderVerbsStayGated(t *testing.T) {
	for _, verb := range []string{"discover", "apply", "adopt", "observe", "converge",
		"probe", "resume", "react", "refresh", "crawl", "preflight"} {
		if !providerVerbs[verb] {
			t.Errorf("%q left providerVerbs — it reaches a driver, so without the gate "+
				"the FAKE provider becomes a silent default (F4)", verb)
		}
	}
}
