package provider_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
)

// D461: the verb-coverage gate. See internal/certifynet/verbs.go for the argument —
// three ownership registers exist because I thought of three verbs, and the third one
// found two defects on a surface nobody had asked about. This gate makes the next such
// surface announce itself instead of waiting to be thought of.
//
// Every method any provider interface declares must be in exactly one of the three maps
// below. A method in none of them fails, and the failure names what it is asking for: is
// this verb capable of writing to a resource, and if so, which register asks whether it
// writes to the right one?

// mutatingVerbs: a driver implementing this can WRITE to a resource, so a foreign-
// refusal register must ask whether it writes to one that is ours. The value names where
// that register lives, or states plainly that none exists yet.
var mutatingVerbs = map[string]string{
	"Create": "internal/{aws,gcp,azure}/adoptexisting_gate_test.go + internal/k8s/foreign_gate_test.go (D391-D438, D462)",
	"Update": "internal/{aws,gcp,azure}/updateforeign_gate_test.go + internal/k8s/foreign_gate_test.go (D459-D462)",
	"Delete": "internal/{aws,gcp,azure}/deleteforeign_gate_test.go + internal/k8s/foreign_gate_test.go (D439-D458, D462)",

	// Probe writes only under allowIntrusive, where it creates and destroys a BILLED
	// scratch resource. All four probers gate on ownership before spending, each with
	// the reasoning written out (aws gateIntrusive, gcp/azure the capability-label
	// match); the class has never been asserted as a class.
	"Probe": "internal/{aws,gcp,azure}/intrusiveprobe_gate_test.go (D461)",

	// Claim is the most consequential write in the system and the one whose register
	// must ask a DIFFERENT question. Claim exists to stamp our ownership marker on a
	// resource we did NOT create (D52/D140/D145), so "is it ours?" is answered no by
	// construction — refusing on that would refuse the verb's whole purpose. The
	// question that does apply is claimLambda's: is this the resource the binding
	// NAMES? Its comment says why — "never tag a foreign function the acting account
	// happens to hold under the same name" — and most of the other claim paths build
	// the ARN from the providerId and stamp without reading. Whether that is a gap or
	// the intended reliance on adoption's own proof is a design question D461 records
	// rather than settles: after a claim lands, every ownership check in the system
	// says "ours", so this is the one write that makes its own mistakes invisible.
	"Claim": "UNREGISTERED (D461) — needs a different question; see the note here",

	// Reconcile concludes an ambiguous outcome from a receipt. It does not write.
	// Listed as mutating because it decides whether a write LANDED, and a wrong
	// conclusion is as damaging as a wrong write — but it is the executor's own
	// machinery, gated by the ledger/receipt suites rather than by an estate probe.
	"Reconcile": "internal/apply + ledger suites (D42/D57) — receipt-driven, not estate-driven",
}

// readOnlyVerbs: cannot write to a resource, so a foreign-refusal register does not
// apply. They still carry their own correctness gates; this map is only about writes.
var readOnlyVerbs = map[string]string{
	"Name":                     "identity",
	"Validate":                 "refuse-before-mutate preflight (D43) — pure",
	"Observe":                  "read + reverse-map (D44)",
	"ClassifyChange":           "pure provider knowledge (D46)",
	"OutputsFor":               "declaration (D275-D284)",
	"ConsumedOperands":         "declaration",
	"OperandTargets":           "declaration",
	"CheckPermissions":         "read (D75)",
	"CheckResourcePermissions": "read (D75)",
	"List":                     "discovery read (D52)",
	"Enumerate":                "scope read (D141)",
	"CompetingManagers":        "read",
	"SetProgress":              "projection only (D257) — changes no mutation semantics",
	"SetFieldReclaim": "consent carrier (D699) — sets driver state from the SEALED plan; " +
		"writes nothing itself, and what it permits is checked at the write it gates",
	"LROTimeout": "policy value",
}

// unregisteredBaseline is the RATCHET. A classification map that accepts "UNREGISTERED"
// freely is not a debt register, it is a place to write excuses (D328) — so the count is
// pinned and may only go down.
const unregisteredBaseline = 1 // Claim

func TestUnregisteredMutatingVerbsRatchet(t *testing.T) {
	var open []string
	for verb, where := range mutatingVerbs {
		if strings.HasPrefix(where, "UNREGISTERED") {
			open = append(open, verb)
		}
	}
	sort.Strings(open)
	if n := len(open); n > unregisteredBaseline {
		t.Errorf("mutating verbs with no foreign-refusal register rose to %d %v "+
			"(baseline %d) — a write nobody asks the ownership question of may only be "+
			"paid down, never grown", n, open, unregisteredBaseline)
	} else if n < unregisteredBaseline {
		t.Errorf("unregistered is down to %d %v — lower unregisteredBaseline to %d "+
			"(this failure is the good kind)", n, open, n)
	}
	if len(mutatingVerbs) == 0 {
		t.Fatal("no mutating verbs declared — the gate would be vacuous (D328)")
	}
}

func TestEveryProviderVerbIsClassified(t *testing.T) {
	raw, err := os.ReadFile("provider.go")
	if err != nil {
		t.Fatal(err)
	}
	methods := certifynet.ProviderMethods(string(raw))
	if len(methods) == 0 {
		t.Fatal("no interface methods found — the gate would be vacuous (D328)")
	}

	var unclassified, both []string
	for _, m := range methods {
		_, mut := mutatingVerbs[m]
		_, ro := readOnlyVerbs[m]
		switch {
		case !mut && !ro:
			unclassified = append(unclassified, m)
		case mut && ro:
			both = append(both, m)
		}
	}
	sort.Strings(unclassified)
	sort.Strings(both)

	if len(unclassified) > 0 {
		t.Errorf("provider verbs with NO write classification: %v\n"+
			"Every method a driver can implement must be declared mutating (and named "+
			"the register that asks whether it writes to a resource that is OURS) or "+
			"read-only. The update register was missed for exactly as long as nothing "+
			"here said it was missing (D461).", unclassified)
	}
	if len(both) > 0 {
		t.Errorf("verbs classified as both mutating and read-only: %v", both)
	}

	// Stale entries matter as much: a verb that left the interface but stayed in a map
	// makes the register look broader than it is.
	live := map[string]bool{}
	for _, m := range methods {
		live[m] = true
	}
	var stale []string
	for k := range mutatingVerbs {
		if !live[k] {
			stale = append(stale, k)
		}
	}
	for k := range readOnlyVerbs {
		if !live[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("classified verbs no provider interface declares: %v — a register that "+
			"names a verb nobody implements reads as coverage it does not have", stale)
	}
}

// proberDecisions: every driver package implementing Prober, and where the intrusive
// path is asserted. Membership is derived from the source (below) rather than declared,
// so a new driver that implements Probe lands undecided.
var proberDecisions = map[string]string{
	"aws":   "TestRefusesIntrusiveProbeForeign{RDS,Aurora}",
	"gcp":   "TestRefusesIntrusiveProbeForeignCloudSQL",
	"azure": "TestRefusesIntrusiveProbeForeignFlexServer",
	// The k8s prober takes allowIntrusive and never reads it: its only measurement is a
	// TCP dial against an annotated target. No write, no spend, nothing to own — the
	// register's question does not arise. Re-derived below rather than asserted.
	"k8s": "no-intrusive-path",
}

func TestEveryProberHasAnIntrusiveDecision(t *testing.T) {
	dirs, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, e := range dirs {
		if !e.IsDir() {
			continue
		}
		files, err := os.ReadDir("../" + e.Name())
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
				continue
			}
			raw, err := os.ReadFile("../" + e.Name() + "/" + f.Name())
			if err != nil {
				continue
			}
			if strings.Contains(string(raw), "func (d *Driver) Probe(service, capability, providerID string,") ||
				strings.Contains(string(raw), "func (d *Driver) Probe(service, capability, providerID string, allowIntrusive bool)") {
				found[e.Name()] = true
			}
		}
	}
	if len(found) == 0 {
		t.Fatal("no Prober implementations found — the gate would be vacuous (D328)")
	}
	var undecided []string
	for pkg := range found {
		if _, ok := proberDecisions[pkg]; !ok {
			undecided = append(undecided, pkg)
		}
	}
	sort.Strings(undecided)
	if len(undecided) > 0 {
		t.Errorf("driver packages implementing Prober with no intrusive-probe decision: "+
			"%v — an intrusive probe bills a restore against the estate it targets, so "+
			"each one owes an answer to whether it checks whose estate that is.", undecided)
	}
	var stale []string
	for pkg := range proberDecisions {
		if !found[pkg] {
			stale = append(stale, pkg)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("proberDecisions names packages that do not implement Prober: %v", stale)
	}

	// Re-derive the one exemption instead of trusting it (D404).
	if proberDecisions["k8s"] == "no-intrusive-path" {
		raw, err := os.ReadFile("../k8s/netpol.go")
		if err != nil {
			t.Fatal(err)
		}
		body := string(raw)
		i := strings.Index(body, "func (d *Driver) Probe(")
		if i < 0 {
			t.Fatal("k8s Probe not found")
		}
		body = body[i:]
		if j := strings.Index(body, "\n}\n"); j > 0 {
			body = body[:j]
		}
		if strings.Count(body, "allowIntrusive") != 1 {
			t.Errorf("k8s claims no-intrusive-path, but its Probe now USES allowIntrusive " +
				"beyond the parameter it ignores — the exemption must be re-examined")
		}
	}
}
