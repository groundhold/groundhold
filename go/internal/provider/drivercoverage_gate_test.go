package provider_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/cloudflare"
	"groundhold/internal/hetzner"
	"groundhold/internal/provider"
	"groundhold/internal/upstash"
)

// D463: D461 asked which VERBS nobody had questioned. D462 found the answer to the
// question it did not ask — which DRIVERS — by noticing the k8s driver was in none of
// the eleven registers and that its create had never pre-read ownership.
//
// That was luck. Every ownership gate in the sweep names the packages it covers, and
// nothing anywhere enumerated the packages that EXIST. So this gate does: every package
// implementing the Provider write verbs must carry a decision, and a package that
// implements them and appears in no register lands here undecided.

// driverDecisions: one entry per package implementing Create/Update/Delete. The value
// either names the registers that ask the ownership question of it, or claims an
// exemption this gate re-derives.
var driverDecisions = map[string]string{
	"aws":   "adoptexisting + updateforeign + deleteforeign + intrusiveprobe gates",
	"gcp":   "adoptexisting + updateforeign + deleteforeign + intrusiveprobe gates",
	"azure": "adoptexisting + updateforeign + deleteforeign + intrusiveprobe gates",
	"k8s":   "foreign_gate_test.go (D462) — one mapped write path, all three verbs",

	// Read-only drivers: every write verb is a categorical refusal, so there is no
	// mutation to aim at the wrong resource. Driven below, never taken on trust — the
	// day one of these is wired, the exemption fails and the driver owes a register.
	"cloudflare": "write-verbs-not-implemented",
	"hetzner":    "write-verbs-not-implemented",
	"upstash":    "write-verbs-not-implemented",
}

func TestEveryDriverPackageHasAnOwnershipDecision(t *testing.T) {
	entries, err := os.ReadDir("..")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		files, err := os.ReadDir("../" + e.Name())
		if err != nil {
			continue
		}
		// Aggregate PER PACKAGE, not per file: gcp declares Create in driver.go and
		// Delete in update.go, and a per-file check silently missed the largest driver
		// in the repo — a gate that under-counts what it is guarding is the D328 shape
		// wearing a different hat.
		var hasCreate, hasDelete bool
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".go") || strings.HasSuffix(f.Name(), "_test.go") {
				continue
			}
			raw, err := os.ReadFile("../" + e.Name() + "/" + f.Name())
			if err != nil {
				continue
			}
			// Matched on receiver+name+leading args, so a signature difference
			// (aws/azure fold the key into the arg list) cannot hide one.
			src := string(raw)
			if strings.Contains(src, "func (d *Driver) Create(service, capability, environment string,") {
				hasCreate = true
			}
			if strings.Contains(src, "func (d *Driver) Delete(service, capability, environment, providerID") {
				hasDelete = true
			}
		}
		if hasCreate && hasDelete {
			found[e.Name()] = true
		}
	}
	if len(found) == 0 {
		t.Fatal("no driver packages found — the gate would be vacuous (D328)")
	}
	// A detector that finds SOME drivers is not enough: it found six of seven on the
	// first run, and the one it missed was the biggest. Assert the floor explicitly so
	// a future signature change cannot quietly shrink what this gate covers.
	for _, must := range []string{"aws", "gcp", "azure", "k8s"} {
		if !found[must] {
			t.Errorf("the driver detector did not find %q — it is under-counting what "+
				"it guards, which is the D328 shape wearing a different hat", must)
		}
	}

	var undecided []string
	for pkg := range found {
		if _, ok := driverDecisions[pkg]; !ok {
			undecided = append(undecided, pkg)
		}
	}
	sort.Strings(undecided)
	if len(undecided) > 0 {
		t.Errorf("driver packages implementing the write verbs with NO ownership "+
			"decision: %v\nEvery register in this repo names the packages it covers and "+
			"none of them names the packages that exist. A driver that mutates owes an "+
			"answer to whether it mutates the right resource (D462: the k8s create "+
			"stamped our labels onto a stranger's object and every downstream check then "+
			"agreed it was ours).", undecided)
	}

	var stale []string
	for pkg := range driverDecisions {
		if !found[pkg] {
			stale = append(stale, pkg)
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("driverDecisions names packages that do not implement the write verbs: "+
			"%v — coverage claimed for a driver that is not there", stale)
	}
}

// TestReadOnlyDriverExemptionsAreBacked re-derives the exemption by DRIVING each write
// verb (the D404 rule). A refusal that reads "not implemented" is only worth something
// if the driver actually produces it.
func TestReadOnlyDriverExemptionsAreBacked(t *testing.T) {
	readOnly := map[string]provider.Provider{
		"cloudflare": cloudflare.NewDriver("acme.example"),
		"hetzner":    hetzner.NewDriver("acme"),
		"upstash":    upstash.NewDriver(),
	}
	for pkg, want := range driverDecisions {
		if want != "write-verbs-not-implemented" {
			continue
		}
		d, ok := readOnly[pkg]
		if !ok {
			t.Errorf("%s claims write-verbs-not-implemented but this gate cannot "+
				"construct it to check", pkg)
			continue
		}
		for verb, res := range map[string]provider.CreateResult{
			"Create": d.Create("x", "c", "prod", nil, nil, "k", 1),
			"Update": d.Update("x", "c", "prod", "pid", nil, nil, nil, "k"),
			"Delete": d.Delete("x", "c", "prod", "pid", "k"),
		} {
			if res.Status != "failed" {
				t.Errorf("%s.%s claims not-implemented but returned %q — a driver that "+
					"writes owes an ownership register", pkg, verb, res.Status)
			}
			low := strings.ToLower(res.Reason)
			if !strings.Contains(low, "not implemented") && !strings.Contains(low, "read-only") {
				t.Errorf("%s.%s refused for some OTHER reason (%q) — the exemption says "+
					"the verb is unwired, so the refusal must say so too", pkg, verb, res.Reason)
			}
		}
	}
}
