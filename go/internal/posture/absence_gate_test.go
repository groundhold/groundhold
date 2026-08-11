package posture

import "testing"

// D652. `resource.absent` is the reserved marker a driver writes when it read the
// provider and got an authoritative 404: the bound resource is GONE. The compiler
// acts on a fresh one by planning a re-create (F-LC3), and refuses to seal against
// a stale one. `posture` did not read it at all — `grep -rn "resource.absent"` over
// the package and over `classifyPosture` returned nothing.
//
// Observations are latest-per-path, so a stale `service.managed: true` keeps
// standing beside a fresh `resource.absent: true`, and the audit verdict computed
// from it stays `satisfied`. A resource the provider has authoritatively 404'd was
// therefore reported `managed-ok` with no remediation — the one class posture
// prints with nothing for the operator to do.
func TestAResourceTheProviderSaysIsGoneIsNotManagedOk(t *testing.T) {
	doc := Classify(Input{
		At:       "2026-07-15T12:05:00Z",
		Scopes:   []Scope{{Provider: "fake", Scope: "s", Complete: true}},
		Bindings: map[string]string{"db": "fake:db-1"},
		Verdict:  map[string]string{"db": "satisfied"}, // from observations that predate the 404
		Absent:   map[string]bool{"db": true},
	})
	row := rowFor(t, doc, "fake:db-1")
	if row.Class == "managed-ok" {
		t.Fatalf("a resource the provider reports GONE is classified managed-ok "+
			"with remediation %+v — managed-ok is the class an operator scrolls "+
			"past", row.Remediation)
	}
	if row.Class != "drifted" {
		t.Errorf("class = %q, want drifted — the world does not match the contract, "+
			"and converge is what re-creates it", row.Class)
	}
	if row.Remediation.Action != "converge" {
		t.Errorf("remediation = %q, want converge", row.Remediation.Action)
	}
	if doc.Summary.Drifted != 1 || doc.Summary.ManagedOK != 0 {
		t.Errorf("summary counts it wrong: %+v", doc.Summary)
	}
}

// Absence outranks a violated constraint: a hard constraint failing on a resource
// that does not exist is noise, and the sentence an operator reads should be the
// one that explains the rest.
func TestAbsenceOutranksAViolatedConstraint(t *testing.T) {
	doc := Classify(Input{
		At:       "2026-07-15T12:05:00Z",
		Scopes:   []Scope{{Provider: "fake", Scope: "s", Complete: true}},
		Bindings: map[string]string{"db": "fake:db-1"},
		Verdict:  map[string]string{"db": "violated"},
		Absent:   map[string]bool{"db": true},
	})
	row := rowFor(t, doc, "fake:db-1")
	if row.Class != "drifted" {
		t.Fatalf("class = %q, want drifted", row.Class)
	}
	if !contains(row.Reason, "gone") && !contains(row.Reason, "absent") {
		t.Errorf("the reason talks about the constraint, not about the resource "+
			"having vanished: %q", row.Reason)
	}
}

// The control: nothing here may make an ordinary bound capability look vanished.
func TestAPresentResourceIsUnaffected(t *testing.T) {
	doc := Classify(Input{
		At:       "2026-07-15T12:05:00Z",
		Scopes:   []Scope{{Provider: "fake", Scope: "s", Complete: true}},
		Bindings: map[string]string{"db": "fake:db-1"},
		Verdict:  map[string]string{"db": "satisfied"},
		Absent:   map[string]bool{}, // observed, present
	})
	if row := rowFor(t, doc, "fake:db-1"); row.Class != "managed-ok" {
		t.Errorf("class = %q, want managed-ok — a present, proven resource must "+
			"still read green", row.Class)
	}
}

func rowFor(t *testing.T, d *Document, pid string) Row {
	t.Helper()
	for _, r := range d.Rows {
		if r.ProviderID == pid {
			return r
		}
	}
	t.Fatalf("no row for %s in %+v", pid, d.Rows)
	return Row{}
}
