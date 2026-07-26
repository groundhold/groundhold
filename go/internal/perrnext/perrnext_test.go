package perrnext

import (
	"reflect"
	"testing"

	"groundhold/internal/perr"
)

func fullInv() Invocation {
	return Invocation{
		Verb: "plan", Contract: "c.yaml", Candidate: "k.yaml",
		Ledger: ".groundhold/ledger.json", Provider: "gcp", Project: "mk-dev",
		At: "2026-07-22T10:00:00Z",
		Argv: []string{"groundhold", "plan", "c.yaml", "k.yaml",
			"--ledger", ".groundhold/ledger.json", "--at", "2026-07-22T10:00:00Z"},
	}
}

func TestObservationRequiredCommandExact(t *testing.T) {
	n := NextFor(fullInv(), perr.ObservationRequired, Detail{})
	if n == nil || n.Kind != KindCommand || !n.Runnable {
		t.Fatalf("want a runnable command, got %+v", n)
	}
	wantArgv := []string{"groundhold", "observe", "--ledger", ".groundhold/ledger.json",
		"--provider", "gcp", "--at", "2026-07-22T10:00:00Z", "--record"}
	if !reflect.DeepEqual(n.Argv, wantArgv) {
		t.Fatalf("argv = %v\nwant %v", n.Argv, wantArgv)
	}
	if n.Command != "groundhold observe --ledger .groundhold/ledger.json --provider gcp --at 2026-07-22T10:00:00Z --record" {
		t.Fatalf("command = %q", n.Command)
	}
	// retry echoes the operator's own invocation
	if n.Retry[1] != "plan" {
		t.Fatalf("retry should echo the invocation: %v", n.Retry)
	}
}

func TestReconcileRequiredCommandExact(t *testing.T) {
	n := NextFor(fullInv(), perr.ReconcileRequired, Detail{})
	want := []string{"groundhold", "resume", "c.yaml", "--ledger", ".groundhold/ledger.json",
		"--provider", "gcp", "--at", "2026-07-22T10:00:00Z"}
	if n == nil || !reflect.DeepEqual(n.Argv, want) {
		t.Fatalf("resume argv = %v\nwant %v", nArgv(n), want)
	}
}

func TestObservationOmittedWhenLedgerUnknown(t *testing.T) {
	inv := fullInv()
	inv.Ledger = "" // required for observe --record
	if n := NextFor(inv, perr.ObservationRequired, Detail{}); n != nil {
		t.Fatalf("no ledger must yield no command (omit over guess), got %+v", n)
	}
}

func TestOptionalProviderOmittedNotPlaceholdered(t *testing.T) {
	inv := fullInv()
	inv.Provider = "" // optional for observe
	n := NextFor(inv, perr.ObservationRequired, Detail{})
	if n == nil {
		t.Fatal("ledger+at known -> command should still emit")
	}
	for _, a := range n.Argv {
		if a == "--provider" {
			t.Fatal("unknown optional flag must be omitted, not placeholdered")
		}
	}
	if len(n.Placeholders) != 0 || !n.Runnable {
		t.Fatal("no placeholders -> runnable")
	}
}

func TestConsentIsEditNotCommand(t *testing.T) {
	n := NextFor(fullInv(), perr.ConsentRequired, Detail{Capability: "ledger-db"})
	if n == nil || n.Kind != KindEdit || n.Edit == nil {
		t.Fatalf("consent must be an edit, got %+v", n)
	}
	if n.Runnable {
		t.Fatal("an edit is never runnable (preserves the consent gate)")
	}
	if n.Edit.Pointer != "autonomy.allow_replace_stateful" {
		t.Fatalf("edit pointer = %q", n.Edit.Pointer)
	}
	// omitted when the capability is unknown
	if NextFor(fullInv(), perr.ConsentRequired, Detail{}) != nil {
		t.Fatal("no capability -> no edit")
	}
}

func TestPermissionDeniedIsSortedGrant(t *testing.T) {
	n := NextFor(fullInv(), perr.ProviderPermissionDenied,
		Detail{Principal: "sa@mk", Permissions: []string{"b.get", "a.create"}})
	if n == nil || n.Kind != KindGrant || n.Grant == nil {
		t.Fatalf("want grant, got %+v", n)
	}
	if !reflect.DeepEqual(n.Grant.Permissions, []string{"a.create", "b.get"}) {
		t.Fatalf("permissions must be sorted: %v", n.Grant.Permissions)
	}
	if n.Grant.Principal != "sa@mk" {
		t.Fatalf("principal = %q", n.Grant.Principal)
	}
}

func TestNoNextCodesYieldNil(t *testing.T) {
	for _, c := range []perr.Code{perr.ReadSetMismatch, perr.LeaseConflict,
		perr.LedgerCorrupted, perr.StructuralError} {
		if NextFor(fullInv(), c, Detail{}) != nil {
			t.Fatalf("%s must have no next (situational/destructive)", c)
		}
	}
}

// TestCompleteness: every remediable code (in perr.Explain) is categorized —
// a builder OR the explicit noNext set. A new code cannot land undecided.
func TestCompleteness(t *testing.T) {
	for c := range perr.Explain {
		_, hasBuilder := nextBuilders[c]
		if !hasBuilder && !noNext[c] {
			t.Errorf("code %q has neither a next builder nor a noNext decision", c)
		}
		if hasBuilder && noNext[c] {
			t.Errorf("code %q is in BOTH nextBuilders and noNext", c)
		}
	}
}

// TestRunnableInvariant: every command-kind argv starts with groundhold, has no
// shell metacharacters, and is a single command.
func TestRunnableInvariant(t *testing.T) {
	inv := fullInv()
	for _, c := range []perr.Code{perr.ObservationRequired, perr.ReconcileRequired} {
		n := NextFor(inv, c, Detail{})
		if n == nil || n.Kind != KindCommand {
			continue
		}
		if n.Argv[0] != "groundhold" {
			t.Fatalf("%s: argv[0] must be groundhold", c)
		}
		for _, a := range n.Argv {
			for _, meta := range []string{"|", "&", ";", ">", "<", "$", "`", "&&"} {
				if a == meta {
					t.Fatalf("%s: argv contains a shell metacharacter %q", c, meta)
				}
			}
		}
	}
}

func TestQuoteMetachars(t *testing.T) {
	if got := quote([]string{"groundhold", "observe", "a b"}); got != "groundhold observe 'a b'" {
		t.Fatalf("quote = %q", got)
	}
}

func nArgv(n *Next) []string {
	if n == nil {
		return nil
	}
	return n.Argv
}
