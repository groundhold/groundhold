package compiler

import (
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
)

// D283: the fold branch of D226 — a $ref to an already-BOUND producer folds
// to a literal from a fresh "outputs.<name>" observation, and every lesser
// state refuses (never a symbolic fallback, never a stale literal).

func foldCand(t *testing.T) *contract.Candidate {
	t.Helper()
	// hand-shaped candidate: db consumes network.privateSubnetIds via $ref
	return &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"network": {}, "db": {},
		},
		Extras: map[string]map[string]any{
			"network": {},
			"db": {"implementation": map[string]any{
				"subnetIds": map[string]any{
					"$ref": map[string]any{"capability": "network", "output": "privateSubnetIds"},
				},
			}},
		},
	}
}

func foldActions() []Action {
	return []Action{{ID: "a-create-db", Capability: "db", Operation: "create",
		IdempotencyKey: "k-db"}}
}

// foldInputs seeds the WIRING projection (D286): outputs live in Inputs.Outputs
// keyed by bare output name, never among the semantic observations.
func foldInputs(obs map[string]ledger.ObsRecord) Inputs {
	return Inputs{
		EvalClock: 1_000_000,
		Bindings:  map[string]string{"network": "fake:net-1"},
		Outputs:   map[string]map[string]ledger.ObsRecord{"network": obs},
	}
}

func TestWireReferencesFoldsFromFreshObservation(t *testing.T) {
	actions := foldActions()
	in := foldInputs(map[string]ledger.ObsRecord{
		"privateSubnetIds": {Value: []any{"subnet-a", "subnet-b"},
			ObservedAt: ledgerTs(999_700), TTLSeconds: 900},
	})
	if err := wireReferences(actions, foldCand(t), in, "candhash"); err != nil {
		t.Fatal(err)
	}
	a := actions[0]
	if len(a.References) != 0 || len(a.DependsOn) != 0 {
		t.Fatalf("a fold must not leave a symbolic reference or an edge: %+v", a)
	}
	if len(a.Folds) != 1 {
		t.Fatalf("folds = %+v", a.Folds)
	}
	f := a.Folds[0]
	if f.Slot != "subnetIds" || f.Capability != "network" ||
		f.Output != "privateSubnetIds" || f.TTLSeconds != 900 {
		t.Fatalf("fold shape = %+v", f)
	}
	got, _ := f.Value.([]any)
	if len(got) != 2 || got[0] != "subnet-a" {
		t.Fatalf("fold value = %#v", f.Value)
	}
}

func TestWireReferencesFoldRefusals(t *testing.T) {
	cases := map[string]struct {
		in   Inputs
		want string
	}{
		"unbound producer": {
			in:   Inputs{EvalClock: 1_000_000},
			want: "the ledger does not bind",
		},
		"no outputs observation": {
			in:   foldInputs(map[string]ledger.ObsRecord{}),
			want: "— re-observe first",
		},
		"stale observation": {
			in: foldInputs(map[string]ledger.ObsRecord{
				"privateSubnetIds": {Value: []any{"subnet-a"},
					ObservedAt: ledgerTs(990_000), TTLSeconds: 900},
			}),
			want: "observation is stale — re-observe first",
		},
		"future-dated observation": {
			in: foldInputs(map[string]ledger.ObsRecord{
				"privateSubnetIds": {Value: []any{"subnet-a"},
					ObservedAt: ledgerTs(1_000_500), TTLSeconds: 900},
			}),
			want: "dated after the evaluation time",
		},
		"kind mismatch": {
			in: foldInputs(map[string]ledger.ObsRecord{
				"privateSubnetIds": {Value: "not-a-list",
					ObservedAt: ledgerTs(999_700), TTLSeconds: 900},
			}),
			want: "expected a list",
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := wireReferences(foldActions(), foldCand(t), c.in, "candhash")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want refusal containing %q, got: %v", c.want, err)
			}
		})
	}
}

func TestWireReferencesRefusesRetiringProducer(t *testing.T) {
	actions := append(foldActions(), Action{ID: "a-delete-network",
		Capability: "network", Operation: "delete", IdempotencyKey: "k-net"})
	in := foldInputs(map[string]ledger.ObsRecord{
		"privateSubnetIds": {Value: []any{"subnet-a", "subnet-b"},
			ObservedAt: ledgerTs(999_700), TTLSeconds: 900},
	})
	err := wireReferences(actions, foldCand(t), in, "candhash")
	if err == nil || !strings.Contains(err.Error(), "ref-producer-retiring") {
		t.Fatalf("a reference to a same-plan-deleted producer must refuse, got: %v", err)
	}
}

func TestWireReferencesFoldNeedsEvalClock(t *testing.T) {
	in := foldInputs(map[string]ledger.ObsRecord{
		"privateSubnetIds": {Value: []any{"subnet-a", "subnet-b"},
			ObservedAt: ledgerTs(999_700), TTLSeconds: 900},
	})
	in.EvalClock = 0
	err := wireReferences(foldActions(), foldCand(t), in, "candhash")
	if err == nil || !strings.Contains(err.Error(), "evaluation clock unset") {
		t.Fatalf("an unset eval clock must refuse (N1), got: %v", err)
	}
}

// ledgerTs renders a unix-second clock as the RFC3339 form ParseTs reads.
func ledgerTs(sec int) string {
	return ledger.FormatTs(sec)
}
