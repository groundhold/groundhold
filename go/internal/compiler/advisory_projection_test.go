package compiler

import (
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/vocab"
)

// D769. A hard constraint whose runtime bar is `static`, on an attribute the vocabulary
// marks as NOT resource state, can only ever be satisfied by the number the author wrote
// — there is no reading for a projection and there never will be, because the compiler
// filters such attributes out before they reach a driver BY DESIGN (D311).
//
// The field met this with a price attached: `cost.monthly lte 15 EUR` read satisfied from
// a declared `6 EUR` while the bill was 14.6, because the tool built a paid managed rule
// group nobody had priced.
//
// The controls matter as much as the case. This must stay quiet for a SOFT constraint
// (an advisory assertion is what soft IS), for a higher bar (asking for a probe on a
// projection is the thesis example's own shape, and being refused until one exists is the
// product), and for an ordinary attribute a driver can read.
func TestUnprovableHardConstraintIsAdvisedAndNothingElseIs(t *testing.T) {
	voc := vocab.Vocabulary{
		Capability: "capability.database.relational",
		Attributes: map[string]map[string]any{
			"cost.monthly":    {"kind": "money", "evidence": "projection"},
			"service.managed": {"kind": "bool"},
		},
	}
	vocabs := map[string]vocab.Vocabulary{"capability.database.relational": voc}

	build := func(severity, runtime, path string) *contract.Contract {
		return &contract.Contract{
			Capabilities: map[string]map[string]any{
				"db": {"type": "capability.database.relational"},
			},
			Constraints: []contract.Constraint{{
				ID: "c-1", Subject: "db", Path: path, Op: "lte",
				Severity: severity, RuntimeMethod: runtime,
			}},
		}
	}

	for _, c := range []struct {
		name     string
		severity string
		runtime  string
		path     string
		want     int
	}{
		{"hard + static on a projection", "hard", "static", "cost.monthly", 1},
		{"soft is what an unprovable assertion already is", "soft", "static", "cost.monthly", 0},
		{"a probe bar on a projection is the thesis, not a mistake", "hard", "probe", "cost.monthly", 0},
		{"an attribute a driver can read", "hard", "static", "service.managed", 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			adv := adviseUnprovableHardConstraint(build(c.severity, c.runtime, c.path), vocabs)
			if len(adv) != c.want {
				t.Fatalf("advisories = %d, want %d: %+v", len(adv), c.want, adv)
			}
			if c.want == 0 {
				return
			}
			if adv[0].Code != "hard-constraint-on-a-projection" {
				t.Fatalf("code = %q", adv[0].Code)
			}
			// It must teach the way out, not just name the problem: a refusal or a
			// warning that routes at nothing is the failure this project treats as
			// critical.
			for _, want := range []string{"probe", "soft"} {
				if !strings.Contains(adv[0].Next, want) {
					t.Errorf("the advisory must name %q as a way forward, got %q", want, adv[0].Next)
				}
			}
		})
	}
}
