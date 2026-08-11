package audit

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/vocab"
)

func embeddedVocabs(t *testing.T) map[string]vocab.Vocabulary {
	t.Helper()
	v, err := vocab.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestAuditSetConstraintIgnoresRecordedOrder pins D963: audit must canonicalize a
// SET attribute (unordered:true) against recorded reality exactly as verify does
// for the candidate. `inference.destinationRegions` is a residency surface. Before
// the fix, audit re-implemented the comparison WITHOUT verify's setCanonical, so a
// hard `not-equals` forbidding an exact region set reported SATISFIED (clean, exit
// 0) when reality held that very set in a different order — a data-residency
// violation certified as compliant. The verify side is pinned by
// verify/unorderedoperand_gate_test.go; this is its audit twin, against
// observations rather than a candidate.
func TestAuditSetConstraintIgnoresRecordedOrder(t *testing.T) {
	for _, tc := range []struct {
		name     string
		op       string
		forbid   []string // the constraint operand (as authored)
		observed []any    // what recorded reality holds
		want     string
	}{
		{"not-equals: forbidden set present, reordered → violated", "not-equals",
			[]string{"eu-central-1", "eu-west-1"}, []any{"eu-west-1", "eu-central-1"}, "violated"},
		{"not-equals: forbidden set present, same order → violated", "not-equals",
			[]string{"eu-central-1", "eu-west-1"}, []any{"eu-central-1", "eu-west-1"}, "violated"},
		{"not-equals: a different set → satisfied", "not-equals",
			[]string{"eu-central-1", "eu-west-1"}, []any{"eu-west-1", "us-east-1"}, "satisfied"},
		{"equals: required set present, reordered → satisfied", "equals",
			[]string{"eu-central-1", "eu-west-1"}, []any{"eu-west-1", "eu-central-1"}, "satisfied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			td := t.TempDir()
			cpath := filepath.Join(td, "c.yaml")
			body := "" +
				"apiVersion: contract/v0.1\n" +
				"kind: InfrastructureContract\n" +
				"meta: { id: rs, environment: test, version: 1 }\n" +
				"capabilities:\n" +
				"  - id: ai\n" +
				"    type: capability.ai.inference\n" +
				"constraints:\n" +
				"  hard:\n" +
				"    - id: c-region-set\n" +
				"      subject: ai\n" +
				"      path: inference.destinationRegions\n" +
				"      op: " + tc.op + "\n" +
				"      value: [" + tc.forbid[0] + ", " + tc.forbid[1] + "]\n" +
				"      verify: { method: static }\n"
			if err := os.WriteFile(cpath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := contract.LoadContract(cpath)
			if err != nil {
				t.Fatal(err)
			}
			led := ledger.New()
			seedObs(led, "ai", map[string]ledger.ObsRecord{
				"inference.destinationRegions": {Value: tc.observed,
					ObservedAt: "2026-07-15T12:00:00Z", TTLSeconds: 86400,
					Derivation: "measured", Source: "provider-api"},
			})
			res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
				"2026-07-15T12:05:00Z", false, embeddedVocabs(t))
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != tc.want {
				t.Fatalf("verdict = %+v, want %q — the same SET in a different order "+
					"must get the same audit answer", res.Verdicts, tc.want)
			}
		})
	}
}
