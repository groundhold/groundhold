package audit

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
)

// TestAuditEvaluatesPresenceConstraints pins D964: presence forms (exists/absent)
// were silently dropped — a hard `absent` that recorded reality VIOLATES (the
// attribute is present) reported clean/exit 0, the "gate that found nothing
// passes" shape and the worst compliance false-negative. Now audit evaluates them:
// a fresh observation ⇒ present; a missing observation ⇒ unknown (audit cannot
// prove absence, so it blocks a hard constraint rather than certifying it).
func TestAuditEvaluatesPresenceConstraints(t *testing.T) {
	for _, tc := range []struct {
		name        string
		op          string
		haveObs     bool
		wantVerdict string
		wantClean   bool
	}{
		{"absent violated by a present attribute", "absent", true, "violated", false},
		{"exists satisfied by a present attribute", "exists", true, "satisfied", true},
		{"absent cannot be certified without evidence → unknown blocks", "absent", false, "unknown", false},
		{"exists unproven without evidence → unknown blocks", "exists", false, "unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			td := t.TempDir()
			cpath := filepath.Join(td, "c.yaml")
			body := "" +
				"apiVersion: contract/v0.1\n" +
				"kind: InfrastructureContract\n" +
				"meta: { id: pres, environment: test, version: 1 }\n" +
				"capabilities:\n" +
				"  - id: db\n" +
				"    type: capability.database.relational\n" +
				"constraints:\n" +
				"  hard:\n" +
				"    - id: c-presence\n" +
				"      subject: db\n" +
				"      path: network.publicExposure\n" +
				"      op: " + tc.op + "\n" +
				"      verify: { method: static }\n"
			if err := os.WriteFile(cpath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := contract.LoadContract(cpath)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			led := ledger.New()
			if tc.haveObs {
				seedObs(led, "db", map[string]ledger.ObsRecord{
					"network.publicExposure": {Value: "true", ObservedAt: "2026-07-15T12:00:00Z",
						TTLSeconds: 86400, Derivation: "measured", Source: "provider-api"},
				})
			}
			res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
				"2026-07-15T12:05:00Z", false, embeddedVocabs(t))
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != tc.wantVerdict {
				t.Fatalf("verdict = %+v, want %q — the presence constraint must be surfaced, not dropped",
					res.Verdicts, tc.wantVerdict)
			}
			if clean := res.Status == "clean" && res.Violations == 0; clean != tc.wantClean {
				t.Fatalf("clean=%v (status=%q violations=%d), want clean=%v",
					clean, res.Status, res.Violations, tc.wantClean)
			}
		})
	}
}
