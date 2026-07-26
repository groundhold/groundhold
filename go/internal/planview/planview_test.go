package planview

import (
	"strings"
	"testing"
)

const twoOp = `{"plan":{
  "contract":"t","environment":"prod",
  "reads":{"contractHash":"sha256:aa","candidateHash":"sha256:bb","heads":{"db":"sha256:cc"},"provider":{"name":"gcp","project":"p"}},
  "writes":["cache","db"],
  "actions":[
    {"id":"a-create-cache","capability":"cache","operation":"create","target":"gcp.redis/cache","idempotencyKey":"k1","dependsOn":["a-delete-db"],
     "risk":{"reversibility":"R1","dataLoss":"none","downtime":"none","securityExposure":"none","costDelta":{"amount":5,"currency":"USD"},"identityReplacement":false}},
    {"id":"a-delete-db","capability":"db","operation":"delete","target":"gcp.cloudsql/db","idempotencyKey":"k2","targetProviderId":"pid","targetGeneration":3,
     "risk":{"reversibility":"R4","dataLoss":"certain","downtime":"certain","securityExposure":"none","costDelta":{"amount":-10,"currency":"USD"},"identityReplacement":false}}
  ],
  "preconditions":[{"type":"report-executable"}]}}`

func TestRenderDestructiveRailAndRecap(t *testing.T) {
	out, err := Render([]byte(twoOp), "sha256:plan")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, rail) {
		t.Fatal("a delete must carry the destructive rail")
	}
	if !strings.Contains(out, "destructive recap") {
		t.Fatal("a destructive plan must carry a recap")
	}
	// the risk vector is verbatim, and no severity adjective or composite exists
	for _, forbidden := range []string{"high", "medium", "danger", "score", "severity"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Fatalf("render leaked a severity/composite word %q:\n%s", forbidden, out)
		}
	}
	// per-axis worst reflects the delete's R4 + certain
	if !strings.Contains(out, "per-axis worst: reversibility R4; dataLoss certain; downtime certain") {
		t.Fatalf("per-axis worst wrong:\n%s", out)
	}
	// cost per currency, honest label
	if !strings.Contains(out, "cost delta (sum of declared cost.monthly; unclaimed counted 0): -5.00 USD/mo") {
		t.Fatalf("cost aggregate wrong:\n%s", out)
	}
}

func TestRenderExecutionOrderIsTopological(t *testing.T) {
	out, err := Render([]byte(twoOp), "")
	if err != nil {
		t.Fatal(err)
	}
	// a-create-cache depends on a-delete-db, so delete renders FIRST despite the
	// array order — order is derived from the DAG.
	di := strings.Index(out, "[1] x  delete db")
	ci := strings.Index(out, "[2] +  create cache")
	if di < 0 || ci < 0 || di > ci {
		t.Fatalf("execution order not topological (delete before its dependent create):\n%s", out)
	}
}

func TestRecapEmptyForBenignNonEmptyForDestructive(t *testing.T) {
	if r := Recap([]byte(twoOp)); r == "" || !strings.Contains(r, "destructive recap") {
		t.Fatalf("destructive plan must yield a recap, got %q", r)
	}
	benign := `{"plan":{"contract":"t","reads":{"contractHash":"a","candidateHash":"b","heads":{}},"writes":["x"],
	  "actions":[{"id":"a","capability":"x","operation":"create","target":"fake.svc/x","idempotencyKey":"k",
	  "risk":{"reversibility":"R1","dataLoss":"none","downtime":"none","securityExposure":"none","costDelta":{"amount":0,"currency":"EUR"},"identityReplacement":false}}],
	  "preconditions":[]}}`
	if r := Recap([]byte(benign)); r != "" {
		t.Fatalf("benign plan must yield no recap, got %q", r)
	}
}

// D286: a compile-FOLDED operand (D283) must render its PROVENANCE, not just
// its value. A sealed literal that looks like the operator's own typing hides
// that the plan rests on an observation with a shelf life — the reviewer
// cannot judge "is this still true?" without the source and the window.
const foldedPlan = `{"plan":{
  "contract":"t","environment":"prod",
  "reads":{"contractHash":"sha256:aa","candidateHash":"sha256:bb","heads":{"db":"sha256:cc"}},
  "writes":["db"],
  "actions":[
    {"id":"a-create-db","capability":"db","operation":"create","target":"aws.aurora/db","idempotencyKey":"k1",
     "folds":[{"slot":"subnetIds","capability":"net","output":"privateSubnetIds",
               "value":["subnet-a","subnet-b"],"observedAt":"2026-07-24T09:55:00Z","ttlSeconds":900}],
     "risk":{"reversibility":"R1","dataLoss":"none","downtime":"none","securityExposure":"none","costDelta":{"amount":0,"currency":"EUR"},"identityReplacement":false}}
  ],
  "preconditions":[{"type":"report-executable"}]}}`

func TestRenderFoldShowsValueSourceAndWindow(t *testing.T) {
	out, err := Render([]byte(foldedPlan), "sha256:plan")
	if err != nil {
		t.Fatal(err)
	}
	for _, must := range []string{
		"folded       subnetIds <- net output privateSubnetIds",
		"[subnet-a subnet-b]",           // the sealed literal itself
		"observed 2026-07-24T09:55:00Z", // WHEN the evidence was taken
		"valid 15m",                     // how long that evidence stands
	} {
		if !strings.Contains(out, must) {
			t.Fatalf("fold render missing %q:\n%s", must, out)
		}
	}
	// a fold is NOT a live wire: it must not claim a producer action exists
	if strings.Contains(out, "wires") {
		t.Fatalf("a folded operand must not render as a same-plan wire:\n%s", out)
	}
}

func TestTTLWindowUnits(t *testing.T) {
	for in, want := range map[int]string{
		900: "15m", 86400: "24h", 3600: "1h", 45: "45s", 0: "no stated window",
	} {
		if got := ttlWindow(in); got != want {
			t.Fatalf("ttlWindow(%d) = %q, want %q", in, got, want)
		}
	}
}
