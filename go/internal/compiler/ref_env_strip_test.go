package compiler

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/aws"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
	"groundhold/internal/scalars"
	"groundhold/internal/verify"
)

// TestBoundLambdaDoesNotStripWiredEnvVar reproduces the $ref-on-update data-loss
// defect. A BOUND function whose env var is WIRED to a producer output
// (implementation.environment[DB_HOST] = {$ref:{capability:db, output:endpoint}})
// was created with the reference RESOLVED — observe recorded the concrete value.
// A re-converge recomputes the DESIRED env through OperandTargets/BuildLambda,
// which DROPS a raw $ref (it is only resolved on the create path). So the desired
// env OMITS the wired var, drifts against the observed concrete value, and the
// reconcile plans to REWRITE the env WITHOUT it — a no-op converge silently
// STRIPS a wired env var and reports success. Dangerous direction (D716): a
// person acting on "converged" is worse off than if the tool had said nothing.
//
// The producer `db` is bound and carries a FRESH outputs.endpoint observation —
// exactly the D283 fold's precondition — so the desired env is derivable; the
// defect is that the D283 fold runs only for CREATE actions, not the drift path.
func TestBoundLambdaDoesNotStripWiredEnvVar(t *testing.T) {
	region, _ := scalars.Parse("eu-central-1")
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"api": {"location.region": {Scalar: region}},
			"db":  {},
		},
		Extras: map[string]map[string]any{
			"api": {
				"service": "lambda",
				"implementation": map[string]any{
					"image_uri": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/api:v1",
					"role_arn":  "arn:aws:iam::123456789012:role/api",
					"environment": map[string]any{
						"DB_HOST": map[string]any{"$ref": map[string]any{
							"capability": "db", "output": "endpoint"}},
					},
				},
			},
			"db": {"provider": "aws", "service": "elasticache-serverless"},
		},
	}
	at := "2026-07-25T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	rec := func(v any) ledger.ObsRecord {
		return ledger.ObsRecord{Value: v, ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}
	}
	in := Inputs{
		Bindings: map[string]string{
			"api": "lambda:eu-central-1:123456789012:api",
			"db":  "elasticache-serverless:eu-central-1:123456789012:db",
		},
		BindingProviders: map[string]string{"db": "aws"},
		Observed:         map[string]bool{"api": true},
		EvalClock:        clock,
		Observations: map[string]map[string]ledger.ObsRecord{
			"api": {
				"location.region":                      rec("eu-central-1"),
				provider.OperandPrefix + "vpcConfig":   rec(""),
				provider.OperandPrefix + "environment": rec("DB_HOST=db.internal:5432"),
				provider.OperandPrefix + "package":     rec("123456789012.dkr.ecr.eu-central-1.amazonaws.com/api:v1"),
			},
		},
		// The bound producer's fresh output — the value the $ref was created from.
		Outputs: map[string]map[string]ledger.ObsRecord{
			"db": {"endpoint": rec("db.internal:5432")},
		},
		Providers: map[string]provider.Provider{"aws": aws.NewDriver("eu-central-1")},
	}

	changes, _, block, _, err := classifyBound(cand, "api", "aws", "lambda", in, functionVocab(t))
	if err != nil {
		t.Fatalf("reconcile errored: %v", err)
	}
	if block != "" {
		t.Fatalf("a wired-env bound function must not block at rest: %q", block)
	}
	for _, ch := range changes {
		if ch.Path == provider.OperandPrefix+"environment" {
			t.Fatalf("a bound function at REST planned to rewrite its env from %q to %q — "+
				"the wired $ref var was dropped and would be STRIPPED on a no-op converge", ch.From, ch.To)
		}
	}
}

// TestBoundLambdaWithStaleWiredOutputRefuses pins the fail-closed edge: when the
// wired producer's output observation is STALE (cannot be trusted to derive the
// desired env), the reconcile REFUSES (re-observe first) rather than dropping the
// $ref and stripping the var. Fail-closed beats a silent delete — the same
// stance as the D283 create-path fold.
func TestBoundLambdaWithStaleWiredOutputRefuses(t *testing.T) {
	region, _ := scalars.Parse("eu-central-1")
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"api": {"location.region": {Scalar: region}},
			"db":  {},
		},
		Extras: map[string]map[string]any{
			"api": {
				"service": "lambda",
				"implementation": map[string]any{
					"image_uri": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/api:v1",
					"role_arn":  "arn:aws:iam::123456789012:role/api",
					"environment": map[string]any{
						"DB_HOST": map[string]any{"$ref": map[string]any{
							"capability": "db", "output": "endpoint"}},
					},
				},
			},
			"db": {"provider": "aws", "service": "elasticache-serverless"},
		},
	}
	at := "2026-07-25T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	fresh := func(v any) ledger.ObsRecord {
		return ledger.ObsRecord{Value: v, ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}
	}
	in := Inputs{
		Bindings: map[string]string{
			"api": "lambda:eu-central-1:123456789012:api",
			"db":  "elasticache-serverless:eu-central-1:123456789012:db",
		},
		BindingProviders: map[string]string{"db": "aws"},
		Observed:         map[string]bool{"api": true},
		EvalClock:        clock,
		Observations: map[string]map[string]ledger.ObsRecord{
			"api": {
				"location.region":                      fresh("eu-central-1"),
				provider.OperandPrefix + "vpcConfig":   fresh(""),
				provider.OperandPrefix + "environment": fresh("DB_HOST=db.internal:5432"),
				provider.OperandPrefix + "package":     fresh("123456789012.dkr.ecr.eu-central-1.amazonaws.com/api:v1"),
			},
		},
		// The producer's output was observed 24 days ago with a 1-day TTL — stale.
		Outputs: map[string]map[string]ledger.ObsRecord{
			"db": {"endpoint": {Value: "db.internal:5432", ObservedAt: "2026-07-01T10:00:00Z",
				TTLSeconds: 86400, Derivation: "measured"}},
		},
		Providers: map[string]provider.Provider{"aws": aws.NewDriver("eu-central-1")},
	}

	_, _, _, _, err := classifyBound(cand, "api", "aws", "lambda", in, functionVocab(t))
	if err == nil {
		t.Fatal("a stale wired output must refuse the reconcile (re-observe first), not " +
			"silently drop the $ref and strip the env var")
	}
}

// TestFoldDriftRefsCarriesTheResolvedLiteral pins hop 2 (the apply side): the
// fold record that the UPDATE action carries — so apply's foldedImplementation
// substitutes the wired literal before the driver builds the patch and a config
// re-push never strips the env var as collateral of an unrelated change.
func TestFoldDriftRefsCarriesTheResolvedLiteral(t *testing.T) {
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{"api": {}, "db": {}},
		Extras: map[string]map[string]any{
			"api": {"service": "lambda", "implementation": map[string]any{
				"environment": map[string]any{
					"DB_HOST": map[string]any{"$ref": map[string]any{
						"capability": "db", "output": "endpoint"}},
				},
			}},
			"db": {"provider": "aws", "service": "elasticache-serverless"},
		},
	}
	at := "2026-07-25T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	in := Inputs{
		Bindings:         map[string]string{"db": "elasticache-serverless:eu-central-1:123456789012:db"},
		BindingProviders: map[string]string{"db": "aws"},
		EvalClock:        clock,
		Outputs: map[string]map[string]ledger.ObsRecord{
			"db": {"endpoint": {Value: "db.internal:5432", ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}},
		},
		Providers: map[string]provider.Provider{"aws": aws.NewDriver("eu-central-1")},
	}
	folded, folds, err := foldDriftRefs("api", implementationOf(cand, "api"), cand, in)
	if err != nil {
		t.Fatalf("a fresh wired output must fold, not error: %v", err)
	}
	if len(folds) != 1 || folds[0].Slot != "environment.DB_HOST" || folds[0].Value != "db.internal:5432" {
		t.Fatalf("the update action must carry the resolved fold, got %+v", folds)
	}
	env, _ := folded["environment"].(map[string]any)
	if env["DB_HOST"] != "db.internal:5432" {
		t.Fatalf("the folded impl must resolve the wired var to a literal, got %v", env["DB_HOST"])
	}
}

// TestUpdateActionCarriesWiredFold pins the wiring: a GENUINE update to a bound
// $ref-lambda (here a VpcConfig drift) must seal the wired env fold on the update
// action, so apply's foldedImplementation resolves it and the config re-push does
// not STRIP the env var as collateral. `db` is a bound external producer — not in
// the contract — exactly as a real cross-capability wiring is at reconcile time.
func TestUpdateActionCarriesWiredFold(t *testing.T) {
	td := t.TempDir()
	cp := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cp, []byte(fnContract), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cp)
	if err != nil {
		t.Fatal(err)
	}
	region, _ := scalars.Parse("eu-central-1")
	cand := &contract.Candidate{
		Capabilities: map[string]map[string]contract.Provenanced{
			"fn": {"location.region": {Scalar: region}},
		},
		Extras: map[string]map[string]any{
			"fn": {
				"provider": "aws", "service": "lambda",
				"implementation": map[string]any{
					"image_uri":       "123456789012.dkr.ecr.eu-central-1.amazonaws.com/fn:v1",
					"role_arn":        "arn:aws:iam::123456789012:role/fn",
					"subnets":         []any{"subnet-b"},
					"security_groups": []any{"sg-1"},
					"environment": map[string]any{
						"DB_HOST": map[string]any{"$ref": map[string]any{
							"capability": "db", "output": "endpoint"}},
					},
				},
			},
			"db": {"provider": "aws", "service": "elasticache-serverless"},
		},
	}
	at := "2026-07-25T10:00:00Z"
	clock, _ := ledger.ParseTs(at)
	rec := func(v any) ledger.ObsRecord {
		return ledger.ObsRecord{Value: v, ObservedAt: at, TTLSeconds: 86400, Derivation: "measured"}
	}
	in := Inputs{
		Bindings: map[string]string{
			"fn": "lambda:eu-central-1:123456789012:fn",
			"db": "elasticache-serverless:eu-central-1:123456789012:db",
		},
		BindingProviders: map[string]string{"fn": "aws", "db": "aws"},
		Generations:      map[string]int{"fn": 1},
		Observed:         map[string]bool{"fn": true},
		EvalClock:        clock,
		Observations: map[string]map[string]ledger.ObsRecord{
			"fn": {
				"location.region":                      rec("eu-central-1"),
				provider.OperandPrefix + "vpcConfig":   rec("subnets=subnet-a;sgs=sg-1"), // GENUINE drift
				provider.OperandPrefix + "environment": rec("DB_HOST=db.internal:5432"),
				provider.OperandPrefix + "package":     rec("123456789012.dkr.ecr.eu-central-1.amazonaws.com/fn:v1"),
			},
		},
		Outputs: map[string]map[string]ledger.ObsRecord{
			"db": {"endpoint": rec("db.internal:5432")},
		},
		Providers: map[string]provider.Provider{"aws": aws.NewDriver("eu-central-1")},
	}
	report := &verify.Report{Executable: true, CandidateHash: "h"}
	doc, err := Compile(c, cand, nil, report, "proj", in)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var up *Action
	for i := range doc.Plan.Actions {
		if doc.Plan.Actions[i].Operation == "update" {
			up = &doc.Plan.Actions[i]
		}
	}
	if up == nil {
		t.Fatalf("expected an update action for the VpcConfig drift, got %+v", doc.Plan.Actions)
	}
	found := false
	for _, f := range up.Folds {
		if f.Slot == "environment.DB_HOST" && f.Value == "db.internal:5432" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the update action dropped the wired env fold — apply's config re-push "+
			"would STRIP DB_HOST as collateral of the VpcConfig update; folds=%+v", up.Folds)
	}
}
