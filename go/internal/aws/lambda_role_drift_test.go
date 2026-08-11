package aws

import (
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// D530, from the field: the execution role was changed in the candidate to a new,
// narrowly-scoped role. `validate` said OK and `plan` produced ZERO actions while
// reality still ran the old role — so the deployment kept the permissions the
// change was meant to remove (bedrock:InvokeModel*, transcribe:*, s3 writes), and
// the operator had to run `aws lambda update-function-configuration` by hand.
//
// `role_arn` was consumed at CREATE and observed nowhere, so the reconciler had
// nothing to compare and reported convergence. This is a SECURITY attribute: a
// divergence between the declared and the actual execution role is exactly what an
// infrastructure contract exists to prevent.
func TestLambdaDeclaresRoleAsAnObservableOperand(t *testing.T) {
	targets, err := (&Driver{Region: "eu-central-1"}).OperandTargets("lambda",
		map[string]any{"location.region": "eu-central-1"},
		map[string]any{
			"role_arn":  "arn:aws:iam::000000000000:role/narrow",
			"image_uri": "example.dkr.ecr.eu-central-1.amazonaws.com/x:1",
		})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	for _, tg := range targets {
		if tg.Path == lambdaRoleOperand {
			got, _ = tg.Desired.(string)
		}
	}
	if got == "" {
		t.Fatalf("the declared execution role is not an operand target, so a change to "+
			"it can never read as drift.\n  targets: %v", targets)
	}
	if !strings.HasSuffix(got, "role/narrow") {
		t.Errorf("operand target = %q, want the declared role", got)
	}
}

// The observed side has to render the same way, or declared and observed compare
// unequal on every run and a converged function reports permanent drift.
func TestLambdaRoleOperandObservesInTheSameShape(t *testing.T) {
	const arn = "arn:aws:iam::000000000000:role/narrow"
	obs := lambdaRoleObservation(arn)
	if obs.Path != lambdaRoleOperand {
		t.Fatalf("path = %q, want %q", obs.Path, lambdaRoleOperand)
	}
	if obs.Value != arn {
		t.Errorf("value = %v, want the ARN verbatim so it compares to the declared operand", obs.Value)
	}
	if obs.Derivation != "measured" {
		t.Errorf("derivation = %q — the role is read from the API, not assumed", obs.Derivation)
	}
}

// ClassifyChange must call it patchable, because updateConfigBody already sends
// Role: a change that reads as immutable would plan a REPLACEMENT of a live
// function for a permission edit.
func TestLambdaRoleChangeIsPatchedInPlace(t *testing.T) {
	class, note := (&Driver{}).ClassifyChange("lambda", lambdaRoleOperand,
		"arn:aws:iam::000000000000:role/old", "arn:aws:iam::000000000000:role/new", nil)
	if class != "mutable" {
		t.Errorf("class = %q (%s) — UpdateFunctionConfiguration already carries Role, so "+
			"a role change must patch in place, never replace the function", class, note)
	}
}

var _ = provider.OperandTarget{}
