package compiler

import (
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/provider"
)

// D530, from the field: `memory_mb` was declared on a BOUND, converged function.
// `validate` said OK, `plan` sealed with zero actions and zero warnings, and the
// operand was silently ignored — while the Lambda was being killed for running out
// of the default 128 MB.
//
// The unknown-operand refusal (v0.1.4) exists and is correct; it iterates over
// ACTIONS. A capability that is bound and converged has none, so its operands were
// never examined at all. The guard covered the moment a resource is created and
// left every moment after it uncovered — which is most of a deployment's life.
func TestUnknownOperandRefusedEvenWithNoAction(t *testing.T) {
	cand := &contract.Candidate{Extras: map[string]map[string]any{
		"fn": {
			"provider": "aws", "service": "lambda",
			"implementation": map[string]any{
				"role_arn":  "arn:aws:iam::000000000000:role/x",
				"image_uri": "example.dkr.ecr.eu-central-1.amazonaws.com/x:1",
				"memory_mb": 1024, // the driver reads no such operand
			},
		},
	}}
	in := Inputs{
		Providers:        map[string]provider.Provider{"aws": awsOperandStub{}},
		Bindings:         map[string]string{"fn": "lambda:eu-central-1:000000000000:fn-prod-1"},
		BindingProviders: map[string]string{"fn": "aws"},
		BindingServices:  map[string]string{"fn": "lambda"},
	}
	err := refuseUnknownOperands(nil, cand, in) // NO actions — the converged case
	if err == nil {
		t.Fatal("an operand the driver never reads was accepted on a bound capability " +
			"with no action; the contract silently does not cover it")
	}
	if !strings.Contains(err.Error(), "memory_mb") {
		t.Errorf("the refusal does not name the operand: %v", err)
	}
}

// The refusal must not fire on operands the driver DOES read, action or not —
// otherwise every converged deployment refuses and the guard is useless.
func TestKnownOperandsStayQuietWithNoAction(t *testing.T) {
	cand := &contract.Candidate{Extras: map[string]map[string]any{
		"fn": {
			"provider": "aws", "service": "lambda",
			"implementation": map[string]any{
				"role_arn":  "arn:aws:iam::000000000000:role/x",
				"image_uri": "example.dkr.ecr.eu-central-1.amazonaws.com/x:1",
			},
		},
	}}
	in := Inputs{
		Providers:        map[string]provider.Provider{"aws": awsOperandStub{}},
		Bindings:         map[string]string{"fn": "lambda:eu-central-1:000000000000:fn-prod-1"},
		BindingProviders: map[string]string{"fn": "aws"},
		BindingServices:  map[string]string{"fn": "lambda"},
	}
	if err := refuseUnknownOperands(nil, cand, in); err != nil {
		t.Fatalf("a converged capability with only KNOWN operands refused: %v", err)
	}
}

// awsOperandStub declares the operand set the real aws/lambda driver declares,
// which is what the guard consults.
type awsOperandStub struct{ provider.Provider }

func (awsOperandStub) Name() string { return "aws" }
func (awsOperandStub) ConsumedOperands(service string) []string {
	if service == "lambda" {
		return []string{"environment", "image_uri", "role_arn", "subnet_ids", "security_group_ids"}
	}
	return nil
}
