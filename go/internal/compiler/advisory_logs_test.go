package compiler

import (
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/provider"
)

// D388. A field report: `capability.monitoring.logs` declared 365-day retention,
// converge went green, and the group it created held zero bytes — the
// application's logs went to the group its own runtime creates, which expires
// never. The capability was satisfied and had no effect.
//
// D226 + a `logGroupName` output made the correct wiring expressible. These pin
// the other half: making the gap VISIBLE.

// logProducer is a driver that AUTO-EMITS its own log group (D1032) — the shape
// AWS Lambda has, whose /aws/lambda/<fn> group its runtime creates on invocation.
type logProducer struct{ provider.Fake }

func (*logProducer) OutputsFor(service string) []provider.OutputSpec {
	if service != "lambda" {
		return nil
	}
	return []provider.OutputSpec{{Name: "logGroupName", Kind: "string"}}
}

func (*logProducer) EmittedCompanions() map[string][]provider.EmittedCompanion {
	return map[string][]provider.EmittedCompanion{
		"lambda": {{GovernedBy: "capability.monitoring.logs", NameOutput: "logGroupName"}},
	}
}

// quietDriver produces nothing — a service that has no log destination of its own.
type quietDriver struct{ provider.Fake }

func (*quietDriver) OutputsFor(string) []provider.OutputSpec { return nil }

// outputOnlyDriver DECLARES a logGroupName output but auto-emits NOTHING — the shape
// of cwlogs itself, which IS a log group (so it publishes its own name for others to
// $ref) but does not bring a SEPARATE one. The old heuristic keyed on the output and
// misfired here; the emission registry does not, so it is not a producer (D1032).
type outputOnlyDriver struct{ provider.Fake }

func (*outputOnlyDriver) OutputsFor(string) []provider.OutputSpec {
	return []provider.OutputSpec{{Name: "logGroupName", Kind: "string"}}
}

func fixture(t *testing.T, logsImpl map[string]any, producerService string) (
	*contract.Contract, *contract.Candidate, Inputs) {
	t.Helper()
	c := &contract.Contract{
		ID: "x",
		Capabilities: map[string]map[string]any{
			"api":  {"type": "capability.function.serverless"},
			"logs": {"type": "capability.monitoring.logs"},
		},
	}
	logsExtras := map[string]any{"provider": "aws", "service": "cwlogs"}
	if logsImpl != nil {
		logsExtras["implementation"] = logsImpl
	}
	cand := &contract.Candidate{
		ContractID: "x",
		Extras: map[string]map[string]any{
			"api":  {"provider": "aws", "service": producerService},
			"logs": logsExtras,
		},
	}
	in := Inputs{Providers: map[string]provider.Provider{"aws": &logProducer{}}}
	return c, cand, in
}

func TestUnattachedLogGroupIsAdvised(t *testing.T) {
	c, cand, in := fixture(t, nil, "lambda")

	adv := adviseUnattachedLogGroup(c, cand, in)

	if len(adv) != 1 {
		t.Fatalf("a logs capability nothing writes to must be advised, got %d", len(adv))
	}
	if adv[0].Code != "logs-group-has-no-producer" {
		t.Errorf("the code must be stable and routable, got %q", adv[0].Code)
	}
	if adv[0].Capability != "logs" {
		t.Errorf("the advisory must name the capability, got %q", adv[0].Capability)
	}
	// "this is dangerous" alone leaves the operator where they were (D364).
	if !strings.Contains(adv[0].Next, "$ref") || !strings.Contains(adv[0].Next, "api") {
		t.Errorf("the advisory must say what to DO, naming the producer: %q", adv[0].Next)
	}
	// And it must say the standalone case is legitimate, so the reader can
	// dismiss it deliberately rather than wonder.
	if !strings.Contains(adv[0].Next, "flow logs") {
		t.Errorf("a legitimate standalone group must be acknowledged: %q", adv[0].Next)
	}
}

// Once the advice is taken, the advisory must go quiet. A warning that keeps
// firing after it has been acted on is one people learn to filter out.
func TestWiredLogGroupIsNotAdvised(t *testing.T) {
	c, cand, in := fixture(t, map[string]any{
		"log_group": map[string]any{
			"$ref": map[string]any{"capability": "api", "output": "logGroupName"},
		},
	}, "lambda")

	if adv := adviseUnattachedLogGroup(c, cand, in); len(adv) != 0 {
		t.Fatalf("a logs capability already bound to a producer must not be "+
			"advised, got: %+v", adv)
	}
}

// THE NEGATIVE CONTROL, and the reason the condition is three-part. A standalone
// log group is perfectly ordinary — VPC flow logs, a cluster control plane. With
// no producer in the candidate there is nothing to attach to, and firing here
// would train people to ignore the advisory (D364's lesson, applied).
func TestStandaloneLogGroupIsNotAdvised(t *testing.T) {
	c, cand, in := fixture(t, nil, "vpc")
	in.Providers = map[string]provider.Provider{"aws": &quietDriver{}}

	if adv := adviseUnattachedLogGroup(c, cand, in); len(adv) != 0 {
		t.Fatalf("no capability in this candidate produces logs of its own — "+
			"there is nothing to advise, got: %+v", adv)
	}
}

// The producer set comes from the DRIVERS' certified emission registry (D1032),
// not from a list in this file (D317). A driver that emits no log companion is not
// named — which is right, and is what keeps this from rotting into a hardcoded table.
func TestProducersComeFromTheDrivers(t *testing.T) {
	c, cand, in := fixture(t, nil, "lambda")
	in.Providers = map[string]provider.Provider{"aws": &quietDriver{}}

	if adv := adviseUnattachedLogGroup(c, cand, in); len(adv) != 0 {
		t.Fatalf("with no driver emitting a log companion there is no producer "+
			"to name, got: %+v", adv)
	}
}

// D1033: the fix the emission registry buys. A service that DECLARES a logGroupName
// output but AUTO-EMITS nothing (cwlogs — which IS a log group) must NOT be named a
// producer. The old heuristic keyed on the output and would advise binding a
// standalone group to another standalone group; the registry keys on the emission,
// so this stays quiet.
func TestOutputWithoutEmissionIsNotAProducer(t *testing.T) {
	c, cand, in := fixture(t, nil, "lambda")
	in.Providers = map[string]provider.Provider{"aws": &outputOnlyDriver{}}

	if adv := adviseUnattachedLogGroup(c, cand, in); len(adv) != 0 {
		t.Fatalf("a service that publishes a logGroupName output but emits no companion "+
			"is not a producer — advising here is the cwlogs misfire, got: %+v", adv)
	}
}

// An advisory is something NOTICED, never something proven: it must not touch
// what gates execution.
func TestAdvisoryDoesNotGate(t *testing.T) {
	c, cand, in := fixture(t, nil, "lambda")
	adv := adviseUnattachedLogGroup(c, cand, in)
	if len(adv) == 0 {
		t.Fatal("fixture should advise")
	}
	body := Body{Preconditions: []Precondition{{Type: "report-executable"}},
		Advisories: adv, Writes: []string{"api", "logs"}}
	if len(body.Preconditions) != 1 {
		t.Error("an advisory must not add a precondition")
	}
	if len(body.Writes) != 2 {
		t.Error("an advisory must not change what the plan writes")
	}
}

// A BOUND capability whose driver never reports whether the resource still exists
// must SAY so. Silence there is what made converge report CONVERGED over five
// resources that had been deleted by hand (D513): the compile cannot distinguish
// "observed, present" from "never asked", because both look like a missing key.
func TestExistenceNotWitnessedIsSaidOutLoud(t *testing.T) {
	in := Inputs{
		Bindings: map[string]string{"db": "aws:rds:orders", "fn": "aws:lambda:worker"},
		Observations: map[string]map[string]ledger.ObsRecord{
			// answers the question: present
			"fn": {"resource.absent": {Value: false}, "service.managed": {Value: true}},
			// never answers it
			"db": {"engine.protocol": {Value: "postgresql/16"}},
		},
	}
	adv := adviseExistenceNotWitnessed(in)
	if len(adv) != 1 {
		t.Fatalf("want exactly one advisory (db), got %d: %+v", len(adv), adv)
	}
	if adv[0].Capability != "db" {
		t.Errorf("advisory names %q; the capability that DOES answer must not be flagged", adv[0].Capability)
	}
	if adv[0].Code != "existence-not-witnessed" {
		t.Errorf("code = %q", adv[0].Code)
	}
}

// An unbound capability, or one with no observations at all, is a different state
// that the observation-required gate already owns. Firing here too would bury the
// real signal under noise on every fresh compile.
func TestExistenceAdvisoryStaysQuietWhereItWouldBeNoise(t *testing.T) {
	for name, in := range map[string]Inputs{
		"unbound": {
			Bindings:     map[string]string{},
			Observations: map[string]map[string]ledger.ObsRecord{"db": {"x": {Value: 1}}},
		},
		"nothing observed": {
			Bindings:     map[string]string{"db": "aws:rds:orders"},
			Observations: map[string]map[string]ledger.ObsRecord{"db": {}},
		},
	} {
		if adv := adviseExistenceNotWitnessed(in); len(adv) != 0 {
			t.Errorf("%s: want silence, got %+v", name, adv)
		}
	}
}
