package verify

import (
	"strings"
	"testing"

	"groundhold/internal/contract"
)

// D635. A capability the CONTRACT declares and the candidate does not implement fell
// between two loops — verify iterates constraints, the compiler iterates the
// candidate's capabilities — so it produced no verdict, no action and no entry
// anywhere. `verify` printed PROVEN and a second `converge` printed CONVERGED over a
// capability that does not exist.
func TestUnimplementedCapabilityBlocks(t *testing.T) {
	c := &contract.Contract{
		ID: "m1", Environment: "test", Version: 1,
		Capabilities: map[string]map[string]any{
			"db":     {"type": "capability.database.relational"},
			"assets": {"type": "capability.storage.object"},
		},
	}
	cand := &contract.Candidate{
		ContractID: "m1",
		Capabilities: map[string]map[string]contract.Provenanced{
			"db": {},
		},
	}
	rep, err := Verify(c, cand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Executable {
		t.Error("a contract capability with no implementation verified as executable — " +
			"silence about a declared capability reads as success")
	}
	if !strings.Contains(strings.Join(rep.BlockingReasons, " "), "does not implement") {
		t.Errorf("the blocking reason does not name the omission: %v", rep.BlockingReasons)
	}

	// The exemption: retirement is how a contract says a capability should NOT exist
	// (D47). Requiring an implementation for one would make retirement unexpressible.
	c.Capabilities["assets"]["state"] = "retired"
	rep, err = Verify(c, cand, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Executable {
		t.Errorf("a RETIRED capability was required to have an implementation: %v",
			rep.BlockingReasons)
	}
}
