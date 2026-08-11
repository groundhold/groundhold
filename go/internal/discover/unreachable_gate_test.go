package discover

import (
	"errors"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// D621. A sweep that could not reach the provider must not come back as an empty
// estate. `discover --provider gcp` with no credentials exited 0 with
// `"resources": []` and 43 diagnostics saying "no usable GCP credentials"; AWS and
// Azure exited 1 on their equivalents. A script branching on the exit status read "the
// project is empty" where the truth was "the cloud was never contacted" — and the
// document it wrote is the input `adopt` and `posture` are told to take.
//
// The gate holds the RULE rather than one driver: a discoverer that fails to reach its
// provider makes Run fail, and one that reaches it and finds nothing succeeds. The
// difference between those two is the whole value of the verb.
type unreachable struct {
	provider.Fake
	err   error
	diags []string
}

func (u *unreachable) List(string) ([]provider.Discovered, []string, error) {
	return nil, u.diags, u.err
}

func TestASweepThatCouldNotHappenIsNotAnEmptyEstate(t *testing.T) {
	_, err := Run(&unreachable{err: errors.New("cannot reach the provider: no usable credentials")},
		"proj", "eu-central-1", "2026-02-01T00:00:00Z")
	if err == nil {
		t.Fatal("a discoverer that could not reach its provider produced a document — " +
			"zero resources then reads as an empty estate, and the caller cannot tell " +
			"the two apart")
	}
	if !strings.Contains(err.Error(), "reach") {
		t.Errorf("the error does not say the provider was unreachable: %v", err)
	}
}

func TestAnEstateThatIsGenuinelyEmptyStillSucceeds(t *testing.T) {
	res, err := Run(&unreachable{diags: []string{"compute: API not enabled in this project"}},
		"proj", "eu-central-1", "2026-02-01T00:00:00Z")
	if err != nil {
		t.Fatalf("a reachable provider with nothing in it must succeed: %v", err)
	}
	if len(res.Discovery.Resources) != 0 {
		t.Errorf("expected zero resources, got %d", len(res.Discovery.Resources))
	}
	if len(res.Diagnostics) == 0 {
		t.Error("the diagnostics were dropped — a partial sweep must still say what " +
			"it could not read")
	}
}
