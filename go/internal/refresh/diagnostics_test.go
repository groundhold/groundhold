package refresh

import (
	"strings"
	"testing"

	"groundhold/internal/pace"
	"groundhold/internal/provider"
)

// diagRefreshFake refreshes fine and says what it could not read — the shape every
// driver uses for an unreadable sub-read.
type diagRefreshFake struct{ *provider.Fake }

func (f diagRefreshFake) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	return []provider.Observation{{Path: "service.managed", Value: true, Derivation: "measured"}},
		[]string{"cost.monthly not observed: billing export is not enabled for this project"},
		nil
}

// D558, third site. `refresh` re-observes proofs before they decay — its whole
// purpose is keeping evidence honest — and it took the observation result as
//
//	_, oerr := observe.Run(...)
//
// so a capability that refreshed SUCCESSFULLY while the driver reported it could not
// read part of it was recorded as plain `refreshed`. Of the three sites (adopt D556,
// converge D558, here) this is the one that matters most: refresh runs unattended on
// a schedule, so nobody is at a terminal when the sentence is dropped.
func TestRefreshReportsWhatCouldNotBeMeasured(t *testing.T) {
	led, lp := fixture(t, "2020-09-13T12:00:00Z", 60)
	sched := pace.New(pace.DefaultPolicy(), noopClock())
	rep, err := Run(led, lp, diagRefreshFake{Fake: &provider.Fake{}}, sched,
		pace.DefaultPolicy().Budget, "2020-09-13T13:00:00Z", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Refreshed) == 0 {
		t.Fatalf("setup: nothing was refreshed, so nothing could report a diagnostic: %+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Notes, " | "), "billing export") {
		t.Errorf("refresh re-observed, the driver said what it could not measure, and the "+
			"report carried only refreshed=%v.\nnotes = %v\nThe scheduled agent whose job "+
			"is keeping proof honest is the one that must not swallow this.",
			rep.Refreshed, rep.Notes)
	}
}
