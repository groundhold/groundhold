package refresh

import (
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/ledger"
	"groundhold/internal/pace"
	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

// deadDriver answers every read with a failure — an unreachable cluster, an expired
// credential, a service the identity may not call. observe.Run turns that into
// Partial/Unreadable and returns a NIL error, which is the contract D242 chose:
// observe reports reality, including the part that reads "currently unreadable".
type deadDriver struct{ provider.Fake }

func (*deadDriver) Name() string { return "fake" }

func (*deadDriver) Observe(service, capability, providerID string) ([]provider.Observation,
	[]string, error) {
	return nil, nil, errUnreadable
}

var errUnreadable = &readErr{}

type readErr struct{}

func (*readErr) Error() string {
	return `fake driver: unknown service "sql" — refusing (no default)`
}

func ledgerWithABinding(t *testing.T) (*ledger.Ledger, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "l.jsonl")
	w := &ledger.Writer{Path: path, Led: ledger.New(), Env: "dev",
		Clock: 1600000000, Actor: "o@e.test"}
	if err := w.Append("contract.published", []string{"db"},
		map[string]any{"contract": "t", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	led.Bindings["db"] = map[string]any{"resources": []any{
		map[string]any{"providerId": "fake:my-db",
			"type": "capability.cache.keyvalue"}}}
	return led, path
}

// D649. `refresh` is the unattended agent that re-observes a capability before its
// proof decays, and `posture` hands it to the operator as step 1 of the DECAYED
// recipe. It reported a read that never happened as a success:
//
//	$ groundhold refresh --ledger l.jsonl --provider aws --at …
//	exit 0  {"refreshed":["shop-db"],"fresh":[],
//	         "notes":["shop-db: unreadable: aws driver: unknown service \"sql\""]}
//	$ wc -l < l.jsonl        # unchanged: zero events appended
//
// `observe.Run` returns nil on a driver read failure (D242 by design), so `oerr ==
// nil`, the capability went into `Refreshed`, and the pacer scored `OK` — meaning
// the circuit breaker can never trip on a provider that is entirely down, and a
// `posture` run straight afterwards still reports the same capability decayed.
func TestAReadThatFailedIsNotARefresh(t *testing.T) {
	led, path := ledgerWithABinding(t)
	sched := pace.New(pace.DefaultPolicy(), noopClock())

	rep, err := Run(led, path, &deadDriver{}, sched, pace.DefaultPolicy().Budget, "2026-07-19T00:00:00Z", 0, 0)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	for _, c := range rep.Refreshed {
		if c == "db" {
			t.Errorf("a capability whose read FAILED is reported as refreshed. The "+
				"proof is untouched and still decaying, and the operator following "+
				"posture's own recipe is told the step succeeded: %+v", rep)
		}
	}
	var named bool
	for _, u := range rep.Unreadable {
		if u.Capability == "db" && strings.Contains(u.Reason, "unknown service") {
			named = true
		}
	}
	if !named {
		t.Errorf("the report does not name the capability that could not be read, "+
			"or does not carry the driver's reason: %+v", rep.Unreadable)
	}
	if !rep.Partial {
		t.Error("the report does not say it is partial — an unattended cron reading " +
			"this JSON has nothing to alert on")
	}

	// The pacer must have been told this call did not succeed, or a provider that
	// is entirely down looks like a healthy sweep and the breaker never trips.
	if sched.Backoffs == 0 && sched.Throttles == 0 {
		t.Errorf("the pacer scored a failed read as OK (backoffs=%d throttles=%d) — "+
			"the crawl breaker cannot fire on a dead provider",
			sched.Backoffs, sched.Throttles)
	}
}

// The control: a capability that IS readable must still refresh, land in
// `refreshed`, and leave the report un-partial. The cheap way to satisfy the case
// above is to call every read a failure.
func TestAReadableCapabilityStillRefreshes(t *testing.T) {
	led, path := ledgerWithABinding(t)
	sched := pace.New(pace.DefaultPolicy(), noopClock())

	rep, err := Run(led, path, &provider.Fake{}, sched, pace.DefaultPolicy().Budget, "2026-07-19T00:00:00Z", 0, 0)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	var got bool
	for _, c := range rep.Refreshed {
		if c == "db" {
			got = true
		}
	}
	if !got {
		t.Errorf("a readable capability did not refresh: %+v", rep)
	}
	if rep.Partial || len(rep.Unreadable) != 0 {
		t.Errorf("a clean sweep must not report itself partial: %+v", rep)
	}
}

// The exit code is the alert: refresh runs unattended on a schedule, so a sweep
// that renewed nothing must not look like a sweep that renewed everything. The
// code comes from the registry rather than a literal (D619).
func TestAFailedRefreshCarriesTheRegistrysCode(t *testing.T) {
	led, path := ledgerWithABinding(t)
	sched := pace.New(pace.DefaultPolicy(), noopClock())
	rep, err := Run(led, path, &deadDriver{}, sched, pace.DefaultPolicy().Budget,
		"2026-07-19T00:00:00Z", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Code != string(perr.ObservationRequired) {
		t.Errorf("code = %q, want %q — spec/errors.md says every JSON-emitting verb "+
			"carries one, and a cron routes on it", rep.Code, perr.ObservationRequired)
	}
	if got := perr.ExitFor(perr.Code(rep.Code)); got == 0 {
		t.Errorf("the registry maps this code to exit %d — a failed refresh that "+
			"exits 0 is a silent one", got)
	}
}
