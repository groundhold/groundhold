// Package refresh is the freshness agent (D141 family): a regular, gentle sweep
// that re-observes the BOUND resources whose proof is stale or about to decay,
// keeping evidence alive so a verdict never rests on a proof that outlived its own
// TTL ("decayed-proof" debt). It does the LEAST work that keeps proofs fresh — a
// still-fresh capability is left alone — and it re-observes through the pace
// scheduler so a large estate is refreshed gently, never in a burst. It records
// through the same observe path as `groundhold observe`; it sits outside the verifier.
package refresh

import (
	"errors"
	"sort"

	"groundhold/internal/ledger"
	"groundhold/internal/observe"
	"groundhold/internal/pace"
	"groundhold/internal/provider"
)

// CapIssue records a capability the sweep could not refresh, with why.
type CapIssue struct {
	Capability string `json:"capability"`
	Reason     string `json:"reason"`
}

// Stats is the gentleness honesty block — how hard the sweep leaned on providers.
type Stats struct {
	RequestsMade int    `json:"requestsMade"`
	Budget       int    `json:"budget"`
	Throttled    int    `json:"throttled"`
	Backoffs     int    `json:"backoffs"`
	StoppedEarly string `json:"stoppedEarly,omitempty"`
}

// Report is the refresh outcome. Refreshed proofs were re-observed; Fresh ones were
// still within TTL and left untouched; Skipped ones hit a paced error or a stop.
type Report struct {
	At        string     `json:"at"`
	Window    int        `json:"windowSeconds"`
	Refreshed []string   `json:"refreshed"`
	Fresh     []string   `json:"fresh"`
	Skipped   []CapIssue `json:"skipped,omitempty"`
	Crawl     Stats      `json:"crawl"`
}

// isStale reports whether a capability's proof is missing, unparseable, or decays by
// at+window. window=0 means "already decayed at `at`"; a positive window refreshes
// PROACTIVELY, before the proof expires (the cron cadence's lead time).
func isStale(led *ledger.Ledger, cap, at string, window int) bool {
	recs := led.Observations[cap]
	if len(recs) == 0 {
		return true // never observed
	}
	atSec, err := ledger.ParseTs(at)
	if err != nil {
		return true
	}
	deadline := atSec + window // seconds
	for _, r := range recs {
		obsSec, err := ledger.ParseTs(r.ObservedAt)
		if err != nil {
			return true // an unparseable proof time is not trustworthy
		}
		if obsSec+r.TTLSeconds <= deadline {
			return true // this proof (the weakest link) decays by the deadline
		}
	}
	return false
}

// Run re-observes every bound capability whose proof is stale or decaying within
// window, GENTLY through the scheduler, recording fresh observations. A paced
// failure (or a budget/breaker stop) is a recorded skip, never a silent gap.
func Run(led *ledger.Ledger, ledgerPath string, prov provider.Provider,
	sched *pace.Scheduler, budget int, at string, window, ttlOverride int) (*Report, error) {

	bindings := led.BoundProviderIDs()
	caps := make([]string, 0, len(bindings))
	for c := range bindings {
		caps = append(caps, c)
	}
	sort.Strings(caps)

	rep := &Report{At: at, Window: window, Refreshed: []string{}, Fresh: []string{}}
	stoppedEarly := ""
	for _, cap := range caps {
		if !isStale(led, cap, at, window) {
			rep.Fresh = append(rep.Fresh, cap)
			continue
		}
		if stoppedEarly != "" {
			rep.Skipped = append(rep.Skipped, CapIssue{cap, "sweep stopped early: " + stoppedEarly})
			continue
		}
		// one paced re-observation per capability; observe records the event
		_, err := sched.Do(prov.Name(), func() pace.Result {
			_, oerr := observe.Run(map[string]string{cap: bindings[cap]}, prov, at, ttlOverride, led, ledgerPath, true)
			if oerr != nil {
				return pace.Result{Outcome: pace.ServerError}
			}
			return pace.Result{Outcome: pace.OK}
		})
		if err != nil {
			rep.Skipped = append(rep.Skipped, CapIssue{cap, err.Error()})
			switch {
			case errors.Is(err, pace.ErrBudget):
				stoppedEarly = "budget"
			case errors.Is(err, pace.ErrBroken):
				if stoppedEarly == "" {
					stoppedEarly = "breaker"
				}
			}
			continue
		}
		rep.Refreshed = append(rep.Refreshed, cap)
	}
	rep.Crawl = Stats{RequestsMade: sched.Spent(), Budget: budget,
		Throttled: sched.Throttles, Backoffs: sched.Backoffs, StoppedEarly: stoppedEarly}
	return rep, nil
}
