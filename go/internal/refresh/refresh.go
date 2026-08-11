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
	"groundhold/internal/perr"
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
	// Notes (D558) carry the driver's own account of what it could NOT read on a
	// capability that refreshed successfully. Dropping them here is the worst of
	// the three sites the same `_` appeared in: refresh runs unattended on a
	// schedule, so nobody is watching a terminal when the sentence is lost, and
	// its entire job is keeping the proof honest.
	Notes []string `json:"notes,omitempty"`
	// Unreadable (D649) names a capability whose re-observation FAILED. It used to
	// land in Refreshed: observe.Run reports a failed read as Partial with a nil
	// error (D242 by design), refresh only looked at the error, and so an
	// unattended sweep over a provider that was entirely down reported every
	// capability refreshed while appending no events at all.
	Unreadable []CapIssue `json:"unreadable,omitempty"`
	// Partial mirrors observe's own field: at least one capability could not be
	// read this run. A cron reading this JSON has one boolean to alert on.
	Partial bool `json:"partial,omitempty"`
	// Code names the outcome the way every other JSON-emitting verb does
	// (spec/errors.md). A refresh that could not renew a proof leaves knowledge
	// about the bound world missing or stale, which is `observation-required`.
	Code  string `json:"code,omitempty"`
	Crawl Stats  `json:"crawl"`
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
		// D666: one predicate, shared with audit/plan/apply/forecast/posture. It
		// treats an unparseable observedAt as expired, which is what the loop's own
		// early return did.
		if ledger.ObservationExpired(r.ObservedAt, r.TTLSeconds, deadline) {
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
		unreadable := ""
		_, err := sched.Do(prov.Name(), func() pace.Result {
			ores, oerr := observe.Run(map[string]string{cap: bindings[cap]}, prov, at, ttlOverride, led, ledgerPath, true)
			if oerr != nil {
				return pace.Result{Outcome: pace.ServerError}
			}
			rep.Notes = append(rep.Notes, ores.Diagnostics...)
			// D649: a read that FAILED is not a refresh. observe returns nil here
			// and records nothing — the proof is untouched and still decaying — so
			// scoring this OK told the pacer a dead provider was a healthy sweep
			// and the breaker could never trip.
			for _, u := range ores.Unreadable {
				if u.Capability == cap {
					unreadable = u.Reason
					return pace.Result{Outcome: pace.ServerError}
				}
			}
			return pace.Result{Outcome: pace.OK}
		})
		if err != nil {
			// A read the pacer gave up on: say WHICH failure it was when the driver
			// gave us one, rather than only the pacer's summary of it.
			detail := err.Error()
			if unreadable != "" {
				detail = unreadable + " (" + err.Error() + ")"
				rep.Unreadable = append(rep.Unreadable, CapIssue{cap, detail})
				rep.Partial = true
			}
			rep.Skipped = append(rep.Skipped, CapIssue{cap, detail})
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
		if unreadable != "" {
			// The pacer's retries eventually returned without an error (attempts
			// exhausted), but nothing was read. Refreshed would be a lie.
			rep.Unreadable = append(rep.Unreadable, CapIssue{cap, unreadable})
			rep.Partial = true
			continue
		}
		rep.Refreshed = append(rep.Refreshed, cap)
	}
	rep.Crawl = Stats{RequestsMade: sched.Spent(), Budget: budget,
		Throttled: sched.Throttles, Backoffs: sched.Backoffs, StoppedEarly: stoppedEarly}
	if len(rep.Unreadable) > 0 {
		rep.Code = string(perr.ObservationRequired)
	}
	return rep, nil
}
