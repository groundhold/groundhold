// Package publish records contract authorship in the ledger (D74).
//
// The audit ledger recorded execution (apply.*, receipts, bindings) but
// not AUTHORSHIP: the event registry defined contract.published yet no
// verb produced it, so "who approved this contract" lived only in VCS.
// `groundhold publish` closes that — it appends contract.published with the
// contract's canonical hash and a HUMAN actor, so the decision chain
// answers the SOC2 change-approval question. It mutates only the ledger,
// never the cloud; it takes no lease (a decision event is not a
// mutation) and is idempotent-safe to re-run (a second identical publish
// is just another dated record of the same hash).
package publish

import (
	"fmt"
	"sort"

	"groundhold/internal/canonical"
	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
)

type Result struct {
	Status       string    `json:"status"` // published | refused
	Code         perr.Code `json:"code,omitempty"`
	ContractHash string    `json:"contractHash,omitempty"`
	Actor        string    `json:"actor,omitempty"`
	Events       []string  `json:"events"`
	Reasons      []string  `json:"reasons,omitempty"`
	Exit         int       `json:"-"`
}

func Run(c *contract.Contract, ledgerPath, actor, at string) *Result {
	res := &Result{Events: []string{}}
	refuse := func(code perr.Code, reason string) *Result {
		res.Status, res.Code, res.Reasons, res.Exit =
			"refused", code, []string{reason}, 2
		return res
	}
	if actor == "" {
		return refuse(perr.ConsentRequired,
			"publish records authorship — name the publisher with --actor")
	}
	h, err := canonical.HashContract(c)
	if err != nil {
		return refuse(perr.StructuralError, err.Error())
	}
	clock, err := ledger.ParseTs(at)
	if err != nil {
		return refuse(perr.StructuralError, fmt.Sprintf("bad --at: %v", err))
	}
	led, err := ledger.ReplayFile(ledgerPath)
	if err != nil {
		res.Status, res.Code, res.Reasons, res.Exit =
			"refused", perr.LedgerCorrupted, []string{err.Error()}, 5
		return res
	}
	if err := ledger.EnforceAnchor(ledgerPath, led); err != nil {
		res.Status, res.Code, res.Reasons, res.Exit =
			"refused", perr.LedgerCorrupted, []string{err.Error()}, 5
		return res
	}
	if clock < led.Clock {
		return refuse(perr.ClockRegress,
			"publish time precedes ledger history")
	}
	led.Clock = clock

	caps := make([]string, 0, len(c.Capabilities))
	for id := range c.Capabilities {
		caps = append(caps, id)
	}
	sort.Strings(caps)

	w := &ledger.Writer{Path: ledgerPath, Led: led, Env: c.Environment,
		Clock: clock, Actor: actor, ActorType: "human", Events: &res.Events}
	body := map[string]any{
		"contract": c.ID, "version": c.Version, "contractHash": h}
	if err := w.Append("contract.published", caps, body, 0); err != nil {
		res.Status, res.Code, res.Reasons, res.Exit =
			"refused", perr.LedgerCorrupted, []string{err.Error()}, 5
		return res
	}
	res.Status, res.ContractHash, res.Actor, res.Exit =
		"published", h, actor, 0
	return res
}
