// Package probe runs outcome probes (D59): measurements that prove
// OUTCOMES (a connection attempt, a restore test) rather than reading
// configuration. Probes feed the SAME observation stream everything
// else consumes — derivation "measured", source "probe" — so verify
// and audit stay untouched; a probe crash is probe.failed, never an
// observation (no reality was measured). Probes are expensive and
// sometimes intrusive: they never run implicitly, and intrusive ones
// need BOTH the operator flag and the contract's autonomy consent.
package probe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

type Measurement struct {
	Capability string `json:"capability"`
	Path       string `json:"path"`
	Value      any    `json:"value"`
	Method     string `json:"method"`
	Evidence   string `json:"evidence,omitempty"`
	Intrusive  bool   `json:"intrusive,omitempty"`
}

type Failure struct {
	Capability string `json:"capability"`
	Path       string `json:"path"`
	Method     string `json:"method"`
	Reason     string `json:"reason"`
	Retryable  bool   `json:"retryable"`
}

type Result struct {
	Status       string        `json:"status"` // probed | refused
	Code         perr.Code     `json:"code,omitempty"`
	RunID        string        `json:"runId,omitempty"`
	Measurements []Measurement `json:"measurements"`
	Failures     []Failure     `json:"failures"`
	Events       []string      `json:"events"`
	Reasons      []string      `json:"reasons,omitempty"`
	Exit         int           `json:"-"`
}

func allowsIntrusive(c *contract.Contract, capID string) bool {
	allowed, _ := c.Autonomy["allow_intrusive_probes"].([]any)
	for _, it := range allowed {
		if s, _ := it.(string); s == capID {
			return true
		}
	}
	return false
}

// Run probes bound capabilities (optionally scoped to one). Intrusive
// probing needs the DOUBLE consent: the operator's flag AND the
// contract's allow_intrusive_probes — a typo must not authorize a
// restore test (review verdict, D59).
func Run(c *contract.Contract, led *ledger.Ledger, ledgerPath string,
	prov provider.Provider, at, onlyCap string, allowIntrusive,
	record bool) *Result {
	res0 := &Result{Measurements: []Measurement{}, Failures: []Failure{},
		Events: []string{}}
	refuse := func(code perr.Code, reasons ...string) *Result {
		res0.Status, res0.Code, res0.Reasons, res0.Exit =
			"refused", code, reasons, 2
		return res0
	}
	prober, ok := prov.(provider.Prober)
	if !ok {
		return refuse(perr.UnsupportedOperation,
			fmt.Sprintf("provider %s has no probes", prov.Name()))
	}
	bound := led.BoundProviderIDs()
	caps := make([]string, 0, len(bound))
	for capID := range bound {
		if onlyCap == "" || capID == onlyCap {
			caps = append(caps, capID)
		}
	}
	sort.Strings(caps)
	if len(caps) == 0 {
		return refuse(perr.BindingConflict, "nothing bound to probe")
	}
	clock, err := ledger.ParseTs(at)
	if err != nil {
		return refuse(perr.StructuralError, fmt.Sprintf("bad --at: %v", err))
	}
	if clock > led.Clock {
		led.Clock = clock
	}
	seed := sha256.Sum256([]byte("probe:" + at + ":" +
		fmt.Sprintf("%v", caps)))
	runID := hex.EncodeToString(seed[:])[:12]
	res := res0
	res.Status, res.RunID, res.Exit = "probed", runID, 0
	w := &ledger.Writer{Path: ledgerPath, Led: led, Env: c.Environment,
		Clock: clock, Actor: "groundhold-probe", Events: &res.Events}

	services := led.BoundServices()
	for _, capID := range caps {
		intrusiveOK := allowIntrusive && allowsIntrusive(c, capID)
		outcome, err := prober.Probe(services[capID], capID, bound[capID], intrusiveOK)
		if err != nil {
			return refuse(perr.ProviderRefused,
				fmt.Sprintf("%s: probe error: %v", capID, err))
		}
		var obsBodies []any
		for _, m := range outcome.Measurements {
			// framework backstop (D188): the double consent is computed here
			// but honored inside the driver — a driver that returns an
			// INTRUSIVE measurement without consent (a bug, or a hostile
			// driver) must not launder it into the observation stream as
			// measured evidence. Refuse the run rather than trust every
			// driver to self-police ("a typo must not authorize a restore
			// test" — enforced in depth, not only at the driver).
			if m.Intrusive && !intrusiveOK {
				return refuse(perr.ProviderRefused, fmt.Sprintf(
					"%s: driver returned an intrusive measurement for %q but "+
						"double consent (operator flag + contract "+
						"allow_intrusive_probes) was not granted — refusing",
					capID, m.Path))
			}
			res.Measurements = append(res.Measurements, Measurement{
				Capability: capID, Path: m.Path, Value: m.Value,
				Method: m.Method, Evidence: m.Evidence,
				Intrusive: m.Intrusive})
			obsBodies = append(obsBodies, map[string]any{
				"kind": "Observation", "capability": capID,
				"path": m.Path, "value": m.Value,
				"source": "probe", "derivation": "measured",
				"method": m.Method, "evidence": m.Evidence,
				"probeRunId": runID,
				"observedAt": at, "ttlSeconds": 900,
			})
		}
		if record && len(obsBodies) > 0 {
			if err := w.Append("observation.recorded", []string{capID},
				map[string]any{
					"provider":     map[string]any{"name": prov.Name()},
					"resource":     map[string]any{"providerId": bound[capID]},
					"observations": obsBodies,
				}, 0); err != nil {
				return refuse(perr.LedgerCorrupted, err.Error())
			}
		}
		for _, f := range outcome.Failures {
			res.Failures = append(res.Failures, Failure{
				Capability: capID, Path: f.Path, Method: f.Method,
				Reason: f.Reason, Retryable: f.Retryable})
			if record {
				if err := w.Append("probe.failed", []string{capID},
					map[string]any{
						"path": f.Path, "method": f.Method,
						"reason": f.Reason, "retryable": f.Retryable,
						"probeRunId": runID,
					}, 0); err != nil {
					return refuse(perr.LedgerCorrupted, err.Error())
				}
			}
		}
	}
	return res
}
