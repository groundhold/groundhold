// Package observe implements `groundhold observe` (D44): read bound
// resources through the provider's reverse mapping and emit Observation
// documents. Observe only what we own — bindings are the input, either
// replayed from the ledger or given directly. Recording appends ONE
// observation.recorded event per capability (knowledge events are
// decision-head-neutral, D41 — fresh observations never invalidate
// anyone's plan).
package observe

import (
	"fmt"
	"sort"

	"groundhold/internal/ledger"
	"groundhold/internal/provider"
)

type Doc struct {
	Capability string `json:"capability"`
	Path       string `json:"path"`
	Value      any    `json:"value"`
	Source     string `json:"source"`
	Derivation string `json:"derivation"`
	ObservedAt string `json:"observedAt"`
	TTLSeconds int    `json:"ttlSeconds"`
}

// Unreadable records a capability whose primary read failed this run (D242). It
// is NOT an observation and NEVER a fabricated value — absence of evidence is the
// signal (verify resolves the gap to unknown; the staleness gate refuses
// observation-required). Reason is free diagnostic text (a request id / HTTP
// status), never hashed and never an event.
type Unreadable struct {
	Capability string `json:"capability"`
	Reason     string `json:"reason"`
}

type Result struct {
	Observations []Doc    `json:"observations"`
	Diagnostics  []string `json:"diagnostics,omitempty"`
	// Partial (D242) is true when at least one bound capability could not be read
	// this run. observe stays exit 0 and best-effort — it reported reality,
	// including the part that reads "this capability is currently unreadable";
	// enforcement is downstream (verify unknown, plan observation-required).
	Partial    bool         `json:"partial,omitempty"`
	Unreadable []Unreadable `json:"unreadable,omitempty"`
}

// layered TTL defaults (D44): immutable-ish provider facts age slowly,
// mutable security posture ages fast. --ttl overrides everything.
var longTTL = map[string]bool{
	"engine.protocol": true, "location.region": true,
	"service.managed": true, "encryption.atRest": true,
}

func ttlFor(path string, override int) int {
	if override > 0 {
		return override
	}
	if longTTL[path] {
		return 86400
	}
	return 900
}

func Run(bindings map[string]string, prov provider.Provider, at string,
	ttlOverride int, led *ledger.Ledger, ledgerPath string,
	record bool) (*Result, error) {
	if record && (led == nil || ledgerPath == "") {
		return nil, fmt.Errorf("--record requires --ledger")
	}
	caps := make([]string, 0, len(bindings))
	for c := range bindings {
		caps = append(caps, c)
	}
	sort.Strings(caps)

	res := &Result{Observations: []Doc{}}
	// D76: dispatch on the bound service (from the ledger). A bindings-file
	// observe with no ledger has no service — the fake ignores it, a real
	// driver refuses (no default).
	services := map[string]string{}
	if led != nil {
		services = led.BoundServices()
	}
	for _, cap := range caps {
		obs, diags, err := prov.Observe(services[cap], cap, bindings[cap])
		if err != nil {
			// D242: a failed PRIMARY read is evidence about THIS capability only —
			// it must not discard the observations already gathered for the others
			// (the observe-side twin of never collapsing unknown). Record it as
			// unreadable + a diagnostic and continue; the capability yields no
			// observations, so verify resolves it to unknown and the staleness gate
			// refuses observation-required. A read failure is never an observation
			// (D59) and never a fabricated value. (Only a ledger WRITE failure below
			// is fatal — that is a broken recording apparatus, not missing evidence.)
			res.Partial = true
			res.Unreadable = append(res.Unreadable, Unreadable{Capability: cap, Reason: err.Error()})
			res.Diagnostics = append(res.Diagnostics, cap+": unreadable: "+err.Error())
			// D1152: the failure goes into the LEDGER, not only into this result. It
			// used to live on stdout alone, so the next `plan` saw an observation
			// ageing out and could not see that the last READ had failed — and said
			// "observation is stale — re-observe first", which is true, useless, and
			// loops forever when the read cannot succeed. Recording it is the move D59
			// made for probe.failed: a failed measurement is knowledge, and it is never
			// an observation. It records NOTHING about the resource's state — absence
			// of evidence stays the signal (D242).
			if record {
				if rerr := recordFailure(led, ledgerPath, cap, at,
					prov.Name(), bindings[cap], err.Error()); rerr != nil {
					return nil, rerr
				}
			}
			continue
		}
		for _, d := range diags {
			res.Diagnostics = append(res.Diagnostics, cap+": "+d)
		}
		sort.Slice(obs, func(i, j int) bool { return obs[i].Path < obs[j].Path })
		docs := make([]Doc, 0, len(obs))
		for _, o := range obs {
			docs = append(docs, Doc{
				Capability: cap, Path: o.Path, Value: o.Value,
				Source: "provider-api", Derivation: o.Derivation,
				ObservedAt: at, TTLSeconds: ttlFor(o.Path, ttlOverride),
			})
		}
		// D283: a driver declaring typed outputs (D226) also re-reads them for a
		// BOUND resource, and observe records each as "outputs.<name>" — the
		// observation the compiler's fold branch resolves a $ref against. A
		// failed or invalid outputs read is a DIAGNOSTIC, never a fabricated
		// value: without the record, a fold refuses observation-required —
		// absence of evidence stays the signal (D242).
		outDocs, outFail := outputDocs(prov, services[cap], cap,
			bindings[cap], at, ttlOverride, res)
		docs = append(docs, outDocs...)
		if outFail != "" && record {
			// D1153: durable, like the primary-read failure — the producer's own
			// state was read fine, so this records the OUTPUTS failure and nothing
			// else. The observation.recorded below still carries what WAS read.
			if rerr := recordFailure(led, ledgerPath, cap, at,
				prov.Name(), bindings[cap], outFail); rerr != nil {
				return nil, rerr
			}
		}
		sort.Slice(docs, func(i, j int) bool { return docs[i].Path < docs[j].Path })
		res.Observations = append(res.Observations, docs...)

		// Record even when docs is EMPTY: a bound capability whose observer read
		// cleanly but yielded no observable attributes still leaves a trace, so the
		// compiler can tell "observed but blind" (isolate) from "never observed"
		// (re-observe). A read FAILURE (err above) is different — it continues as
		// Unreadable and records nothing (absence of evidence stays the signal, D242).
		if record {
			if err := recordEvent(led, ledgerPath, cap, at, prov.Name(),
				bindings[cap], docs); err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}

// recordEvent: one observation.recorded per capability per run (D44) —
// per-path events would bloat the ledger and churn full heads.
func recordEvent(led *ledger.Ledger, path, cap, at, providerName,
	providerID string, docs []Doc) error {
	clock, err := ledger.ParseTs(at)
	if err != nil {
		return err
	}
	obsBodies := make([]any, 0, len(docs))
	for _, d := range docs {
		obsBodies = append(obsBodies, map[string]any{
			"kind": "Observation", "capability": d.Capability,
			"path": d.Path, "value": d.Value, "source": d.Source,
			"derivation": d.Derivation, "observedAt": d.ObservedAt,
			"ttlSeconds": d.TTLSeconds,
		})
	}
	// linearizable append (D67): re-replays under the lock so prev
	// pins the CURRENT head — building it from a stale in-memory ledger
	// (e.g. after an adopt's own commits) forged prev=genesis and broke
	// the hash chain (C2 caught it).
	// The event's envelope carries the environment the capability's own
	// history declares — "observed" is a derivation, not an environment,
	// and a sentinel there broke every environment-scoped consumer.
	w := &ledger.Writer{Path: path, Led: led, Env: led.Environments[cap],
		Clock: clock, Actor: "groundhold-observe"}
	return w.Append("observation.recorded", []string{cap},
		map[string]any{
			"provider":     map[string]any{"name": providerName},
			"resource":     map[string]any{"providerId": providerID},
			"observations": obsBodies,
		}, 0)
}

// recordFailure appends the D1152 event: this bound capability could not be read
// this run, and why. It carries no observations by construction — the whole point
// is that nothing about the resource's state was learned. `plan` reads it to tell
// a stale reading apart from a failing one, so its refusal can name the cause
// instead of prescribing a re-observe that cannot work.
func recordFailure(led *ledger.Ledger, path, cap, at, providerName,
	providerID, reason string) error {
	clock, err := ledger.ParseTs(at)
	if err != nil {
		return err
	}
	w := &ledger.Writer{Path: path, Led: led, Env: led.Environments[cap],
		Clock: clock, Actor: "groundhold-observe"}
	return w.Append("observation.failed", []string{cap},
		map[string]any{
			"provider":    map[string]any{"name": providerName},
			"resource":    map[string]any{"providerId": providerID},
			"reason":      reason,
			"attemptedAt": at,
		}, 0)
}

// outputDocs re-reads a bound resource's DECLARED typed outputs (D283) and
// shapes them as observations under "outputs.<name>". Only declared names,
// each kind-checked — a missing or wrong-kinded declared output drops the
// WHOLE set with a diagnostic (a partial output set could fold one operand
// and starve its sibling mid-plan; all-or-nothing keeps the refusal at plan
// time, observation-required, where it is cheap).
// D1153: returns the failure reason alongside the docs. A failed outputs read is a
// failed READ — the caller records it exactly like a failed primary read (D1152), so
// a `$ref` to this producer can be refused by NAME instead of by symptom.
func outputDocs(prov provider.Provider, service, cap, providerID, at string,
	ttlOverride int, res *Result) ([]Doc, string) {
	op, isProducer := prov.(provider.OutputProducer)
	rd, isReader := prov.(provider.OutputReader)
	if !isProducer || !isReader {
		return nil, ""
	}
	specs := op.OutputsFor(service)
	if len(specs) == 0 {
		return nil, ""
	}
	raw, err := rd.ReadOutputs(service, providerID)
	if err != nil {
		// D1153: this is a READ that failed, and it was neither marked Partial nor
		// recorded — so the run looked complete, the ledger kept no outputs for the
		// producer, and a `$ref` to it refused with "no outputs.<name> observation —
		// re-observe first". Re-observing fails the same way: the same loop D1152
		// closed for the primary read, one field over. Reported from the field as
		// "$ref works as a literal and refuses as a reference".
		res.Partial = true
		res.Unreadable = append(res.Unreadable,
			Unreadable{Capability: cap, Reason: "outputs: " + err.Error()})
		res.Diagnostics = append(res.Diagnostics,
			cap+": outputs unreadable (references to this producer will refuse "+
				"observation-required): "+err.Error())
		return nil, "outputs: " + err.Error()
	}
	docs := make([]Doc, 0, len(specs))
	// D774, from the field: one unreadable output discarded EVERY readable one. The
	// driver had just adopted a function BY its ARN and then recorded no outputs at all,
	// including that ARN, because a second declared output was absent — so every $ref to
	// the function refused and the plan blocked by a route that had nothing to do with
	// the missing value. The reporter's sentence: "nie umiem jednego, więc nie zapisuję
	// nic" zamienia lukę w blokadę.
	//
	// Record what was read; name what was not. A consumer that needs the missing output
	// still refuses AT THE POINT OF USE ("bound producer has no outputs.X observation"),
	// which is where the refusal belongs — not over the outputs that were there.
	for _, s := range specs {
		v, ok := raw[s.Name]
		if !ok {
			if !s.Conditional {
				res.Diagnostics = append(res.Diagnostics, cap+": declared output "+
					s.Name+" missing from the driver read — recording the outputs that "+
					"were readable; a $ref to this one will refuse where it is used")
			}
			continue
		}
		got, kindErr := provider.OutputValueOfKind(v, s.Kind)
		if kindErr != "" {
			res.Diagnostics = append(res.Diagnostics, cap+": declared output "+
				s.Name+" "+kindErr+" — not recorded; the readable outputs are")
			continue
		}
		docs = append(docs, Doc{
			Capability: cap, Path: "outputs." + s.Name, Value: got,
			Source: "provider-api", Derivation: "measured",
			ObservedAt: at, TTLSeconds: ttlFor("outputs."+s.Name, ttlOverride),
		})
	}
	return docs, ""
}
