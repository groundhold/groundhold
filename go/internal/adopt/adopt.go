// Package adopt binds pre-existing resources to capabilities (D52).
// Adoption is the ONLY door for infrastructure Groundhold did not create:
// it mutates the ledger, never the cloud, and it must not lie — every
// candidate-declared attribute is checked against a live observation
// before the binding is written. Refusals use the same no-coercion
// comparison as the compiler: incomparable is a refusal, never a false.
package adopt

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/observe"
	"groundhold/internal/perr"
	"groundhold/internal/provider"
	"groundhold/internal/scalars"
	"groundhold/internal/verify"
)

// intentAttr is a NON-OBSERVABLE declared attribute adopt records as
// declared-intent (F-LC3 part 3): the candidate's value + provenance, carried
// into the ledger under provider.DeclaredIntentSource so provenance survives
// (invariant #3) without pretending the value was measured.
type intentAttr struct {
	cap   string
	path  string
	value any
	basis string // the candidate's provenance: declared | inferred
}

type Result struct {
	Status   string            `json:"status"` // adopted | refused
	Code     perr.Code         `json:"code,omitempty"`
	RunID    string            `json:"runId,omitempty"`
	Bindings map[string]string `json:"bindings,omitempty"`
	Events   []string          `json:"events,omitempty"`
	Reasons  []string          `json:"reasons,omitempty"`
	// Notes (D322) are facts the adoption OBSERVED but did not refuse on — today,
	// an `assumed` declaration the live reading contradicts. An assumed value is
	// deliberately exempt from the gate (it claims an assumption, not reality; D5
	// keeps the provenance and D195 lets policy gate satisfied-but-assumed), but
	// adopt is holding the contradicting observation in its hand at the one moment
	// designed to confront a declaration with the world. Skipping it silently is
	// the lie of omission the package's own first line forbids.
	Notes []string `json:"notes,omitempty"`
}

// Run adopts mapping (capability -> providerId) after the gates pass.
// The report must come from verifying the same candidate against the
// same contract — adoption without an executable candidate is refused.
// discoveryHash, when set, cites the discovery the adoption derives
// from (provenance root, D52).
func Run(c *contract.Contract, cand *contract.Candidate,
	report *verify.Report, mapping map[string]string,
	prov provider.Provider, led *ledger.Ledger, ledgerPath, at,
	discoveryHash string) (*Result, int) {
	refuse := func(code perr.Code, reasons ...string) (*Result, int) {
		return &Result{Status: "refused", Code: code, Reasons: reasons}, 2
	}
	if !report.Executable {
		return refuse(perr.NotExecutable,
			"candidate is not executable against the contract")
	}
	if len(mapping) == 0 {
		return refuse(perr.StructuralError,
			"nothing to adopt — pass --map capability=providerId")
	}

	caps := make([]string, 0, len(mapping))
	for capID := range mapping {
		caps = append(caps, capID)
	}
	sort.Strings(caps)

	// projections: no double adoption, in either direction
	bound := led.BoundProviderIDs()
	owner := map[string]string{}
	for capID, pid := range bound {
		owner[pid] = capID
	}
	var reasons []string
	for _, capID := range caps {
		pid := mapping[capID]
		if _, ok := cand.Capabilities[capID]; !ok {
			reasons = append(reasons, fmt.Sprintf(
				"%s: not declared in the candidate", capID))
			continue
		}
		if cur := bound[capID]; cur != "" {
			reasons = append(reasons, fmt.Sprintf(
				"%s: already bound to %s", capID, cur))
		}
		if led.PendingCount(capID) > 0 {
			reasons = append(reasons, fmt.Sprintf(
				"%s: in-flight operations must be reconciled first "+
					"(D29) — run resume", capID))
		}
		if by, ok := owner[pid]; ok && by != capID {
			reasons = append(reasons, fmt.Sprintf(
				"%s: providerId %s is already bound to %s", capID, pid, by))
		}
	}
	if len(reasons) > 0 {
		code := perr.BindingConflict
		for _, r := range reasons {
			if strings.Contains(r, "reconciled first") {
				code = perr.ReconcileRequired
				break
			}
		}
		return refuse(code, reasons...)
	}

	// competing-reconciler gate (D52 fail-closed): if the driver can report
	// a foreign continuous reconciler (ArgoCD/Helm/...) owning the object,
	// refuse LOUDLY rather than bind into an apply war. An error cannot prove
	// absence, so it refuses too. Drivers that do not implement it skip this.
	if cm, ok := prov.(provider.CompetingManagers); ok {
		var cReasons []string
		for _, capID := range caps {
			pid := mapping[capID]
			svc, _ := cand.Extras[capID]["service"].(string)
			managers, err := cm.CompetingManagers(svc, pid)
			if err != nil {
				cReasons = append(cReasons, fmt.Sprintf(
					"%s: cannot confirm no competing reconciler owns %s: %v",
					capID, pid, err))
				continue
			}
			if len(managers) > 0 {
				cReasons = append(cReasons, fmt.Sprintf(
					"%s: %s is owned by a competing reconciler (%s) — release it "+
						"there first, then adopt (groundhold will not fight a controller)",
					capID, pid, strings.Join(managers, ", ")))
			}
		}
		if len(cReasons) > 0 {
			return refuse(perr.BindingConflict, cReasons...)
		}
	}

	// adoption must not lie: observe NOW, compare every declared
	// attribute; unknown or incomparable refuses (four-valued honesty).
	// A non-observable declared attribute is INTENT, recorded with the
	// candidate's provenance after binding (F-LC3 part 3), never a lie.
	observations := map[string]map[string]any{}
	var intents []intentAttr
	var notes []string
	for _, capID := range caps {
		svc, _ := cand.Extras[capID]["service"].(string)
		obs, _, err := prov.Observe(svc, capID, mapping[capID])
		if err != nil {
			return refuse(perr.ProviderRefused,
				fmt.Sprintf("%s: observe failed: %v", capID, err))
		}
		byPath := map[string]any{}
		for _, o := range obs {
			byPath[o.Path] = o.Value
		}
		observations[capID] = byPath
		for path, pv := range cand.Capabilities[capID] {
			if pv.Scalar == nil {
				continue
			}
			if pv.Status == "assumed" {
				// an assumed value claims an ASSUMPTION, not reality —
				// provenance survives (D5); probes prove it after
				// adoption (D59), the gate confirms declared facts only.
				// D322: exempt from the REFUSAL, not from being said out loud. If
				// the live reading contradicts the assumption, the operator learns
				// it here rather than at some later audit.
				if got, ok := byPath[path]; ok {
					if obsScalar, perr := scalars.Parse(got); perr == nil {
						if eq, cerr := scalars.Operators["equals"](obsScalar, pv.Scalar); cerr == nil && !eq {
							notes = append(notes, fmt.Sprintf(
								"%s.%s: assumed %v but the live observation reads %v — "+
									"adopted anyway (an assumption is not a claim about "+
									"reality), but the assumption is wrong",
								capID, path, pv.Scalar.Raw, got))
						}
					}
				}
				continue
			}
			got, ok := byPath[path]
			if !ok {
				// F-LC3 part 3 (owner-decided): a NON-OBSERVABLE declared attribute
				// (the driver's observe emits no value for this path — cost.monthly,
				// a driver that cannot read replicas.minimum, ...) is INTENT, not a
				// lie. Adopt records it with the candidate's OWN provenance
				// (declared/inferred, never measured) so invariant #3 survives, rather
				// than refusing. The audit evidence lattice ranks it 0 — it satisfies
				// a static constraint but is rejected for a provider-api/probe method,
				// so intent never passes for measurement. Contrast the OBSERVABLE
				// mismatch below (got present, value differs): that IS a lie and still
				// refuses.
				intents = append(intents, intentAttr{
					cap: capID, path: path, value: pv.Scalar.Raw, basis: pv.Status})
				continue
			}
			obsScalar, err := scalars.Parse(got)
			if err != nil {
				reasons = append(reasons, fmt.Sprintf(
					"%s.%s: observation unparseable", capID, path))
				continue
			}
			var confirmed bool
			if pv.Scalar.Kind == scalars.Protocol {
				// A protocol (version) attribute is confirmed at the DECLARED
				// granularity, not by strict equality: a major-only declaration
				// (postgresql/16) is confirmed by any same-major reality
				// (postgresql/16.13) — the declared fact "PostgreSQL 16" is TRUE of a
				// 16.13 database; a minor/patch-precise declaration (postgresql/16.5)
				// is confirmed only to that precision, so 16.13 does NOT confirm 16.5
				// (adoption must not lie). No coercion (#2): a non-protocol observation
				// is incomparable; no new operator (#4).
				if obsScalar.Kind != scalars.Protocol {
					reasons = append(reasons, fmt.Sprintf(
						"%s.%s: observation incomparable with the declared value", capID, path))
					continue
				}
				confirmed = protocolConfirms(fmt.Sprint(pv.Scalar.Raw), fmt.Sprint(got))
			} else {
				eq, err := scalars.Operators["equals"](obsScalar, pv.Scalar)
				if err != nil {
					reasons = append(reasons, fmt.Sprintf(
						"%s.%s: observation incomparable with the declared "+
							"value", capID, path))
					continue
				}
				confirmed = eq
			}
			if !confirmed {
				reasons = append(reasons, fmt.Sprintf(
					"%s.%s: declared %v but reality says %v — fix the "+
						"candidate or the resource, adoption must not lie",
					capID, path, pv.Scalar.Raw, got))
			}
		}
	}
	if len(reasons) > 0 {
		return refuse(perr.AdoptionMismatch, reasons...)
	}

	// gates passed: bind under a lease, then record what we saw
	clock, err := ledger.ParseTs(at)
	if err != nil {
		return refuse(perr.StructuralError, fmt.Sprintf("bad --at: %v", err))
	}
	if clock > led.Clock {
		led.Clock = clock
	}
	seed := sha256.Sum256([]byte("adopt:" + at + ":" + strings.Join(caps, ",")))
	runID := hex.EncodeToString(seed[:])[:12]
	res := &Result{Status: "adopted", RunID: runID,
		Bindings: map[string]string{}, Events: []string{}, Notes: notes}
	w := &ledger.Writer{Path: ledgerPath, Led: led, Env: c.Environment,
		Clock: clock, Actor: "groundhold-adopt", Events: &res.Events}

	tok, err := w.AppendLease(caps,
		map[string]any{"ttlSeconds": 300, "adoptRunId": runID})
	if err != nil {
		code := perr.LeaseConflict
		if strings.Contains(err.Error(), "regresses") {
			code = perr.ClockRegress
		}
		return refuse(code, err.Error())
	}
	for _, capID := range caps {
		// same body shape apply writes — projections must not know who
		// bound the capability, only that it is bound
		resource := map[string]any{
			"id": "primary", "type": targetOf(cand, prov, capID),
			"providerId": mapping[capID], "generation": 1,
			"origin": "adopted",
		}
		if discoveryHash != "" {
			resource["adoptedFromDiscoveryHash"] = discoveryHash
		}
		if err := w.Append("binding.updated", []string{capID},
			map[string]any{
				"adoptRunId":  runID,
				"capability":  capID,
				"environment": c.Environment,
				"provider":    map[string]any{"name": prov.Name()},
				"resources":   []any{resource},
			}, tok); err != nil {
			_ = w.Append("lease.released", caps, nil, tok)
			return refuse(perr.LedgerCorrupted, err.Error())
		}
		res.Bindings[capID] = mapping[capID]
	}
	if err := w.Append("lease.released", caps, nil, tok); err != nil {
		return refuse(perr.LedgerCorrupted, err.Error())
	}

	// knowledge events: the observations adoption was decided on. Use
	// w.Led, not led: commitUnderLock replaced the writer's ledger with a
	// fresh replay that has the new bindings folded — the original `led`
	// still lacks them, so its BoundServices() would hand observe an empty
	// service and a real driver refuses (no default).
	if _, err := observe.Run(res.Bindings, prov, at, 0, w.Led,
		ledgerPath, true); err != nil {
		return refuse(perr.LedgerCorrupted, "bindings written but observation recording "+
			"failed: "+err.Error())
	}
	res.Events = append(res.Events, "observation.recorded")

	// F-LC3 part 3: record the NON-OBSERVABLE declared attributes as
	// declared-intent — one observation.recorded per capability, provenance
	// preserved (basis), source DeclaredIntentSource so the audit lattice and the
	// compiler treat it as intent, never measured reality.
	if len(intents) > 0 {
		byCap := map[string][]intentAttr{}
		capOrder := make([]string, 0)
		for _, ia := range intents {
			if _, seen := byCap[ia.cap]; !seen {
				capOrder = append(capOrder, ia.cap)
			}
			byCap[ia.cap] = append(byCap[ia.cap], ia)
		}
		sort.Strings(capOrder)
		for _, capID := range capOrder {
			list := byCap[capID]
			sort.Slice(list, func(i, j int) bool { return list[i].path < list[j].path })
			obsBodies := make([]any, 0, len(list))
			for _, ia := range list {
				obsBodies = append(obsBodies, map[string]any{
					"kind": "Observation", "capability": capID,
					"path": ia.path, "value": ia.value,
					"source": provider.DeclaredIntentSource, "derivation": ia.basis,
					"observedAt": at, "ttlSeconds": 86400,
				})
			}
			// w carries the res.Events sink, so Append records the event type —
			// no manual append (that would double-count it).
			if err := w.Append("observation.recorded", []string{capID},
				map[string]any{
					"provider":     map[string]any{"name": prov.Name()},
					"resource":     map[string]any{"providerId": res.Bindings[capID]},
					"observations": obsBodies,
				}, 0); err != nil {
				return refuse(perr.LedgerCorrupted, "bindings written but declared-intent "+
					"recording failed: "+err.Error())
			}
		}
	}
	return res, 0
}

// targetOf mirrors the compiler's target derivation: provider.service
// from candidate extras when declared, otherwise the adoption marker.
// protocolConfirms reports whether an observed protocol/version string confirms a
// DECLARED one at the declared's granularity: the engine names must match, and
// every version component the declaration specifies must equal the observation's
// (which may be MORE precise). So "postgresql/16" is confirmed by "postgresql/16.13"
// (major-only declaration), but "postgresql/16.5" is NOT confirmed by
// "postgresql/16.13", and a declaration more precise than reality is never
// confirmed. Honest by construction — adoption records only a statement true of
// reality (F8).
func protocolConfirms(declared, observed string) bool {
	dn, dv := splitProto(declared)
	on, ov := splitProto(observed)
	if dn != on || len(dv) > len(ov) {
		return false
	}
	for i := range dv {
		if dv[i] != ov[i] {
			return false
		}
	}
	return true
}

// splitProto splits "name/major.minor.patch" into the name and the version
// components ("postgresql/16.13" -> "postgresql", ["16","13"]).
func splitProto(s string) (name string, ver []string) {
	parts := strings.SplitN(s, "/", 2)
	name = parts[0]
	if len(parts) == 2 && parts[1] != "" {
		ver = strings.Split(parts[1], ".")
	}
	return name, ver
}

func targetOf(cand *contract.Candidate, prov provider.Provider,
	capID string) string {
	extras := cand.Extras[capID]
	p, _ := extras["provider"].(string)
	svc, _ := extras["service"].(string)
	if p != "" && svc != "" {
		return fmt.Sprintf("%s.%s/%s", p, svc, capID)
	}
	return prov.Name() + ".adopted/" + capID
}

// Unadopt reverses a mistaken adoption: it removes the BINDING, never
// the resource (contrast D47 retirement, which destroys). The prior
// identity is recorded verbatim so the release is auditable and the
// resource can be re-adopted.
func Unadopt(capability string, led *ledger.Ledger, ledgerPath,
	environment, at string) (*Result, int) {
	refuse := func(code perr.Code, reasons ...string) (*Result, int) {
		return &Result{Status: "refused", Code: code, Reasons: reasons}, 2
	}
	bound := led.BoundProviderIDs()
	pid := bound[capability]
	if pid == "" {
		return refuse(perr.BindingConflict, fmt.Sprintf(
			"%s: not bound — nothing to unadopt", capability))
	}
	// F2 (D192): unadopt reverses an ADOPTION only. A capability groundhold
	// CREATED (origin != adopted) must not be released this way — dropping
	// the binding would make the ledger forget a live, groundhold-owned resource
	// (a future discover then sees it as a shadow). Retire/delete it instead.
	if !led.AdoptedCapabilities()[capability] {
		return refuse(perr.BindingConflict, fmt.Sprintf(
			"%s: bound to %s but NOT adopted (groundhold created it) — unadopt "+
				"reverses an adoption; retire or delete a created resource, "+
				"never abandon it", capability, pid))
	}
	// F5 (D192): mirror adopt's D29 gate — releasing a binding with an
	// operation still in flight orphans its receipt (nothing left to resume
	// against). Reconcile first.
	if led.PendingCount(capability) > 0 {
		return refuse(perr.ReconcileRequired, fmt.Sprintf(
			"%s: in-flight operations must be reconciled first (D29) — run resume",
			capability))
	}
	gen := led.BoundGenerations()[capability]
	clock, err := ledger.ParseTs(at)
	if err != nil {
		return refuse(perr.StructuralError, fmt.Sprintf("bad --at: %v", err))
	}
	if clock > led.Clock {
		led.Clock = clock
	}
	seed := sha256.Sum256([]byte("unadopt:" + at + ":" + capability))
	runID := hex.EncodeToString(seed[:])[:12]
	res := &Result{Status: "unadopted", RunID: runID,
		Bindings: map[string]string{}, Events: []string{}}
	w := &ledger.Writer{Path: ledgerPath, Led: led, Env: environment,
		Clock: clock, Actor: "groundhold-adopt", Events: &res.Events}
	caps := []string{capability}
	tok, err := w.AppendLease(caps,
		map[string]any{"ttlSeconds": 300, "adoptRunId": runID})
	if err != nil {
		code := perr.LeaseConflict
		if strings.Contains(err.Error(), "regresses") {
			code = perr.ClockRegress
		}
		return refuse(code, err.Error())
	}
	if err := w.Append("binding.updated", caps, map[string]any{
		"adoptRunId":  runID,
		"capability":  capability,
		"environment": environment,
		"resources":   []any{},
		"unadopted": map[string]any{
			"providerId": pid, "generation": gen,
		},
	}, tok); err != nil {
		_ = w.Append("lease.released", caps, nil, tok)
		return refuse(perr.LedgerCorrupted, err.Error())
	}
	if err := w.Append("lease.released", caps, nil, tok); err != nil {
		return refuse(perr.LedgerCorrupted, err.Error())
	}
	return res, 0
}
