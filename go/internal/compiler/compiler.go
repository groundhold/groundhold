// Package compiler turns a VERIFIED candidate into a Sealed Plan (D36,
// D39). No Terraform on the execution path: the plan's actions are what
// the executor will drive against provider APIs directly.
//
// The compiler is a pure, deterministic function of its inputs — same
// contract, candidate and vocabularies always produce byte-identical
// plans (idempotency keys derive from the candidate hash, never from
// randomness or time).
//
// The compiler classifies each capability against ledger reality
// (bindings, fresh observations, deposed orphans) and emits the fitting
// action — create, update (D46), replace (D48), retire/delete (D47) or
// a deposed cleanup (D71) — each with a conservative, table-driven risk
// vector. It refuses to compile anything that is not executable: the
// thesis, enforced at one more layer.
package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/policy"
	"groundhold/internal/provider"
	"groundhold/internal/scalars"
	"groundhold/internal/verify"
	"groundhold/internal/vocab"
)

// Sentinel refusal texts — porcelain (converge) routes on these as
// FULL first-line prefixes; user-controlled ids cannot forge them.
const ErrNothingToChange = "nothing to change — the world already " +
	"converges with the candidate; a plan exists to change things"

const ErrNothingDeposed = "nothing deposed — the ledger records no " +
	"orphaned identities; a deposed plan exists to clean up after a " +
	"failed replacement"

const Version = "groundhold-go/0.1.0"

type Money struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

// RefusalError is a compile refusal that carries the structured facts a CLI needs
// to build an actionable `next` (D230): the offending capability for a consent
// gate, the $ref location for an invalid reference. Error() returns the human
// reason (so planRefusalCode's string mapping still works); plain fmt.Errorf
// refusals stay plain and get only the generic remediation.
type RefusalError struct {
	Reason     string
	Capability string // consent-required: the stateful capability
	RefPointer string // reference-invalid: the $ref location in the candidate
	Note       string // reference-invalid: structured "what's wrong" prose
}

func (e *RefusalError) Error() string { return e.Reason }

type Risk struct {
	Reversibility       string `json:"reversibility"`
	DataLoss            string `json:"dataLoss"`
	Downtime            string `json:"downtime"`
	SecurityExposure    string `json:"securityExposure"`
	CostDelta           Money  `json:"costDelta"`
	IdentityReplacement bool   `json:"identityReplacement"`
}

// Change is a reviewed transition (D46): from/to are denormalized
// decision-record fields — the patch source of truth stays the pinned
// candidate, scoped by path.
type Change struct {
	Path   string `json:"path"`
	From   any    `json:"from"`
	To     any    `json:"to"`
	Caveat string `json:"caveat,omitempty"`
}

// ReplaceInfo (D48): a replacement create names WHAT it replaces and WHY
// — the immutable paths that forced it. Reviewers see the reason, not a
// bare create/delete pair.
type ReplaceInfo struct {
	ProviderID string   `json:"providerId"`
	Generation int      `json:"generation"`
	Because    []Change `json:"because"`
}

type Action struct {
	ID               string       `json:"id"`
	Capability       string       `json:"capability"`
	Operation        string       `json:"operation"`
	Target           string       `json:"target"`
	IdempotencyKey   string       `json:"idempotencyKey"`
	DependsOn        []string     `json:"dependsOn,omitempty"`
	Changes          []Change     `json:"changes,omitempty"`
	TargetProviderID string       `json:"targetProviderId,omitempty"` // D47
	TargetGeneration int          `json:"targetGeneration,omitempty"` // D47/D48
	Replaces         *ReplaceInfo `json:"replaces,omitempty"`         // D48
	// Deposed marks a delete whose target is an ORPHAN (D71): the pin
	// is validated against the deposed projection, not the binding —
	// which by definition points at the orphan's successor.
	Deposed bool `json:"deposed,omitempty"`
	// RequiredPermissions (D75): the provider permissions this action's
	// driver call sequence needs — deterministic, sorted, deduped, from
	// provider.PermissionsFor. Enters the plan hash; the executor preflights
	// the union against the acting identity before mutating.
	RequiredPermissions []string `json:"requiredPermissions,omitempty"`
	// References (D226/F13) are intra-plan output references: an operand of
	// THIS action is another same-plan capability's typed output, resolved from
	// the producer's receipt at apply (refuse-before-mutate). Only the symbolic
	// structure enters the plan hash — never a runtime value — so the plan stays
	// restart-stable. Sorted by Slot for determinism.
	References []OperandRef `json:"references,omitempty"`
	// Folds (D283) are references RESOLVED AT COMPILE: the producer is already
	// BOUND, so the operand folds to a LITERAL from a fresh "outputs.<name>"
	// observation (D45 projection, TTL-gated against --at, N1). The literal is
	// part of the sealed decision — it enters the plan hash, and a new
	// observation yields a new plan — and apply re-checks the backing
	// observation (value still operative, still fresh) before any mutation.
	Folds []OperandFold `json:"folds,omitempty"`
	Risk  Risk          `json:"risk"`
}

// OperandFold (D283) pins ONE compile-folded reference: the consumer Slot,
// the bound producer Capability + Output, the folded literal Value, and the
// observation identity (ObservedAt + TTLSeconds) apply re-judges freshness
// against at ITS OWN --at — a fold sealed fresh must not apply decayed.
type OperandFold struct {
	Slot       string `json:"slot"`
	Capability string `json:"capability"`
	Output     string `json:"output"`
	Value      any    `json:"value"`
	ObservedAt string `json:"observedAt"`
	TTLSeconds int    `json:"ttlSeconds"`
}

// OperandRef (D226) pins ONE reference: the consumer operand Slot, the producer
// create action (ProducerAction — the id capID:gN, which pins the generation
// under D48 replace), the producer Capability + Output name, and the output Kind
// (a scalars.Kind, checked again at resolve). No transform, no default — the
// closed-operator-set wall (invariant #4).
type OperandRef struct {
	Slot           string `json:"slot"`
	ProducerAction string `json:"producerAction"`
	Capability     string `json:"capability"`
	Output         string `json:"output"`
	Kind           string `json:"kind"`
}

type Toolchain struct {
	Compiler string `json:"compiler"`
	Spec     string `json:"spec"`
}

// candAttrs is the raw attribute map for a capability — feeds the
// attribute-aware permission table (D75/D76: e.g. a public Cloud Run
// service needs IAM permissions a private one does not).
func candAttrs(cand *contract.Candidate, capID string) map[string]any {
	out := map[string]any{}
	for p, v := range cand.Capabilities[capID] {
		if v.Scalar != nil {
			out[p] = v.Scalar.Raw
		}
	}
	return out
}

// nonProjectionAttrs is candAttrs minus the attributes the vocabulary marks as
// NOT resource state (evidence: projection/probe — cost.monthly, recovery.rto).
// A driver's operand builder REFUSES any attribute it cannot map, and a
// projection maps to no provider setting BY DESIGN (D311); it must therefore be
// filtered out before it reaches a driver — exactly as the apply boundary
// (attributesRaw) already does. Without a vocabulary nothing is filtered.
func nonProjectionAttrs(cand *contract.Candidate, capID string, voc vocab.Vocabulary) map[string]any {
	out := map[string]any{}
	for p, v := range cand.Capabilities[capID] {
		if v.Scalar == nil {
			continue
		}
		if isProjectionAttr(voc, p) {
			continue
		}
		out[p] = v.Scalar.Raw
	}
	return out
}

type Provider struct {
	Name    string `json:"name"`
	Project string `json:"project,omitempty"` // pinned identity (D28)
}

type Reads struct {
	ContractHash  string            `json:"contractHash"`
	CandidateHash string            `json:"candidateHash"`
	Heads         map[string]string `json:"heads"`
	Vocabularies  map[string]string `json:"vocabularies,omitempty"`
	Toolchain     Toolchain         `json:"toolchain"`
	Provider      *Provider         `json:"provider,omitempty"`
}

type Precondition struct {
	Type string `json:"type"`
}

type Body struct {
	Contract      string                 `json:"contract"`
	Environment   string                 `json:"environment,omitempty"`
	Reads         Reads                  `json:"reads"`
	Writes        []string               `json:"writes"`
	Actions       []Action               `json:"actions"`
	Witnessed     []WitnessRecord        `json:"witnessed,omitempty"`  // D177
	Blocked       []BlockedCapability    `json:"blocked,omitempty"`    // D249
	Unverified    []UnverifiedCapability `json:"unverified,omitempty"` // D249
	NoOp          []NoOpCapability       `json:"noop,omitempty"`       // Part B
	Preconditions []Precondition         `json:"preconditions"`
}

// BlockedCapability (D249) is a BOUND capability the compile could not reconcile at
// all — an incomparable/unparseable observation, or an unwired change class (Acme
// F15). It is held back per-capability (no action, never in `writes`) rather than
// aborting the whole compile, so an unrelated capability's problem no longer freezes
// every other capability's plan (Acme F16/F17). Recorded explicitly so it is NEVER
// mistaken for converged: planview renders it and converge refuses the clean verdict
// (exit 2) while any block stands. Invariant 1 is untouched (it gates the verifier's
// DECLARED-value verdict via report-executable, not this D28 reconcile gate).
type BlockedCapability struct {
	Capability string `json:"capability"`
	Reason     string `json:"reason"`
}

// UnverifiedCapability (D249) is a BOUND capability that DID reconcile its observable
// attributes but declares one or more attributes the driver cannot observe (Acme
// F16/F17 — e.g. cost.monthly, a budget alert threshold, a TLS flag with no observer
// yet). Those attributes are taken at their DECLARED value (skipped from the
// change-set, like a projection) so the capability is not frozen — but the run
// reports them honestly as un-verified (D136 inconclusive), never as proven
// converged. Unlike Blocked, the capability still emits its actions.
type UnverifiedCapability struct {
	Capability string   `json:"capability"`
	Attributes []string `json:"attributes"`
}

// NoOpCapability (Part B) is a BOUND capability the compile produced no action
// for — a converged no-op. It records WHY, honestly, so "converge did nothing"
// is never a mystery: the world was observed equal to the declared values, or the
// binding was never witnessed so there was nothing to compare. It carries no
// action and is never in `writes`; it is display-only (planview + converge render
// it), routed through the stderr channel like the cost block. It is NOT emitted
// for a capability already reported as Unverified (that path names its own reason)
// and, when EVERY bound capability is a no-op with no other work, the compile
// still returns nothing-to-change rather than a plan (the whole-world converged
// signal converge already handles).
type NoOpCapability struct {
	Capability string `json:"capability"`
	Reason     string `json:"reason"`
}

// WitnessRecord (D177) is a capability the plan VERIFIED but deliberately did NOT
// author, because its provider can only observe/verify it (a GitOps controller's
// Application, D175). It is recorded explicitly — an omission-resistant fact in a
// signed/capsuled plan — so no reader mistakes "witnessed" for "forgotten". It
// carries no action, no permissions, no risk (it mutates nothing) and is never in
// `writes`. Its constraints are still gated by verify (report-executable), so a
// witness whose truth is unknown makes the plan non-executable.
type WitnessRecord struct {
	Capability string `json:"capability"`
	Provider   string `json:"provider"`
	Service    string `json:"service"`
	Reason     string `json:"reason"` // today: "not-authorable"
}

type Document struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Plan       Body   `json:"plan"`
}

// Inputs carries the world knowledge the compiler classifies against
// (D46): bindings decide create-vs-update; observations decide what
// changed — and MUST be fresh for every bound decision.
type Inputs struct {
	Heads    map[string]string
	Bindings map[string]string
	// Deposed feeds CompileDeposed (D71): orphans of failed
	// replacements, projected from full ledger history.
	Deposed []ledger.DeposedResource
	// BindingProviders: capability -> provider name from the binding
	// body — retirement plans have no candidate extras to read it from
	// (D48 first-contact fix)
	BindingProviders map[string]string
	// BindingServices: capability -> service token from the binding
	// (D76) — the retirement/deposed analog, so a retired capability's
	// delete can still dispatch to the right service.
	BindingServices map[string]string
	Generations     map[string]int // capability -> bound resource generation
	Observations    map[string]map[string]ledger.ObsRecord
	// Outputs (D286) is the WIRING projection — a bound producer's typed
	// outputs, keyed capability -> output name. Separate from Observations by
	// construction: a wiring record is an identity to fold a reference from,
	// never evidence that a capability's attributes were observed.
	Outputs   map[string]map[string]ledger.ObsRecord
	EvalClock int
	// Providers maps a provider NAME to its pure-ClassifyChange driver. A
	// candidate can be mixed (aws podidentity + k8s witness), so the change
	// classification and claim-gating MUST dispatch by each capability's own
	// provider — selecting one driver for the whole candidate by map order
	// made the plan nondeterministic (D186). Absent/"fake" names fall back
	// to the Fake driver.
	Providers map[string]provider.Provider
	// Adopted / Claimed drive the takeover claim step (D52): an adopted but
	// not-yet-claimed binding gets a one-time claim action so a converged
	// no-op cannot pass for takeover before groundhold owns the object. Both
	// are ledger projections; empty on greenfield.
	Adopted map[string]bool
	Claimed map[string]bool
	// Observed marks capabilities that observe was RECORDED for (even with zero
	// observable attributes). It separates "never observed" (re-observe recovers,
	// stays an ObservationRequired refusal) from "observed but blind" (re-observe
	// cannot help — isolate as unverifiable, never freeze the compile). A ledger
	// projection (ObservedCapabilities); empty when observe never ran.
	Observed map[string]bool
}

// Compile refuses non-executable reports — a sealed plan without a passing
// verification cannot exist (D36). With Inputs it also refuses: stale or
// missing observations behind a bound decision ("re-observe first"),
// both surfaced through exported sentinels so porcelain can route on
// them without guessing (review fix: substring matching over stderr
// that embeds user-controlled ids is spoofable),
// immutable drift (a replacement diagnosis, not a paper plan), and a
// fully converged world ("nothing to change").
// providerFor resolves a capability's driver by its provider name — the
// per-capability dispatch that keeps a mixed candidate's plan deterministic
// (D186). An absent/"fake"/unknown name uses the service-agnostic Fake.
func (in Inputs) providerFor(name string) provider.Provider {
	if d, ok := in.Providers[name]; ok && d != nil {
		return d
	}
	return &provider.Fake{}
}

func Compile(c *contract.Contract, cand *contract.Candidate,
	vocabs map[string]vocab.Vocabulary,
	report *verify.Report, project string, in Inputs) (*Document, error) {
	if !report.Executable {
		return nil, fmt.Errorf(
			"candidate is not executable against the contract")
	}

	// D47: retirement flows from the CONTRACT; candidates may omit
	// retired capabilities — declaring attributes for one contradicts
	retiredCaps := map[string]bool{}
	for id, capRaw := range c.Capabilities {
		if s, _ := capRaw["state"].(string); s == "retired" {
			retiredCaps[id] = true
			if _, declared := cand.Capabilities[id]; declared {
				return nil, fmt.Errorf(
					"candidate declares attributes for retired capability %s",
					id)
			}
		}
	}

	caps := make([]string, 0, len(cand.Capabilities)+len(retiredCaps))
	for id := range cand.Capabilities {
		caps = append(caps, id)
	}
	for id := range retiredCaps {
		caps = append(caps, id)
	}
	sort.Strings(caps)

	heads := map[string]string{}
	vocabVersions := map[string]string{}
	actions := make([]Action, 0, len(caps))
	witnessed := make([]WitnessRecord, 0)
	blocked := make([]BlockedCapability, 0)
	unverified := make([]UnverifiedCapability, 0)
	noop := make([]NoOpCapability, 0)
	providerName := ""
	uniformProvider := true

	for _, capID := range caps {
		if h, ok := in.Heads[capID]; ok {
			heads[capID] = h
		} else {
			heads[capID] = "genesis"
		}

		if capRaw, ok := c.Capabilities[capID]; ok {
			if typ, _ := capRaw["type"].(string); typ != "" {
				if voc, ok := vocabs[typ]; ok {
					vocabVersions[typ] = voc.Version
				}
			}
		}

		extras := cand.Extras[capID]
		prov, _ := extras["provider"].(string)
		svc, _ := extras["service"].(string)
		if prov == "" {
			prov = in.BindingProviders[capID]
		}
		// D76: retired capabilities have no candidate extras, so the service
		// falls back to the binding — without it a retirement plan's target
		// is "unbound/cap" and the driver cannot dispatch the delete.
		if svc == "" {
			svc = in.BindingServices[capID]
		}
		// Real providers must name a service (dispatch + permissions depend
		// on it); the fake is service-agnostic, so it is exempt (D76). Neutral
		// across providers: any non-fake provider must name a service — never
		// hardcode a provider name here (an aws/azure candidate must gate too).
		if prov != "" && prov != "fake" && svc == "" {
			return nil, fmt.Errorf(
				"capability %s uses provider %q but declares no service — "+
					"cannot dispatch or derive permissions (D76)", capID, prov)
		}
		if providerName == "" {
			providerName = prov
		} else if prov != providerName {
			uniformProvider = false
		}
		target := "unbound/" + capID
		if prov != "" && svc != "" {
			target = fmt.Sprintf("%s.%s/%s", prov, svc, capID)
		}

		// D177: author-vs-witness in the plan. A WITNESS capability (a service the
		// provider can only observe/verify, never author — e.g. a GitOps controller's
		// Application, D175) gets NO mutating action: emitting a create would lie (the
		// driver refuses it at apply). It is recorded in `witnessed` instead — an
		// explicit fact, not silence, so a signed/capsuled plan cannot be misread as
		// "capability forgotten". Its constraints are still verified (executability
		// gates on verify), so a witness whose truth is unknown blocks the plan.
		witness := prov != "" && prov != "fake" && svc != "" && !provider.CanAuthor(prov, svc)

		if retiredCaps[capID] {
			if witness || in.Bindings[capID] == "" {
				continue // a witness / retired-unbound capability was never authored
			}
			stateful := policy.StatefulOf(c, capID, vocabs)
			if policy.ForbidsDeleteStateful(c) && stateful {
				return nil, fmt.Errorf(
					"retiring %s destroys a stateful capability and the "+
						"contract forbids delete_stateful", capID)
			}
			gen := in.Generations[capID]
			if gen < 1 {
				gen = 1
			}
			actions = append(actions, Action{
				ID:                  "a-delete-" + capID,
				Capability:          capID,
				Operation:           "delete",
				Target:              target,
				IdempotencyKey:      idemKey(report.CandidateHash, capID+":delete"),
				TargetProviderID:    in.Bindings[capID],
				TargetGeneration:    gen,
				RequiredPermissions: provider.PermissionsFor(prov, svc, "delete", candAttrs(cand, capID)),
				Risk:                deleteRisk(stateful),
			})
			continue
		}

		if witness {
			witnessed = append(witnessed, WitnessRecord{
				Capability: capID,
				Provider:   prov,
				Service:    svc,
				Reason:     "not-authorable",
			})
			continue
		}

		if in.Bindings[capID] == "" {
			actions = append(actions, Action{
				ID:                  "a-create-" + capID,
				Capability:          capID,
				Operation:           "create",
				Target:              target,
				IdempotencyKey:      idemKey(report.CandidateHash, capID),
				RequiredPermissions: provider.PermissionsFor(prov, svc, "create", candAttrs(cand, capID)),
				Risk:                createRisk(cand, capID),
			})
			continue
		}

		// F-LC3 part 2: a bound resource that observe found authoritatively GONE
		// (a readable 404 → reserved absence marker) is re-created, not a no-op.
		// A CREATE re-provisions it under the same deterministic identity; the
		// driver's create pre-read makes it idempotent if it reappeared. Freshness
		// is gated (a stale/future absence is re-observe-fixable, GLOBAL refusal);
		// a read ERROR never reaches here — it stays observe's returned error, so
		// the binding blocks re-observe-first (unknown), never a spurious recreate.
		if rec, ok := in.Observations[capID][provider.ResourceAbsentPath]; ok {
			if serr := stalenessRefusal(capID, provider.ResourceAbsentPath, rec, in.EvalClock); serr != nil {
				return nil, serr
			}
			if gone, _ := rec.Value.(bool); gone {
				actions = append(actions, Action{
					ID:                  "a-create-" + capID,
					Capability:          capID,
					Operation:           "create",
					Target:              target,
					IdempotencyKey:      idemKey(report.CandidateHash, capID),
					RequiredPermissions: provider.PermissionsFor(prov, svc, "create", candAttrs(cand, capID)),
					Risk:                createRisk(cand, capID),
				})
				continue
			}
		}

		// D52 takeover: an adopted binding is bound in the ledger, but until
		// groundhold stamps its authorship on the object a converged no-op is a
		// read-only proof that hides a hole — the first later drift hits the
		// driver's "not ours" guard with no writer to repair it. Emit a
		// one-time claim (drivers able to take ownership opt in via
		// provider.Claimer); it orders before any update/replace in this run.
		changes, immutable, block, unverif, err := classifyBound(cand, capID, prov, svc, in,
			vocabs[capTypeOf(c, capID)])
		if err != nil {
			return nil, err
		}
		if block != "" {
			// D249 per-capability isolation: this bound capability cannot be
			// reconciled at all. Hold IT back — no claim, no update — but DO NOT
			// abort the compile: independent capabilities still plan. Never silently
			// converged (see BlockedCapability). Invariant 1 untouched.
			blocked = append(blocked, BlockedCapability{Capability: capID, Reason: block})
			continue
		}
		if len(unverif) > 0 {
			// D249: reconciles below, but declares non-observable attributes — carry
			// them so the run reports inconclusive, never a false "converged".
			unverified = append(unverified, UnverifiedCapability{Capability: capID, Attributes: unverif})
		}

		claimID := ""
		if in.Adopted[capID] && !in.Claimed[capID] {
			if _, ok := in.providerFor(prov).(provider.Claimer); ok {
				claimID = "a-claim-" + capID
				actions = append(actions, Action{
					ID:                  claimID,
					Capability:          capID,
					Operation:           "claim",
					Target:              target,
					IdempotencyKey:      idemKey(report.CandidateHash, capID+":claim"),
					TargetProviderID:    in.Bindings[capID],
					TargetGeneration:    in.Generations[capID],
					RequiredPermissions: provider.PermissionsFor(prov, svc, "claim", candAttrs(cand, capID)),
					Risk:                claimRisk(),
				})
			}
		}

		if len(immutable) > 0 {
			// D48: immutable drift means replacement — a create-before-
			// destroy composition in the existing action DAG. Stateful
			// replacement needs EXPLICIT, scoped contract consent: a
			// typo must not quietly propose "create empty DB, delete
			// old DB".
			stateful := policy.StatefulOf(c, capID, vocabs)
			if stateful {
				if policy.ForbidsDeleteStateful(c) {
					return nil, fmt.Errorf(
						"replacing %s destroys a stateful capability and "+
							"the contract forbids delete_stateful", capID)
				}
				if !policy.AllowsReplaceStateful(c, capID) {
					return nil, &RefusalError{Capability: capID, Reason: fmt.Sprintf(
						"replacing stateful %s yields an EMPTY successor "+
							"(data migration is out of scope) — requires "+
							"explicit autonomy.allow_replace_stateful consent "+
							"in the contract", capID)}
				}
			}
			oldGen := in.Generations[capID]
			if oldGen < 1 {
				oldGen = 1
			}
			newGen := oldGen + 1
			createID := fmt.Sprintf("a-create-%s-g%d", capID, newGen)
			createRiskV := createRisk(cand, capID)
			createRiskV.IdentityReplacement = true
			actions = append(actions, Action{
				ID:               createID,
				Capability:       capID,
				Operation:        "create",
				Target:           target,
				IdempotencyKey:   idemKey(report.CandidateHash, fmt.Sprintf("%s:g%d", capID, newGen)),
				TargetGeneration: newGen,
				Replaces: &ReplaceInfo{ProviderID: in.Bindings[capID],
					Generation: oldGen, Because: immutable},
				RequiredPermissions: provider.PermissionsFor(prov, svc, "create", candAttrs(cand, capID)),
				Risk:                createRiskV,
			})
			actions = append(actions, Action{
				ID:                  "a-delete-" + capID + "-g" + fmt.Sprint(oldGen),
				Capability:          capID,
				Operation:           "delete",
				Target:              target,
				IdempotencyKey:      idemKey(report.CandidateHash, capID+":delete"),
				DependsOn:           withClaim([]string{createID}, claimID), // create BEFORE destroy; own BEFORE delete
				TargetProviderID:    in.Bindings[capID],
				TargetGeneration:    oldGen,
				RequiredPermissions: provider.PermissionsFor(prov, svc, "delete", candAttrs(cand, capID)),
				Risk:                deleteRisk(stateful),
			})
			continue
		}
		if len(changes) == 0 {
			// Part B: a bound capability with no drift is a converged no-op — name
			// WHY, honestly, so "converge did nothing" is never a mystery. A cap
			// with non-observable attrs is ALREADY reported as Unverified (which
			// names its own reason); do not double-report it here.
			if len(unverif) == 0 {
				noop = append(noop, NoOpCapability{
					Capability: capID, Reason: noopReason(capID, in)})
			}
			continue // converged — no action for this capability
		}
		actions = append(actions, Action{
			ID:                  "a-update-" + capID,
			Capability:          capID,
			Operation:           "update",
			Target:              target,
			IdempotencyKey:      idemKey(report.CandidateHash, capID+":update"),
			Changes:             changes,
			DependsOn:           withClaim(nil, claimID), // own BEFORE patch
			RequiredPermissions: provider.PermissionsFor(prov, svc, "update", candAttrs(cand, capID)),
			Risk:                updateRisk(),
		})
	}
	if len(actions) == 0 && len(blocked) == 0 && len(unverified) == 0 {
		return nil, fmt.Errorf("%s", ErrNothingToChange)
	}
	// actions == 0 with blocked/unverified present is NOT "nothing to change": a
	// blocked capability is held back, and an unverified one converged on its
	// observable attrs but has non-observable ones. Seal a plan carrying both so
	// converge reports them honestly (blocked -> exit 2; unverified -> inconclusive)
	// instead of a false "converged".
	// writes = capabilities with actions only
	written := map[string]bool{}
	for _, a := range actions {
		written[a.Capability] = true
	}
	writtenCaps := make([]string, 0, len(written))
	writtenHeads := map[string]string{}
	for _, capID := range caps {
		if written[capID] {
			writtenCaps = append(writtenCaps, capID)
			writtenHeads[capID] = heads[capID]
		}
	}
	caps, heads = writtenCaps, writtenHeads

	reads := Reads{
		ContractHash:  report.ContractHash,
		CandidateHash: report.CandidateHash,
		Heads:         heads,
		Toolchain:     Toolchain{Compiler: Version, Spec: "contract/v0.1"},
	}
	if len(vocabVersions) > 0 {
		reads.Vocabularies = vocabVersions
	}
	if uniformProvider && providerName != "" {
		reads.Provider = &Provider{Name: providerName, Project: project}
	}

	// writes declares the capabilities groundhold MUTATES — witnessed capabilities are
	// excluded (a witness in writes would be a lie, D177). Deterministic: caps is
	// already sorted; the witness set is a subset removed in place.
	witnessSet := make(map[string]bool, len(witnessed))
	for _, w := range witnessed {
		witnessSet[w.Capability] = true
	}
	writes := make([]string, 0, len(caps))
	for _, capID := range caps {
		if !witnessSet[capID] {
			writes = append(writes, capID)
		}
	}

	// D226/F13: wire intra-plan output references now that every action id is
	// known (a producer may be declared after its consumer). Refuses on the
	// reference-invalid set; never coerces, never falls back to a literal.
	if err := wireReferences(actions, cand, in, report.CandidateHash); err != nil {
		return nil, err
	}

	// The SILENT-IGNORE GUARD: after $ref operands are resolved, refuse any
	// implementation operand no driver reads — a free-form (D26) block must not
	// let a key the driver silently drops through to a "succeeded" apply. Runs
	// after wireReferences so a malformed $ref surfaces as reference-invalid, not
	// unknown-operand.
	if err := refuseUnknownOperands(actions, cand, in); err != nil {
		return nil, err
	}

	// D195: report-executable is mandatory (the thesis); the contract opts
	// into the hard-only assumed-basis gate, which the executor enforces.
	preconds := []Precondition{{Type: "report-executable"}}
	if policy.RequiresProvenHardBasis(c) {
		preconds = append(preconds, Precondition{Type: "no-assumed-hard-basis"})
	}
	return &Document{
		APIVersion: "plan/v0",
		Kind:       "SealedPlan",
		Plan: Body{
			Contract:      c.ID,
			Environment:   c.Environment,
			Reads:         reads,
			Writes:        writes,
			Actions:       actions,
			Witnessed:     witnessed,
			Blocked:       blocked,
			Unverified:    unverified,
			NoOp:          noop,
			Preconditions: preconds,
		},
	}, nil
}

// CompileDeposed (D71) seals a cleanup plan for the orphans of failed
// replacements: one pinned delete per deposed identity, nothing else.
// The pin comes from the deposed projection (id + the generation it
// held when last bound), and the executor re-validates it against a
// FRESH projection — a normal delete's binding-match check cannot
// apply, because an orphan's capability is by definition bound to its
// successor. Consent mirrors replacement (D48): the orphan is the
// destroy half of a replacement arriving late, so deleting a stateful
// one requires the same scoped allow_replace_stateful — consent may
// have been revoked since the original plan, and fail-closed means
// checking NOW, not remembering then.
func CompileDeposed(c *contract.Contract, cand *contract.Candidate,
	vocabs map[string]vocab.Vocabulary,
	report *verify.Report, project string, in Inputs) (*Document, error) {
	if !report.Executable {
		return nil, fmt.Errorf(
			"candidate is not executable against the contract")
	}
	if len(in.Deposed) == 0 {
		return nil, fmt.Errorf("%s", ErrNothingDeposed)
	}

	heads := map[string]string{}
	var writes []string
	written := map[string]bool{}
	actions := make([]Action, 0, len(in.Deposed))
	providerName := ""
	uniformProvider := true
	for _, dep := range in.Deposed {
		if dep.Status != "deposed" {
			continue // pending-delete is resume's territory (D58)
		}
		capID := dep.Capability
		stateful := policy.StatefulOf(c, capID, vocabs)
		if policy.ForbidsDeleteStateful(c) && stateful {
			return nil, fmt.Errorf(
				"deleting deposed %s of %s destroys a stateful capability "+
					"and the contract forbids delete_stateful",
				dep.ProviderID, capID)
		}
		if stateful && !policy.AllowsReplaceStateful(c, capID) {
			return nil, &RefusalError{Capability: capID, Reason: fmt.Sprintf(
				"deleting deposed %s completes a replacement of stateful "+
					"%s — requires explicit autonomy.allow_replace_stateful "+
					"consent in the contract, checked now, not remembered",
				dep.ProviderID, capID)}
		}

		extras := cand.Extras[capID]
		prov, _ := extras["provider"].(string)
		svc, _ := extras["service"].(string)
		if prov == "" {
			prov = in.BindingProviders[capID]
		}
		// D76: retired capabilities have no candidate extras, so the service
		// falls back to the binding — without it a retirement plan's target
		// is "unbound/cap" and the driver cannot dispatch the delete.
		if svc == "" {
			svc = in.BindingServices[capID]
		}
		// Real providers must name a service (dispatch + permissions depend
		// on it); the fake is service-agnostic, so it is exempt (D76). Neutral
		// across providers: any non-fake provider must name a service — never
		// hardcode a provider name here (an aws/azure candidate must gate too).
		if prov != "" && prov != "fake" && svc == "" {
			return nil, fmt.Errorf(
				"capability %s uses provider %q but declares no service — "+
					"cannot dispatch or derive permissions (D76)", capID, prov)
		}
		if providerName == "" {
			providerName = prov
		} else if prov != providerName {
			uniformProvider = false
		}
		target := "unbound/" + capID
		if prov != "" && svc != "" {
			target = fmt.Sprintf("%s.%s/%s", prov, svc, capID)
		}

		actions = append(actions, Action{
			ID: fmt.Sprintf("a-delete-deposed-%s-g%d", capID,
				dep.Generation),
			Capability: capID,
			Operation:  "delete",
			Target:     target,
			IdempotencyKey: idemKey(report.CandidateHash, fmt.Sprintf(
				"%s:deposed:%s", capID, dep.ProviderID)),
			TargetProviderID:    dep.ProviderID,
			TargetGeneration:    dep.Generation,
			Deposed:             true,
			RequiredPermissions: provider.PermissionsFor(prov, svc, "delete", candAttrs(cand, capID)),
			Risk:                deleteRisk(stateful),
		})
		if !written[capID] {
			written[capID] = true
			writes = append(writes, capID)
			if h, ok := in.Heads[capID]; ok {
				heads[capID] = h
			} else {
				heads[capID] = "genesis"
			}
		}
	}
	if len(actions) == 0 {
		return nil, fmt.Errorf("%s", ErrNothingDeposed)
	}
	sort.Strings(writes)

	reads := Reads{
		ContractHash:  report.ContractHash,
		CandidateHash: report.CandidateHash,
		Heads:         heads,
		Toolchain:     Toolchain{Compiler: Version, Spec: "contract/v0.1"},
	}
	if uniformProvider && providerName != "" {
		reads.Provider = &Provider{Name: providerName, Project: project}
	}
	// D195: same gate as Compile — uniform on the contract's opt-in. A
	// deposed-cleanup plan is delete-only (no action rests on an assumed
	// value), so the precondition is inert here, but emitting it keeps one
	// decision read from one place.
	deposedPreconds := []Precondition{{Type: "report-executable"}}
	if policy.RequiresProvenHardBasis(c) {
		deposedPreconds = append(deposedPreconds,
			Precondition{Type: "no-assumed-hard-basis"})
	}
	return &Document{
		APIVersion: "plan/v0",
		Kind:       "SealedPlan",
		Plan: Body{
			Contract:      c.ID,
			Environment:   c.Environment,
			Reads:         reads,
			Writes:        writes,
			Actions:       actions,
			Preconditions: deposedPreconds,
		},
	}, nil
}

// capTypeOf resolves a capability's declared TYPE from the contract — the key the
// vocabulary map is indexed by. An unknown capability yields "", which selects the
// zero Vocabulary and therefore the pre-D311 behaviour (every attribute is state).
func capTypeOf(c *contract.Contract, capID string) string {
	raw, ok := c.Capabilities[capID]
	if !ok {
		return ""
	}
	typ, _ := raw["type"].(string)
	return typ
}

// isProjectionAttr reports whether an attribute is a PROJECTION / probe target
// rather than reconcilable resource state: a cost forecast (cost.monthly) or a
// recovery-time objective proven by a probe (recovery.rto). These are declared in
// a candidate but never emitted as observations, so a reconcile must not require
// (or gate on) an observation for them.
//
// D311: the pair used to be a hardcoded switch here — the engine re-encoding a
// fact the vocabulary already stated in prose. It is now DERIVED from the
// attribute's declared `evidence:` class, so a new attribute of this kind needs
// zero engine changes (D23/D55). An absent vocabulary yields false: without a
// type system there is nothing to claim, and the old behaviour for an unknown
// capability was to treat every attribute as resource state.
func isProjectionAttr(voc vocab.Vocabulary, path string) bool {
	return voc.NotResourceState(path)
}

// stalenessRefusal folds one observation's freshness gate into a re-observe-
// fixable GLOBAL error (or nil when fresh). Shared by the attribute loop and
// the operand-drift step (F-LC3) so both judge evidence identically: an unset
// eval clock (N1), a stale reading, or a future-dated one all refuse rather
// than seal against knowledge that did not exist at the evaluated instant.
func stalenessRefusal(capID, path string, rec ledger.ObsRecord, evalClock int) error {
	obsClock, perr := ledger.ParseTs(rec.ObservedAt)
	if evalClock <= 0 {
		return fmt.Errorf(
			"%s.%s: evaluation clock unset — cannot judge staleness (N1)", capID, path)
	}
	if perr != nil || evalClock-obsClock > rec.TTLSeconds {
		return fmt.Errorf(
			"%s.%s: observation is stale — re-observe first", capID, path)
	}
	if evalClock-obsClock < 0 {
		return fmt.Errorf(
			"%s.%s: observation is dated after the evaluation time — "+
				"invalid, cannot seal against it", capID, path)
	}
	return nil
}

// classifyBound decides the change-set for a bound capability (D46).
// The staleness gate lives HERE: sealing a change-set derived from stale
// knowledge would contradict the read-set's honesty (D28).
// classifyBound returns (changes, immutable, block, err). A non-empty `block` is a
// per-capability reconcile refusal (missing/stale/incomparable observation, unwired
// change class) that the caller ISOLATES (D249) — it never aborts the whole compile.
// `err` is reserved for a GLOBAL fatal (an unset evaluation clock, N1): that is a
// caller precondition affecting every capability identically, not a per-capability
// condition, so it stays a hard abort.
// noopReason names WHY a bound capability converged with NO action (Part B),
// honestly and true of the converged state — never inventing work. Three cases,
// mirroring the three the operator actually wants told apart: live observations
// were compared and equalled the declared values; observe ran but recorded
// nothing comparable; or the binding was never witnessed, so there was nothing to
// observe.
func noopReason(capID string, in Inputs) string {
	switch {
	case len(in.Observations[capID]) > 0:
		return "bound, observed==declared"
	case in.Observed[capID]:
		return "bound, no diff"
	default:
		return "bound, unwitnessed — nothing to observe"
	}
}

func classifyBound(cand *contract.Candidate, capID, prov, svc string,
	in Inputs, voc vocab.Vocabulary) ([]Change, []Change, string, []string, error) {
	attrs := cand.Capabilities[capID]
	paths := make([]string, 0, len(attrs))
	for p := range attrs {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	obs := in.Observations[capID]
	impl, _ := cand.Extras[capID]["implementation"].(map[string]any)
	var changes, immutable []Change
	var unverifiable []string // non-observable declared attrs (D249)
	for _, path := range paths {
		pv := attrs[path]
		if pv.Scalar == nil {
			continue // status unknown — nothing to converge toward
		}
		if isProjectionAttr(voc, path) {
			// cost.monthly is a cost FORECAST and recovery.rto a probe TARGET —
			// neither is reconcilable resource state, and neither is emitted as an
			// observation, so a reconcile of a BOUND resource must skip them rather
			// than block on the (correctly) missing observation. Without this, one
			// mid-flight partial froze every subsequent apply: the reconcile of an
			// already-bound resource refused "cost.monthly: no observation" (F16).
			continue
		}
		rec, has := obs[path]
		if !has {
			// D249, the key distinction. observe records ALL observable attrs of a
			// capability atomically, so a missing observation is either:
			// (a) the capability was NEVER observed (it has no observations at all)
			//     -> ObservationRequired refusal, so converge's auto-observe and a
			//     human's `observe` can fix it (the re-observe recovery is kept); or
			// (b) the capability WAS observed but this attribute was not emitted ->
			//     the attribute is structurally non-observable. Do NOT block the
			//     capability (its observable attrs still reconcile) and do NOT
			//     freeze the plan (Acme F16/F17): skip this path from the
			//     change-set (treat as declared) and mark it UNVERIFIABLE, so the
			//     capability converges on what can be seen while the run reports
			//     honestly that this attribute was not verified (D136 inconclusive).
			//
			// The two are told apart by in.Observed (observe was RECORDED for the
			// capability, even with zero attributes). len(obs)==0 alone conflated
			// them, so a bound capability with a blind/empty observer froze every
			// converge on the second plan even though re-observe could never help.
			// Now zero-obs freezes ONLY when observe never ran; an observed-but-blind
			// capability isolates as unverifiable, exactly like (b).
			if len(obs) == 0 && !in.Observed[capID] {
				return nil, nil, "", nil, fmt.Errorf(
					"%s.%s: no observation — re-observe first", capID, path)
			}
			unverifiable = append(unverifiable, path)
			continue
		}
		if rec.Source == provider.DeclaredIntentSource {
			// F-LC3 part 3: adopt recorded this NON-OBSERVABLE attribute as
			// declared-intent (the candidate's own provenance, not measured
			// reality). It is intent, never drift and never a staleness freeze —
			// carry it as unverified (D249), exactly like an unobserved attribute.
			unverifiable = append(unverifiable, path)
			continue
		}
		if serr := stalenessRefusal(capID, path, rec, in.EvalClock); serr != nil {
			// stale/future/unset-clock is re-observe-fixable, so it stays an
			// ObservationRequired GLOBAL refusal (converge auto-observes) — never
			// isolated. N1/D188 fail-closed defense-in-depth lives in the helper.
			return nil, nil, "", nil, serr
		}
		obsScalar, err := scalars.Parse(rec.Value)
		if err != nil {
			return nil, nil, fmt.Sprintf(
				"%s.%s: observation unparseable — cannot decide", capID, path), nil, nil
		}
		// F16-B: a protocol/version attribute declared at MAJOR granularity
		// (postgresql/16) is satisfied by any observed minor of that major
		// (postgresql/16.11), so a bound resource does not perpetually "update" toward a
		// minor the operator never pinned. Precision-aware: a declared minor still pins.
		// Every other kind compares by equality. The observer keeps the real minor.
		var equal bool
		if pv.Scalar.Kind == scalars.Protocol {
			equal, err = scalars.ProtocolSatisfiedBy(pv.Scalar, obsScalar)
		} else {
			equal, err = scalars.Operators["equals"](obsScalar, pv.Scalar)
		}
		if err != nil {
			return nil, nil, fmt.Sprintf(
				"%s.%s: observation incomparable with the desired value "+
					"— cannot decide", capID, path), nil, nil
		}
		if equal {
			continue
		}
		class, note := in.providerFor(prov).ClassifyChange(
			svc, path, rec.Value, pv.Scalar.Raw, impl)
		switch class {
		case "mutable", "caveated":
			changes = append(changes, Change{Path: path, From: rec.Value,
				To: pv.Scalar.Raw, Caveat: note})
		case "immutable":
			// D48: replacement, composed by the caller
			immutable = append(immutable, Change{Path: path,
				From: rec.Value, To: pv.Scalar.Raw, Caveat: note})
		default:
			// an unwired change class (e.g. a service whose reconcile is not yet
			// classified) blocks THIS capability, not the whole plan (D249).
			return nil, nil, fmt.Sprintf("%s.%s: %s", capID, path, note), nil, nil
		}
	}

	// F-LC3 part 1: operand drift. IMPLEMENTATION operands (a Lambda's VpcConfig,
	// Environment, container image) are not typed vocab attributes, so the loop
	// above never compares them — a change to a bound resource's operands would be
	// a silent no-op (the F16/F25 class). A driver that governs mutable operands
	// (provider.OperandDrifter) reports the DECLARED operand targets; each is
	// compared to observe's recorded operand state and routed through the SAME
	// ClassifyChange/staleness machinery, never a parallel drift engine.
	if od, ok := in.providerFor(prov).(provider.OperandDrifter); ok {
		// D311: strip PROJECTION attributes (cost.monthly, recovery.rto — evidence:
		// projection/probe) before handing the operand shape to the driver. A builder
		// REFUSES any attribute it cannot map, and a projection maps to no provider
		// setting BY DESIGN; leaving it in made OperandTargets refuse "no mapping",
		// which the caller isolated as a block — a legal update silently collapsed to
		// an empty SEALED plan (Acme field regression). The apply boundary already
		// filters here (attributesRaw); the reconcile classifier must too.
		targets, terr := od.OperandTargets(svc, nonProjectionAttrs(cand, capID, voc), impl)
		if terr != nil {
			// building the desired operand shape refused (e.g. a partial VpcConfig)
			// — isolate THIS capability (D249), never abort the whole compile.
			return nil, nil, fmt.Sprintf("%s: %v", capID, terr), nil, nil
		}
		for _, tgt := range targets {
			rec, has := obs[tgt.Path]
			if !has {
				// operand observation absent: an old ledger observed before operands
				// were recorded. Mirror the attribute path — re-observe if the
				// capability was never observed, else carry as unverified (never freeze).
				if len(obs) == 0 && !in.Observed[capID] {
					return nil, nil, "", nil, fmt.Errorf(
						"%s.%s: no observation — re-observe first", capID, tgt.Path)
				}
				unverifiable = append(unverifiable, tgt.Path)
				continue
			}
			if rec.Source == provider.DeclaredIntentSource {
				unverifiable = append(unverifiable, tgt.Path)
				continue
			}
			if serr := stalenessRefusal(capID, tgt.Path, rec, in.EvalClock); serr != nil {
				return nil, nil, "", nil, serr
			}
			// operands are opaque canonical strings (not typed scalars), compared by
			// string equality — no coercion (invariant #2), no scalar parsing.
			if fmt.Sprint(rec.Value) == fmt.Sprint(tgt.Desired) {
				continue
			}
			class, note := in.providerFor(prov).ClassifyChange(
				svc, tgt.Path, rec.Value, tgt.Desired, impl)
			switch class {
			case "mutable", "caveated":
				changes = append(changes, Change{Path: tgt.Path, From: rec.Value,
					To: tgt.Desired, Caveat: note})
			case "immutable":
				immutable = append(immutable, Change{Path: tgt.Path,
					From: rec.Value, To: tgt.Desired, Caveat: note})
			default:
				return nil, nil, fmt.Sprintf("%s.%s: %s", capID, tgt.Path, note), nil, nil
			}
		}
	}
	return changes, immutable, "", unverifiable, nil
}

func deleteRisk(stateful bool) Risk {
	dataLoss := "none"
	if stateful {
		dataLoss = "certain"
	}
	return Risk{
		Reversibility:       "R4",
		DataLoss:            dataLoss,
		Downtime:            "certain",
		SecurityExposure:    "none",
		CostDelta:           Money{Amount: 0, Currency: "EUR"},
		IdentityReplacement: true,
	}
}

func updateRisk() Risk {
	return Risk{
		Reversibility:       "R1",
		DataLoss:            "none",
		Downtime:            "possible", // Cloud SQL patches can restart
		SecurityExposure:    "none",
		CostDelta:           Money{Amount: 0, Currency: "EUR"},
		IdentityReplacement: false,
	}
}

// claimRisk: taking authorship of an already-existing resource stamps an
// ownership marker (labels/tags, or a field-manager). It changes no semantic
// attribute, destroys nothing, and causes no downtime — the safest write.
func claimRisk() Risk {
	return Risk{
		Reversibility:       "R1",
		DataLoss:            "none",
		Downtime:            "none",
		SecurityExposure:    "none",
		CostDelta:           Money{Amount: 0, Currency: "EUR"},
		IdentityReplacement: false,
	}
}

// withClaim prepends the one-time claim dependency (if any) so ownership is
// stamped before the run patches or deletes the resource.
func withClaim(deps []string, claimID string) []string {
	if claimID == "" {
		return deps
	}
	return append([]string{claimID}, deps...)
}

// implementationOf returns a capability's free-form implementation operand map
// (D26), or nil.
func implementationOf(cand *contract.Candidate, capID string) map[string]any {
	m, _ := cand.Extras[capID]["implementation"].(map[string]any)
	return m
}

// refErr builds a reference-invalid RefusalError carrying the $ref's candidate
// location, so a CLI can offer an edit `next` pointing at exactly the operand to
// fix (D230). The pointer is the candidate path to the operand slot.
func refErr(capID, slot, reason string) error {
	return &RefusalError{
		Reason:     reason,
		RefPointer: fmt.Sprintf("capabilities.%s.implementation.%s", capID, slot),
		Note:       reason,
	}
}

// outRef is a parsed $ref operand (D226): a reference to another same-candidate
// capability's typed output.
type outRef struct{ Capability, Output string }

// parseOutputRef recognizes an intra-plan output reference (D226/F13). A ref is a
// mapping whose SOLE key is `$ref`, itself a mapping with exactly capability+output.
// Anything shaped like a reference but malformed refuses (the anti-interpolation
// wall) rather than being read as a literal or a mini-language.
func parseOutputRef(v any) (outRef, bool, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return outRef{}, false, nil
	}
	raw, has := m["$ref"]
	if !has {
		return outRef{}, false, nil
	}
	if len(m) != 1 {
		return outRef{}, false, fmt.Errorf("malformed $ref: it must be the operand's sole key (D226)")
	}
	rm, ok := raw.(map[string]any)
	if !ok {
		return outRef{}, false, fmt.Errorf("malformed $ref: expected a mapping with capability and output (D226)")
	}
	for k := range rm {
		if k != "capability" && k != "output" {
			return outRef{}, false, fmt.Errorf("malformed $ref: unexpected key %q (only capability, output) (D226)", k)
		}
	}
	c, _ := rm["capability"].(string)
	o, _ := rm["output"].(string)
	if c == "" || o == "" {
		return outRef{}, false, fmt.Errorf("malformed $ref: capability and output are both required (D226)")
	}
	return outRef{c, o}, true, nil
}

// outputKind looks up an output's declared kind in a producer driver's typed
// contract (D226). A driver that does not implement OutputProducer produces
// nothing, so any reference to it is unknown-output.
func outputKind(drv provider.Provider, service, output string) (string, bool) {
	op, ok := drv.(provider.OutputProducer)
	if !ok {
		return "", false
	}
	for _, s := range op.OutputsFor(service) {
		if s.Name == output {
			return s.Kind, true
		}
	}
	return "", false
}

func addDep(deps []string, id string) []string {
	for _, d := range deps {
		if d == id {
			return deps
		}
	}
	return append(deps, id)
}

// wireReferences resolves intra-plan output references (D226/F13) in a second
// pass, once every action id is known. For each create action, an implementation
// operand shaped as {$ref:{capability,output}} becomes a symbolic OperandRef + a
// DependsOn edge on the producer's same-plan create, and the consumer's
// idempotency key folds the producer keys so a producer change (e.g. a D48 replace
// bumping the generation) re-keys the consumer. Every failure refuses
// (reference-invalid) — no coercion (invariant #2), no literal fallback.
func wireReferences(actions []Action, cand *contract.Candidate, in Inputs, candidateHash string) error {
	// Only a create yields fresh outputs; map capability -> its create action.
	// A same-plan DELETE marks the producer retiring: a value read from a
	// resource this very plan destroys is a lie, whichever branch resolves it.
	createIdx := map[string]int{}
	deleting := map[string]bool{}
	for i := range actions {
		if actions[i].Operation == "create" {
			createIdx[actions[i].Capability] = i
		}
		if actions[i].Operation == "delete" {
			deleting[actions[i].Capability] = true
		}
	}
	for i := range actions {
		a := &actions[i]
		if a.Operation != "create" {
			continue
		}
		impl := implementationOf(cand, a.Capability)
		if impl == nil {
			continue
		}
		// handleRef validates ONE parsed $ref at operand path `slot` (a top-level
		// key, or `map.subkey` for a $ref nested in a map operand's value) and
		// records it as a same-plan OperandRef (+ DependsOn) or a D283 fold.
		handleRef := func(slot string, ref outRef) error {
			if ref.Capability == a.Capability {
				return refErr(a.Capability, slot, fmt.Sprintf(
					"%s.%s references its own output — a dependency cycle (D226)", a.Capability, slot))
			}
			if _, declared := cand.Capabilities[ref.Capability]; !declared {
				return refErr(a.Capability, slot, fmt.Sprintf(
					"%s.%s references unknown capability %q (D226)", a.Capability, slot, ref.Capability))
			}
			if deleting[ref.Capability] {
				return refErr(a.Capability, slot, fmt.Sprintf(
					"%s.%s references %q, which this same plan DELETES — a value "+
						"from a resource being destroyed is a lie (ref-producer-retiring) (D226)",
					a.Capability, slot, ref.Capability))
			}
			pExtras := cand.Extras[ref.Capability]
			pProv, _ := pExtras["provider"].(string)
			if pProv == "" {
				pProv = in.BindingProviders[ref.Capability]
			}
			pSvc, _ := pExtras["service"].(string)
			kind, ok := outputKind(in.providerFor(pProv), pSvc, ref.Output)
			if !ok {
				return refErr(a.Capability, slot, fmt.Sprintf(
					"%s.%s references output %q that capability %q does not produce (D226)",
					a.Capability, slot, ref.Output, ref.Capability))
			}
			pIdx, sameplan := createIdx[ref.Capability]
			if !sameplan {
				// D283 — the FOLD branch: the producer is not created this plan.
				// Bound + a FRESH "outputs.<name>" observation folds the operand
				// to a LITERAL; anything less refuses. NEVER a symbolic fallback,
				// never the candidate's old literal, never a stale reading.
				if in.Bindings[ref.Capability] == "" {
					return refErr(a.Capability, slot, fmt.Sprintf(
						"%s.%s references %q, which this plan does not create and "+
							"the ledger does not bind — create it, adopt it, or fix the $ref (D226)",
						a.Capability, slot, ref.Capability))
				}
				if in.EvalClock <= 0 {
					// N1 defense-in-depth, same as classifyBound: never judge
					// freshness against an unset safety clock.
					return fmt.Errorf(
						"%s.%s: evaluation clock unset — cannot judge the fold "+
							"observation's staleness (N1)", a.Capability, slot)
				}
				rec, has := in.Outputs[ref.Capability][ref.Output]
				if !has {
					return fmt.Errorf(
						"%s.%s: bound producer %q has no outputs.%s observation "+
							"(observe records a bound resource's declared outputs) — re-observe first",
						a.Capability, slot, ref.Capability, ref.Output)
				}
				obsClock, terr := ledger.ParseTs(rec.ObservedAt)
				if terr != nil || in.EvalClock-obsClock > rec.TTLSeconds {
					return fmt.Errorf(
						"%s.%s: outputs.%s of %q — observation is stale — re-observe first",
						a.Capability, slot, ref.Output, ref.Capability)
				}
				if in.EvalClock-obsClock < 0 {
					return fmt.Errorf(
						"%s.%s: outputs.%s of %q — observation is dated after the "+
							"evaluation time — invalid, cannot seal against it",
						a.Capability, slot, ref.Output, ref.Capability)
				}
				val, kindErr := provider.OutputValueOfKind(rec.Value, kind)
				if kindErr != "" {
					return refErr(a.Capability, slot, fmt.Sprintf(
						"%s.%s: outputs.%s of %q %s (D226)",
						a.Capability, slot, ref.Output, ref.Capability, kindErr))
				}
				a.Folds = append(a.Folds, OperandFold{
					Slot: slot, Capability: ref.Capability, Output: ref.Output,
					Value: val, ObservedAt: rec.ObservedAt, TTLSeconds: rec.TTLSeconds,
				})
				return nil
			}
			producerID := actions[pIdx].ID
			a.References = append(a.References, OperandRef{
				Slot: slot, ProducerAction: producerID,
				Capability: ref.Capability, Output: ref.Output, Kind: kind,
			})
			a.DependsOn = addDep(a.DependsOn, producerID)
			return nil
		}

		// Walk the operand slots. A slot value that IS a $ref wires directly; a
		// MAP operand (e.g. lambda's environment) may carry a $ref in any of its
		// values, so walk one level so an env var can wire a producer output
		// (e.g. an Aurora endpoint host) instead of a hand-pasted literal (D226).
		slots := make([]string, 0, len(impl))
		for k := range impl {
			slots = append(slots, k)
		}
		sort.Strings(slots)
		for _, slot := range slots {
			ref, isRef, err := parseOutputRef(impl[slot])
			if err != nil {
				return refErr(a.Capability, slot, fmt.Sprintf("%s.%s: %v", a.Capability, slot, err))
			}
			if isRef {
				if err := handleRef(slot, ref); err != nil {
					return err
				}
				continue
			}
			sub, ok := impl[slot].(map[string]any)
			if !ok {
				continue
			}
			subKeys := make([]string, 0, len(sub))
			for k := range sub {
				subKeys = append(subKeys, k)
			}
			sort.Strings(subKeys)
			for _, sk := range subKeys {
				r, isR, e := parseOutputRef(sub[sk])
				if e != nil {
					return refErr(a.Capability, slot+"."+sk,
						fmt.Sprintf("%s.%s.%s: %v", a.Capability, slot, sk, e))
				}
				if !isR {
					continue
				}
				if err := handleRef(slot+"."+sk, r); err != nil {
					return err
				}
			}
		}
		if len(a.Folds) > 0 {
			sort.Slice(a.Folds, func(x, y int) bool { return a.Folds[x].Slot < a.Folds[y].Slot })
		}
		if len(a.References) > 0 {
			sort.Slice(a.References, func(x, y int) bool { return a.References[x].Slot < a.References[y].Slot })
			sort.Strings(a.DependsOn)
			deps := make([]string, 0, len(a.References))
			for _, r := range a.References {
				deps = append(deps, actions[createIdx[r.Capability]].IdempotencyKey)
			}
			sort.Strings(deps)
			a.IdempotencyKey = idemKey(candidateHash, a.Capability+"|deps="+strings.Join(deps, ","))
		}
	}
	return detectRefCycle(actions)
}

// refuseUnknownOperands is the SILENT-IGNORE GUARD. The candidate's
// implementation block is free-form (D26), but a driver silently drops any
// operand key it does not read — a candidate with e.g. implementation.vpcSubnetIds
// on a driver that never reads it would compile clean, preflight "ready" and
// apply to "succeeded" with the operand dropped, a cardinal-invariant violation
// (the fail-closed rule the per-attribute allowlists already enforce, missing on
// the operand half). For every action that feeds operands to a driver — create
// and update; delete/claim read no implementation — every TOP-LEVEL operand key
// must be a key the driver DECLARES it consumes (provider.OperandConsumer) or a
// resolved $ref slot (already validated by wireReferences); anything else refuses
// with unknown-operand before the plan is sealed. Only TOP-LEVEL keys are
// checked: a map-valued operand (e.g. an env/labels map) whose arbitrary
// SUBkeys are free is honored — the driver declares the top-level key. A driver
// that declares no consumed set (the Fake double, which reads no operands) is
// exempt; the guard binds the real cloud drivers.
func refuseUnknownOperands(actions []Action, cand *contract.Candidate, in Inputs) error {
	for i := range actions {
		a := &actions[i]
		if a.Operation != "create" && a.Operation != "update" {
			continue
		}
		impl := implementationOf(cand, a.Capability)
		if len(impl) == 0 {
			continue
		}
		extras := cand.Extras[a.Capability]
		prov, _ := extras["provider"].(string)
		if prov == "" {
			prov = in.BindingProviders[a.Capability]
		}
		svc, _ := extras["service"].(string)
		if svc == "" {
			svc = in.BindingServices[a.Capability]
		}
		oc, ok := in.providerFor(prov).(provider.OperandConsumer)
		if !ok {
			continue // no declared consumed set (Fake) — the guard binds real drivers
		}
		allowed := map[string]bool{}
		for _, k := range oc.ConsumedOperands(svc) {
			allowed[k] = true
		}
		keys := make([]string, 0, len(impl))
		for k := range impl {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if allowed[k] {
				continue
			}
			if _, isRef, _ := parseOutputRef(impl[k]); isRef {
				continue // a resolved $ref slot — wireReferences validated it
			}
			return &RefusalError{
				Reason: fmt.Sprintf(
					"%s.%s is not an operand the %s/%s driver reads — refusing rather "+
						"than silently dropping it (unknown-operand); declare it under a "+
						"key the driver consumes, or remove it",
					a.Capability, k, prov, svc),
				RefPointer: fmt.Sprintf("capabilities.%s.implementation.%s", a.Capability, k),
				Note: fmt.Sprintf(
					"the %s/%s driver does not read operand %q — declare it under a key "+
						"the driver consumes, or remove it (an ignored operand is refused, "+
						"not silently dropped)", prov, svc, k),
			}
		}
	}
	return nil
}

// detectRefCycle refuses a reference graph with a cycle (D226): references add
// consumer->producer edges, and the executor cannot order a cycle.
func detectRefCycle(actions []Action) error {
	adj := map[string][]string{}
	for i := range actions {
		for _, r := range actions[i].References {
			adj[actions[i].ID] = append(adj[actions[i].ID], r.ProducerAction)
		}
	}
	const (
		white, gray, black = 0, 1, 2
	)
	color := map[string]int{}
	var visit func(string) bool
	visit = func(n string) bool {
		color[n] = gray
		for _, m := range adj[n] {
			if color[m] == gray {
				return true
			}
			if color[m] == white && visit(m) {
				return true
			}
		}
		color[n] = black
		return false
	}
	for id := range adj {
		if color[id] == white && visit(id) {
			return fmt.Errorf("intra-plan references form a dependency cycle (D226)")
		}
	}
	return nil
}

// idemKey derives deterministically from candidate identity — a re-run of
// the same compile produces the same keys, so the provider dedups (D29).
func idemKey(candidateHash, capID string) string {
	sum := sha256.Sum256([]byte(candidateHash + ":" + capID))
	return capID + "-" + hex.EncodeToString(sum[:])[:12]
}

// createRisk: conservative v0 table for `create` — a fresh resource holds
// no data yet, so dataLoss/downtime are none; exposure is governed by the
// verified constraints, not the action. Cost comes from the candidate's
// own cost.monthly claim when declared.
func createRisk(cand *contract.Candidate, capID string) Risk {
	risk := Risk{
		Reversibility:       "R1",
		DataLoss:            "none",
		Downtime:            "none",
		SecurityExposure:    "none",
		CostDelta:           Money{Amount: 0, Currency: "EUR"},
		IdentityReplacement: false,
	}
	if pv, ok := cand.Capabilities[capID]["cost.monthly"]; ok &&
		pv.Scalar != nil && pv.Scalar.Kind == scalars.Money {
		mv := pv.Scalar.Value.(scalars.MoneyValue)
		risk.CostDelta = Money{Amount: mv.Amount, Currency: mv.Currency}
	}
	return risk
}
