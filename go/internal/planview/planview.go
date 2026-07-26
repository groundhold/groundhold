// Package planview renders a Sealed Plan (the machine IR that `plan` emits) into
// a scannable human preview — the review surface before `apply` (the praised
// "plan mode"). It is PRESENTATION ONLY (D89): never parsed for control flow;
// the JSON stays the sole machine contract. It is a pure, deterministic function
// of the plan bytes (no wall clock, no color here), so it is golden-testable.
//
// Honesty rules it obeys (four-valued discipline applied to a plan):
//   - the six-field Risk vector is printed VERBATIM on every action; there is no
//     composite "danger" score, no severity adjective, anywhere;
//   - destructive actions (delete/replace, dataLoss certain, identity replaced,
//     R4) get a full-width rail AND a recap footer — they cannot be buried;
//   - cost is summed PER CURRENCY (never coerced across currencies, invariant
//     #2) and labelled as the sum of DECLARED cost.monthly deltas — an action
//     without a claim carries 0 and is not distinguishable in the IR, so the
//     label says exactly that rather than implying a complete total.
package planview

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type money struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

type risk struct {
	Reversibility       string `json:"reversibility"`
	DataLoss            string `json:"dataLoss"`
	Downtime            string `json:"downtime"`
	SecurityExposure    string `json:"securityExposure"`
	CostDelta           money  `json:"costDelta"`
	IdentityReplacement bool   `json:"identityReplacement"`
}

type change struct {
	Path   string `json:"path"`
	From   any    `json:"from"`
	To     any    `json:"to"`
	Caveat string `json:"caveat,omitempty"`
}

type replaceInfo struct {
	ProviderID string   `json:"providerId"`
	Generation int      `json:"generation"`
	Because    []change `json:"because"`
}

type reference struct {
	Slot           string `json:"slot"`
	ProducerAction string `json:"producerAction"`
	Capability     string `json:"capability"`
	Output         string `json:"output"`
	Kind           string `json:"kind"`
}

// fold is a reference RESOLVED AT COMPILE (D283): the producer was already
// bound, so the operand carries a LITERAL folded from a fresh wiring
// observation. The view must say WHERE the value came from and HOW OLD the
// evidence is — a sealed literal that reads like an operator's own typing
// would hide that this plan rests on an observation with a shelf life.
type fold struct {
	Slot       string `json:"slot"`
	Capability string `json:"capability"`
	Output     string `json:"output"`
	Value      any    `json:"value"`
	ObservedAt string `json:"observedAt"`
	TTLSeconds int    `json:"ttlSeconds"`
}

type action struct {
	ID                  string       `json:"id"`
	Capability          string       `json:"capability"`
	Operation           string       `json:"operation"`
	Target              string       `json:"target"`
	IdempotencyKey      string       `json:"idempotencyKey"`
	DependsOn           []string     `json:"dependsOn,omitempty"`
	Changes             []change     `json:"changes,omitempty"`
	TargetProviderID    string       `json:"targetProviderId,omitempty"`
	TargetGeneration    int          `json:"targetGeneration,omitempty"`
	Replaces            *replaceInfo `json:"replaces,omitempty"`
	Deposed             bool         `json:"deposed,omitempty"`
	RequiredPermissions []string     `json:"requiredPermissions,omitempty"`
	References          []reference  `json:"references,omitempty"`
	Folds               []fold       `json:"folds,omitempty"`
	Risk                risk         `json:"risk"`
}

type witness struct {
	Capability string `json:"capability"`
	Provider   string `json:"provider"`
	Service    string `json:"service"`
	Reason     string `json:"reason"`
}

type blockedCap struct {
	Capability string `json:"capability"`
	Reason     string `json:"reason"`
}

type unverifiedCap struct {
	Capability string   `json:"capability"`
	Attributes []string `json:"attributes"`
}

type precondition struct {
	Type string `json:"type"`
}

type provider struct {
	Name    string `json:"name"`
	Project string `json:"project,omitempty"`
}

type reads struct {
	ContractHash  string            `json:"contractHash"`
	CandidateHash string            `json:"candidateHash"`
	Heads         map[string]string `json:"heads"`
	Provider      *provider         `json:"provider,omitempty"`
}

type body struct {
	Contract      string          `json:"contract"`
	Environment   string          `json:"environment,omitempty"`
	Reads         reads           `json:"reads"`
	Writes        []string        `json:"writes"`
	Actions       []action        `json:"actions"`
	Witnessed     []witness       `json:"witnessed,omitempty"`
	Blocked       []blockedCap    `json:"blocked,omitempty"`
	Unverified    []unverifiedCap `json:"unverified,omitempty"`
	Preconditions []precondition  `json:"preconditions"`
}

type document struct {
	Plan body `json:"plan"`
}

const rail = "################################################################################"

// Render turns sealed-plan JSON into the human preview. planHash is the plan's
// own hash (bound in the header so the reviewed artifact and the applied one are
// provably the same); pass "" if unknown.
func Render(planJSON []byte, planHash string) (string, error) {
	var doc document
	if err := json.Unmarshal(planJSON, &doc); err != nil {
		return "", fmt.Errorf("not a sealed plan: %w", err)
	}
	p := doc.Plan
	order := topo(p.Actions)

	var b strings.Builder
	writeHeader(&b, p, planHash, len(order))

	fmt.Fprintf(&b, "\nexecution order -- %d %s\n", len(order), plural(len(order), "action"))
	for i, id := range order {
		writeAction(&b, byID(p.Actions, id), i+1)
	}
	writeRecap(&b, p.Actions, order)
	writeWitnessed(&b, p.Witnessed)
	writeBlocked(&b, p.Blocked)
	writeUnverified(&b, p.Unverified)
	writePreconditions(&b, p.Preconditions)
	writePermissions(&b, p.Actions)
	writeAggregate(&b, p.Actions)
	return b.String(), nil
}

// Recap returns just the destructive-recap block for a plan (D228), or "" if
// the plan has no destructive action. `apply` prints it to stderr immediately
// before mutating, so the last thing a human sees before the change is the same
// vocabulary they reviewed with `show`.
func Recap(planJSON []byte) string {
	var doc document
	if err := json.Unmarshal(planJSON, &doc); err != nil {
		return ""
	}
	var b strings.Builder
	writeRecap(&b, doc.Plan.Actions, topo(doc.Plan.Actions))
	return strings.TrimPrefix(b.String(), "\n")
}

func writeHeader(b *strings.Builder, p body, planHash string, n int) {
	fmt.Fprintln(b, "GROUNDHOLD SEALED PLAN  (preview only -- apply consumes the JSON)")
	if planHash != "" {
		fmt.Fprintf(b, "plan %s\n", planHash)
	}
	env := p.Environment
	if env == "" {
		env = "-"
	}
	fmt.Fprintf(b, "contract %s @ env %s\n", p.Contract, env)
	prov := "-"
	if p.Reads.Provider != nil {
		prov = p.Reads.Provider.Name
		if p.Reads.Provider.Project != "" {
			prov += "/" + p.Reads.Provider.Project
		}
	}
	fmt.Fprintf(b, "reads  contract %s  candidate %s  heads %d  provider %s\n",
		short(p.Reads.ContractHash), short(p.Reads.CandidateHash), len(p.Reads.Heads), prov)
}

func writeAction(b *strings.Builder, a action, n int) {
	destructive := isDestructive(a)
	line := func(format string, args ...any) {
		if destructive {
			b.WriteString("## ")
		}
		fmt.Fprintf(b, format+"\n", args...)
	}
	b.WriteByte('\n')
	if destructive {
		fmt.Fprintln(b, rail)
	}
	suffix := ""
	if a.Deposed {
		suffix = "  (deposed)"
	}
	line("[%d] %s %s%s", n, glyph(a), a.Capability, suffix)
	line("      target       %s   idempotency %s", a.Target, a.IdempotencyKey)
	if a.TargetProviderID != "" {
		line("      pinned       %s gen %d", a.TargetProviderID, a.TargetGeneration)
	}
	if a.Replaces != nil {
		line("      replaces     %s gen %d", a.Replaces.ProviderID, a.Replaces.Generation)
		for _, c := range a.Replaces.Because {
			line("      because      %s: %s -> %s   (immutable)", c.Path, val(c.From), val(c.To))
		}
	}
	if len(a.Changes) > 0 {
		line("      changes")
		for _, c := range a.Changes {
			line("        %s: %s -> %s", c.Path, val(c.From), val(c.To))
			if c.Caveat != "" {
				line("            caveat: %s", c.Caveat)
			}
		}
	}
	for _, r := range a.References {
		line("      wires        %s <- [%s] %s output %s (kind %s)",
			r.Slot, r.ProducerAction, r.Capability, r.Output, r.Kind)
	}
	for _, f := range a.Folds {
		// the value is SEALED into this plan; the observation stamp is the
		// honest expiry of the knowledge it rests on (apply re-checks both).
		line("      folded       %s <- %s output %s = %s",
			f.Slot, f.Capability, f.Output, val(f.Value))
		line("                     observed %s, valid %s", f.ObservedAt, ttlWindow(f.TTLSeconds))
	}
	line("      risk         %s", riskVector(a.Risk))
	if len(a.RequiredPermissions) > 0 {
		line("      permissions  %d required", len(a.RequiredPermissions))
	}
	if destructive {
		fmt.Fprintln(b, rail)
	}
}

// riskVector prints all six fields verbatim — no composite, no adjective.
func riskVector(r risk) string {
	id := "kept"
	if r.IdentityReplacement {
		id = "REPLACED"
	}
	return fmt.Sprintf("reversibility %s | dataLoss %s | downtime %s | exposure %s | identity %s | cost %s",
		r.Reversibility, r.DataLoss, r.Downtime, r.SecurityExposure, id, cost(r.CostDelta))
}

func writeRecap(b *strings.Builder, actions []action, order []string) {
	var d []string
	for _, id := range order {
		if isDestructive(byID(actions, id)) {
			d = append(d, id)
		}
	}
	if len(d) == 0 {
		return
	}
	fmt.Fprintln(b, "\ndestructive recap -- read before apply")
	for _, id := range d {
		a := byID(actions, id)
		fmt.Fprintf(b, "  %s %s   %s\n", glyph(a), a.Capability, destructiveWhy(a))
	}
}

func writeWitnessed(b *strings.Builder, ws []witness) {
	if len(ws) == 0 {
		return
	}
	fmt.Fprintln(b, "\n= witnessed (verified, not authored -- untouched by this plan)")
	for _, w := range ws {
		fmt.Fprintf(b, "  %s   %s %s   reason: %s\n", w.Capability, w.Provider, w.Service, w.Reason)
	}
}

// writeBlocked (D249) surfaces capabilities held back because they could not be
// reconciled (a missing/stale observation, an unwired change class). Never silent:
// a reader must see that these were NOT converged and need a re-observe.
func writeBlocked(b *strings.Builder, bs []blockedCap) {
	if len(bs) == 0 {
		return
	}
	fmt.Fprintln(b, "\n= blocked (NOT converged -- re-observe, then re-plan)")
	for _, x := range bs {
		fmt.Fprintf(b, "  %s   %s\n", x.Capability, x.Reason)
	}
}

// writeUnverified (D249) surfaces capabilities that reconciled their observable
// attributes but declare one or more the driver cannot observe: taken as declared,
// reported inconclusive so a reader never mistakes them for proven-converged.
func writeUnverified(b *strings.Builder, us []unverifiedCap) {
	if len(us) == 0 {
		return
	}
	fmt.Fprintln(b, "\n= unverified (reconciled, but these attributes are not observable -- taken as declared)")
	for _, u := range us {
		fmt.Fprintf(b, "  %s   %s\n", u.Capability, strings.Join(u.Attributes, ", "))
	}
}

func writePreconditions(b *strings.Builder, pc []precondition) {
	if len(pc) == 0 {
		return
	}
	fmt.Fprintln(b, "\npreconditions")
	for _, p := range pc {
		fmt.Fprintf(b, "  %s\n", p.Type)
	}
}

func writePermissions(b *strings.Builder, actions []action) {
	set := map[string]bool{}
	for _, a := range actions {
		for _, p := range a.RequiredPermissions {
			set[p] = true
		}
	}
	if len(set) == 0 {
		return
	}
	perms := make([]string, 0, len(set))
	for p := range set {
		perms = append(perms, p)
	}
	sort.Strings(perms)
	fmt.Fprintf(b, "\npermissions  union preflighted before the lease (%d)\n", len(perms))
	fmt.Fprintf(b, "  %s\n", strings.Join(perms, "  "))
}

func writeAggregate(b *strings.Builder, actions []action) {
	// a replace is a create-with-Replaces in the IR; count it as replace, not create.
	var create, update, replace, del, destructive int
	for _, a := range actions {
		switch {
		case a.Operation == "create" && a.Replaces != nil:
			replace++
		case a.Operation == "create":
			create++
		case a.Operation == "update":
			update++
		case a.Operation == "delete":
			del++
		}
		if isDestructive(a) {
			destructive++
		}
	}
	fmt.Fprintf(b, "\n%s\n", strings.Repeat("-", 80))
	fmt.Fprintf(b, "%d actions: %d create, %d update, %d replace, %d delete | destructive: %d\n",
		len(actions), create, update, replace, del, destructive)
	// per-axis worst is a max per axis — the vector's silhouette, never a collapse
	fmt.Fprintf(b, "per-axis worst: reversibility %s; dataLoss %s; downtime %s; exposure %s\n",
		worst(actions, func(a action) string { return a.Risk.Reversibility }, revRank),
		worst(actions, func(a action) string { return a.Risk.DataLoss }, tri),
		worst(actions, func(a action) string { return a.Risk.Downtime }, tri),
		worst(actions, func(a action) string { return a.Risk.SecurityExposure }, tri))
	writeCost(b, actions)
}

// writeCost sums declared cost.monthly deltas PER CURRENCY (no coercion). Because
// an unpriced action is indistinguishable from a declared 0 in the IR, the label
// says exactly "declared deltas", not a complete total — no fabricated precision.
func writeCost(b *strings.Builder, actions []action) {
	byCur := map[string]float64{}
	var order []string
	for _, a := range actions {
		c := a.Risk.CostDelta.Currency
		if c == "" {
			c = "?"
		}
		if _, seen := byCur[c]; !seen {
			order = append(order, c)
		}
		byCur[c] += a.Risk.CostDelta.Amount
	}
	sort.Strings(order)
	parts := make([]string, 0, len(order))
	for _, c := range order {
		parts = append(parts, fmt.Sprintf("%+.2f %s/mo", byCur[c], c))
	}
	fmt.Fprintf(b, "cost delta (sum of declared cost.monthly; unclaimed counted 0): %s\n",
		strings.Join(parts, "; "))
}
