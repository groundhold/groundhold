// Package plan implements Sealed Plan IR v0 loading + structural
// validation (spec/sealed-plan.md, D36). Fail-closed (D19): unknown
// operations, dangling or cyclic dependencies, unpinned writes and
// missing report-executable preconditions are refused at load.
package plan

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"

	"groundhold/internal/docio"
)

var Operations = map[string]bool{
	"create": true, "update": true, "replace": true,
	"delete": true, "adopt": true, "noop": true, "claim": true,
}

// LoadOnlyOperations names the members of `Operations` that this project's compiler
// never emits and its executor refuses. D1174.
//
// They were not declared anywhere; they were simply in the set, which meant the
// published closed set invited a producer to write an action our own executor turns
// away. `replace` is the sharp one: `planview/helpers.go` says in so many words that
// "there is no `replace` operation in the IR" — a replacement is composed as
// create-before-destroy (D48) — while `spec/sealed-plan.md` published it as a valid
// operation. We were publishing an operation we had documented as nonexistent.
//
// They stay ACCEPTED rather than being deleted, for reasons that differ per member
// and are worth stating rather than assuming:
//
//   - `adopt`   a conformance case pins what `forecast` says about one
//     (`unsupported-effect-model`) — the honest answer for an action whose
//     effect this project does not model. Refusing it at load would delete
//     that answer rather than improve it. Note the collision: `groundhold
//     adopt` is a VERB (D52 onboarding) that writes bindings directly and
//     compiles no plan; this is the plan ACTION of the same name.
//   - `noop`    a converged plan has zero ACTIONS (D533), not a no-op one, so nothing
//     emits it; it is accepted so a third-party producer that spells
//     "nothing to do" this way still loads.
//   - `replace` accepted for the same reason and for no other: it is what a reader of
//     the old published list would have written.
//
// What changes is that the fact is now DECLARED and gated, so the published prose can
// say which operations apply and which merely load, and a new member cannot join
// `Operations` without a reader deciding which of the two it is.
var LoadOnlyOperations = map[string]bool{
	"replace": true, "adopt": true, "noop": true,
}
var PreconditionTypes = map[string]bool{
	"report-executable": true, "no-assumed-basis": true, "within-autonomy": true,
	"no-assumed-hard-basis": true, // D195: hard-only, assumed-only gate
}
var RiskLevels = map[string]bool{"none": true, "possible": true, "certain": true}
var Reversibility = map[string]bool{
	"R0": true, "R1": true, "R2": true, "R3": true, "R4": true,
}

// The key sets this document admits, one per level the loader walks. D1171.
//
// Nine conformance cases pinned the plan's semantics before this and every one of
// them was about a VALUE or a RELATION — an unknown operation, a cycle, a dangling
// dependency, an unpinned write, a missing precondition, a bad risk vector. None was
// about a KEY, which is D673's sentence ("true of values, false of keys") one
// document further along and on the EXECUTION path.
//
// The sharp one is `dependsOn`: an OPTIONAL read (below), so `dependson:` is not an
// error — it reads as "this action has no dependencies". apply then trusts the graph
// verbatim in topoOrder AND depFailed, so a lost edge moves both the execution order
// and the fail-isolation set. In a D48 replace composition the destroy leg depends on
// the create leg; lose that edge and the destroy may go first, on a stateful resource.
//
// These sets are DERIVED from what the compiler emits, not from what this loader
// reads — the loader reads 7 of the 12 fields in a plan body, so closing on its own
// reads would refuse `requiredPermissions` (D75, read by apply), `references` (D226),
// `folds` (D283), the D249 triple and the two sealed consents. The gate in
// plancompilerparity_gate_test.go holds them to the compiler's struct tags, so the
// rule is "the loader accepts exactly what our compiler emits" and neither side can
// drift alone.
var (
	planDocKeys = map[string]bool{"apiVersion": true, "kind": true, "plan": true}

	planBodyKeys = map[string]bool{
		"contract": true, "environment": true, "reads": true, "writes": true,
		"actions": true, "witnessed": true, "blocked": true, "unverified": true,
		"noop": true, "preconditions": true, "advisories": true,
	}

	planReadsKeys = map[string]bool{
		"contractHash": true, "candidateHash": true, "heads": true,
		"vocabularies": true, "toolchain": true, "provider": true,
	}

	planActionKeys = map[string]bool{
		"id": true, "capability": true, "operation": true, "target": true,
		"idempotencyKey": true, "dependsOn": true, "changes": true,
		"targetProviderId": true, "targetGeneration": true, "replaces": true,
		"deposed": true, "fieldReclaim": true, "emissionAdopt": true,
		"requiredPermissions": true, "references": true, "folds": true, "risk": true,
	}

	planRiskKeys = map[string]bool{
		"reversibility": true, "dataLoss": true, "downtime": true,
		"securityExposure": true, "costDelta": true, "identityReplacement": true,
	}

	planChangeKeys = map[string]bool{
		"path": true, "from": true, "to": true, "caveat": true,
	}

	planWitnessKeys = map[string]bool{
		"capability": true, "provider": true, "service": true, "reason": true,
	}

	planPreconditionKeys = map[string]bool{"type": true}

	// D1172. The debt D1171 recorded rather than hid: seven nested lists the loader
	// admitted by NAME and never walked, so their inner keys were as open as the whole
	// document had been. Measured harm, on `replaces`: apply builds the binding's
	// `lineage.replaces` from `a["replaces"]["providerId"]` and NOTHING else, so a
	// misspelling there drops the succession record — the answer to "what did this
	// resource replace", which is what an audit and a capsule are read for. The D48
	// safety backstop does NOT fall with it: D1056 re-derives the replaced id from the
	// paired delete's REQUIRED targetProviderId precisely so it never rests on this
	// forgeable field. So the damage here is to the evidence, not to the guard — which
	// is worth saying plainly, because the first framing of this debt overstated it.
	planReplacesKeys = map[string]bool{
		"providerId": true, "generation": true, "because": true,
	}
	planReferenceKeys = map[string]bool{
		"slot": true, "producerAction": true, "capability": true,
		"output": true, "kind": true,
	}
	planFoldKeys = map[string]bool{
		"slot": true, "capability": true, "output": true, "value": true,
		"observedAt": true, "ttlSeconds": true,
	}
	planBlockedKeys    = map[string]bool{"capability": true, "reason": true}
	planUnverifiedKeys = map[string]bool{"capability": true, "attributes": true}
	planNoOpKeys       = map[string]bool{"capability": true, "reason": true}
	planAdvisoryKeys   = map[string]bool{
		"code": true, "capability": true, "pointer": true,
		"detail": true, "next": true,
	}

	// D1171. The shipped example and the published prose both wrote
	// `provider: { name, project, region }`. The compiler emits name and project;
	// apply reads name and project; nothing anywhere reads a region here. A reader
	// consults a sealed plan to learn WHERE it will act, finds `region:
	// europe-west1` in the example this project ships, and believes the plan pins
	// it. It does not — region reaches a driver from the candidate, and this line
	// was decoration in the block D28 calls the pinned read-set.
	planProviderKeys = map[string]bool{"name": true, "project": true}
)

var hashRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func requireHash(v any, what string) error {
	s, ok := v.(string)
	if !ok || !hashRE.MatchString(s) {
		return fmt.Errorf("%s must be a sha256:<hex> hash", what)
	}
	return nil
}

// checkNestedItems closes ONE list of mappings. The list itself is optional — the
// compiler emits every one of these with `omitempty` — but a present list must be a
// list, and an item must be a mapping: a fail-closed loader that shrugged at
// `replaces: "yes"` would be reading the document less carefully than the shape it
// then refuses keys against.
func checkNestedItems(v any, known map[string]bool, where, why string) error {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("%s must be a list", where)
	}
	for i, it := range list {
		m, ok := it.(map[string]any)
		if !ok {
			return fmt.Errorf("%s[%d] must be a mapping", where, i)
		}
		if err := docio.CheckKnownKeys(m, known,
			fmt.Sprintf("%s[%d]", where, i), why); err != nil {
			return err
		}
	}
	return nil
}

func checkRisk(aid string, riskAny any) error {
	risk, ok := riskAny.(map[string]any)
	if !ok {
		return fmt.Errorf("action %s: risk vector is required (D33)", aid)
	}
	if err := docio.CheckKnownKeys(risk, planRiskKeys,
		fmt.Sprintf("action %s: risk", aid),
		"the risk vector is what the autonomy gate reads (D33); a dimension "+
			"nothing reads is a dimension nothing gates on"); err != nil {
		return err
	}
	if r, _ := risk["reversibility"].(string); !Reversibility[r] {
		return fmt.Errorf("action %s: invalid reversibility", aid)
	}
	for _, dim := range []string{"dataLoss", "downtime", "securityExposure"} {
		if v, _ := risk[dim].(string); !RiskLevels[v] {
			return fmt.Errorf("action %s: invalid risk dimension %s", aid, dim)
		}
	}
	if _, ok := risk["identityReplacement"].(bool); !ok {
		return fmt.Errorf("action %s: identityReplacement must be a bool", aid)
	}
	cd, ok := risk["costDelta"].(map[string]any)
	if !ok {
		return fmt.Errorf("action %s: costDelta must be {amount, currency}", aid)
	}
	switch cd["amount"].(type) {
	case int, int64, float64:
	default:
		return fmt.Errorf("action %s: costDelta must be {amount, currency}", aid)
	}
	if c, _ := cd["currency"].(string); c == "" {
		return fmt.Errorf("action %s: costDelta must be {amount, currency}", aid)
	}
	return nil
}

func LoadPlan(path string) (map[string]any, error) {
	raw, err := docio.ReadDoc(path)
	if err != nil {
		return nil, err
	}
	var docAny any
	if err := yaml.Unmarshal(raw, &docAny); err != nil {
		return nil, err
	}
	doc, ok := docAny.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("plan document is empty or not a mapping")
	}
	if s, _ := doc["kind"].(string); s != "SealedPlan" {
		return nil, fmt.Errorf("kind must be SealedPlan")
	}
	if s, _ := doc["apiVersion"].(string); s != "plan/v0" {
		return nil, fmt.Errorf("apiVersion must be plan/v0")
	}
	if err := docio.CheckKnownKeys(doc, planDocKeys, "sealed plan",
		"a plan is executed, and a block the executor does not read decides nothing "+
			"while looking like it does"); err != nil {
		return nil, err
	}
	p, ok := doc["plan"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("plan block is required")
	}
	if err := docio.CheckKnownKeys(p, planBodyKeys, "plan",
		"a plan is executed, and a block the executor does not read decides nothing "+
			"while looking like it does"); err != nil {
		return nil, err
	}
	for _, nb := range []struct {
		key   string
		known map[string]bool
		why   string
	}{
		{"blocked", planBlockedKeys, "a blocked capability is the record that a " +
			"compile could NOT reconcile it (D249) — a key nothing reads weakens the " +
			"one thing standing between this and being read as converged"},
		{"unverified", planUnverifiedKeys, "same record, same consequence (D249)"},
		{"noop", planNoOpKeys, "a no-op entry says a capability needed nothing done; " +
			"a key nothing reads makes that claim less legible, not more"},
		{"advisories", planAdvisoryKeys, "an advisory is carried so an AGENT reads it " +
			"(D388); a field nothing reads is an advisory nobody receives"},
	} {
		if err := checkNestedItems(p[nb.key], nb.known, "plan."+nb.key, nb.why); err != nil {
			return nil, err
		}
	}
	if c, _ := p["contract"].(string); c == "" {
		return nil, fmt.Errorf("plan.contract is required")
	}

	reads, ok := p["reads"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("plan.reads is required (D28: pin the read-set)")
	}
	if err := docio.CheckKnownKeys(reads, planReadsKeys, "plan.reads",
		"the read-set is what D28 pins; an entry nothing reads pins nothing"); err != nil {
		return nil, err
	}
	if pv, present := reads["provider"].(map[string]any); present {
		if err := docio.CheckKnownKeys(pv, planProviderKeys, "plan.reads.provider",
			"this block is the PINNED provider identity (D28); a key nothing reads "+
				"tells a reader something is pinned when it is not"); err != nil {
			return nil, err
		}
	}
	if err := requireHash(reads["contractHash"], "reads.contractHash"); err != nil {
		return nil, err
	}
	if err := requireHash(reads["candidateHash"], "reads.candidateHash"); err != nil {
		return nil, err
	}
	// D533: `present but empty` is not `missing`. Heads are pinned per capability
	// WITH AN ACTION, so a plan with no actions legitimately has none — and the
	// compiler seals exactly such a plan on purpose when a capability is blocked or
	// unverified (compiler.go: "actions == 0 with blocked/unverified present is NOT
	// nothing to change"). Conflating the two made apply refuse an artefact its own
	// compiler intends to produce: converged infrastructure exited 2, which a
	// caller cannot tell from a real refusal. The invariant that DOES hold is
	// checked below, against the actions.
	heads, ok := reads["heads"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("reads.heads must pin a head per capability")
	}
	for cap, h := range heads {
		if s, _ := h.(string); s != "genesis" {
			if err := requireHash(h, fmt.Sprintf("reads.heads[%s]", cap)); err != nil {
				return nil, err
			}
		}
	}
	tc, ok := reads["toolchain"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("reads.toolchain must carry compiler and spec")
	}
	if c, _ := tc["compiler"].(string); c == "" {
		return nil, fmt.Errorf("reads.toolchain must carry compiler and spec")
	}
	if s, _ := tc["spec"].(string); s == "" {
		return nil, fmt.Errorf("reads.toolchain must carry compiler and spec")
	}

	// D533: a converged plan writes nothing, and that is the point of it.
	writesAny, ok := p["writes"].([]any)
	if !ok {
		return nil, fmt.Errorf("plan.writes must be a list of ids")
	}
	writes := map[string]bool{}
	for _, w := range writesAny {
		s, ok := w.(string)
		if !ok {
			return nil, fmt.Errorf("plan.writes must be a non-empty list of ids")
		}
		if _, pinned := heads[s]; !pinned {
			return nil, fmt.Errorf("write %q has no pinned head — you cannot "+
				"write what you did not read (D28)", s)
		}
		writes[s] = true
	}

	// D533: same distinction. An absent or ill-typed `actions` is malformed; an
	// EMPTY one is a converged plan, which `show`, `forecast` and `apply` must all
	// accept — apply then does nothing, which is the honest outcome.
	actions, ok := p["actions"].([]any)
	if !ok {
		return nil, fmt.Errorf("plan.actions must be a list")
	}
	if len(actions) > 0 && len(heads) == 0 {
		return nil, fmt.Errorf("reads.heads must pin a head per capability with an action")
	}
	ids := map[string]bool{}
	deps := map[string][]string{}
	for _, it := range actions {
		a, ok := it.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("action missing id")
		}
		aid, _ := a["id"].(string)
		if aid == "" {
			return nil, fmt.Errorf("action missing id")
		}
		if err := docio.CheckKnownKeys(a, planActionKeys, "action "+aid,
			"`dependsOn` is read OPTIONALLY, so a misspelling is not an error — it "+
				"reads as `no dependencies`, and apply trusts the graph verbatim for "+
				"both ordering and fail-isolation (a D48 replace would destroy before "+
				"it created)"); err != nil {
			return nil, err
		}
		if ids[aid] {
			return nil, fmt.Errorf("duplicate action id: %s", aid)
		}
		ids[aid] = true
		if rep, present := a["replaces"]; present {
			m, ok := rep.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("action %s: replaces must be a mapping", aid)
			}
			if err := docio.CheckKnownKeys(m, planReplacesKeys,
				"action "+aid+": replaces",
				"apply builds the binding's `lineage.replaces` from `providerId` here "+
					"and nothing else, so a misspelling drops the record of what this "+
					"resource SUCCEEDED — the question an audit and a capsule are read "+
					"for. (The D48 backstop does not fall with it: D1056 re-derives the "+
					"replaced id from the paired delete's required pin.)"); err != nil {
				return nil, err
			}
		}
		if err := checkNestedItems(a["references"], planReferenceKeys,
			"action "+aid+": references",
			"a reference resolves an operand from another action's receipt at apply "+
				"(D226); a key nothing reads is an operand silently unresolved"); err != nil {
			return nil, err
		}
		if err := checkNestedItems(a["folds"], planFoldKeys,
			"action "+aid+": folds",
			"a fold is a literal SEALED into the decision (D283) — its identity fields "+
				"are what a reader checks the seal against"); err != nil {
			return nil, err
		}
		if cap, _ := a["capability"].(string); !writes[cap] {
			return nil, fmt.Errorf("action %s: capability outside plan.writes", aid)
		}
		if op, _ := a["operation"].(string); !Operations[op] {
			return nil, fmt.Errorf("action %s: unknown operation %q", aid,
				a["operation"])
		}
		if k, _ := a["idempotencyKey"].(string); k == "" {
			return nil, fmt.Errorf("action %s: idempotencyKey is required (D29)", aid)
		}
		if err := checkRisk(aid, a["risk"]); err != nil {
			return nil, err
		}
		if op, _ := a["operation"].(string); op == "delete" {
			// D47: a delete pins the exact identity it destroys — a
			// rebind between seal and apply must not redirect it
			if t, _ := a["targetProviderId"].(string); t == "" {
				return nil, fmt.Errorf(
					"action %s: delete requires targetProviderId", aid)
			}
			gen, ok := a["targetGeneration"].(int)
			if !ok || gen < 1 {
				return nil, fmt.Errorf(
					"action %s: delete requires targetGeneration >= 1", aid)
			}
		}
		if op, _ := a["operation"].(string); op == "update" {
			// D46: an update is a reviewed change-set, never an implicit diff
			changes, ok := a["changes"].([]any)
			if !ok || len(changes) == 0 {
				return nil, fmt.Errorf(
					"action %s: update requires a non-empty changes list", aid)
			}
			for _, chAny := range changes {
				ch, ok := chAny.(map[string]any)
				if !ok {
					return nil, fmt.Errorf(
						"action %s: each change needs path and to", aid)
				}
				if err := docio.CheckKnownKeys(ch, planChangeKeys,
					"action "+aid+": change",
					"an update is a REVIEWED change-set (D46), and a field nothing "+
						"reads was never reviewed"); err != nil {
					return nil, err
				}
				_, hasTo := ch["to"]
				if p, _ := ch["path"].(string); p == "" || !hasTo {
					return nil, fmt.Errorf(
						"action %s: each change needs path and to", aid)
				}
			}
		}
		var ds []string
		if dl, ok := a["dependsOn"].([]any); ok {
			for _, d := range dl {
				s, _ := d.(string)
				ds = append(ds, s)
			}
		}
		deps[aid] = ds
	}
	for aid, ds := range deps {
		for _, d := range ds {
			if !ids[d] {
				return nil, fmt.Errorf("action %s: dependsOn unknown action %q",
					aid, d)
			}
		}
	}
	// cycle check (Kahn)
	indeg := map[string]int{}
	rev := map[string][]string{}
	for aid, ds := range deps {
		indeg[aid] = len(ds)
		for _, d := range ds {
			rev[d] = append(rev[d], aid)
		}
	}
	queue := []string{}
	for aid, n := range indeg {
		if n == 0 {
			queue = append(queue, aid)
		}
	}
	seen := 0
	for len(queue) > 0 {
		n := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		seen++
		for _, m := range rev[n] {
			indeg[m]--
			if indeg[m] == 0 {
				queue = append(queue, m)
			}
		}
	}
	if seen != len(deps) {
		return nil, fmt.Errorf("action dependency graph has a cycle")
	}

	// D533: a converged plan has no actions, so it has no preconditions to pin.
	pre, ok := p["preconditions"].([]any)
	if !ok {
		return nil, fmt.Errorf("plan.preconditions must be a list")
	}
	hasExecutable := false
	for _, it := range pre {
		pc, _ := it.(map[string]any)
		if err := docio.CheckKnownKeys(pc, planPreconditionKeys, "precondition",
			"a precondition is a gate; a key nothing reads is a gate nothing "+
				"applies"); err != nil {
			return nil, err
		}
		t, _ := pc["type"].(string)
		if !PreconditionTypes[t] {
			return nil, fmt.Errorf("unknown precondition type: %q", pc["type"])
		}
		if t == "report-executable" {
			hasExecutable = true
		}
	}
	if !hasExecutable {
		return nil, fmt.Errorf("preconditions must include report-executable — " +
			"a plan that does not require verification to pass contradicts " +
			"the thesis")
	}

	// D177: witnessed capabilities are VERIFIED but not authored. Each must be
	// well-formed, have a pinned head (verified => read, D28), and be DISJOINT from
	// writes (a witness mutates nothing — being in writes would be a lie).
	if wl, present := p["witnessed"]; present {
		list, ok := wl.([]any)
		if !ok {
			return nil, fmt.Errorf("plan.witnessed must be a list")
		}
		for _, it := range list {
			w, ok := it.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("witnessed entry must be a mapping")
			}
			capID, _ := w["capability"].(string)
			if capID == "" {
				return nil, fmt.Errorf("witnessed entry missing capability")
			}
			if err := docio.CheckKnownKeys(w, planWitnessKeys,
				"witnessed "+capID,
				"a witness record is the claim that something was VERIFIED but not "+
					"authored (D177); a key nothing reads weakens that claim "+
					"silently"); err != nil {
				return nil, err
			}
			for _, k := range []string{"provider", "service", "reason"} {
				if s, _ := w[k].(string); s == "" {
					return nil, fmt.Errorf("witnessed %s: %s is required", capID, k)
				}
			}
			if _, pinned := heads[capID]; !pinned {
				return nil, fmt.Errorf("witnessed %s has no pinned head — a "+
					"witnessed capability is verified, so it must be read (D28)", capID)
			}
			if writes[capID] {
				return nil, fmt.Errorf("witnessed %s is also in plan.writes — a "+
					"witness mutates nothing (D177)", capID)
			}
		}
	}
	return doc, nil
}
