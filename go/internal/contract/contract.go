// Package contract loads and structurally validates Contract and
// ImplementationCandidate documents. Fail-fast, fail-closed (D19):
// anything the loader does not recognize is refused, never silently
// non-gating. Constraint values parse eagerly; candidate values are
// kind/enum-checked against a vocabulary when one is provided (D23).
package contract

import (
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"groundhold/internal/docio"
	"groundhold/internal/scalars"
	"groundhold/internal/vocab"
)

// candidateCapabilityKeys is the capability block's shape, and it is CLOSED (D1160).
// `implementation` is the free-form half (D26); this level is structure, and a key
// here that the loader does not read is a stated intent nothing will act on.
// Reconciled against `spec/candidate.schema.json` by
// TestCandidateCapabilityKeysMatchThePublishedShape — the published document and the
// loader must accept the same four, or a document valid for one is dropped by the other.
// D1161: the levels INSIDE a contract, closed for the same reason the top level is.
// Reconciled against `spec/contract.schema.json` by
// TestContractInnerKeysMatchThePublishedShape — the published document and the loader
// must accept the same keys.
// D1162: the constraint object and its verify block, closed for a sharper reason than
// the levels around them. `verify` is guarded meticulously against every wrong VALUE —
// `method` beside `design`/`runtime` is refused, half of the two-bar form is refused,
// a non-string bar is refused with "a bar the loader cannot read must not fall back to
// the weakest evidence there is". A wrong KEY walked past all three and landed in
// exactly that weakest evidence: `method` initialises to "static", so `vrify:` or
// `methdo:` silently turned a constraint the contract says must be proven against the
// provider into one proven by reading the candidate's own claim.
//
// Measured on a residency constraint:
//
//	verify: {method: provider-api}  -> executable=false, unknown, "requires provider-api"
//	vrify:  {method: provider-api}  -> executable=TRUE,  SATISFIED, "declared eu-central-1"
//
// `budget` entries share $defs/constraint, so this covers them too. `objective` is
// soft-only in the schema but the loader parses both severities in one pass, so it is
// accepted here and its placement stays the schema's business.
var constraintKeys = map[string]bool{
	"id": true, "subject": true, "path": true, "op": true, "value": true,
	"verify": true}

// The two context-only keys. Checked where the CONTEXT is known rather than as one
// permissive union: `newConstraint` takes an already-resolved severity, so it cannot
// tell a budget entry from a hard constraint, and a union set would let `objective`
// sit unread on a hard constraint — the same silent-drop one key over.
var softConstraintKeys = withKey(constraintKeys, "objective")
var budgetConstraintKeys = withKey(constraintKeys, "severity")

// constraintKeysFor picks the set by CONTEXT. A function rather than a local variable
// so the choice is one expression a mutant can replace without leaving an unused
// binding behind — the meter reports that as NO-BUILD, which measures nothing (D799).
func constraintKeysFor(severity string) map[string]bool {
	if severity == "soft" {
		return softConstraintKeys
	}
	return constraintKeys
}

func withKey(base map[string]bool, extra string) map[string]bool {
	out := make(map[string]bool, len(base)+1)
	for k := range base {
		out[k] = true
	}
	out[extra] = true
	return out
}

// verifyKeys is the two published spellings of a bar: one (`method`) or two
// (`design` + `runtime`, D728). The loader already refuses mixing them and refuses
// half of the pair; what it did not refuse was a third spelling nobody reads.
var verifyKeys = map[string]bool{
	"method": true, "design": true, "runtime": true}

var contractCapabilityKeys = map[string]bool{
	"id": true, "type": true, "requirements": true, "state": true}

// requirementKeys is D8's short form, and it is exactly what the published schema
// publishes for it: `op` and `value`. The sugar builds a hard constraint with a STATIC
// bar and reads nothing else, so any other key here is a stated intent nothing acts on.
var requirementKeys = map[string]bool{"op": true, "value": true}

var contractMetaKeys = map[string]bool{
	"id": true, "environment": true, "version": true, "owner": true}

// provenancedKeys is the attribute block a candidate writes when it carries explicit
// provenance (D5). A typo here — `confidance` — dropped the confidence and the
// document passed at exit 0, so an assumption's strength vanished silently.
var provenancedKeys = map[string]bool{
	"status": true, "value": true, "source": true, "confidence": true}

var candidateCapabilityKeys = map[string]bool{
	"attributes": true, "implementation": true, "provider": true, "service": true}

var validStatuses = map[string]bool{
	"declared": true, "inferred": true, "assumed": true, "unknown": true}
var presenceOps = map[string]bool{"exists": true, "absent": true}

// validOps is DERIVED from the implementation, never hand-listed (D327). It used
// to be a literal copy of the same closed set, which is the D311 shape — the same
// knowledge written twice — and here the drift mode is a crash: `validOps` gating
// an operator `scalars.Operators` does not implement makes `Operators[c.Op]` a nil
// function, and verify calls it directly. A valid-looking contract would panic.
// The Python reference already derives it (`VALID_OPS = set(OPERATORS) |
// PRESENCE_OPERATORS`); this is the Go half catching up, so the two cannot
// disagree either (D25).
var validOps = func() map[string]bool {
	ops := map[string]bool{}
	for name := range scalars.Operators {
		ops[name] = true
	}
	for name := range presenceOps {
		ops[name] = true
	}
	return ops
}()
var validMethods = map[string]bool{
	"static": true, "provider-api": true, "probe": true}
var capabilityTypesV01 = map[string]bool{
	"capability.database.relational":      true,
	"capability.storage.object":           true,
	"capability.network.private":          true,
	"capability.workload.container":       true,
	"capability.function.serverless":      true,
	"capability.identity.sso":             true,
	"capability.identity.oauth-client":    true,
	"capability.messaging.queue":          true,
	"capability.messaging.topic":          true,
	"capability.secret":                   true,
	"capability.cache.keyvalue":           true,
	"capability.dns.zone":                 true,
	"capability.dns.record":               true,
	"capability.authorization.grant":      true,
	"capability.authorization.role":       true,
	"capability.compute.quota":            true,
	"capability.cluster.namespace":        true,
	"capability.gitops.application":       true,
	"capability.cluster.kubernetes":       true,
	"capability.cluster.addon":            true,
	"capability.identity.podidentity":     true,
	"capability.email.sending":            true,
	"capability.ai.inference":             true,
	"capability.ai.speech":                true,
	"capability.compute.instance":         true,
	"capability.storage.block":            true,
	"capability.compute.image":            true,
	"capability.compute.autoscaling":      true,
	"capability.cost.budget":              true,
	"capability.observability.changefeed": true,
	"capability.network.loadbalancer":     true,
	"capability.monitoring.alert":         true,
	"capability.monitoring.dashboard":     true,
	"capability.monitoring.uptime":        true,
	"capability.monitoring.logmetric":     true,
	"capability.registry.image":           true,
	"capability.storage.filesystem":       true,
	"capability.database.nosql":           true,
	"capability.search.index":             true,
	"capability.streaming.pipe":           true,
	"capability.messaging.kafka":          true,
	"capability.security.waf":             true,
	"capability.certificate.tls":          true,
	"capability.cdn.distribution":         true,
	"capability.apigateway.http":          true,
	"capability.container.job":            true,
	"capability.identity.serviceaccount":  true,
	"capability.warehouse.analytics":      true,
	"capability.scheduler.cron":           true,
	"capability.key.encryption":           true,
	"capability.vpn.gateway":              true,
	"capability.backup.vault":             true,
	"capability.backup.plan":              true,
	"capability.audit.trail":              true,
	"capability.email.inbound":            true,
	"capability.security.threatdetection": true,
	"capability.monitoring.logs":          true,
}

type Constraint struct {
	ID       string
	Subject  string
	Path     string
	Op       string
	Value    any
	Severity string
	// VerifyMethod is the DESIGN bar: what `verify` demands before a plan may seal.
	// RuntimeMethod is the RUNTIME bar: what `audit` demands of recorded reality.
	// They are equal unless the contract writes the two-bar form (D728).
	VerifyMethod  string
	RuntimeMethod string
	Objective     string
	Expected      *scalars.Scalar // D19: value parsed at load
}

type Contract struct {
	ID           string
	Environment  string
	Version      int
	Capabilities map[string]map[string]any // cap id -> raw capability doc
	Constraints  []Constraint              // contract order, deterministic
	Assumptions  []any                     // raw, id-validated (D11)
	Outcomes     []any
	Autonomy     map[string]any
}

type Provenanced struct {
	Scalar     *scalars.Scalar // nil only when Status == "unknown"
	Status     string
	Source     string
	Confidence *float64
}

type Candidate struct {
	ContractID   string
	Capabilities map[string]map[string]Provenanced
	// Extras: cap id -> non-attribute keys (provider, service,
	// implementation); ignored by the verifier, part of candidate
	// identity (D26, D34)
	Extras map[string]map[string]any
}

// PublicExposureByCap projects the candidate's declared network.publicExposure
// per capability — true ONLY where it is explicitly declared true. The
// post-apply reachability probe (D330) consults it to gate a public-edge target
// for capability types whose URL output exists regardless of exposure (a Cloud
// Run service always has a *.run.app uri even when ingress=internal). It mirrors
// AWS's no-public-output "nothing measured": an undeclared or false value yields
// no target, never a false unknown.
func (c *Candidate) PublicExposureByCap() map[string]bool {
	out := map[string]bool{}
	for capID, attrs := range c.Capabilities {
		pv, ok := attrs["network.publicExposure"]
		if !ok || pv.Scalar == nil {
			continue
		}
		if b, ok := pv.Scalar.Value.(bool); ok && b {
			out[capID] = true
		}
	}
	return out
}

// idIsClean rejects control characters (incl. NUL) in a stable id. A NUL would
// let two distinct (capability, constraint) pairs collide in the "\x00"-delimited
// violation-state key (D179 review), forging a shared snapshot identity; any
// control character is pathological in an identifier. Ordinary ids
// (letters/digits/./-/_ …) are unaffected — YAML's `\0` escape is the only way a
// NUL reaches an id, and no real id carries one.
func idIsClean(id string) bool {
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// D627: a field of the WRONG SHAPE must refuse, not read as empty.
//
// Every one of these sites was `x, _ := doc["k"].(T)`. A wrong type yields the zero
// value, so the content DISAPPEARS and the loader carries on. Measured on the most
// natural YAML slip there is — keying constraints by id instead of listing them:
//
//	constraints:
//	  hard:
//	    encryption:            # a MAPPING where the schema says array
//	      subject: db
//	      path: encryption.atRest
//	      op: equals
//	      value: true
//
//	$ groundhold verify c.yaml k.yaml     # candidate declares encryption.atRest: false
//	  0 satisfied, 0 violated, 0 unknown, 0 unverifiable
//	  PROVEN                               exit 0
//	$ groundhold plan … ; groundhold apply …    exit 0 — the resource is created
//
// A contract that plainly requires encryption proved a candidate that plainly refuses
// it, because the requirement was never loaded. `validate` said "0 constraints (0
// hard)" and exited 0. spec/contract.schema.json says `array`; nothing enforced it.
//
// The rule: if a key is PRESENT, its shape is part of the document's meaning.
// wantString reads a string-typed field. D681: every one of these sites was
// `x, _ := raw["k"].(string)`, so a NON-STRING value became "" and the field was
// omitted from the canonical model — while the reference implementation
// canonicalized the raw value instead. One document therefore had TWO identities,
// and each was a DIFFERENT valid document's identity:
//
//	A: `path: 7`   ref sha256:0707a8e8…   go sha256:147f3436…
//	B: `path: "7"` ref sha256:0707a8e8…   go sha256:0707a8e8…
//	C: no `path`   ref sha256:147f3436…   go sha256:147f3436…
//
// A plan sealed on B's contractHash is satisfied by A under the reference; a plan
// sealed on C's is satisfied by A under the runtime. `spec/contract.schema.json`
// types these as strings and neither implementation refused.
func wantString(m map[string]any, key, where string) (string, error) {
	raw, present := m[key]
	if !present || raw == nil {
		return "", nil
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string, got %T (%v) — a value of the "+
			"wrong type is not an absent one, and dropping it silently gives this "+
			"document the identity of a DIFFERENT one", where, raw, raw)
	}
	return s, nil
}

func wantList(doc map[string]any, key, where string) ([]any, error) {
	raw, present := doc[key]
	if !present || raw == nil {
		return nil, nil
	}
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list, got %T — a block of the wrong shape "+
			"is not an empty block, and reading it as one would silently drop "+
			"everything in it", where, raw)
	}
	return list, nil
}

func wantMap(doc map[string]any, key, where string) (map[string]any, error) {
	raw, present := doc[key]
	if !present || raw == nil {
		return nil, nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a mapping, got %T — a block of the wrong "+
			"shape is not an empty block", where, raw)
	}
	return m, nil
}

func LoadContract(path string) (*Contract, error) {
	doc, err := loadMapping(path, "contract")
	if err != nil {
		return nil, err
	}
	return LoadContractDoc(doc)
}

// LoadContractDoc runs the full contract validation on an already-parsed
// mapping — the same checks LoadContract applies after reading a file.
// `groundhold compose` uses it to refuse emitting an invalid merged contract.

// knownTopLevel is what a document of each kind MEANS. D673: nothing checked this,
// so a misspelled block was silently dropped — `constraint:` (singular) made a
// contract requiring encryption PROVE a candidate that refuses it, at exit 0, and
// the contract then hashed IDENTICALLY to one with no constraints at all. The
// package doc has claimed since D19 that "anything the loader does not recognize is
// refused, never silently non-gating"; that was true of VALUES and false of KEYS.
//
// An `x-` prefix is the escape hatch: a YAML anchor block or a tool's own metadata
// lives under `x-defaults`, `x-notes` and so on, and says by its name that the
// runtime does not read it. Every shipped contract and candidate in this repository
// was checked before this landed: zero used an unknown key.
var knownTopLevel = map[string]map[string]bool{
	"InfrastructureContract": {
		"apiVersion": true, "kind": true, "meta": true, "capabilities": true,
		"constraints": true, "assumptions": true, "outcomes": true,
		"autonomy": true, "budget": true, "requirements": true,
	},
	"ImplementationCandidate": {
		"apiVersion": true, "kind": true, "contract": true, "capabilities": true,
		"meta": true,
	},
}

// checkKnownKeys is the D673 rule with the LEVEL as an argument (D1161).
//
// It has taken the whole document since D673 and nothing else, so the two levels
// INSIDE a contract stayed open: a stray key in a capability or in `meta` was read
// by nothing and the document still validated. That is the same silent-non-gating
// the top-level check exists to stop, and it is worse here — a contract is where a
// REQUIREMENT is declared, so a key nobody reads is a requirement that never
// existed while the tool says OK.
//
// `where` names the level in the refusal, because "unknown key(s) owner" is a
// different problem to solve depending on whether it sat in `meta` or a capability.
func checkKnownKeys(doc map[string]any, known map[string]bool, where, why string) error {
	if known == nil {
		return nil
	}
	unknown := make([]string, 0, 2)
	for k := range doc {
		if known[k] || strings.HasPrefix(k, "x-") {
			continue
		}
		unknown = append(unknown, k)
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%s declares unknown key(s) %s — %s. Rename it, or prefix it "+
		"with `x-` if it is deliberately not runtime data",
		where, strings.Join(unknown, ", "), why)
}

func checkTopLevelKeys(doc map[string]any, kind string) error {
	known := knownTopLevel[kind]
	if known == nil {
		return nil
	}
	unknown := make([]string, 0, 2)
	for k := range doc {
		if known[k] || strings.HasPrefix(k, "x-") {
			continue
		}
		unknown = append(unknown, k)
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	return fmt.Errorf("%s declares unknown top-level key(s) %s — a block this "+
		"loader does not read is silently non-gating, and a misspelling of "+
		"`constraints` proves a candidate that violates them. Rename it, or prefix "+
		"it with `x-` if it is deliberately not runtime data",
		kind, strings.Join(unknown, ", "))
}

func LoadContractDoc(doc map[string]any) (*Contract, error) {
	if s, _ := doc["kind"].(string); s != "InfrastructureContract" {
		return nil, fmt.Errorf("kind must be InfrastructureContract")
	}
	if s, _ := doc["apiVersion"].(string); s != "contract/v0.1" {
		return nil, fmt.Errorf("apiVersion must be contract/v0.1")
	}
	if err := checkTopLevelKeys(doc, "InfrastructureContract"); err != nil {
		return nil, err
	}
	meta, _ := doc["meta"].(map[string]any)
	if err := checkKnownKeys(meta, contractMetaKeys, "meta",
		"a field this loader does not read carries no meaning into the document"); err != nil {
		return nil, err
	}
	id, iderr := wantString(meta, "id", "meta.id")
	if iderr != nil {
		return nil, iderr
	}
	if id == "" {
		return nil, fmt.Errorf("meta.id is required")
	}

	caps := map[string]map[string]any{}
	retired := map[string]bool{}
	var capOrder []string
	capList, err := wantList(doc, "capabilities", "capabilities")
	if err != nil {
		return nil, err
	}
	var unknownTypes []string
	for _, it := range capList {
		cap, _ := it.(map[string]any)
		if err := checkKnownKeys(cap, contractCapabilityKeys, "a capability",
			"a contract is where a REQUIREMENT is declared, so a key nothing reads "+
				"is a requirement that never existed"); err != nil {
			return nil, err
		}
		cid, cerr := wantString(cap, "id", "capability id")
		if cerr != nil {
			return nil, cerr
		}
		if cid == "" {
			return nil, fmt.Errorf("capability missing id")
		}
		if !idIsClean(cid) {
			return nil, fmt.Errorf("capability id %q contains a control character", cid)
		}
		if _, dup := caps[cid]; dup {
			return nil, fmt.Errorf("duplicate capability id: %s", cid)
		}
		ct, terr := wantString(cap, "type", "capability "+cid+" type")
		if terr != nil {
			return nil, terr
		}
		if !capabilityTypesV01[ct] {
			// D719: collect, do not return. A contract carrying two unknown types used
			// to cost two runs to discover, because this refused at the first one — and
			// the reader was told what was wrong without being told what is right, over
			// a CLOSED vocabulary the loader is holding in its hand.
			unknownTypes = append(unknownTypes, ct)
			continue
		}
		state := "active"
		if s, has := cap["state"]; has {
			state, _ = s.(string)
		}
		switch state {
		case "active":
		case "retired":
			// D47: retirement is explicit, never absence — and a retired
			// capability with requirements is a contradiction
			if _, has := cap["requirements"]; has {
				return nil, fmt.Errorf(
					"%s: retired capability cannot carry requirements", cid)
			}
			retired[cid] = true
		default:
			return nil, fmt.Errorf("%s: invalid state %q", cid, state)
		}
		caps[cid] = cap
		capOrder = append(capOrder, cid)
	}
	if len(unknownTypes) > 0 {
		return nil, unknownTypeError(unknownTypes)
	}

	constraints, err := collectConstraints(doc, caps, capOrder)
	if err != nil {
		return nil, err
	}

	cids := map[string]bool{}
	for _, c := range constraints {
		if cids[c.ID] {
			return nil, fmt.Errorf("duplicate constraint ids: [%s]", c.ID)
		}
		cids[c.ID] = true
	}
	for _, c := range constraints {
		if c.Subject != "" && caps[c.Subject] == nil {
			return nil, fmt.Errorf("%s: unknown subject %q", c.ID, c.Subject)
		}
		if retired[c.Subject] {
			return nil, fmt.Errorf(
				"%s: constraint targets retired capability %q", c.ID, c.Subject)
		}
	}
	if err := checkReferences(doc, cids); err != nil {
		return nil, err
	}
	if err := checkAutonomyCapabilities(doc, caps); err != nil {
		return nil, err
	}

	// D683: D610 refused a non-integer `meta.version`; this sibling was left, so a
	// non-string environment was dropped and the contract hashed IDENTICALLY to one
	// with no environment at all — while `environment` reaches resource tags and
	// names, stamping the estate with an empty one.
	env, eerr := wantString(meta, "environment", "meta.environment")
	if eerr != nil {
		return nil, eerr
	}
	// D610: a version that is present but not an integer used to fall back to 1, so a
	// contract declaring `version: "7"` validated OK and reported v1 — the declared
	// input dropped, in silence, exactly the shape D530 refuses in a candidate operand.
	// The reference coerced instead, so the two also disagreed about the document hash.
	version := 1
	if raw, present := meta["version"]; present {
		v, ok := raw.(int)
		if !ok {
			return nil, fmt.Errorf("meta.version must be an integer, got %T", raw)
		}
		version = v
	}
	assumptions, _ := doc["assumptions"].([]any)
	// D683: `assumptions` beside it is shape-gated and this was not.
	outcomes, oerr := wantList(doc, "outcomes", "outcomes")
	if oerr != nil {
		return nil, oerr
	}
	// D658: `autonomy` holds the CONSENT GATES, and it was the one major block D627
	// left ungated. Written as a list or a scalar it was dropped whole — and the
	// contract then hashed identically to one with no autonomy block at all, so the
	// identity every sealed plan pins could not tell "I disarmed the gates" from "I
	// never had any".
	autonomy, aerr := wantMap(doc, "autonomy", "autonomy")
	if aerr != nil {
		return nil, aerr
	}
	if err := checkAutonomyShape(autonomy); err != nil {
		return nil, err
	}
	return &Contract{
		ID: id, Environment: env, Version: version,
		Capabilities: caps, Constraints: constraints,
		Assumptions: assumptions, Outcomes: outcomes, Autonomy: autonomy,
	}, nil
}

func collectConstraints(doc map[string]any, caps map[string]map[string]any,
	capOrder []string) ([]Constraint, error) {
	var out []Constraint
	cblock, err := wantMap(doc, "constraints", "constraints")
	if err != nil {
		return nil, err
	}
	for _, sev := range []string{"hard", "soft"} {
		items, err := wantList(cblock, sev, "constraints."+sev)
		if err != nil {
			return nil, err
		}
		for i, it := range items {
			raw, ok := it.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s constraint #%d is not a mapping", sev, i)
			}
			if err := checkKnownKeys(raw, constraintKeysFor(sev), sev+" constraint",
				"a key this loader does not read cannot change what the constraint "+
					"demands, and `verify` misspelled leaves the bar at its weakest "+
					"default"); err != nil {
				return nil, err
			}
			c, err := newConstraint(raw, sev)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	budget, err := wantList(doc, "budget", "budget")
	if err != nil {
		return nil, err
	}
	for i, it := range budget {
		raw, ok := it.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("budget constraint #%d is not a mapping", i)
		}
		sev, sverr := wantString(raw, "severity", "constraint severity")
		if sverr != nil {
			return nil, sverr
		}
		if _, has := raw["severity"]; !has {
			sev = "hard"
		}
		if err := checkKnownKeys(raw, budgetConstraintKeys, "a budget constraint",
			"a key this loader does not read cannot change what the constraint "+
				"demands"); err != nil {
			return nil, err
		}
		c, err := newConstraint(raw, sev)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	// capability.requirements are sugar for hard constraints (D8);
	// capOrder keeps constraint order deterministic
	for _, capID := range capOrder {
		reqs, rerr := wantMap(caps[capID], "requirements",
			"capabilities."+capID+".requirements")
		if rerr != nil {
			return nil, rerr
		}
		var rpaths []string
		for rpath := range reqs {
			rpaths = append(rpaths, rpath)
		}
		sort.Strings(rpaths)
		for _, rpath := range rpaths {
			sp, _ := reqs[rpath].(map[string]any)
			// D1166: this sugar hardcodes `verify: {method: static}` below and reads
			// nothing else out of `sp`. So a requirement written with a verification
			// bar had it SILENTLY DROPPED — measured, the same residency requirement
			// is `unknown` and blocking as a constraint and `satisfied` and executable
			// as sugar, with no typo involved at all.
			//
			// Refused rather than honoured, deliberately. `requirements` is D8's short
			// form for the simple case; teaching it a bar would make it a second
			// spelling of a full constraint, which is what the verify block itself
			// refuses ("one bar or two, never both spellings of the same thing").
			// Widening the language is not a thing to do while fixing a silent drop.
			if err := checkKnownKeys(sp, requirementKeys,
				"capabilities."+capID+".requirements."+rpath,
				"this short form is STATIC-bar sugar (D8) and reads only `op` and "+
					"`value` — a verification bar written here is dropped, so put "+
					"the requirement under `constraints.hard` with its `verify:` "+
					"instead"); err != nil {
				return nil, err
			}
			op, _ := sp["op"].(string)
			if op == "" {
				op = "equals"
			}
			c, err := newConstraint(map[string]any{
				"id": fmt.Sprintf("req-%s-%s", capID, rpath), "subject": capID,
				"path": rpath, "op": op, "value": sp["value"],
				"verify": map[string]any{"method": "static"},
			}, "hard")
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	return out, nil
}

func newConstraint(raw map[string]any, severity string) (Constraint, error) {
	id, ierr := wantString(raw, "id", "constraint id")
	if ierr != nil {
		return Constraint{}, ierr
	}
	if id == "" {
		return Constraint{}, fmt.Errorf("constraint missing id")
	}
	if !idIsClean(id) {
		return Constraint{}, fmt.Errorf("constraint id %q contains a control character", id)
	}
	// fail-closed (D19): an unrecognized severity would silently bypass
	// the hard gate if allowed through
	if severity != "hard" && severity != "soft" {
		return Constraint{}, fmt.Errorf("%s: invalid severity %q", id, severity)
	}
	op, operr := wantString(raw, "op", "constraint op")
	if operr != nil {
		return Constraint{}, operr
	}
	objective, objerr := wantString(raw, "objective", "constraint objective")
	if objerr != nil {
		return Constraint{}, objerr
	}
	_, hasValue := raw["value"]
	if obj, has := raw["objective"]; has {
		if objective != "minimize" && objective != "maximize" {
			return Constraint{}, fmt.Errorf("%s: invalid objective %v", id, obj)
		}
		if severity == "hard" {
			return Constraint{}, fmt.Errorf(
				"%s: objectives are only valid on soft constraints", id)
		}
		if op != "" || hasValue {
			return Constraint{}, fmt.Errorf(
				"%s: objective is mutually exclusive with op/value", id)
		}
	} else {
		if !validOps[op] {
			return Constraint{}, fmt.Errorf("%s: unknown operator %q", id, op)
		}
		if !presenceOps[op] && !hasValue {
			return Constraint{}, fmt.Errorf("%s: operator %s requires a value", id, op)
		}
	}
	method := "static"
	runtime := ""
	// D627: both assertions used to fail OPEN to the initialised "static". A bogus
	// STRING was refused ("unknown verify method"); a bogus TYPE was not — so
	// `verify: {method: null}` turned a constraint the contract says must be proven
	// against the provider into one proven by reading the candidate's own claim, and
	// reported `satisfied`.
	if vraw, present := raw["verify"]; present && vraw != nil {
		vb, ok := vraw.(map[string]any)
		if !ok {
			return Constraint{}, fmt.Errorf(
				"%s: verify must be a mapping, got %T", id, vraw)
		}
		// D1162: the three refusals below guard every wrong VALUE in this block and
		// none of them sees a wrong KEY. `method` initialises to "static", so a
		// misspelling lands in exactly the weakest evidence the third refusal warns
		// about — silently, and the plan becomes executable.
		if err := checkKnownKeys(vb, verifyKeys, id+": verify",
			"a bar this loader cannot find is a bar nobody set, and the default is "+
				"the weakest evidence there is"); err != nil {
			return Constraint{}, err
		}
		if mraw, has := vb["method"]; has {
			// An explicit `method: null` is a written key, not an absent one: the
			// author said something about the method, and it is unreadable.
			m, ok := mraw.(string)
			if !ok {
				return Constraint{}, fmt.Errorf(
					"%s: verify.method must be a string, got %T — a method the loader "+
						"cannot read must not fall back to `static`, which is the "+
						"weakest evidence there is", id, mraw)
			}
			method = m
			runtime = m // one bar: it governs both commands (the pre-D728 form)
		}
		// D728, the two-bar form. `verify` compares the contract with the CANDIDATE,
		// before anything exists, so it can never hold provider evidence; `audit`
		// judges recorded reality, where provider evidence is the whole point. One
		// field served both, so a field report measured the corner: demanding
		// measurement made `verify` unpassable — 130 unknown out of 146 — and
		// accepting `static` let a hard security constraint be satisfied by the
		// document's own word. 127 of their 131 hard constraints want to say
		// "declaration before, measurement after", and there was no way to say it.
		design, hasDesign := vb["design"]
		rt, hasRuntime := vb["runtime"]
		if hasDesign || hasRuntime {
			if _, hasMethod := vb["method"]; hasMethod {
				return Constraint{}, fmt.Errorf(
					"%s: verify carries both `method` and `design`/`runtime` — one bar "+
						"or two, never both spellings of the same thing", id)
			}
			if !hasDesign || !hasRuntime {
				return Constraint{}, fmt.Errorf(
					"%s: the two-bar verify form needs BOTH `design` and `runtime` — "+
						"half of it would leave the other bar to a default nobody wrote", id)
			}
			ds, dok := design.(string)
			rs, rok := rt.(string)
			if !dok || !rok {
				return Constraint{}, fmt.Errorf(
					"%s: verify.design and verify.runtime must be strings — a bar the "+
						"loader cannot read must not fall back to the weakest evidence "+
						"there is", id)
			}
			method, runtime = ds, rs
		}
	}
	if runtime == "" {
		runtime = method
	}
	if !validMethods[method] {
		return Constraint{}, fmt.Errorf("%s: unknown verify method %q", id, method)
	}
	if !validMethods[runtime] {
		return Constraint{}, fmt.Errorf("%s: unknown verify.runtime %q", id, runtime)
	}
	// D728: the design bar may not exceed the runtime bar. A constraint that demands
	// probe evidence before shipping and accepts a config read forever after abandons
	// the guarantee at the moment it starts mattering — the same principle the two
	// bars exist to serve, applied to their relationship.
	if methodRank(method) > methodRank(runtime) {
		return Constraint{}, fmt.Errorf(
			"%s: verify.design %q is stronger than verify.runtime %q — a constraint "+
				"cannot demand more evidence before it ships than after", id, method, runtime)
	}
	// D19: parse the value now — an ill-typed value in the contract itself
	// is a load error, never a runtime unverifiable
	var expected *scalars.Scalar
	if objective == "" && !presenceOps[op] {
		exp, err := scalars.Parse(raw["value"])
		if err != nil {
			return Constraint{}, fmt.Errorf("%s: ill-typed value: %v", id, err)
		}
		switch {
		case (op == "in" || op == "not-in" || op == "subset-of") &&
			exp.Kind != scalars.List:
			return Constraint{}, fmt.Errorf(
				"%s: operator %s requires a list value", id, op)
		case op == "compatible-with" && exp.Kind != scalars.Protocol:
			return Constraint{}, fmt.Errorf(
				"%s: operator %s requires a protocol value", id, op)
		case (op == "lte" || op == "gte") && !scalars.OrderableKinds[exp.Kind]:
			return Constraint{}, fmt.Errorf(
				"%s: %s value is not orderable", id, exp.Kind)
		}
		expected = exp
	}
	subject, serr := wantString(raw, "subject", "constraint "+id+" subject")
	if serr != nil {
		return Constraint{}, serr
	}
	path, perr := wantString(raw, "path", "constraint "+id+" path")
	if perr != nil {
		return Constraint{}, perr
	}
	return Constraint{
		ID: id, Subject: subject, Path: path, Op: op, Value: raw["value"],
		Severity: severity, VerifyMethod: method, RuntimeMethod: runtime,
		Objective: objective,
		Expected:  expected,
	}, nil
}

// checkReferences: D11 + D19 — every reference between stable ids must
// resolve at load.
func checkReferences(doc map[string]any, cids map[string]bool) error {
	assumptions, aerr := wantList(doc, "assumptions", "assumptions")
	if aerr != nil {
		return aerr
	}
	for i, it := range assumptions {
		a, ok := it.(map[string]any)
		if !ok {
			return fmt.Errorf("assumptions[%d] must be a mapping, got %T", i, it)
		}
		aid, _ := a["id"].(string)
		if aid == "" {
			return fmt.Errorf("assumption missing id")
		}
		// D1157: `statement` is published as required beside `id` and `status`, every
		// assumption in the repository except one carries it, and the conformance cases
		// beside this were written as if it were enforced. It was not read at all — so a
		// shipped example held assumptions with a `source` saying where they came from
		// and nothing saying WHAT was assumed, and `validate` reported OK on a document
		// the published schema rejects.
		//
		// `source` is provenance; `statement` is the proposition. An assumption without
		// one travels into a verdict's basis and into a capsule as a citation for a claim
		// nobody wrote down, which is the opposite of what this block is for. Blank
		// counts as absent: a document that satisfies the letter by holding spaces
		// records nothing.
		stmt, _ := a["statement"].(string)
		if strings.TrimSpace(stmt) == "" {
			return fmt.Errorf("assumption %s: statement is required — `source` says "+
				"where the assumption came from, `statement` says what is assumed, "+
				"and a verdict's basis carries the latter", aid)
		}
		status, _ := a["status"].(string)
		if !validStatuses[status] {
			return fmt.Errorf("assumption %s: invalid status %v", aid, a["status"])
		}
		if cv, has := a["confidence"]; has && cv != nil {
			f, ok := toFloat(cv)
			if !ok || f < 0 || f > 1 {
				return fmt.Errorf(
					"assumption %s: confidence must be a number in [0,1]", aid)
			}
		}
		affects, ferr := wantList(a, "affects", "assumptions."+aid+".affects")
		if ferr != nil {
			return ferr
		}
		for _, r := range affects {
			rs, _ := r.(string)
			if !cids[rs] {
				return fmt.Errorf(
					"assumption %s: affects unknown constraint %q", aid, rs)
			}
		}
	}
	autonomy, _ := doc["autonomy"].(map[string]any) // shape checked at load (D658)
	forbidden, _ := autonomy["forbidden"].([]any)
	for _, it := range forbidden {
		entry, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if d, has := entry["disable"]; has {
			ds, _ := d.(string)
			if !cids[ds] {
				return fmt.Errorf(
					"autonomy.forbidden: disable references unknown constraint %q", ds)
			}
		}
	}
	return nil
}

// checkAutonomyShape refuses an autonomy block whose sub-blocks are the wrong
// shape (D658). Every one of these is a consent gate: `forbidden` written as a
// mapping loses `delete_stateful`, and a bound stateful database is then destroyed
// at exit 0 with `validate` reporting OK. The list of keys is one place, so a knob
// added later is covered without anyone remembering to add a branch (D597's lesson,
// applied to shape rather than to reference-checking).
// autonomyListKeys are the consent blocks written as LISTS. Named once so the shape
// check, the capability check and the key check below all read the same set — three
// places that disagreed would be three ways to leave a gate unarmed (D597's lesson,
// which named the same risk for the capability check).
var autonomyListKeys = []string{"forbidden",
	"allow_replace_stateful", "allow_intrusive_probes", "allow_protection_lift",
	"allow_field_reclaim", "allow_emission_adopt"}

// autonomyKeys is the whole block, CLOSED (D1164). D658 shape-gated these sub-blocks
// after a `forbidden` written as a MAPPING lost `delete_stateful` and "a bound stateful
// database is then destroyed at exit 0 with `validate` reporting OK". A misspelled KEY
// does the identical thing and nothing looked: `forbiden:` loads clean, the prohibition
// list is empty, and the apply-time gate that refuses a stateful delete has nothing to
// check.
//
// D597, two functions down, reasoned about a typo in this very block and stopped at the
// `allow_*` keys — where the effect is a refusal, which is fail-CLOSED and merely
// annoying. The key beside them is a prohibition, where the same typo is fail-OPEN.
var autonomyKeys = func() map[string]bool {
	m := map[string]bool{"auto_execute": true, "no_assumed_hard_basis": true}
	for _, k := range autonomyListKeys {
		m[k] = true
	}
	return m
}()

func checkAutonomyShape(autonomy map[string]any) error {
	if autonomy == nil {
		return nil
	}
	if err := checkKnownKeys(autonomy, autonomyKeys, "autonomy",
		"every key here is a consent gate or a prohibition, and one this loader does "+
			"not read is a gate nobody armed — a misspelled `forbidden` leaves the "+
			"apply-time refusal with an empty list to check"); err != nil {
		return err
	}
	// The shapes are not uniform, and the shipped spec example is the authority:
	// `auto_execute` is a MAPPING of thresholds (max_reversibility, max_cost_delta),
	// while the consent lists are LISTS. Writing this as one loop over one shape
	// would have refused `spec/examples/orders-production.contract.yaml` — which is
	// how I learned it, and why the example is a better specification of the block
	// than my reading of the code that ignores it.
	for _, key := range autonomyListKeys {
		if _, err := wantList(autonomy, key, "autonomy."+key); err != nil {
			return err
		}
	}
	if _, err := wantMap(autonomy, "auto_execute", "autonomy.auto_execute"); err != nil {
		return err
	}
	return nil
}

func checkAutonomyCapabilities(doc map[string]any,
	caps map[string]map[string]any) error {
	autonomy, _ := doc["autonomy"].(map[string]any)
	// D597: every consent list that names capabilities, from ONE list of keys rather
	// than an `if` per key. `allow_replace_stateful` was checked and
	// `allow_intrusive_probes` was not — and the unchecked one is the one that
	// SPENDS (D59's restore-test restores a backup into a scratch instance). A typo
	// there loaded clean, granted nothing, and would surface as a refusal later,
	// quite possibly during the incident the probe was meant to measure. A third
	// list added here is covered without anyone remembering to add a branch.
	// D1164: the SAME list the shape check reads. This was a second hand-typed copy,
	// and a mutant on the first one left this one still checking — two lists agreeing
	// today is not one list, and the reference implementation had drifted to three
	// keys against the runtime's five for exactly this reason.
	for _, key := range autonomyListKeys {
		if key == "forbidden" {
			continue // its entries are mappings, reference-checked above
		}
		allowed, _ := autonomy[key].([]any)
		for _, it := range allowed {
			s, _ := it.(string)
			if caps[s] == nil {
				return fmt.Errorf("autonomy.%s references unknown capability %q", key, s)
			}
		}
	}
	// D195: a malformed knob must not silently disarm the gate — refuse a
	// non-bool no_assumed_hard_basis rather than read it as false.
	if v, ok := autonomy["no_assumed_hard_basis"]; ok {
		if _, isBool := v.(bool); !isBool {
			return fmt.Errorf("autonomy.no_assumed_hard_basis must be a boolean")
		}
	}
	return nil
}

func LoadCandidate(path string, c *Contract,
	vocabs map[string]vocab.Vocabulary) (*Candidate, error) {
	doc, err := loadMapping(path, "candidate")
	if err != nil {
		return nil, err
	}
	if s, _ := doc["kind"].(string); s != "ImplementationCandidate" {
		return nil, fmt.Errorf("kind must be ImplementationCandidate")
	}
	if s, _ := doc["apiVersion"].(string); s != "candidate/v0.1" {
		return nil, fmt.Errorf("apiVersion must be candidate/v0.1")
	}
	if err := checkTopLevelKeys(doc, "ImplementationCandidate"); err != nil {
		return nil, err
	}
	if s, _ := doc["contract"].(string); s == "" {
		return nil, fmt.Errorf("candidate must name its contract")
	}
	caps := map[string]map[string]Provenanced{}
	extras := map[string]map[string]any{}
	capsRaw, err := wantMap(doc, "capabilities", "capabilities")
	if err != nil {
		return nil, err
	}
	for capID, bodyRaw := range capsRaw {
		body, ok := bodyRaw.(map[string]any)
		if !ok {
			return nil, fmt.Errorf(
				"capabilities.%s must be a mapping, got %T — a capability body the "+
					"loader cannot read declares nothing, and nothing is what it "+
					"would then be verified against", capID, bodyRaw)
		}
		attrs := map[string]Provenanced{}
		attrsRaw, aerr := wantMap(body, "attributes", "capabilities."+capID+".attributes")
		if aerr != nil {
			return nil, aerr
		}
		for p, v := range attrsRaw {
			pv, err := provenanced(v)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", capID, p, err)
			}
			attrs[p] = pv
		}
		caps[capID] = attrs
		// D677: a capability body may not carry `id:`. The identity is the map key,
		// and this field flowed into the canonical model where it OVERWROTE it — two
		// candidates implementing different capabilities shared one hash, one
		// verifying PROVEN and the other BLOCKED. Silently ignoring it would be the
		// D673 shape (a declared field the loader does not read); it is refused.
		if _, has := body["id"]; has {
			return nil, fmt.Errorf("capabilities.%s carries an `id:` field — the "+
				"capability's identity is the key it is written under, and a second "+
				"one can only disagree with it", capID)
		}
		// D1160: the same rule as the `id:` refusal above, applied to the whole
		// block instead of one key. It was stated there — a declared field the
		// loader does not read is the D673 shape — and enforced for `id` alone,
		// so every OTHER stray key was collected into `extra` and dropped.
		//
		// Reported from the field: an operand written one level too high. The
		// `implementation:` block is free-form (D26) and a key no driver reads is
		// refused there (unknown-operand); the block ABOVE it takes exactly four
		// keys and nothing checked them. `plan` sealed at exit 0 with no warning
		// and the resource kept running on the default the author believed they
		// had changed — the silent-ignore defect the operand guard exists to
		// prevent, one floor up, where no guard was looking.
		extra := map[string]any{}
		for k, v := range body {
			if k == "attributes" {
				continue
			}
			if !candidateCapabilityKeys[k] {
				return nil, fmt.Errorf("capabilities.%s carries %q, which is not one "+
					"of the four keys a capability block takes (attributes, "+
					"implementation, provider, service). If it is a driver operand, "+
					"it belongs under `implementation:` — written here it is read by "+
					"nothing and silently dropped", capID, k)
			}
			extra[k] = v
		}
		if len(extra) > 0 {
			extras[capID] = extra
		}
	}
	contractID, _ := doc["contract"].(string)
	cand := &Candidate{ContractID: contractID, Capabilities: caps,
		Extras: extras}
	if c != nil && vocabs != nil {
		if err := vocabCheck(cand, c, vocabs); err != nil {
			return nil, err
		}
	}
	return cand, nil
}

// vocabCheck: D23 — values on vocabulary paths must match the declared
// kind (and enum, if any). Ill-typed authorship is refused at load (D19),
// before any constraint is evaluated. Paths outside the vocabulary are
// legal.
func vocabCheck(cand *Candidate, c *Contract,
	vocabs map[string]vocab.Vocabulary) error {
	for capID, attrs := range cand.Capabilities {
		capRaw, ok := c.Capabilities[capID]
		if !ok {
			continue
		}
		typ, _ := capRaw["type"].(string)
		voc, ok := vocabs[typ]
		if !ok {
			continue
		}
		for p, pv := range attrs {
			spec := voc.Attributes[p]
			if spec == nil || pv.Scalar == nil {
				continue
			}
			if want, _ := spec["kind"].(string); want != "" &&
				string(pv.Scalar.Kind) != want {
				return fmt.Errorf(
					"%s.%s: vocabulary defines kind %s, got %s (%v)",
					capID, p, want, pv.Scalar.Kind, pv.Scalar.Raw)
			}
			// D532: a list the vocabulary marks `unordered: true` is a SET, and a
			// set has no order. Canonicalize it (sort) here, where the vocabulary is
			// known, so DECLARED and OBSERVED compare equal everywhere — verifier,
			// adopt, reconcile — without a second meaning of equality and without a
			// new operator (invariant #4 untouched). A plain `kind: list` is an
			// ordered sequence and is left exactly as written (D21).
			//
			// From the field: an attribute documented as "the full set of regions"
			// refused adoption because the cloud returned the same six regions in a
			// different order, with the message "adoption must not lie".
			if unordered, _ := spec["unordered"].(bool); unordered {
				scalars.SortList(pv.Scalar)
			}
			if enum, ok := spec["enum"].([]any); ok {
				found := false
				for _, e := range enum {
					// compare CANONICAL value to CANONICAL enum element:
					// a numeric enum decodes from YAML as int while the
					// scalar Value is float64, so raw interface equality
					// (float64==int) never matched — rejecting candidates
					// the reference accepts (3.0==3). Parse each element
					// through the same scalar model (cross-impl, review fix).
					if es, err := scalars.Parse(e); err == nil &&
						es.Kind == pv.Scalar.Kind && es.Value == pv.Scalar.Value {
						found = true
						break
					}
					if pv.Scalar.Value == e { // strings/bools already match
						found = true
						break
					}
				}
				if !found {
					return fmt.Errorf("%s.%s: %v not in vocabulary enum %v",
						capID, p, pv.Scalar.Raw, enum)
				}
			}
		}
	}
	return nil
}

func provenanced(v any) (Provenanced, error) {
	if m, ok := v.(map[string]any); ok {
		if st, has := m["status"]; has {
			if err := checkKnownKeys(m, provenancedKeys, "a provenanced attribute",
				"the provenance this loader does not read is dropped, and the "+
					"attribute keeps only what was spelled correctly"); err != nil {
				return Provenanced{}, err
			}
			status, _ := st.(string)
			if !validStatuses[status] {
				return Provenanced{}, fmt.Errorf("invalid provenance status: %v", st)
			}
			var sc *scalars.Scalar
			if m["value"] != nil {
				parsed, err := scalars.Parse(m["value"])
				if err != nil {
					return Provenanced{}, err
				}
				sc = parsed
			} else if status != "unknown" {
				return Provenanced{}, fmt.Errorf("status %s requires a value", status)
			}
			var conf *float64
			if cv, has := m["confidence"]; has && cv != nil {
				f, ok := toFloat(cv)
				if !ok || f < 0 || f > 1 {
					return Provenanced{}, fmt.Errorf(
						"confidence must be a number in [0,1]: %v", cv)
				}
				conf = &f
			}
			src, serr := wantString(m, "source", "attribute source")
			if serr != nil {
				return Provenanced{}, serr
			}
			return Provenanced{
				Scalar: sc, Status: status, Source: src, Confidence: conf,
			}, nil
		}
	}
	sc, err := scalars.Parse(v)
	if err != nil {
		return Provenanced{}, err
	}
	return Provenanced{Scalar: sc, Status: "declared"}, nil
}

func loadMapping(path, what string) (map[string]any, error) {
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
		return nil, fmt.Errorf("%s document is empty or not a mapping", what)
	}
	if err := docio.CheckSafeNumbers(doc); err != nil {
		return nil, fmt.Errorf("%s: %v", what, err)
	}
	return doc, nil
}

func toFloat(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case float64:
		return x, true
	}
	return 0, false
}

// unknownTypeError names EVERY unknown capability type in one refusal, each with the
// known types nearest to it (D719). The vocabulary is closed and the loader is holding
// it, so refusing with "unknown capability type: X" and nothing else made the reader
// go and find a list the tool already had — and refusing at the FIRST one made a
// contract with two mistakes cost two runs to discover.
func unknownTypeError(unknown []string) error {
	known := make([]string, 0, len(capabilityTypesV01))
	for t := range capabilityTypesV01 {
		known = append(known, t)
	}
	sort.Strings(known)

	var b strings.Builder
	if len(unknown) == 1 {
		fmt.Fprintf(&b, "unknown capability type: %s", unknown[0])
	} else {
		fmt.Fprintf(&b, "%d unknown capability types", len(unknown))
	}
	for _, u := range unknown {
		near := nearestTypes(u, known, 3)
		if len(unknown) > 1 {
			fmt.Fprintf(&b, "\n  %s", u)
		}
		if len(near) > 0 {
			fmt.Fprintf(&b, "\n    closest known types: %s", strings.Join(near, ", "))
		}
	}
	fmt.Fprintf(&b, "\n  the vocabulary is closed and has %d types; `groundhold explain "+
		"<capability.type>` describes one", len(known))
	return fmt.Errorf("%s", b.String())
}

// nearestTypes returns up to n known types closest to want by edit distance, ties
// broken lexicographically. Deterministic, and identical in the Python reference —
// two implementations that suggest different things are two tools.
func nearestTypes(want string, known []string, n int) []string {
	type scored struct {
		d int
		t string
	}
	all := make([]scored, 0, len(known))
	for _, k := range known {
		all = append(all, scored{editDistance(want, k), k})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].d != all[j].d {
			return all[i].d < all[j].d
		}
		return all[i].t < all[j].t
	})
	out := []string{}
	for _, s := range all {
		if len(out) == n {
			break
		}
		out = append(out, s.t)
	}
	return out
}

// editDistance is Levenshtein over runes.
func editDistance(a, b string) int {
	ar, br := []rune(a), []rune(b)
	prev := make([]int, len(br)+1)
	cur := make([]int, len(br)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ar); i++ {
		cur[0] = i
		for j := 1; j <= len(br); j++ {
			cost := 1
			if ar[i-1] == br[j-1] {
				cost = 0
			}
			cur[j] = min(min(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(br)]
}

// methodRank orders the evidence bars (D728). It is the same ladder the audit uses;
// kept here so the loader can refuse an incoherent pair at load time rather than
// letting it surface as a verdict.
func methodRank(method string) int {
	switch method {
	case "probe":
		return 2
	case "provider-api":
		return 1
	default: // static
		return 0
	}
}
