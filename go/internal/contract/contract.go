// Package contract loads and structurally validates Contract and
// ImplementationCandidate documents. Fail-fast, fail-closed (D19):
// anything the loader does not recognize is refused, never silently
// non-gating. Constraint values parse eagerly; candidate values are
// kind/enum-checked against a vocabulary when one is provided (D23).
package contract

import (
	"fmt"
	"sort"

	"gopkg.in/yaml.v3"

	"groundhold/internal/docio"
	"groundhold/internal/scalars"
	"groundhold/internal/vocab"
)

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
	ID           string
	Subject      string
	Path         string
	Op           string
	Value        any
	Severity     string
	VerifyMethod string
	Objective    string
	Expected     *scalars.Scalar // D19: value parsed at load
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
func LoadContractDoc(doc map[string]any) (*Contract, error) {
	if s, _ := doc["kind"].(string); s != "InfrastructureContract" {
		return nil, fmt.Errorf("kind must be InfrastructureContract")
	}
	if s, _ := doc["apiVersion"].(string); s != "contract/v0.1" {
		return nil, fmt.Errorf("apiVersion must be contract/v0.1")
	}
	meta, _ := doc["meta"].(map[string]any)
	id, _ := meta["id"].(string)
	if id == "" {
		return nil, fmt.Errorf("meta.id is required")
	}

	caps := map[string]map[string]any{}
	retired := map[string]bool{}
	var capOrder []string
	capList, _ := doc["capabilities"].([]any)
	for _, it := range capList {
		cap, _ := it.(map[string]any)
		cid, _ := cap["id"].(string)
		if cid == "" {
			return nil, fmt.Errorf("capability missing id")
		}
		if !idIsClean(cid) {
			return nil, fmt.Errorf("capability id %q contains a control character", cid)
		}
		if _, dup := caps[cid]; dup {
			return nil, fmt.Errorf("duplicate capability id: %s", cid)
		}
		ct, _ := cap["type"].(string)
		if !capabilityTypesV01[ct] {
			return nil, fmt.Errorf("unknown capability type: %v", cap["type"])
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

	env, _ := meta["environment"].(string)
	version := 1
	if v, ok := meta["version"].(int); ok {
		version = v
	}
	assumptions, _ := doc["assumptions"].([]any)
	outcomes, _ := doc["outcomes"].([]any)
	autonomy, _ := doc["autonomy"].(map[string]any)
	return &Contract{
		ID: id, Environment: env, Version: version,
		Capabilities: caps, Constraints: constraints,
		Assumptions: assumptions, Outcomes: outcomes, Autonomy: autonomy,
	}, nil
}

func collectConstraints(doc map[string]any, caps map[string]map[string]any,
	capOrder []string) ([]Constraint, error) {
	var out []Constraint
	cblock, _ := doc["constraints"].(map[string]any)
	for _, sev := range []string{"hard", "soft"} {
		items, _ := cblock[sev].([]any)
		for i, it := range items {
			raw, ok := it.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s constraint #%d is not a mapping", sev, i)
			}
			c, err := newConstraint(raw, sev)
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	budget, _ := doc["budget"].([]any)
	for i, it := range budget {
		raw, ok := it.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("budget constraint #%d is not a mapping", i)
		}
		sev, _ := raw["severity"].(string)
		if _, has := raw["severity"]; !has {
			sev = "hard"
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
		reqs, _ := caps[capID]["requirements"].(map[string]any)
		var rpaths []string
		for rpath := range reqs {
			rpaths = append(rpaths, rpath)
		}
		sort.Strings(rpaths)
		for _, rpath := range rpaths {
			sp, _ := reqs[rpath].(map[string]any)
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
	id, _ := raw["id"].(string)
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
	op, _ := raw["op"].(string)
	objective, _ := raw["objective"].(string)
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
	if vb, ok := raw["verify"].(map[string]any); ok {
		if m, ok := vb["method"].(string); ok {
			method = m
		}
	}
	if !validMethods[method] {
		return Constraint{}, fmt.Errorf("%s: unknown verify method %q", id, method)
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
	subject, _ := raw["subject"].(string)
	path, _ := raw["path"].(string)
	return Constraint{
		ID: id, Subject: subject, Path: path, Op: op, Value: raw["value"],
		Severity: severity, VerifyMethod: method, Objective: objective,
		Expected: expected,
	}, nil
}

// checkReferences: D11 + D19 — every reference between stable ids must
// resolve at load.
func checkReferences(doc map[string]any, cids map[string]bool) error {
	assumptions, _ := doc["assumptions"].([]any)
	for _, it := range assumptions {
		a, _ := it.(map[string]any)
		aid, _ := a["id"].(string)
		if aid == "" {
			return fmt.Errorf("assumption missing id")
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
		affects, _ := a["affects"].([]any)
		for _, r := range affects {
			rs, _ := r.(string)
			if !cids[rs] {
				return fmt.Errorf(
					"assumption %s: affects unknown constraint %q", aid, rs)
			}
		}
	}
	autonomy, _ := doc["autonomy"].(map[string]any)
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

func checkAutonomyCapabilities(doc map[string]any,
	caps map[string]map[string]any) error {
	autonomy, _ := doc["autonomy"].(map[string]any)
	allowed, _ := autonomy["allow_replace_stateful"].([]any)
	for _, it := range allowed {
		s, _ := it.(string)
		if caps[s] == nil {
			return fmt.Errorf("autonomy.allow_replace_stateful references "+
				"unknown capability %q", s)
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
	if s, _ := doc["contract"].(string); s == "" {
		return nil, fmt.Errorf("candidate must name its contract")
	}
	caps := map[string]map[string]Provenanced{}
	extras := map[string]map[string]any{}
	capsRaw, _ := doc["capabilities"].(map[string]any)
	for capID, bodyRaw := range capsRaw {
		body, _ := bodyRaw.(map[string]any)
		attrs := map[string]Provenanced{}
		attrsRaw, _ := body["attributes"].(map[string]any)
		for p, v := range attrsRaw {
			pv, err := provenanced(v)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", capID, p, err)
			}
			attrs[p] = pv
		}
		caps[capID] = attrs
		extra := map[string]any{}
		for k, v := range body {
			if k != "attributes" {
				extra[k] = v
			}
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
			src, _ := m["source"].(string)
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
