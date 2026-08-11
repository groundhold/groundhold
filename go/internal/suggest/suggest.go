// Package suggest is the deterministic, cited best-practice advisor (D203). For a
// contract it points out recommended-but-absent hardening constraints and emits
// ready-to-paste constraint snippets — ADVISORY ONLY, never gating.
//
// It lives OUTSIDE the verification core (invariant #6): the verifier NEVER reads
// the vocab's `recommended` marker; only this package does. It adds NO grammar
// (invariant #4) — every suggestion is the existing constraint shape
// ({id, subject, path, op, value, verify}) with an operator already in the closed
// set. Runtime is a pure, table-driven lookup: no network, no LLM, deterministic.
package suggest

import (
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/contract"
	"groundhold/internal/vocab"
)

// Suggestion is one recommended-but-absent hardening constraint for a contract.
type Suggestion struct {
	Capability string              `json:"capability"` // contract capability id (the subject)
	Type       string              `json:"type"`       // capability type
	Path       string              `json:"path"`
	Op         string              `json:"op"`
	Value      any                 `json:"value"`
	Scope      string              `json:"scope"`
	Rationale  string              `json:"rationale"`
	RuleID     string              `json:"ruleId"`
	Controls   map[string][]string `json:"controls"`
	Snippet    string              `json:"snippet"` // ready-to-paste constraint list item
}

// Result is the full advisory outcome: the suggestions plus how many recommended
// constraints the contract ALREADY enforces (so a skip is visible, never silent —
// D203 / prior-art lesson #6).
type Result struct {
	Environment     string       `json:"environment,omitempty"`
	Suggestions     []Suggestion `json:"suggestions"`
	AlreadyEnforced int          `json:"alreadyEnforced"`
}

// controlPrecedence orders frameworks for the single "(source: …)" label shown
// in the human snippet comment. The structured `controls` map keeps every
// citation; this only picks which one leads the one-line comment. Deterministic.
var controlPrecedence = []string{
	"FSBP", "MCSB", "CIS-AWS_5.0.0", "CIS-AWS", "CIS-GCP", "CIS-EKS",
	"CIS-AZURE", "GDPR", "ISO27001_2022",
}

// Source returns the lead citation label for a suggestion's comment, e.g.
// "FSBP RDS.16". Empty when the rule carries no controls.
func (s Suggestion) Source() string {
	for _, fw := range controlPrecedence {
		if ids := s.Controls[fw]; len(ids) > 0 {
			return fw + " " + ids[0]
		}
	}
	// deterministic fallback: any remaining framework, sorted
	var fws []string
	for fw := range s.Controls {
		fws = append(fws, fw)
	}
	sort.Strings(fws)
	for _, fw := range fws {
		if ids := s.Controls[fw]; len(ids) > 0 {
			return fw + " " + ids[0]
		}
	}
	return ""
}

// Compute produces the sorted, deterministic suggestion set for a contract. cand
// may be nil; when present it strengthens the `when` guard (the guard can hold on
// a candidate attribute value, not only a contract constraint). The verifier is
// never consulted — this reads only the `recommended` markers the vocab carries.
func Compute(c *contract.Contract, vocabs map[string]vocab.Vocabulary, cand *contract.Candidate) Result {
	env := c.Environment
	// (subject,path) already constrained by the contract — never re-suggest.
	constrained := map[string]bool{}
	for _, cn := range c.Constraints {
		constrained[cn.Subject+"\x00"+cn.Path] = true
	}

	res := Result{Environment: env}
	// iterate capabilities in id order for stable output
	capIDs := make([]string, 0, len(c.Capabilities))
	for id := range c.Capabilities {
		capIDs = append(capIDs, id)
	}
	sort.Strings(capIDs)

	for _, capID := range capIDs {
		capDoc := c.Capabilities[capID]
		capType, _ := capDoc["type"].(string)
		voc, ok := vocabs[capType]
		if !ok {
			continue
		}
		paths := make([]string, 0, len(voc.Attributes))
		for p := range voc.Attributes {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, path := range paths {
			for _, rec := range recommendedEntries(voc.Attributes[path]) {
				if !scopeMatches(rec.scope, env) {
					continue
				}
				if rec.when != nil && !whenHolds(*rec.when, capID, c, cand) {
					continue
				}
				if constrained[capID+"\x00"+path] {
					res.AlreadyEnforced++
					continue
				}
				sg := Suggestion{
					Capability: capID,
					Type:       capType,
					Path:       path,
					Op:         rec.op,
					Value:      rec.value,
					Scope:      rec.scope,
					Rationale:  rec.rationale,
					RuleID:     rec.ruleID,
					Controls:   rec.controls,
				}
				sg.Snippet = snippet(sg, voc.EvidenceOf(path))
				res.Suggestions = append(res.Suggestions, sg)
			}
		}
	}
	sort.SliceStable(res.Suggestions, func(i, j int) bool {
		a, b := res.Suggestions[i], res.Suggestions[j]
		if a.Capability != b.Capability {
			return a.Capability < b.Capability
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.RuleID < b.RuleID
	})
	return res
}

// rec is a parsed `recommended` marker.
type rec struct {
	op        string
	value     any
	scope     string
	rationale string
	ruleID    string
	controls  map[string][]string
	when      *guard
}

type guard struct {
	path  string
	op    string
	value any
}

// recommendedEntries normalizes an attribute's `recommended` marker into zero or
// more parsed entries. The marker may be a single mapping or a list of mappings
// (e.g. rpo lte 24h all + lte 5m prod). A deprecated rule is skipped.
func recommendedEntries(attr map[string]any) []rec {
	raw, ok := attr["recommended"]
	if !ok {
		return nil
	}
	var maps []map[string]any
	switch v := raw.(type) {
	case map[string]any:
		maps = []map[string]any{v}
	case []any:
		for _, it := range v {
			if m, ok := it.(map[string]any); ok {
				maps = append(maps, m)
			}
		}
	default:
		return nil
	}
	var out []rec
	for _, m := range maps {
		if dep, _ := m["deprecated"].(bool); dep {
			continue
		}
		op, _ := m["op"].(string)
		scope, _ := m["scope"].(string)
		if op == "" || scope == "" {
			continue
		}
		r := rec{
			op:        op,
			value:     m["value"],
			scope:     scope,
			rationale: asString(m["rationale"]),
			ruleID:    asString(m["ruleId"]),
			controls:  parseControls(m["controls"]),
		}
		if wm, ok := m["when"].(map[string]any); ok {
			g := guard{path: asString(wm["path"]), op: asString(wm["op"]), value: wm["value"]}
			if g.path != "" {
				r.when = &g
			}
		}
		out = append(out, r)
	}
	return out
}

func parseControls(v any) map[string][]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string][]string{}
	for fw, ids := range m {
		switch l := ids.(type) {
		case []any:
			for _, id := range l {
				out[fw] = append(out[fw], fmt.Sprintf("%v", id))
			}
		case string:
			out[fw] = []string{l}
		}
	}
	return out
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// scopeMatches keys a recommendation off meta.environment. "all" always matches;
// otherwise the environment must equal the scope (production/development are
// normalized to prod/dev so common spellings still match).
func scopeMatches(scope, env string) bool {
	if scope == "all" {
		return true
	}
	switch env {
	case "production":
		env = "prod"
	case "development":
		env = "dev"
	}
	return scope == env
}

// whenHolds evaluates the optional `when` guard against the SAME capability's
// known attribute value — first a matching contract constraint, then (if given) a
// candidate attribute. Deterministic; only equality is compared (no expression
// language, invariant #4). A guard that cannot be evaluated does not hold.
func whenHolds(g guard, capID string, c *contract.Contract, cand *contract.Candidate) bool {
	for _, cn := range c.Constraints {
		if cn.Subject == capID && cn.Path == g.path && cn.Op == g.op {
			if valuesEqual(cn.Value, g.value) {
				return true
			}
		}
	}
	if cand != nil {
		if attrs, ok := cand.Capabilities[capID]; ok {
			if pv, ok := attrs[g.path]; ok && pv.Scalar != nil {
				if valuesEqual(pv.Scalar.Value, g.value) {
					return true
				}
			}
		}
	}
	return false
}

func valuesEqual(a, b any) bool {
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// snippet renders one ready-to-paste constraint list item from a suggestion —
// the "good example" (prior-art lesson #4), generated deterministically from
// {subject, path, op, value}. Pinned by a golden test per rule.
// snippetMethod derives the evidence bar a recommendation should carry, instead of
// baking one (D773). Every attribute this advisor recommends is HARDENING — encryption,
// exposure, flow logs, rotation — and the snippet shipped `verify: {method: static}` for
// all of them, which is the bar the author's own declaration meets. Paste the tool's
// advice, declare the value it told you to declare, and the control reads satisfied from
// the assertion. That is the shape the field named for a budget ("a constraint based on a
// number I typed is a restatement of my assumption") — here generated by the tool itself,
// for security.
//
// The vocabulary already says which bar is REACHABLE, so nothing needs to guess: an
// attribute that is ordinary resource state can be read from the provider, and a probe
// attribute needs a probe. Measured when this was written: all 12 recommended attributes
// are resource state and every one is emitted by a driver, so the stronger bar is not
// aspirational — it is meetable today.
//
// A pasted constraint therefore BLOCKS until an observation exists, which is the point of
// a hardening control and the direction D722 chose deliberately: unknown blocks.
func snippetMethod(evidence string) string {
	switch evidence {
	case vocab.EvidenceProbe:
		return "probe"
	case vocab.EvidenceProjection:
		// No reading will ever exist (D311/D769); static is the only reachable bar,
		// and the advisory that says so is attached at compile.
		return "static"
	}
	return "provider-api"
}

func snippet(s Suggestion, evidence string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "- id: rec-%s-%s\n", s.Capability, s.Path)
	fmt.Fprintf(&b, "  subject: %s\n", s.Capability)
	fmt.Fprintf(&b, "  path: %s\n", s.Path)
	fmt.Fprintf(&b, "  op: %s\n", s.Op)
	fmt.Fprintf(&b, "  value: %s\n", valueYAML(s.Value))
	fmt.Fprintf(&b, "  verify: { method: %s }", snippetMethod(evidence))
	return b.String()
}

// valueYAML renders a scalar or list marker value as inline YAML.
func valueYAML(v any) string {
	switch t := v.(type) {
	case bool:
		if t {
			return "true"
		}
		return "false"
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = fmt.Sprintf("%v", e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}
