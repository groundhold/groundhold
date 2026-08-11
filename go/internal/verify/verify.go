// Package verify implements four-valued verification (D6):
// satisfied | violated | unknown | unverifiable. The engine never
// pretends: hard constraints gate on unknown and unverifiable alike.
// A verdict based on an inferred/assumed value is still satisfied or
// violated, but carries basis + confidence so policy can gate on it (D5).
package verify

import (
	"fmt"
	"sort"

	"groundhold/internal/canonical"
	"groundhold/internal/contract"
	"groundhold/internal/scalars"
	"groundhold/internal/vocab"
)

type Verdict struct {
	Constraint string `json:"constraint"`
	// Subject and Path name what the verdict is ABOUT (additive, D91):
	// downstream projections join verdicts to observations by
	// (subject, path) instead of parsing prose.
	Subject string `json:"subject"`
	Path    string `json:"path"`
	// VerifyMethod names HOW the constraint can be proven (static |
	// provider-api | probe) — additive, D94: the discharging action for
	// an unknown is a field, never prose to mine.
	VerifyMethod     string   `json:"verifyMethod"`
	Severity         string   `json:"severity"`
	Verdict          string   `json:"verdict"`
	Reason           string   `json:"reason"`
	Basis            *string  `json:"basis"`
	Confidence       *float64 `json:"confidence"`
	Observed         *string  `json:"observed"`
	PathInVocabulary *bool    `json:"pathInVocabulary"`
}

type Summary struct {
	Total                   int `json:"total"`
	Satisfied               int `json:"satisfied"`
	Violated                int `json:"violated"`
	Unknown                 int `json:"unknown"`
	Unverifiable            int `json:"unverifiable"`
	VerdictsOnAssumedValues int `json:"verdictsOnAssumedValues"`
}

// Advisory is a machine-readable warning: something groundhold noticed that is
// not a verdict but that an operator — or an AGENT — should know about (D365).
// It never blocks. It carries a stable Code precisely so an agent can route on it
// without parsing prose.
type Advisory struct {
	Code    string `json:"code"`
	Pointer string `json:"pointer"`
	Detail  string `json:"detail"`
	Next    string `json:"next"`
}

type Report struct {
	SpecVersion     string    `json:"specVersion"`
	ContractHash    string    `json:"contractHash"`
	CandidateHash   string    `json:"candidateHash"`
	Contract        string    `json:"contract"`
	ContractVersion int       `json:"contractVersion"`
	CandidateFor    string    `json:"candidateFor"`
	Summary         Summary   `json:"summary"`
	Executable      bool      `json:"executable"`
	Code            string    `json:"code,omitempty"` // "not-executable" gdy blokuje (D64/D65)
	BlockingReasons []string  `json:"blockingReasons"`
	Verdicts        []Verdict `json:"verdicts"`
	// Advisories ride in the REPORT rather than only on stderr: an agent reads
	// this document and never sees the terminal, so a warning that lives only in
	// prose is a warning the agent is structurally unable to act on.
	Advisories []Advisory `json:"advisories,omitempty"`
}

func codeOf(executable bool) string {
	if executable {
		return ""
	}
	return "not-executable"
}

func Verify(c *contract.Contract, cand *contract.Candidate,
	vocabs map[string]vocab.Vocabulary) (*Report, error) {
	verdicts := make([]Verdict, 0, len(c.Constraints))
	for _, cn := range c.Constraints {
		// D660: canonicalize the constraint's own list operand the same way the
		// candidate's value was canonicalized at load. `unordered: true` means the
		// attribute is a SET, list equality is POSITIONAL, and only one side was
		// being sorted — so an `equals` constraint failed and a `not-equals`
		// constraint PASSED against the very set it forbids, decided by the order
		// the contract author happened to type.
		v := eval(setCanonical(cn, c, vocabs), cand)
		v.Subject = cn.Subject
		v.Path = cn.Path
		v.VerifyMethod = cn.VerifyMethod
		v.PathInVocabulary = pathFlag(cn, c, vocabs)
		verdicts = append(verdicts, v)
	}

	// D635: a capability the CONTRACT declares and the candidate does not implement
	// used to vanish. Verify iterates constraints, and the compiler iterates the
	// CANDIDATE's capabilities — so a declared capability with no hard constraint and
	// no `requirements` produced no verdict, no action, and no entry in blocked,
	// unverified, noop, witnessed or advisories. `verify` printed PROVEN and a second
	// `converge` printed CONVERGED over a capability that does not exist and never
	// will. This is `witnessed`'s failure mode (D-omission-resistance) reached by the
	// plainer route of a forgotten candidate entry.
	//
	// A retired capability is deliberately exempt: retirement is how a contract says
	// "this should NOT exist" (D47).
	blocking := make([]string, 0)
	capIDs := make([]string, 0, len(c.Capabilities))
	for capID := range c.Capabilities {
		capIDs = append(capIDs, capID)
	}
	sort.Strings(capIDs) // deterministic: the report is hashed and diffed
	for _, capID := range capIDs {
		if state, _ := c.Capabilities[capID]["state"].(string); state == "retired" {
			continue
		}
		if _, ok := cand.Capabilities[capID]; !ok {
			blocking = append(blocking, fmt.Sprintf(
				"contract declares capability %q and the candidate does not implement "+
					"it — a capability with no implementation cannot converge, and "+
					"silence about it reads as success", capID))
		}
	}
	if cand.ContractID != c.ID {
		blocking = append(blocking, fmt.Sprintf(
			"candidate targets contract '%s', not '%s'", cand.ContractID, c.ID))
	}

	summary := Summary{Total: len(verdicts)}
	for _, v := range verdicts {
		switch v.Verdict {
		case "satisfied":
			summary.Satisfied++
		case "violated":
			summary.Violated++
		case "unknown":
			summary.Unknown++
		case "unverifiable":
			summary.Unverifiable++
		}
		if (v.Verdict == "satisfied" || v.Verdict == "violated") &&
			v.Basis != nil && (*v.Basis == "assumed" || *v.Basis == "inferred") {
			summary.VerdictsOnAssumedValues++
		}
	}
	// violated first, then not-proven — mirrors the reference order
	for _, v := range verdicts {
		if v.Severity == "hard" && v.Verdict == "violated" {
			blocking = append(blocking, "hard constraint violated: "+v.Constraint)
		}
	}
	for _, v := range verdicts {
		if v.Severity == "hard" &&
			(v.Verdict == "unknown" || v.Verdict == "unverifiable") {
			blocking = append(blocking, fmt.Sprintf(
				"hard constraint not proven: %s (%s)", v.Constraint, v.Verdict))
		}
	}

	// Typed scalar values are validated at load, but the free-form implementation
	// block (D26) is NOT — it can carry a value with no canonical form (e.g. a
	// sub-1e-17 float, D179). A report with a swallowed/empty hash would be a
	// dishonest identity, so refuse instead: an un-canonicalizable candidate has
	// no identity and cannot be sealed. (The reference impl refuses here too; the
	// two must agree.)
	contractHash, err := canonical.HashContract(c)
	if err != nil {
		return nil, fmt.Errorf("contract cannot be canonicalized: %w", err)
	}
	candidateHash, err := canonical.HashCandidate(cand)
	if err != nil {
		return nil, fmt.Errorf("candidate cannot be canonicalized: %w", err)
	}

	return &Report{
		SpecVersion:     "contract/v0.1",
		ContractHash:    contractHash,
		CandidateHash:   candidateHash,
		Contract:        c.ID,
		ContractVersion: c.Version,
		CandidateFor:    cand.ContractID,
		Summary:         summary,
		Executable:      len(blocking) == 0,
		BlockingReasons: blocking,
		Code:            codeOf(len(blocking) == 0),
		Verdicts:        verdicts,
		Advisories:      advisoriesFor(cand),
	}, nil
}

// advisoriesFor lifts the candidate scan (D364) into the report. It never affects
// `executable`: an advisory is something noticed, not something proven.
func advisoriesFor(cand *contract.Candidate) []Advisory {
	findings := contract.ScanForPlaintextSecrets(cand)
	if len(findings) == 0 {
		return nil
	}
	out := make([]Advisory, 0, len(findings))
	for _, f := range findings {
		out = append(out, Advisory{
			Code:    f.Code,
			Pointer: f.Pointer,
			Detail: "looks like " + f.Kind + "; groundhold will apply and persist this " +
				"value in the ledger verbatim",
			Next: f.Advice,
		})
	}
	return out
}

func eval(c contract.Constraint, cand *contract.Candidate) Verdict {
	v := Verdict{Constraint: c.ID, Severity: c.Severity}

	if c.Objective != "" {
		// objectives are scored by the planner, not gated by the verifier
		pv, ok := cand.Capabilities[c.Subject][c.Path]
		if !ok || pv.Scalar == nil || pv.Status == "unknown" {
			// D16: nothing observed -> nothing to score
			v.Verdict = "unknown"
			v.Reason = fmt.Sprintf(
				"objective %s %s: not declared by the candidate",
				c.Objective, c.Path)
			if ok {
				v.Basis = &pv.Status
			}
			return v
		}
		v.Verdict = "satisfied"
		v.Reason = fmt.Sprintf(
			"objective %s %s (scored, not gated)", c.Objective, c.Path)
		v.Basis = strPtr(pv.Status)
		v.Confidence = pv.Confidence
		v.Observed = strPtr(pv.Scalar.String())
		return v
	}

	if c.VerifyMethod != "static" {
		v.Verdict = "unknown"
		v.Reason = fmt.Sprintf(
			"requires %s verification; not evaluable from the candidate alone",
			c.VerifyMethod)
		return v
	}

	attrs, ok := cand.Capabilities[c.Subject]
	if !ok {
		v.Verdict = "unknown"
		v.Reason = fmt.Sprintf(
			"candidate does not implement capability %q", c.Subject)
		return v
	}

	pv, present := attrs[c.Path]
	if c.Op == "exists" || c.Op == "absent" {
		state := "absent"
		if present {
			state = "present"
		}
		v.Reason = fmt.Sprintf("path %s %s", c.Path, state)
		if present == (c.Op == "exists") {
			v.Verdict = "satisfied"
		} else {
			v.Verdict = "violated"
		}
		return v
	}
	if !present {
		v.Verdict = "unknown"
		v.Reason = fmt.Sprintf("candidate does not declare %s", c.Path)
		return v
	}

	if pv.Status == "unknown" || pv.Scalar == nil {
		v.Verdict = "unknown"
		v.Reason = fmt.Sprintf("candidate marks %s as unknown", c.Path)
		v.Basis = strPtr("unknown")
		v.Confidence = pv.Confidence
		return v
	}

	// c.Expected was parsed at load (D19); a TypeMismatch here is a
	// contract<->candidate disagreement, the last legitimate source of
	// unverifiable
	ok2, err := scalars.Operators[c.Op](pv.Scalar, c.Expected)
	if err != nil {
		v.Verdict = "unverifiable"
		v.Reason = err.Error()
		v.Basis = strPtr(pv.Status)
		v.Observed = strPtr(pv.Scalar.String())
		return v
	}
	if ok2 {
		v.Verdict = "satisfied"
	} else {
		v.Verdict = "violated"
	}
	// D766, from the field: this said "observed" whatever the basis was. A budget
	// constraint compared a number the AUTHOR wrote against a threshold the author
	// wrote, and reported `observed 6 EUR` — while the bill was 2.4x that. The basis
	// tag beside it said `declared`, which is how the reporter caught it, and the
	// sentence a person reads still claimed a measurement. The verb now follows the
	// provenance: nothing observed a declaration.
	v.Reason = fmt.Sprintf("%s %s %v: %s %v",
		c.Path, c.Op, c.Value, basisVerb(pv.Status), pv.Scalar.Raw)
	v.Basis = strPtr(pv.Status)
	v.Confidence = pv.Confidence
	v.Observed = strPtr(pv.Scalar.String())
	return v
}

// basisVerb names how a value came to be known, in the sentence a human reads. The
// provenance set is closed (D5): declared | inferred | assumed | unknown, plus the
// observed case an observation supplies. "observed" for a declaration is the one word
// that turns a repeated assumption into a measurement (D766).
func basisVerb(status string) string {
	switch status {
	case "declared":
		return "declared"
	case "inferred":
		return "inferred"
	case "assumed":
		return "assumed"
	case "unknown":
		return "of unknown provenance:"
	}
	return "observed"
}

func strPtr(s string) *string { return &s }

func pathFlag(cn contract.Constraint, c *contract.Contract,
	vocabs map[string]vocab.Vocabulary) *bool {
	// D23: only claim vocabulary membership when a vocabulary exists for
	// the subject's capability type — never guess
	if vocabs == nil || cn.Path == "" {
		return nil
	}
	capRaw, ok := c.Capabilities[cn.Subject]
	if !ok {
		return nil
	}
	typ, _ := capRaw["type"].(string)
	voc, ok := vocabs[typ]
	if !ok {
		return nil
	}
	_, in := voc.Attributes[cn.Path]
	return &in
}

// setCanonical returns cn with its list operand sorted when the vocabulary marks
// the attribute `unordered: true` (D660). It copies rather than mutating: the
// contract's identity is hashed from these values, and a contract must not have
// one hash with a vocabulary and another without.
func setCanonical(cn contract.Constraint, c *contract.Contract,
	vocabs map[string]vocab.Vocabulary) contract.Constraint {
	cn.Expected = SortIfUnordered(cn.Expected, cn.Subject, cn.Path, c, vocabs)
	return cn
}

// isUnorderedList reports whether (subject, path) is a list attribute the
// vocabulary marks `unordered: true` (D660) — a SET, whose element order carries
// no meaning. Shared by setCanonical (the constraint operand) and audit (the
// recorded observation), so both canonicalize a set identically.
func isUnorderedList(subject, path string, c *contract.Contract,
	vocabs map[string]vocab.Vocabulary) bool {
	if vocabs == nil {
		return false
	}
	capRaw, ok := c.Capabilities[subject]
	if !ok {
		return false
	}
	typ, _ := capRaw["type"].(string)
	voc, ok := vocabs[typ]
	if !ok {
		return false
	}
	spec := voc.Attributes[path]
	if spec == nil {
		return false
	}
	u, _ := spec["unordered"].(bool)
	return u
}

// SortIfUnordered returns a sorted COPY of sc when (subject, path) is an unordered
// list attribute (D660), else sc unchanged. It never mutates sc — the contract's
// hash and the ledger's records are read-only here. Both verify (the candidate's
// declared value + the constraint operand) and audit (a recorded observation) call
// it, so a SET compares the same whichever side it came from and whatever order
// the cloud returned it in. Without it on the audit side, `not-equals` on the very
// forbidden set reports SATISFIED when reality holds that set in another order
// (a false-clean compliance verdict — the D716 dangerous direction).
func SortIfUnordered(sc *scalars.Scalar, subject, path string, c *contract.Contract,
	vocabs map[string]vocab.Vocabulary) *scalars.Scalar {
	if sc == nil || sc.Kind != scalars.List {
		return sc
	}
	if !isUnorderedList(subject, path, c, vocabs) {
		return sc
	}
	dup := *sc
	if elems, ok := sc.Value.([]*scalars.Scalar); ok {
		dup.Value = append([]*scalars.Scalar(nil), elems...)
	}
	if raw, ok := sc.Raw.([]any); ok {
		dup.Raw = append([]any(nil), raw...)
	}
	scalars.SortList(&dup)
	return &dup
}
