// Package collector is the witness-side extensibility contract (spec/collector.md):
// the honest way a THIRD PARTY extends groundhold's reality-gathering without entering
// the trusted, credentialed core.
//
// A collector runs out-of-band at the vantage, holds its OWN scoped credentials
// (never groundhold's paired creds), and emits a signed evidence capsule (D103). The
// core IMPORTS and RE-VERIFIES it — it never runs the collector's code and never
// believes the collector's clock. This is groundhold's answer to "community drivers":
// an out-of-process live driver would move untrusted code inside the credentialed
// blast radius AND make its Observe output an untrusted input to the DETERMINISTIC
// verifier (a lie would become a deterministic false verdict). A collector keeps the
// trust boundary intact — its evidence is signed and re-verified like any capsule —
// so the verifier stays deterministic over evidence whose signatures the operator
// chose to trust.
//
// Certify is the collector's self-certification gate AND the core's import-time
// check. Beyond VerifyCapsule's structural + signature + linkage proof, it enforces
// the honesty SHAPE a collector must produce:
//   - D53 secrets exclusion, as a SCANNER at the boundary — because a third-party
//     collector is not trusted to have excluded them structurally the way an in-tree
//     driver is;
//   - the four-valued derivation vocabulary on every observation (measured |
//     config-intent), never an unlabeled or invented basis;
//   - observedAt present, and nothing dated past the capsule's asOf — the core owns
//     the clock (N1); a collector cannot forge freshness.
package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"groundhold/internal/ledger"
	"groundhold/internal/secretshape"
)

// Load reads a capsule document from a file for certification. JSON decodes every
// number as float64; whole-number floats are folded back to int (the same
// normalization ReplayFile applies) so ValidateEvent's shape checks pass — the
// canonical hash is representation-stable, so heads are unaffected.
func Load(path string) (*ledger.Capsule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ledger.Capsule
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("%s: not a capsule document: %v", path, err)
	}
	for _, doc := range c.Events {
		normalizeNumbers(doc)
	}
	return &c, nil
}

func normalizeNumbers(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if f, ok := val.(float64); ok && f == float64(int(f)) {
				x[k] = int(f)
			} else {
				normalizeNumbers(val)
			}
		}
	case []any:
		for _, it := range x {
			normalizeNumbers(it)
		}
	}
}

// Finding is one honesty violation the collector's capsule must not contain.
type Finding struct {
	Event  int    `json:"event"` // 1-based index into the capsule's events
	Path   string `json:"path,omitempty"`
	Kind   string `json:"kind"` // secret | derivation | observedAt | future-dated | structure
	Detail string `json:"detail"`
}

// Report is the deterministic certification receipt.
type Report struct {
	APIVersion string    `json:"apiVersion"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"` // certified | rejected
	Capability string    `json:"capability,omitempty"`
	LedgerID   string    `json:"ledgerId,omitempty"`
	Events     int       `json:"events"`
	Findings   []Finding `json:"findings,omitempty"`
}

// allowed observation derivations (D3/D45): a measured read of live state, or a
// config-intent value the resource stores but does not itself enforce.
// D759: three kinds of fact, three labels. `platform-invariant` is a claim about the
// SERVICE ("every ElastiCache Serverless cache encrypts at rest"), established from the
// provider's contract and read from nothing on this resource — 65 of 72 config-intent
// observations were that, wearing a label whose published definition says the resource
// STORES the value.
var okDerivation = map[string]bool{
	"measured": true, "config-intent": true, "platform-invariant": true}

// secretKey flags an object KEY whose name signals a secret payload.
// D648: shared with the redactor and the publish-time scan (internal/secretshape).
func secretKeyName(k string) bool { return secretshape.KeyLooksLikeCredential(k) }

// A STRING VALUE carrying an unambiguous secret signature is refused the same way,
// through the same shared alphabet (D648) — this list used to know bearer tokens
// and JWTs while the publish-time scan knew connection strings, and a capsule
// carrying a plaintext DSN was certified.

// Certify verifies a collector's capsule and enforces the honesty shape. On any
// violation Status is "rejected" and Findings names each; the core imports nothing
// it cannot certify (invariant #1 then makes downstream answer honestly).
func Certify(c *ledger.Capsule) *Report {
	rep := &Report{APIVersion: "collector-certify/v0.1", Kind: "CollectorCertifyReport",
		Status: "rejected", Capability: c.Capability, Events: len(c.Events)}

	// structure + signatures + hash-chain linkage + recomputed head/asOf (D103).
	lid, err := ledger.VerifyCapsule(c, nil)
	if err != nil {
		rep.Findings = append(rep.Findings, Finding{Kind: "structure", Detail: err.Error()})
		return rep
	}
	rep.LedgerID = lid

	asOf := c.AsOf
	asOfSec, asOfErr := ledger.ParseTs(asOf)
	if asOf != "" && asOfErr != nil {
		rep.Findings = append(rep.Findings, Finding{Kind: "structure",
			Detail: fmt.Sprintf("capsule asOf %q is not a parseable RFC3339 time", asOf)})
	}
	for i, doc := range c.Events {
		ev, _ := doc["event"].(map[string]any)
		if ev == nil {
			rep.Findings = append(rep.Findings, Finding{Event: i + 1, Kind: "structure", Detail: "event has no event block"})
			continue
		}
		// Nothing may be dated past the capsule's own asOf — the core owns the
		// clock (N1); a collector cannot forge freshness. Fail closed on an
		// unparseable occurredAt — freshness that cannot be proven is not fresh.
		if occ, _ := ev["occurredAt"].(string); occ != "" && asOf != "" && asOfErr == nil {
			future, occBad := futureDated(occ, asOfSec)
			switch {
			case occBad:
				rep.Findings = append(rep.Findings, Finding{Event: i + 1, Kind: "future-dated",
					Detail: fmt.Sprintf("occurredAt %q is not a parseable RFC3339 time — freshness cannot be proven", occ)})
			case future:
				rep.Findings = append(rep.Findings, Finding{Event: i + 1, Kind: "future-dated",
					Detail: fmt.Sprintf("occurredAt %s is past the capsule asOf %s", occ, asOf)})
			}
		}
		// D53 secrets scan over the WHOLE event body (observations, diagnostics,
		// reasons) — a third-party collector is not trusted to have excluded them.
		scanSecrets(ev["body"], "", i+1, rep)
		// observation-shape honesty.
		body, _ := ev["body"].(map[string]any)
		if body == nil {
			continue
		}
		obs, _ := body["observations"].([]any)
		for _, o := range obs {
			om, _ := o.(map[string]any)
			if om == nil {
				continue
			}
			path, _ := om["path"].(string)
			if secretKeyName(path) {
				rep.Findings = append(rep.Findings, Finding{Event: i + 1, Path: path, Kind: "secret",
					Detail: "observation path is secret-named — a capability attribute is never a secret (D53)"})
			}
			if d, _ := om["derivation"].(string); !okDerivation[d] {
				rep.Findings = append(rep.Findings, Finding{Event: i + 1, Path: path, Kind: "derivation",
					Detail: fmt.Sprintf("derivation %q is not measured|config-intent|"+
						"platform-invariant", d)})
			}
			if oa, _ := om["observedAt"].(string); oa == "" {
				rep.Findings = append(rep.Findings, Finding{Event: i + 1, Path: path, Kind: "observedAt",
					Detail: "observation carries no observedAt"})
			}
		}
	}

	// The receipt is deterministic: findings are collected across a map walk
	// (scanSecrets) whose iteration order is random, so sort on a stable key
	// before the verdict — two runs over the same capsule print byte-identically.
	sort.Slice(rep.Findings, func(a, b int) bool {
		fa, fb := rep.Findings[a], rep.Findings[b]
		if fa.Event != fb.Event {
			return fa.Event < fb.Event
		}
		if fa.Path != fb.Path {
			return fa.Path < fb.Path
		}
		if fa.Kind != fb.Kind {
			return fa.Kind < fb.Kind
		}
		return fa.Detail < fb.Detail
	})
	if len(rep.Findings) == 0 {
		rep.Status = "certified"
	}
	return rep
}

// futureDated reports whether occurredAt is chronologically past asOfSec (the
// capsule's parsed asOf), and whether occurredAt could not be parsed at all.
// NUMERIC compare: RFC3339 permits UTC offsets, so a lexical `>` mis-orders a
// future-dated observation whose offset makes its string sort low — e.g.
// 2026-07-19T20:00:00-05:00 is 2026-07-20T01:00:00Z, LATER than
// 2026-07-19T23:00:00Z, yet its string sorts BEFORE. The collector is the trust
// boundary where a forged-fresh observation must not leak (mirrors obsNewer).
func futureDated(occ string, asOfSec int) (future, unparseable bool) {
	occSec, err := ledger.ParseTs(occ)
	if err != nil {
		return false, true
	}
	return occSec > asOfSec, false
}

// scanSecrets walks a value recursively, flagging any key whose NAME signals a
// secret or any string whose VALUE carries a secret signature.
func scanSecrets(v any, path string, event int, rep *Report) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if secretKeyName(k) {
				rep.Findings = append(rep.Findings, Finding{Event: event, Path: p, Kind: "secret",
					Detail: fmt.Sprintf("field %q is secret-named — secrets are structurally excluded (D53)", k)})
			}
			scanSecrets(val, p, event, rep)
		}
	case []any:
		for i, it := range x {
			scanSecrets(it, fmt.Sprintf("%s[%d]", path, i), event, rep)
		}
	case string:
		if kind, ok := secretshape.ValueLooksLikeCredential(x); ok {
			rep.Findings = append(rep.Findings, Finding{Event: event, Path: path,
				Kind: "secret",
				Detail: fmt.Sprintf("value carries a secret signature (%s) — secrets "+
					"are structurally excluded (D53)", kind)})
			return
		}
	}
}
