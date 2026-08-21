// Package state implements State Model v0 ledger event loading
// (spec/state-model.md, D35). Fail-closed (D19): unknown event types,
// missing envelope fields and unquoted timestamps are refused at load.
package state

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"groundhold/internal/docio"
)

var EventTypes = map[string]bool{
	"contract.published": true, "candidate.verified": true, "plan.sealed": true,
	"apply.started": true, "apply.finished": true, "apply.failed": true,
	"observation.recorded": true, "violation.detected": true,
	"violation.resolved": true, "binding.updated": true,
	"probe.failed": true,
	// D1152: a bound capability the provider could not be READ at all. Symmetric
	// with probe.failed and for the same reason (D59): a failed measurement is
	// knowledge, and it is never an observation. Without it the failure lived on
	// stdout only, so `plan` could see an ageing observation and not that the
	// last read had failed — and told the operator to re-observe, which was the
	// one thing that could not help.
	"observation.failed": true,
	"lease.acquired":     true, "lease.renewed": true, "lease.released": true,
	"lease.broken": true, "operation.receipt": true,
	"ownership.claimed": true, // D140: takeover authorship stamp
	// D229: converge lifecycle markers — run-scoped, lease-free, neither
	// mutations nor decisions. They let status/wait speak the converge tree.
	"converge.started":       true,
	"converge.phase.entered": true,
	"converge.finished":      true,
	"converge.failed":        true,
}

var ActorTypes = map[string]bool{"human": true, "agent": true, "runtime": true}

// UnknownTypeError is refused-because-unrecognized, kept DISTINCT from every other
// validation failure in this file (D1154).
//
// The event-type registry is additive-only, so "a type this build does not know" has
// exactly one likely cause: the file was written by a NEWER build. That is not the
// same condition as a malformed document, and — the reason this type exists — it is
// not the same condition as a DAMAGED one. Replay used to return it as a bare error
// alongside broken-chain and unparseable-line, every caller mapped the lot to exit 5,
// and the banner for exit 5 is CORRUPTED. So a reader who added an event type and went
// back to the previous binary was told their intact ledger was corrupt.
//
// The prose is unchanged on purpose: the string is what every existing caller and test
// already reads. What is new is that the condition can now be TOLD APART, which is the
// whole fix — a caller that cannot distinguish two conditions cannot advise on either.
type UnknownTypeError struct {
	// What names the closed set, so one error type serves every registry the
	// ledger is fail-closed on and replay needs only one branch to route them all
	// (D1159). The message keeps the exact wording each set already published.
	What string // "event type" | "observation source"
	Type string
}

func (e *UnknownTypeError) Error() string {
	what := e.What
	if what == "" {
		what = "event type"
	}
	return fmt.Sprintf("unknown %s: %q", what, e.Type)
}

// ObservationSources is the closed set of ways a value can have been LEARNED
// (D1159). It is published in `spec/state.schema.json` and it was, until now,
// enforced nowhere: the five values lived as string literals across twenty-nine
// emission sites with nothing to compare them against — which is exactly how the
// published enum came to be missing two of them (D1151).
//
// It is not decoration. The compiler BRANCHES on this field: an observation whose
// source is `candidate-declared` is adopt-recorded intent, so the path is carried
// as unverifiable — never drift, never a staleness freeze. A source this build does
// not recognize misses that branch and the value is then compared as measured
// reality, which turns "this cannot be verified" into "verified by the candidate's
// own word". That is the false-secure direction, reached by a typo.
var ObservationSources = map[string]bool{
	"provider-api":       true, // read from the provider's own API
	"probe":              true, // measured by an outcome probe (D59)
	"reachability":       true, // measured at the public edge
	"manual":             true, // supplied by a human, provenance carried
	"candidate-declared": true, // adopt recorded the candidate's intent (F-LC3)
}

func LoadEvent(path string) (map[string]any, error) {
	raw, err := docio.ReadDoc(path)
	if err != nil {
		return nil, err
	}
	var docAny any
	if err := yaml.Unmarshal(raw, &docAny); err != nil {
		return nil, err
	}
	return ValidateEvent(docAny)
}

func ValidateEvent(docAny any) (map[string]any, error) {
	doc, ok := docAny.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("event document is empty or not a mapping")
	}
	if s, _ := doc["kind"].(string); s != "LedgerEvent" {
		return nil, fmt.Errorf("kind must be LedgerEvent")
	}
	if s, _ := doc["apiVersion"].(string); s != "state/v0" {
		return nil, fmt.Errorf("apiVersion must be state/v0")
	}
	ev, ok := doc["event"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("event block is required")
	}
	etype, _ := ev["type"].(string)
	if !EventTypes[etype] {
		return nil, &UnknownTypeError{Type: etype}
	}
	caps, ok := ev["capabilities"].([]any)
	if !ok || len(caps) == 0 {
		return nil, fmt.Errorf("event.capabilities must be a non-empty list of ids")
	}
	for _, c := range caps {
		if _, ok := c.(string); !ok {
			return nil, fmt.Errorf("event.capabilities must be a non-empty list of ids")
		}
	}
	occurredAt, ok := ev["occurredAt"].(string)
	if !ok {
		return nil, fmt.Errorf("event.occurredAt must be a quoted RFC3339 string " +
			"(unquoted YAML timestamps are not canonicalizable)")
	}
	// D315: enforce what the message has always promised. Checking only the
	// QUOTING let a string like "whenever" through, and the permissiveness was not
	// uniform: ReplayFile parses occurredAt and refuses the file, while `export`
	// (which verifies the chain itself and never replays) accepted it and then, in
	// a --from/--to window, dropped the unplaceable event with a bare `continue`.
	// A consumer got a short stream with nothing saying an event was withheld,
	// from a file the rest of the system considers corrupt.
	if _, err := time.Parse(time.RFC3339, occurredAt); err != nil {
		return nil, fmt.Errorf("event.occurredAt %q is not an RFC3339 time: %v",
			occurredAt, err)
	}
	actor, ok := ev["actor"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("event.actor must carry id and type (human|agent|runtime)")
	}
	aid, _ := actor["id"].(string)
	atype, _ := actor["type"].(string)
	if aid == "" || !ActorTypes[atype] {
		return nil, fmt.Errorf("event.actor must carry id and type (human|agent|runtime)")
	}
	if tv, has := ev["fencingToken"]; has && tv != nil {
		t, ok := tv.(int)
		if !ok || t < 1 {
			return nil, fmt.Errorf("event.fencingToken must be a positive integer")
		}
	}
	if sv, has := doc["sig"]; has && sv != nil {
		if err := validateSig(sv); err != nil {
			return nil, err
		}
	}
	// D1159: the OTHER closed set this document carries. The event type has been
	// fail-closed here since D19; `source` — which the compiler branches on to tell
	// intent from measurement — was checked nowhere, so a typo silently promoted an
	// adopt-recorded intent into evidence. Refused on the write path, where every
	// other alphabet of the ledger is refused, and with the same error type so a
	// build meeting a NEWER source reports a version gap rather than corruption
	// (D1154).
	if etype == "observation.recorded" {
		body, _ := ev["body"].(map[string]any)
		obs, _ := body["observations"].([]any)
		for _, o := range obs {
			om, _ := o.(map[string]any)
			if om == nil {
				continue
			}
			src, _ := om["source"].(string)
			if !ObservationSources[src] {
				return nil, &UnknownTypeError{What: "observation source", Type: src}
			}
		}
	}
	return doc, nil
}

func isHex(v any, width int) bool {
	s, ok := v.(string)
	if !ok || len(s) != width || s != strings.ToLower(s) {
		return false // lowercase only: one spelling, one hash, no aliasing
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func isEventHash(v any) bool {
	s, ok := v.(string)
	return ok && strings.HasPrefix(s, "sha256:") && isHex(s[len("sha256:"):], 64)
}

// validateSig (D102/D134): when present, the detached signature
// envelope must be well-formed — a truncated signature or a missing
// ledger claim is refused at load, not carried. Lowercase hex only.
// The envelope is excluded from the event hash (see canonical).
func validateSig(v any) error {
	sig, ok := v.(map[string]any)
	if !ok || sig["alg"] != "ed25519" ||
		!isHex(sig["pub"], 64) || !isHex(sig["sig"], 128) ||
		!isEventHash(sig["ledger"]) {
		return fmt.Errorf("sig must be an ed25519 envelope: " +
			"{alg: ed25519, pub: 32-byte hex, sig: 64-byte hex, " +
			"ledger: sha256:<64 hex> (the genesis event's hash, D134)}")
	}
	return nil
}
