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
	"probe.failed":   true,
	"lease.acquired": true, "lease.renewed": true, "lease.released": true,
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
		return nil, fmt.Errorf("unknown event type: %q", etype)
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
