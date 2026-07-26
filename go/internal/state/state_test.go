package state

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validEvent returns a minimal, well-formed LedgerEvent document.
// Each case mutates a fresh copy so tests never share state.
func validEvent() map[string]any {
	return map[string]any{
		"kind":       "LedgerEvent",
		"apiVersion": "state/v0",
		"event": map[string]any{
			"type":         "contract.published",
			"capabilities": []any{"cap-db"},
			"occurredAt":   "2026-07-12T00:00:00Z",
			"actor":        map[string]any{"id": "u1", "type": "human"},
		},
	}
}

func ev(doc map[string]any) map[string]any {
	return doc["event"].(map[string]any)
}

// TestValidateEvent_Valid pins that a minimal well-formed event is accepted
// and returned verbatim.
func TestValidateEvent_Valid(t *testing.T) {
	doc := validEvent()
	got, err := ValidateEvent(doc)
	if err != nil {
		t.Fatalf("valid event refused: %v", err)
	}
	if got["kind"] != "LedgerEvent" {
		t.Fatalf("ValidateEvent must return the doc unchanged, got %v", got["kind"])
	}
}

// TestValidateEvent_Envelope pins the fail-closed envelope checks (D19).
func TestValidateEvent_Envelope(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(map[string]any)
		wantErr string
	}{
		{"wrong-kind", func(d map[string]any) { d["kind"] = "Contract" }, "kind must be LedgerEvent"},
		{"missing-kind", func(d map[string]any) { delete(d, "kind") }, "kind must be LedgerEvent"},
		{"wrong-apiVersion", func(d map[string]any) { d["apiVersion"] = "state/v1" }, "apiVersion must be state/v0"},
		{"missing-apiVersion", func(d map[string]any) { delete(d, "apiVersion") }, "apiVersion must be state/v0"},
		{"missing-event", func(d map[string]any) { delete(d, "event") }, "event block is required"},
		{"event-not-mapping", func(d map[string]any) { d["event"] = "nope" }, "event block is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := validEvent()
			c.mutate(doc)
			_, err := ValidateEvent(doc)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("got err %v, want containing %q", err, c.wantErr)
			}
		})
	}
}

// TestValidateEvent_NotAMapping pins that non-mapping top-level docs are refused.
func TestValidateEvent_NotAMapping(t *testing.T) {
	for _, in := range []any{nil, "string", 42, []any{"a"}} {
		if _, err := ValidateEvent(in); err == nil ||
			!strings.Contains(err.Error(), "not a mapping") {
			t.Errorf("ValidateEvent(%#v) got %v, want 'not a mapping'", in, err)
		}
	}
}

// TestValidateEvent_KnownTypes pins that every declared event type is accepted
// and an undeclared one is refused. Regression guard: dropping a type from the
// closed set here would break the ledger it pins.
func TestValidateEvent_KnownTypes(t *testing.T) {
	if len(EventTypes) == 0 {
		t.Fatal("EventTypes is empty")
	}
	for etype := range EventTypes {
		doc := validEvent()
		ev(doc)["type"] = etype
		if _, err := ValidateEvent(doc); err != nil {
			t.Errorf("declared type %q refused: %v", etype, err)
		}
	}
	for _, bad := range []string{"", "foo.bar", "contract.Published", "apply"} {
		doc := validEvent()
		ev(doc)["type"] = bad
		if _, err := ValidateEvent(doc); err == nil ||
			!strings.Contains(err.Error(), "unknown event type") {
			t.Errorf("type %q got %v, want 'unknown event type'", bad, err)
		}
	}
}

// TestValidateEvent_Capabilities pins the non-empty-list-of-ids rule.
func TestValidateEvent_Capabilities(t *testing.T) {
	cases := []struct {
		name string
		caps any
	}{
		{"missing", nil},
		{"not-a-list", "cap-db"},
		{"empty-list", []any{}},
		{"non-string-elem", []any{"ok", 7}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := validEvent()
			if c.caps == nil {
				delete(ev(doc), "capabilities")
			} else {
				ev(doc)["capabilities"] = c.caps
			}
			_, err := ValidateEvent(doc)
			if err == nil || !strings.Contains(err.Error(), "non-empty list of ids") {
				t.Fatalf("got %v, want 'non-empty list of ids'", err)
			}
		})
	}
	// Multiple valid ids accepted.
	doc := validEvent()
	ev(doc)["capabilities"] = []any{"a", "b", "c"}
	if _, err := ValidateEvent(doc); err != nil {
		t.Fatalf("multi-id capabilities refused: %v", err)
	}
}

// TestValidateEvent_OccurredAt pins that occurredAt must be a (quoted) string.
// An unquoted YAML timestamp decodes to time.Time, not string, and is refused
// because it is not canonicalizable — this is the load-path invariant.
func TestValidateEvent_OccurredAt(t *testing.T) {
	// non-string values (what an unquoted YAML timestamp / int would become)
	for _, v := range []any{nil, 1234, mustTime()} {
		doc := validEvent()
		if v == nil {
			delete(ev(doc), "occurredAt")
		} else {
			ev(doc)["occurredAt"] = v
		}
		if _, err := ValidateEvent(doc); err == nil ||
			!strings.Contains(err.Error(), "occurredAt must be a quoted RFC3339 string") {
			t.Errorf("occurredAt=%v got %v, want refusal", v, err)
		}
	}
}

// TestValidateEvent_Actor pins actor id + closed type set.
func TestValidateEvent_Actor(t *testing.T) {
	bad := []struct {
		name  string
		actor any
	}{
		{"missing", nil},
		{"not-mapping", "human"},
		{"empty-id", map[string]any{"id": "", "type": "human"}},
		{"missing-id", map[string]any{"type": "human"}},
		{"bad-type", map[string]any{"id": "u1", "type": "robot"}},
		{"missing-type", map[string]any{"id": "u1"}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			doc := validEvent()
			if c.actor == nil {
				delete(ev(doc), "actor")
			} else {
				ev(doc)["actor"] = c.actor
			}
			if _, err := ValidateEvent(doc); err == nil ||
				!strings.Contains(err.Error(), "actor must carry id and type") {
				t.Fatalf("got %v, want actor refusal", err)
			}
		})
	}
	for atype := range ActorTypes {
		doc := validEvent()
		ev(doc)["actor"] = map[string]any{"id": "x", "type": atype}
		if _, err := ValidateEvent(doc); err != nil {
			t.Errorf("actor type %q refused: %v", atype, err)
		}
	}
}

// TestValidateEvent_FencingToken pins the optional positive-int fencing token.
func TestValidateEvent_FencingToken(t *testing.T) {
	ok := []struct {
		name string
		set  bool
		val  any
	}{
		{"absent", false, nil},
		{"nil", true, nil},
		{"one", true, 1},
		{"large", true, 999999},
	}
	for _, c := range ok {
		t.Run("ok/"+c.name, func(t *testing.T) {
			doc := validEvent()
			if c.set {
				ev(doc)["fencingToken"] = c.val
			}
			if _, err := ValidateEvent(doc); err != nil {
				t.Fatalf("fencingToken %v refused: %v", c.val, err)
			}
		})
	}
	bad := []struct {
		name string
		val  any
	}{
		{"zero", 0},
		{"negative", -3},
		{"string", "1"},
		{"int64", int64(5)}, // pins: only the yaml-native int type is accepted
		{"float", 1.0},
	}
	for _, c := range bad {
		t.Run("bad/"+c.name, func(t *testing.T) {
			doc := validEvent()
			ev(doc)["fencingToken"] = c.val
			if _, err := ValidateEvent(doc); err == nil ||
				!strings.Contains(err.Error(), "fencingToken must be a positive integer") {
				t.Fatalf("fencingToken %v(%T) got %v, want refusal", c.val, c.val, err)
			}
		})
	}
}

const (
	hex32 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff" // 64 chars
	hex64 = hex32 + hex32                                                      // 128 chars
	ledgH = "sha256:" + hex32
)

// TestValidateEvent_Sig pins the detached ed25519 signature envelope (D102).
func TestValidateEvent_Sig(t *testing.T) {
	goodSig := func() map[string]any {
		return map[string]any{"alg": "ed25519", "pub": hex32, "sig": hex64, "ledger": ledgH}
	}
	// absent / nil sig is allowed
	for _, c := range []struct {
		name string
		set  bool
	}{{"absent", false}, {"nil", true}} {
		doc := validEvent()
		if c.set {
			doc["sig"] = nil
		}
		if _, err := ValidateEvent(doc); err != nil {
			t.Errorf("sig %s refused: %v", c.name, err)
		}
	}
	// well-formed sig accepted
	doc := validEvent()
	doc["sig"] = goodSig()
	if _, err := ValidateEvent(doc); err != nil {
		t.Fatalf("well-formed sig refused: %v", err)
	}
	// malformed variants refused
	bad := []struct {
		name  string
		build func() any
	}{
		{"not-a-mapping", func() any { return "sig" }},
		{"wrong-alg", func() any { s := goodSig(); s["alg"] = "rsa"; return s }},
		{"short-pub", func() any { s := goodSig(); s["pub"] = hex32[:62]; return s }},
		{"upper-pub", func() any { s := goodSig(); s["pub"] = strings.ToUpper(hex32); return s }},
		{"short-sig", func() any { s := goodSig(); s["sig"] = hex64[:126]; return s }},
		{"bad-ledger-prefix", func() any { s := goodSig(); s["ledger"] = hex32; return s }},
		{"bad-ledger-len", func() any { s := goodSig(); s["ledger"] = "sha256:" + hex32[:62]; return s }},
		{"missing-pub", func() any { s := goodSig(); delete(s, "pub"); return s }},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			doc := validEvent()
			doc["sig"] = c.build()
			if _, err := ValidateEvent(doc); err == nil ||
				!strings.Contains(err.Error(), "sig must be an ed25519 envelope") {
				t.Fatalf("got %v, want sig refusal", err)
			}
		})
	}
}

// TestIsHex pins the lowercase-only, exact-width hex predicate.
func TestIsHex(t *testing.T) {
	cases := []struct {
		v     any
		width int
		want  bool
	}{
		{hex32, 64, true},
		{"abcdef", 6, true},
		{"ABCDEF", 6, false}, // uppercase refused: one spelling
		{"abcde", 6, false},  // wrong width
		{"abcdez", 6, false}, // non-hex char
		{123, 64, false},     // not a string
		{"", 0, true},        // empty matches width 0 and decodes
	}
	for _, c := range cases {
		if got := isHex(c.v, c.width); got != c.want {
			t.Errorf("isHex(%v,%d)=%v want %v", c.v, c.width, got, c.want)
		}
	}
}

// TestIsEventHash pins the sha256:<64 lowercase hex> shape.
func TestIsEventHash(t *testing.T) {
	cases := []struct {
		v    any
		want bool
	}{
		{ledgH, true},
		{"sha256:" + strings.ToUpper(hex32), false},
		{hex32, false},                  // missing prefix
		{"sha256:" + hex32[:62], false}, // too short
		{"sha1:" + hex32, false},        // wrong algo prefix
		{42, false},                     // not a string
	}
	for _, c := range cases {
		if got := isEventHash(c.v); got != c.want {
			t.Errorf("isEventHash(%v)=%v want %v", c.v, got, c.want)
		}
	}
}

// --- LoadEvent (file + YAML decode path) --------------------------------

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "event.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestLoadEvent_Valid exercises the full read+decode+validate path.
func TestLoadEvent_Valid(t *testing.T) {
	doc, err := LoadEvent(writeTmp(t, `
kind: LedgerEvent
apiVersion: state/v0
event:
  type: contract.published
  capabilities: ["cap-db"]
  occurredAt: "2026-07-12T00:00:00Z"
  actor: {id: u1, type: human}
`))
	if err != nil {
		t.Fatalf("valid file refused: %v", err)
	}
	if doc["kind"] != "LedgerEvent" {
		t.Fatalf("unexpected doc: %v", doc)
	}
}

// TestLoadEvent_UnquotedTimestamp pins the load-path invariant: an unquoted
// YAML timestamp decodes to a native time value (not a string) and is refused
// as non-canonicalizable.
func TestLoadEvent_UnquotedTimestamp(t *testing.T) {
	_, err := LoadEvent(writeTmp(t, `
kind: LedgerEvent
apiVersion: state/v0
event:
  type: contract.published
  capabilities: ["cap-db"]
  occurredAt: 2026-07-12T00:00:00Z
  actor: {id: u1, type: human}
`))
	if err == nil || !strings.Contains(err.Error(), "occurredAt must be a quoted RFC3339 string") {
		t.Fatalf("unquoted timestamp got %v, want refusal", err)
	}
}

// TestLoadEvent_FencingTokenFromYAML pins that a YAML integer fencing token
// decodes to the int type ValidateEvent accepts (round-trip of the type gate).
func TestLoadEvent_FencingTokenFromYAML(t *testing.T) {
	doc, err := LoadEvent(writeTmp(t, `
kind: LedgerEvent
apiVersion: state/v0
event:
  type: lease.acquired
  capabilities: ["cap-db"]
  occurredAt: "2026-07-12T00:00:00Z"
  actor: {id: u1, type: runtime}
  fencingToken: 7
`))
	if err != nil {
		t.Fatalf("fencingToken from YAML refused: %v", err)
	}
	if got := ev(doc)["fencingToken"]; got != 7 {
		t.Fatalf("fencingToken = %v (%T), want int 7", got, got)
	}
}

func TestLoadEvent_Errors(t *testing.T) {
	if _, err := LoadEvent(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Error("missing file should error")
	}
	if _, err := LoadEvent(writeTmp(t, "kind: [unterminated")); err == nil {
		t.Error("malformed YAML should error")
	}
}

// mustTime returns a value of the type an unquoted YAML timestamp decodes to,
// so the occurredAt string-gate can be exercised in-memory too.
func mustTime() any {
	// time.Time is what yaml.v3 yields for an unquoted RFC3339 scalar;
	// any non-string stands in for the gate.
	return struct{ notAString bool }{true}
}
