package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// golden transcript: the protocol layer against an injected runner —
// fail-closed framing, tool listing gated by allowApply, the two-step
// apply with a single-use token (D50).
func testServer(t *testing.T, in string, allowApply bool,
	run Runner) []map[string]any {
	t.Helper()
	var out strings.Builder
	s := &Server{in: strings.NewReader(in), out: &out, run: run,
		allowApply: allowApply, tokens: map[string]token{},
		now: func() time.Time { return time.Unix(1000, 0) }}
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	var msgs []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad frame: %v", err)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

func toolText(t *testing.T, msg map[string]any) map[string]any {
	t.Helper()
	res, _ := msg["result"].(map[string]any)
	items, _ := res["content"].([]any)
	first, _ := items[0].(map[string]any)
	var payload map[string]any
	if err := json.Unmarshal([]byte(first["text"].(string)), &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestProtocolGolden(t *testing.T) {
	in := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
garbage line that must be dropped, fail closed
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"no/such"}
`
	msgs := testServer(t, in, false, nil)
	if len(msgs) != 3 {
		t.Fatalf("expected 3 responses (garbage + notification silent), got %d", len(msgs))
	}
	init, _ := msgs[0]["result"].(map[string]any)
	if init["protocolVersion"] != protocolVersion {
		t.Error("protocol version missing")
	}
	tools, _ := msgs[1]["result"].(map[string]any)["tools"].([]any)
	for _, tl := range tools {
		if tl.(map[string]any)["name"] == "groundhold_apply" {
			t.Error("apply must not exist without GROUNDHOLD_MCP_ALLOW_APPLY")
		}
	}
	if msgs[2]["error"] == nil {
		t.Error("unknown method must error")
	}
}

func TestTwoStepApply(t *testing.T) {
	runner := func(args ...string) (int, string, string) {
		switch args[0] {
		case "hash":
			return 0, "sha256:planhash\n", ""
		case "apply":
			return 0, `{"status":"applied","events":[]}`, ""
		}
		return 1, "", "unexpected"
	}
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"groundhold_apply","arguments":{"contract":"c","candidate":"k","plan":"p","ledger":"l"}}}
`
	msgs := testServer(t, call, true, runner)
	step1 := toolText(t, msgs[0])
	if step1["status"] != "confirmation_required" {
		t.Fatalf("step 1: %v", step1["status"])
	}
	tok, _ := step1["confirm_token"].(string)
	if tok == "" || step1["planHash"] != "sha256:planhash" {
		t.Fatal("token/hash missing")
	}

	// step 2 with the token, then reuse — must refuse
	in2 := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"groundhold_apply","arguments":{"contract":"c","candidate":"k","plan":"p","ledger":"l","confirm_token":"TOK"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"groundhold_apply","arguments":{"contract":"c","candidate":"k","plan":"p","ledger":"l","confirm_token":"TOK"}}}
`
	var out strings.Builder
	s := &Server{in: strings.NewReader(in2), out: &out, run: runner,
		allowApply: true,
		// D319: the token binds the whole decision, so the fixture must carry the
		// same target the calls below present. Built with applyTarget itself, so
		// the fixture cannot drift from the implementation.
		tokens: map[string]token{"TOK": {planHash: "sha256:planhash",
			target: applyTarget(map[string]any{
				"contract": "c", "candidate": "k", "ledger": "l"}),
			expires: time.Unix(2000, 0)}},
		now: func() time.Time { return time.Unix(1000, 0) }}
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var m1, m2 map[string]any
	json.Unmarshal([]byte(lines[0]), &m1)
	json.Unmarshal([]byte(lines[1]), &m2)
	p1, p2 := toolText(t, m1), toolText(t, m2)
	if p1["status"] != "ok" {
		t.Errorf("valid token must execute, got %v", p1)
	}
	if p2["status"] != "refused" {
		t.Errorf("token reuse must refuse, got %v", p2)
	}
}

func TestApplyDisabledByDefault(t *testing.T) {
	call := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"groundhold_apply","arguments":{}}}
`
	msgs := testServer(t, call, false, nil)
	p := toolText(t, msgs[0])
	if p["status"] != "refused" {
		t.Errorf("apply without the env gate must refuse, got %v", p)
	}
}

// TestTokenConsumedOnHashFailure pins D50 "single-use, success or not": a token
// presented against a plan that then FAILS to hash is still spent — it must not
// survive for a retry (before the fix, the structural-error early return ran
// before the token was consumed, leaving it live until expiry).
func TestTokenConsumedOnHashFailure(t *testing.T) {
	hashCalls := 0
	runner := func(args ...string) (int, string, string) {
		if args[0] == "hash" {
			hashCalls++
			if hashCalls == 1 {
				return 1, "", "plan unreadable" // the first hash step FAILS
			}
			return 0, "sha256:x\n", "" // later it succeeds AND matches the pin
		}
		return 0, `{"status":"applied"}`, ""
	}
	// call 1: token against an unhashable plan -> structural-error, token spent.
	// call 2: token now hashes to the pinned value — if the token had SURVIVED the
	// hash failure it would EXECUTE; it must instead refuse (unknown), proving the
	// first attempt consumed it.
	in := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"groundhold_apply","arguments":{"plan":"p","confirm_token":"TOK"}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"groundhold_apply","arguments":{"plan":"p","confirm_token":"TOK"}}}
`
	var out strings.Builder
	s := &Server{in: strings.NewReader(in), out: &out, run: runner,
		allowApply: true,
		tokens:     map[string]token{"TOK": {planHash: "sha256:x", expires: time.Unix(2000, 0)}},
		now:        func() time.Time { return time.Unix(1000, 0) }}
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	if _, live := s.tokens["TOK"]; live {
		t.Fatal("token must be consumed even when the plan fails to hash (single-use, success or not)")
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var m1, m2 map[string]any
	json.Unmarshal([]byte(lines[0]), &m1)
	json.Unmarshal([]byte(lines[1]), &m2)
	p1, p2 := toolText(t, m1), toolText(t, m2)
	if p1["status"] != "structural-error" {
		t.Errorf("hash failure must be structural-error, got %v", p1)
	}
	if p2["status"] != "refused" {
		t.Errorf("the spent token must refuse on reuse, got %v", p2)
	}
}

// TestConfineToWorkspaceRejectsSymlinkEscape pins the F4 fix: a `..`-free relative
// path that escapes the workspace THROUGH A SYMLINK (a linked parent dir) must be
// refused before it reaches a writer — Clean() alone does not catch it.
func TestConfineToWorkspaceRejectsSymlinkEscape(t *testing.T) {
	work := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(work, "sub")); err != nil {
		t.Skipf("symlinks unsupported here: %v", err)
	}
	t.Chdir(work)
	if _, err := confineToWorkspace("sub/plan.yaml"); err == nil {
		t.Fatal("a path through a workspace-escaping symlink must be refused")
	}
	// a normal in-workspace path is still allowed
	if _, err := confineToWorkspace(".groundhold/plan.yaml"); err != nil {
		t.Fatalf("a normal in-workspace path must be allowed: %v", err)
	}
}
