// Package mcp is the THIN adapter (D50) exposing Groundhold's lifecycle as
// MCP tools over stdio — stdlib-only JSON-RPC, newline-delimited,
// wrapping the D22-frozen CLI protocol by exec'ing our own binary.
// Read-only by default: apply exists only under GROUNDHOLD_MCP_ALLOW_APPLY
// and is a structural two-step: confirmation_required returns the plan
// text plus a short-lived single-use token that PINS the plan hash, so
// the apply re-executes EXACTLY the reviewed plan.
//
// Honest boundary (compliance review): the token forces a second,
// hash-pinned round-trip; it does NOT authenticate a human. It is
// delivered in-band to the same MCP client, so an autonomous (or
// prompt-injected) agent can complete both steps alone — do not rely on
// it as SoC/human-approval evidence. Its real guarantees are
// plan-pinning, single use, 5-minute expiry, and the env gate; the
// executor's own consent gates (autonomy, --allow-data-loss) stay
// authoritative and are never satisfied by the token.
package mcp

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const protocolVersion = "2024-11-05"

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type token struct {
	planHash string
	// target (D319) binds the rest of the decision — contract, candidate,
	// ledger, provider, at. Pinning only the plan hash let a token confirmed for
	// one ledger/provider be spent applying the identical plan somewhere else,
	// writing bindings into a ledger nobody reviewed. What the confirmation
	// DISPLAYS and what the second call EXECUTES must be the same decision.
	target  string
	expires time.Time
}

// applyTarget is the canonical fingerprint of everything besides the plan that
// shapes the apply argv. Any field added to the apply arg list must be added
// here too, or the token stops covering the decision.
func applyTarget(a map[string]any) string {
	return strings.Join([]string{
		"contract=" + str(a, "contract", ""),
		"candidate=" + str(a, "candidate", ""),
		"ledger=" + str(a, "ledger", ""),
		"vocab=" + str(a, "vocab", ""),
		"provider=" + str(a, "provider", "gcp"),
		"at=" + str(a, "at", ""),
	}, "\n")
}

// Runner executes a plumbing command; injectable for golden tests.
type Runner func(args ...string) (exitCode int, stdout, stderr string)

type Server struct {
	in         io.Reader
	out        io.Writer
	run        Runner
	allowApply bool
	tokens     map[string]token
	now        func() time.Time
}

func New(in io.Reader, out io.Writer, bin string) *Server {
	return &Server{
		in:  in,
		out: out,
		run: func(args ...string) (int, string, string) {
			cmd := exec.Command(bin, args...)
			var so, se strings.Builder
			cmd.Stdout, cmd.Stderr = &so, &se
			err := cmd.Run()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				code = -1
			}
			return code, so.String(), se.String()
		},
		allowApply: os.Getenv("GROUNDHOLD_MCP_ALLOW_APPLY") == "1",
		tokens:     map[string]token{},
		now:        time.Now,
	}
}

func (s *Server) Serve() error {
	scanner := bufio.NewScanner(s.in)
	scanner.Buffer(make([]byte, 0, 1<<20), 1<<24)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue // fail closed: unparseable frames are dropped
		}
		if req.ID == nil {
			continue // notifications need no response
		}
		result, rpcErr := s.dispatch(req)
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		if rpcErr != nil {
			resp["error"] = rpcErr
		} else {
			resp["result"] = result
		}
		raw, _ := json.Marshal(resp)
		fmt.Fprintf(s.out, "%s\n", raw)
	}
	return scanner.Err()
}

func (s *Server) dispatch(req rpcRequest) (any, map[string]any) {
	switch req.Method {
	case "initialize":
		return map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo": map[string]any{
				"name": "groundhold", "version": "0.1.0"},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": s.toolDefs()}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return nil, rpcError(-32602, "invalid params")
		}
		return s.callTool(p.Name, p.Arguments), nil
	}
	return nil, rpcError(-32601, "method not found: "+req.Method)
}

func rpcError(code int, msg string) map[string]any {
	return map[string]any{"code": code, "message": msg}
}

// ---- tools ------------------------------------------------------------------

func pathArg(name, desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc + " (file path)"}
}

func (s *Server) toolDefs() []map[string]any {
	str := func(d string) map[string]any {
		return map[string]any{"type": "string", "description": d}
	}
	tool := func(name, desc string, required []string,
		props map[string]any) map[string]any {
		return map[string]any{
			"name": name, "description": desc,
			"inputSchema": map[string]any{"type": "object",
				"properties": props, "required": required},
		}
	}
	defs := []map[string]any{
		tool("groundhold_verify",
			"Four-valued verification of a candidate against a contract. "+
				"unknown/unverifiable on hard constraints blocks — that is "+
				"the system working, never route around it.",
			[]string{"contract", "candidate"},
			map[string]any{"contract": pathArg("contract", "InfrastructureContract"),
				"candidate": pathArg("candidate", "ImplementationCandidate"),
				"vocab":     str("optional vocabulary directory that EXTENDS the built-in vocabulary")}),
		tool("groundhold_plan",
			"Compile a VERIFIED candidate into a Sealed Plan. Refusals "+
				"(not executable, stale observations, immutable drift, "+
				"missing consents, nothing-to-change) come back verbatim.",
			[]string{"contract", "candidate"},
			map[string]any{"contract": pathArg("contract", "contract"),
				"candidate": pathArg("candidate", "candidate"),
				"project":   str("provider project to pin (D28)"),
				"ledger":    pathArg("ledger", "JSONL ledger"),
				"vocab":     str("vocabulary directory"),
				"at":        str("evaluation time RFC3339"),
				"out":       str("where to write the plan (default .groundhold/plan.yaml)")}),
		tool("groundhold_forecast",
			"Deterministic forecast of a sealed plan: effects per action, "+
				"four-valued attribute predictions, freshness degradation.",
			[]string{"plan", "candidate"},
			map[string]any{"plan": pathArg("plan", "SealedPlan"),
				"candidate": pathArg("candidate", "candidate"),
				"ledger":    pathArg("ledger", "JSONL ledger"),
				"at":        str("evaluation time RFC3339")}),
		tool("groundhold_observe",
			"Read bound resources through the provider's reverse mapping; "+
				"derivation-tagged facts, optionally recorded to the ledger.",
			[]string{"ledger"},
			map[string]any{"ledger": pathArg("ledger", "JSONL ledger"),
				"provider": str("fake|gcp (default gcp)"),
				"at":       str("observation time RFC3339"),
				"record": map[string]any{"type": "boolean",
					"description": "append observation.recorded events"}}),
		tool("groundhold_hash",
			"Canonical identity of any Groundhold document (D34).",
			[]string{"document"},
			map[string]any{"document": pathArg("document", "any Groundhold document")}),
		tool("groundhold_draft",
			"Materialize inline YAML as a DRAFT under .groundhold/drafts/ — "+
				"returns {path, hash, draft: true}. Nothing seals or "+
				"applies from inline content (D50).",
			[]string{"yaml"},
			map[string]any{"yaml": str("the draft document content")}),
	}
	if s.allowApply {
		defs = append(defs, tool("groundhold_apply",
			"Execute a sealed plan — STRUCTURAL TWO-STEP: the first call "+
				"returns confirmation_required with the plan hash, risk "+
				"vectors and a short-lived token; call again with "+
				"confirm_token to execute EXACTLY that plan. The token "+
				"pins the plan hash (single-use, 5-min); it does NOT "+
				"authenticate a human and never supplies missing consent.",
			[]string{"contract", "candidate", "plan", "ledger"},
			map[string]any{"contract": pathArg("contract", "contract"),
				"candidate":     pathArg("candidate", "candidate"),
				"plan":          pathArg("plan", "SealedPlan"),
				"ledger":        pathArg("ledger", "JSONL ledger"),
				"provider":      str("fake|gcp"),
				"vocab":         str("vocabulary directory"),
				"at":            str("evaluation time RFC3339"),
				"confirm_token": str("token from the confirmation step")}))
	}
	return defs
}

func str(m map[string]any, k, def string) string {
	if v, ok := m[k].(string); ok && v != "" {
		return v
	}
	return def
}

// vocabArgs passes --vocab ONLY when the caller supplied one. The binary ships
// the full vocabulary compiled in (D140), so the default is no flag (embedded);
// a supplied dir EXTENDS it. Never default to "spec/vocab" — a downloaded
// binary running `groundhold mcp` has no repo beside it.
func vocabArgs(a map[string]any) []string {
	if v := str(a, "vocab", ""); v != "" {
		return []string{"--vocab", v}
	}
	return nil
}

func (s *Server) callTool(name string, a map[string]any) map[string]any {
	switch name {
	case "groundhold_verify":
		if err := rejectFlagLike(str(a, "contract", ""),
			str(a, "candidate", ""), str(a, "vocab", "")); err != nil {
			return content(map[string]any{"status": "error", "error": err.Error()})
		}
		return content(s.exec(append([]string{"verify", str(a, "contract", ""),
			str(a, "candidate", ""), "--json"}, vocabArgs(a)...)...))
	case "groundhold_plan":
		out, err := confineToWorkspace(str(a, "out", ".groundhold/plan.yaml"))
		if err != nil {
			return content(map[string]any{"status": "error",
				"error": "out: " + err.Error()})
		}
		if err := rejectFlagLike(str(a, "contract", ""),
			str(a, "candidate", ""), str(a, "vocab", "")); err != nil {
			return content(map[string]any{"status": "error",
				"error": err.Error()})
		}
		args := append([]string{"plan", str(a, "contract", ""),
			str(a, "candidate", "")}, vocabArgs(a)...)
		if p := str(a, "project", ""); p != "" {
			args = append(args, "--project", p)
		}
		if l := str(a, "ledger", ""); l != "" {
			args = append(args, "--ledger", l)
		}
		if t := str(a, "at", ""); t != "" {
			args = append(args, "--at", t)
		}
		res := s.exec(args...)
		if code, _ := res["exitCode"].(int); code == 0 {
			var body []byte
			if raw, ok := res["stdout"].(string); ok {
				body = []byte(raw)
			} else if parsed, ok := res["result"]; ok {
				body, _ = json.MarshalIndent(parsed, "", "  ")
			}
			if len(body) > 0 {
				_ = os.MkdirAll(filepath.Dir(out), 0o755)
				if err := os.WriteFile(out, body, 0o600); err == nil {
					res["planPath"] = out
					delete(res, "stdout")
					delete(res, "result")
				}
			}
		}
		return content(res)
	case "groundhold_forecast":
		if err := rejectFlagLike(str(a, "plan", ""), str(a, "candidate", "")); err != nil {
			return content(map[string]any{"status": "error", "error": err.Error()})
		}
		args := []string{"forecast", str(a, "plan", ""), str(a, "candidate", "")}
		if l := str(a, "ledger", ""); l != "" {
			args = append(args, "--ledger", l)
		}
		if t := str(a, "at", ""); t != "" {
			args = append(args, "--at", t)
		}
		return content(s.exec(args...))
	case "groundhold_observe":
		args := []string{"observe", "--ledger", str(a, "ledger", ""),
			"--provider", str(a, "provider", "gcp")}
		if t := str(a, "at", ""); t != "" {
			args = append(args, "--at", t)
		}
		if r, _ := a["record"].(bool); r {
			args = append(args, "--record")
		}
		return content(s.exec(args...))
	case "groundhold_hash":
		if err := rejectFlagLike(str(a, "document", "")); err != nil {
			return content(map[string]any{"status": "error", "error": err.Error()})
		}
		return content(s.exec("hash", str(a, "document", "")))
	case "groundhold_draft":
		return content(s.draft(str(a, "yaml", "")))
	case "groundhold_apply":
		if !s.allowApply {
			return content(map[string]any{"status": "refused",
				"reasons": []string{"apply is disabled: set " +
					"GROUNDHOLD_MCP_ALLOW_APPLY=1 to enable"}})
		}
		return content(s.apply(a))
	}
	return content(map[string]any{"status": "error",
		"reasons": []string{"unknown tool " + name}})
}

// exec runs the plumbing and maps the D22 exit-code protocol into a
// structured payload — refusals arrive verbatim, never summarized away.
func (s *Server) exec(args ...string) map[string]any {
	code, stdout, stderr := s.run(args...)
	payload := map[string]any{"exitCode": code}
	payload["status"] = map[int]string{0: "ok", 1: "structural-error",
		2: "refused", 3: "stale-or-conflict", 4: "failed-mid-flight",
		5: "corrupted-ledger"}[code]
	var parsed any
	if json.Unmarshal([]byte(stdout), &parsed) == nil {
		payload["result"] = parsed
	} else if strings.TrimSpace(stdout) != "" {
		payload["stdout"] = stdout
	}
	if strings.TrimSpace(stderr) != "" {
		payload["reasons"] = strings.Split(strings.TrimSpace(stderr), "\n")
	}
	return payload
}

func (s *Server) draft(body string) map[string]any {
	if strings.TrimSpace(body) == "" {
		return map[string]any{"status": "error",
			"reasons": []string{"empty draft"}}
	}
	sum := sha256.Sum256([]byte(body))
	name := "draft-" + hex.EncodeToString(sum[:])[:8] + ".yaml"
	dir := filepath.Join(".groundhold", "drafts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return map[string]any{"status": "error", "reasons": []string{err.Error()}}
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return map[string]any{"status": "error", "reasons": []string{err.Error()}}
	}
	return map[string]any{"status": "ok", "path": path,
		"hash": "sha256:" + hex.EncodeToString(sum[:]), "draft": true}
}

// apply: the structural two-step (D50).
func (s *Server) apply(a map[string]any) map[string]any {
	planPath := str(a, "plan", "")
	if err := rejectFlagLike(planPath, str(a, "contract", ""),
		str(a, "candidate", ""), str(a, "ledger", ""),
		str(a, "vocab", "")); err != nil {
		return map[string]any{"status": "error", "reasons": []string{err.Error()}}
	}
	// Consume the token UP FRONT — single-use, success or not (D50): a token
	// presented against a plan that then fails to hash (below) is still spent, so
	// it can never be retried. The tokenless first call has nothing to consume.
	tok := str(a, "confirm_token", "")
	info, ok := s.tokens[tok]
	if tok != "" {
		delete(s.tokens, tok)
	}

	code, stdout, stderr := s.run("hash", planPath)
	if code != 0 {
		return map[string]any{"status": "structural-error",
			"reasons": []string{strings.TrimSpace(stderr)}}
	}
	planHash := strings.TrimSpace(stdout)

	if tok == "" {
		return s.confirmationRequired(planPath, planHash, a)
	}
	switch {
	case !ok:
		return map[string]any{"status": "refused",
			"reasons": []string{"unknown confirm_token — request a fresh " +
				"confirmation"}}
	case s.now().After(info.expires):
		return map[string]any{"status": "refused",
			"reasons": []string{"confirm_token expired — the human must see " +
				"the decision again"}}
	case info.planHash != planHash:
		return map[string]any{"status": "refused",
			"reasons": []string{"plan changed since confirmation (" +
				info.planHash + " != " + planHash + ") — re-confirm"}}
	case info.target != applyTarget(a):
		// D319: same plan, different destination. The confirmation showed one
		// decision; this call is a different one.
		return map[string]any{"status": "refused",
			"reasons": []string{"the apply target changed since confirmation " +
				"(contract/candidate/ledger/vocab/provider/at) — a token confirms " +
				"ONE decision, not one plan document; re-confirm for this target"}}
	}

	args := append([]string{"apply", str(a, "contract", ""),
		str(a, "candidate", ""), planPath, "--ledger", str(a, "ledger", "")},
		vocabArgs(a)...)
	args = append(args, "--provider", str(a, "provider", "gcp"))
	if t := str(a, "at", ""); t != "" {
		args = append(args, "--at", t)
	}
	return s.exec(args...)
}

func (s *Server) confirmationRequired(planPath, planHash string, a map[string]any) map[string]any {
	// sweep expired tokens (D319): they are only removed on redemption today, so a
	// long-lived server accumulates one per confirmation forever.
	now := s.now()
	for k, v := range s.tokens {
		if now.After(v.expires) {
			delete(s.tokens, k)
		}
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		// FAIL CLOSED: a token we cannot make unpredictable must not be
		// issued — an all-zero token would be a guessable apply gate.
		return map[string]any{"status": "error",
			"error": "cannot generate a confirmation token: " + err.Error()}
	}
	tok := hex.EncodeToString(buf)
	s.tokens[tok] = token{planHash: planHash, target: applyTarget(a),
		expires: s.now().Add(5 * time.Minute)}
	// surface the decision itself — never hide the risk (D49)
	raw, err := os.ReadFile(planPath)
	planText := ""
	if err == nil {
		planText = string(raw)
	}
	return map[string]any{
		"status":   "confirmation_required",
		"planHash": planHash,
		"plan":     planText,
		// D319: the decision is the plan AND where it lands — show both, and the
		// token refuses a second call that changes any of it.
		"target": map[string]any{
			"contract": str(a, "contract", ""), "candidate": str(a, "candidate", ""),
			"ledger": str(a, "ledger", ""), "vocab": str(a, "vocab", ""),
			"provider": str(a, "provider", "gcp"), "at": str(a, "at", ""),
		},
		"confirm_token":    tok,
		"expiresInSeconds": 300,
		"note": "Show the plan (risk vectors, delete targets, consents) AND the " +
			"target to the human. Call groundhold_apply again with confirm_token to " +
			"execute EXACTLY this plan against EXACTLY this target. The token never " +
			"supplies consent.",
	}
}

// confineToWorkspace resolves a client-supplied output path and refuses
// anything that escapes the current working directory — an MCP client
// is semi-trusted; it must not turn `plan --out` into an arbitrary file
// write (e.g. ~/.bashrc, a crontab drop).
func confineToWorkspace(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(p) {
		return "", fmt.Errorf("absolute paths are refused; use a path "+
			"under the workspace (got %q)", p)
	}
	clean := filepath.Clean(p)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the workspace (got %q)", p)
	}
	// A `..`-free relative path can still ESCAPE via a symlink — e.g. `sub/plan`
	// where `sub` links outside, or `plan` is itself a link to /etc. Resolve the
	// deepest existing component and confirm the real target stays under the
	// workspace root before we hand the path to a writer.
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	abs := filepath.Join(wd, clean)
	target := abs
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		target = resolved // the path exists (maybe a symlink) — use its real target
	} else if resolved, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		target = filepath.Join(resolved, filepath.Base(abs)) // resolve the parent
	}
	if rel, err := filepath.Rel(wd, target); err != nil ||
		rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path resolves outside the workspace via a symlink (got %q)", p)
	}
	return clean, nil
}

// rejectFlagLike refuses path arguments that begin with '-': passed
// positionally to the child CLI they would be parsed as flags and
// silently shift the argument vector (argument injection). The CLI
// protocol is frozen (D22) and has no '--' terminator, so this is the
// boundary that enforces it.
func rejectFlagLike(vals ...string) error {
	for _, v := range vals {
		if strings.HasPrefix(v, "-") {
			return fmt.Errorf("argument %q may not begin with '-'", v)
		}
	}
	return nil
}

// content wraps a payload in the MCP tool-result envelope.
func content(payload map[string]any) map[string]any {
	raw, _ := json.MarshalIndent(payload, "", "  ")
	isErr := payload["status"] != "ok" &&
		payload["status"] != "confirmation_required"
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": string(raw)}},
		"isError": isErr,
	}
}
