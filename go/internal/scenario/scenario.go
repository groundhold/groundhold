// Package scenario implements the deterministic concurrency scenario
// engine (D37). The rules themselves live in internal/ledger — the same
// code the apply engine drives (D42), so what these scenarios pin is
// what apply obeys. This package only parses steps, builds event
// documents from the logical clock and resolves symbolic references.
package scenario

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"groundhold/internal/ledger"
)

type engine struct {
	led        *ledger.Ledger
	env        string
	stepHashes map[int]string
}

func ts(clock int) string {
	return time.Unix(int64(clock), 0).UTC().Format("2006-01-02T15:04:05Z")
}

func (e *engine) resolve(ref any) (string, error) {
	s, ok := ref.(string)
	if !ok {
		return "", fmt.Errorf("head reference must be a string")
	}
	if strings.HasPrefix(s, "@") {
		idx, err := strconv.Atoi(s[1:])
		if err != nil {
			return "", fmt.Errorf("bad step reference %q", s)
		}
		h, ok := e.stepHashes[idx]
		if !ok {
			return "", fmt.Errorf("reference %s: step has no event hash", s)
		}
		return h, nil
	}
	return s, nil
}

func Run(docAny any) ([]map[string]any, error) {
	doc, ok := docAny.(map[string]any)
	if !ok || doc["kind"] != "ConcurrencyScenario" {
		return nil, fmt.Errorf("kind must be ConcurrencyScenario")
	}
	if doc["apiVersion"] != "scenario/v0" {
		return nil, fmt.Errorf("apiVersion must be scenario/v0")
	}
	steps, ok := doc["steps"].([]any)
	if !ok || len(steps) == 0 {
		return nil, fmt.Errorf("steps must be a non-empty list")
	}
	env, _ := doc["environment"].(string)
	if env == "" {
		env = "test"
	}
	e := &engine{led: ledger.New(), env: env, stepHashes: map[int]string{}}
	var results []map[string]any
	for i, stepAny := range steps {
		idx := i + 1
		step, ok := stepAny.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("step %d: not a mapping", idx)
		}
		r, err := e.step(idx, step)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", idx, err)
		}
		results = append(results, r)
	}
	return results, nil
}

func (e *engine) step(idx int, step map[string]any) (map[string]any, error) {
	if n, has := step["tick"]; has {
		ticks, ok := n.(int)
		// time only moves forward — a reversible clock would resurrect
		// expired leases and break fencing
		if !ok || ticks <= 0 {
			return nil, fmt.Errorf("tick must be a positive integer")
		}
		e.led.Clock += ticks
		return map[string]any{"status": "ok"}, nil
	}

	if chk, has := step["checkHeads"]; has {
		return e.checkHeads(chk, e.led.Heads)
	}
	if chk, has := step["checkDecisionHeads"]; has {
		return e.checkHeads(chk, e.led.DecisionHeads)
	}

	a, ok := step["append"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unknown step form")
	}
	capsAny, _ := a["capabilities"].([]any)
	actor, _ := a["actor"].(string)
	if actor == "" {
		actor = "runtime-1"
	}
	actorType, _ := a["actorType"].(string)
	if actorType == "" {
		actorType = "runtime"
	}
	prev := map[string]any{}
	for _, cAny := range capsAny {
		c, _ := cAny.(string)
		h, ok := e.led.Heads[c]
		if !ok {
			h = "genesis"
		}
		prev[c] = h
	}
	ev := map[string]any{
		"type": a["type"], "environment": e.env,
		"capabilities": capsAny, "occurredAt": ts(e.led.Clock),
		"actor": map[string]any{"id": actor, "type": actorType},
		"prev":  prev,
	}
	if b, has := a["body"]; has {
		ev["body"] = b
	}
	if t, has := a["fencingToken"]; has {
		ev["fencingToken"] = t
	}
	eventDoc := map[string]any{
		"apiVersion": "state/v0", "kind": "LedgerEvent", "event": ev,
	}

	var expected map[string]string
	if expAny, has := step["expectedHeads"]; has {
		exp, ok := expAny.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("expectedHeads must be a mapping")
		}
		expected = map[string]string{}
		for c, ref := range exp {
			w, err := e.resolve(ref)
			if err != nil {
				return nil, err
			}
			expected[c] = w
		}
	}

	res, err := e.led.Append(eventDoc, expected)
	if err != nil {
		return nil, err // malformed scenario = authoring error
	}
	switch res.Status {
	case "conflict":
		return map[string]any{"status": "conflict"}, nil
	case "rejected":
		return map[string]any{"status": "rejected", "reason": res.Reason}, nil
	}
	e.stepHashes[idx] = res.Hash
	result := map[string]any{"status": "ok"}
	if res.Token > 0 {
		result["token"] = res.Token
	}
	return result, nil
}

func (e *engine) checkHeads(chk any,
	stream map[string]string) (map[string]any, error) {
	want, ok := chk.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("head check must be a mapping")
	}
	fresh := true
	for c, ref := range want {
		w, err := e.resolve(ref)
		if err != nil {
			return nil, err
		}
		cur, ok := stream[c]
		if !ok {
			cur = "genesis"
		}
		if cur != w {
			fresh = false
		}
	}
	status := "stale"
	if fresh {
		status = "fresh"
	}
	return map[string]any{"status": status}, nil
}
