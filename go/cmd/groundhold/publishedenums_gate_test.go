package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"groundhold/internal/probe"
	"groundhold/internal/reach"
)

// D696/D697: a published closed set must be the set the runtime can emit.
//
// Two were wrong. `applyResult.reachability` and `convergeResult.reachability`
// advertised `denied` — removed from the runtime when a 403 became ambiguous, and
// producible by no code path since — while `failing` did not exist yet.
// `probeResult.status` listed `probed | refused`, and a probe run in which every
// measurement failed reported `probed`.
//
// A consumer generating types from this schema gets values that never arrive and
// misses ones that do — in exactly the fields a policy is keyed on. The sets have one
// home each in the packages that own them; this holds the schema to them.
//
// One gate over a table rather than one per field: the first version of this was a
// reachability-only test, and adding the probe field would have meant copying it —
// which is how the two reachability locations drifted apart from the runtime in the
// first place.
func TestPublishedEnumsMatchTheRuntime(t *testing.T) {
	want := []struct {
		def, field string
		set        []string
	}{
		{"applyResult", "reachability", reach.ReportedVerdicts},
		{"convergeResult", "reachability", reach.ReportedVerdicts},
		{"probeResult", "status", probe.ReportedStatuses},
	}

	root := repoRootFromCmd(t)
	raw, err := os.ReadFile(filepath.Join(root, "spec", "outputs.schema.json"))
	if err != nil {
		t.Skip("no spec/outputs.schema.json in this tree")
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	defs, _ := doc["definitions"].(map[string]any)
	if defs == nil {
		defs, _ = doc["$defs"].(map[string]any)
	}
	if len(defs) == 0 {
		t.Fatal("the schema has no definitions — this gate would check nothing (D328)")
	}

	checked := 0
	for _, w := range want {
		def, _ := defs[w.def].(map[string]any)
		props, _ := def["properties"].(map[string]any)
		field, _ := props[w.field].(map[string]any)
		rawEnum, _ := field["enum"].([]any)
		if len(rawEnum) == 0 {
			t.Errorf("%s.%s publishes no enum — the field is a free string to anyone "+
				"reading the schema", w.def, w.field)
			continue
		}
		checked++
		got := make([]string, 0, len(rawEnum))
		for _, v := range rawEnum {
			s, _ := v.(string)
			got = append(got, s)
		}
		if !reflect.DeepEqual(got, w.set) {
			t.Errorf("%s.%s publishes %v; the runtime emits %v — a consumer generating "+
				"types from this schema gets values that never arrive, or misses ones "+
				"that do", w.def, w.field, got, w.set)
		}
	}
	if checked != len(want) {
		t.Fatalf("checked %d of %d published enums — the lookup broke and this gate "+
			"would pass over a drifted schema (D328)", checked, len(want))
	}
}
