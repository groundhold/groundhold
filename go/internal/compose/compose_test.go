package compose

import (
	"reflect"
	"testing"
)

func base() map[string]any {
	return map[string]any{
		"apiVersion": "contract/v0.1",
		"kind":       "InfrastructureContract",
		"meta":       map[string]any{"id": "svc", "environment": "dev", "version": 1},
		"capabilities": []any{
			map[string]any{"id": "db", "type": "capability.database.relational"},
		},
		"constraints": map[string]any{
			"hard": []any{
				map[string]any{"id": "eu", "subject": "db", "path": "location.region", "op": "equals", "value": "eu-central-1"},
				map[string]any{"id": "atrest", "subject": "db", "path": "encryption.atRest", "op": "equals", "value": true},
			},
		},
	}
}

func hardList(doc map[string]any) []any {
	return doc["constraints"].(map[string]any)["hard"].([]any)
}

func TestMergeUnionsNewConstraintByID(t *testing.T) {
	ov := map[string]any{
		"meta": map[string]any{"environment": "prod"},
		"constraints": map[string]any{
			"hard": []any{
				map[string]any{"id": "cmek", "subject": "db", "path": "encryption.customerManagedKeys", "op": "equals", "value": true},
			},
		},
	}
	out, err := Merge(base(), ov)
	if err != nil {
		t.Fatal(err)
	}
	if got := out["meta"].(map[string]any)["environment"]; got != "prod" {
		t.Errorf("meta.environment: got %v, want prod", got)
	}
	// base id preserved from meta override
	if got := out["meta"].(map[string]any)["id"]; got != "svc" {
		t.Errorf("meta.id should survive overlay: got %v", got)
	}
	ids := []string{}
	for _, it := range hardList(out) {
		ids = append(ids, it.(map[string]any)["id"].(string))
	}
	// sorted by id: atrest, cmek, eu
	if !reflect.DeepEqual(ids, []string{"atrest", "cmek", "eu"}) {
		t.Errorf("hard ids: got %v, want [atrest cmek eu]", ids)
	}
}

func TestMergeOverridesConstraintByID(t *testing.T) {
	ov := map[string]any{
		"constraints": map[string]any{
			"hard": []any{
				map[string]any{"id": "eu", "subject": "db", "path": "location.region", "op": "in", "value": []any{"eu-central-1", "eu-west-1"}},
			},
		},
	}
	out, err := Merge(base(), ov)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(hardList(out)); n != 2 {
		t.Fatalf("override must not add a row: got %d hard constraints", n)
	}
	for _, it := range hardList(out) {
		m := it.(map[string]any)
		if m["id"] == "eu" && m["op"] != "in" {
			t.Errorf("overlay did not override constraint eu: op=%v", m["op"])
		}
	}
}

func TestMergeDeterministicRegardlessOfInputOrder(t *testing.T) {
	ov1 := map[string]any{"constraints": map[string]any{"hard": []any{
		map[string]any{"id": "zzz", "subject": "db", "path": "p.z", "op": "equals", "value": 1},
		map[string]any{"id": "aaa", "subject": "db", "path": "p.a", "op": "equals", "value": 1},
	}}}
	a, _ := Merge(base(), ov1)
	b, _ := Merge(base(), ov1)
	if !reflect.DeepEqual(a, b) {
		t.Error("Merge is not deterministic for identical inputs")
	}
	ids := []string{}
	for _, it := range hardList(a) {
		ids = append(ids, it.(map[string]any)["id"].(string))
	}
	if !reflect.DeepEqual(ids, []string{"aaa", "atrest", "eu", "zzz"}) {
		t.Errorf("hard ids not sorted: %v", ids)
	}
}

func TestMergeUnionsCapabilities(t *testing.T) {
	ov := map[string]any{"capabilities": []any{
		map[string]any{"id": "cache", "type": "capability.cache.keyvalue"},
	}}
	out, _ := Merge(base(), ov)
	caps := out["capabilities"].([]any)
	if len(caps) != 2 {
		t.Fatalf("want 2 capabilities, got %d", len(caps))
	}
}

func TestMergeRejectsOverlayItemWithoutID(t *testing.T) {
	ov := map[string]any{"constraints": map[string]any{"hard": []any{
		map[string]any{"subject": "db", "path": "p.x", "op": "equals", "value": 1},
	}}}
	if _, err := Merge(base(), ov); err == nil {
		t.Error("expected error for overlay constraint without id")
	}
}

func TestDiffSubset(t *testing.T) {
	dev := base()
	prod, _ := Merge(base(), map[string]any{"constraints": map[string]any{"hard": []any{
		map[string]any{"id": "cmek", "subject": "db", "path": "encryption.customerManagedKeys", "op": "equals", "value": true},
	}}})
	d := Diff(dev, prod)
	if !d.ASubsetOfB {
		t.Errorf("dev ⊆ prod should hold: %+v", d)
	}
	if !reflect.DeepEqual(d.HardOnlyInB, []string{"cmek"}) {
		t.Errorf("prod-only should be [cmek]: %v", d.HardOnlyInB)
	}
	// prod is NOT a subset of dev (it is stricter)
	if Diff(prod, dev).ASubsetOfB {
		t.Error("prod should not be a subset of dev")
	}
}
