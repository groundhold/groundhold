package mapping

import (
	"reflect"
	"testing"
)

func TestParseFieldPath(t *testing.T) {
	cases := map[string][]string{
		`spec.hard["limits.cpu"]`: {"spec", "hard", "limits.cpu"},
		`metadata.labels["a/b"]`:  {"metadata", "labels", "a/b"},
		`spec.replicas`:           {"spec", "replicas"},
	}
	for p, want := range cases {
		got, err := ParseFieldPath(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s -> %v, want %v", p, got, want)
		}
	}
	for _, bad := range []string{`spec..x`, `spec.hard[limits]`, ``} {
		if _, err := ParseFieldPath(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestResolveAndSetField(t *testing.T) {
	obj := map[string]any{"spec": map[string]any{"hard": map[string]any{"limits.cpu": "10"}}}
	v, ok, err := ResolveField(obj, `spec.hard["limits.cpu"]`)
	if err != nil || !ok || v != "10" {
		t.Fatalf("resolve = %v %v %v", v, ok, err)
	}
	if _, ok, _ := ResolveField(obj, "spec.missing"); ok {
		t.Fatal("absent path must report not-present")
	}
	// SetField descends into existing maps rather than clobbering siblings.
	if err := SetField(obj, "spec.replicas", 3); err != nil {
		t.Fatal(err)
	}
	spec := obj["spec"].(map[string]any)
	if spec["replicas"] != 3 || spec["hard"] == nil {
		t.Fatalf("set clobbered a sibling: %v", spec)
	}
}
