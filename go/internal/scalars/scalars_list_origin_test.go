package scalars

import (
	"reflect"
	"testing"
)

// D376. The same fact must be the same value whatever produced it.
//
// A driver emits Go values: `[]string{"eu-central-1", "eu-west-1"}`. The
// conformance suite supplies the same fact as YAML, which decodes to
// `[]any{"eu-central-1", "eu-west-1"}`. If those two parsed to scalars that
// differed in any way, the identical observation would compare, canonicalize and
// HASH differently depending on where it came from — and a contract satisfied
// through one path would be violated through the other.
//
// This is the property the widening exists to preserve, so it is pinned directly
// rather than assumed from "both are lists".
func TestListsAreEqualWhicheverGoTypeProducedThem(t *testing.T) {
	fromDriver, err := Parse([]string{"eu-central-1", "eu-west-1"})
	if err != nil {
		t.Fatalf("a driver's []string was refused: %v", err)
	}
	fromYAML, err := Parse([]any{"eu-central-1", "eu-west-1"})
	if err != nil {
		t.Fatalf("YAML's []any was refused: %v", err)
	}
	if fromDriver.Kind != fromYAML.Kind {
		t.Errorf("kind differs: %v vs %v", fromDriver.Kind, fromYAML.Kind)
	}
	// Raw is what canonicalization and hashing see. It must be the SAME shape, or
	// one origin hashes differently from the other.
	if !reflect.DeepEqual(fromDriver.Raw, fromYAML.Raw) {
		t.Errorf("Raw differs by origin:\n  driver: %#v\n  yaml:   %#v",
			fromDriver.Raw, fromYAML.Raw)
	}
	if !reflect.DeepEqual(fromDriver.Value, fromYAML.Value) {
		t.Errorf("Value differs by origin:\n  driver: %#v\n  yaml:   %#v",
			fromDriver.Value, fromYAML.Value)
	}
}

// An empty list is the case a driver hits when it read the resource and found no
// entries — distinct from "unread", and it must not be refused.
func TestEmptyStringSliceParses(t *testing.T) {
	s, err := Parse([]string{})
	if err != nil {
		t.Fatalf("an empty []string was refused: %v", err)
	}
	if s.Kind != List {
		t.Errorf("kind = %v, want List", s.Kind)
	}
}
