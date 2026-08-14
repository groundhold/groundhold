package adoptcheck

import (
	"strings"
	"testing"

	"groundhold/internal/provider"
)

func measured(path string, v any) provider.Observation {
	return provider.Observation{Path: path, Value: v, Derivation: "measured"}
}

// the two DynamoDB controls, used across the cases: CMEK immutable, deletion
// protection mutable with a wired in-place update.
var ddbControls = []Control{
	{Path: "encryption.customerManagedKeys", Direction: SecureTrue, ImmutableAtCreate: true},
	{Path: "deletion.protection", Direction: SecureTrue, UpdateWired: true},
}

func TestCompareImmutableMissingIsFailed(t *testing.T) {
	// declared CMEK, live resource not customer-key encrypted → dangerous, immutable → failed.
	v := Compare(
		map[string]any{"encryption.customerManagedKeys": true},
		[]provider.Observation{measured("encryption.customerManagedKeys", false)},
		ddbControls)
	if v.Status != "failed" {
		t.Fatalf("immutable control missing must be failed, got %+v", v)
	}
	if len(v.Missing) != 1 || v.Missing[0] != "encryption.customerManagedKeys" {
		t.Fatalf("missing = %v, want the cmek path", v.Missing)
	}
}

func TestCompareMutableWiredMissingIsUnknown(t *testing.T) {
	// declared deletion protection, live off → dangerous, mutable+wired → unknown (converge fixes).
	v := Compare(
		map[string]any{"deletion.protection": true},
		[]provider.Observation{measured("deletion.protection", false)},
		ddbControls)
	if v.Status != "unknown" {
		t.Fatalf("mutable+wired missing must be unknown, got %+v", v)
	}
	if len(v.Missing) != 1 || v.Missing[0] != "deletion.protection" {
		t.Fatalf("missing = %v", v.Missing)
	}
}

func TestCompareMutableUnwiredMissingIsFailed(t *testing.T) {
	ctrl := []Control{{Path: "retention.minimum", Direction: Floor}} // no UpdateWired
	v := Compare(
		map[string]any{"retention.minimum": 30},
		[]provider.Observation{measured("retention.minimum", 7)},
		ctrl)
	if v.Status != "failed" {
		t.Fatalf("mutable but unwired missing must be failed (no path to repair), got %+v", v)
	}
}

func TestCompareSatisfiedIsClean(t *testing.T) {
	v := Compare(
		map[string]any{"encryption.customerManagedKeys": true, "deletion.protection": true},
		[]provider.Observation{
			measured("encryption.customerManagedKeys", true),
			measured("deletion.protection", true),
		}, ddbControls)
	if v.Status != "clean" {
		t.Fatalf("every control satisfied must be clean, got %+v", v)
	}
}

func TestCompareSafeDirectionAdoptsClean(t *testing.T) {
	// declared FALSE for a SecureTrue control (candidate does not require CMEK); the
	// live resource is MORE secure (CMEK on). Must adopt clean, never false-fail.
	v := Compare(
		map[string]any{"encryption.customerManagedKeys": false},
		[]provider.Observation{measured("encryption.customerManagedKeys", true)},
		ddbControls)
	if v.Status != "clean" {
		t.Fatalf("a resource more secure than declared must adopt clean, got %+v", v)
	}
}

func TestCompareSecureFalsePublicExposure(t *testing.T) {
	ctrl := []Control{{Path: "network.publicExposure", Direction: SecureFalse, UpdateWired: true}}
	// declared private (false), live public (true) → dangerous.
	v := Compare(
		map[string]any{"network.publicExposure": false},
		[]provider.Observation{measured("network.publicExposure", true)},
		ctrl)
	if v.Status != "unknown" || len(v.Missing) != 1 {
		t.Fatalf("declared-private over a public resource must flag, got %+v", v)
	}
	// declared allows public (true) → nothing required, clean even over a public resource.
	v2 := Compare(
		map[string]any{"network.publicExposure": true},
		[]provider.Observation{measured("network.publicExposure", true)},
		ctrl)
	if v2.Status != "clean" {
		t.Fatalf("a candidate that allows public exposure has nothing to check, got %+v", v2)
	}
}

func TestCompareFloorSatisfied(t *testing.T) {
	ctrl := []Control{{Path: "retention.minimum", Direction: Floor, UpdateWired: true}}
	// live retention EXCEEDS the declared floor → safe direction, clean.
	v := Compare(
		map[string]any{"retention.minimum": 7},
		[]provider.Observation{measured("retention.minimum", 30)},
		ctrl)
	if v.Status != "clean" {
		t.Fatalf("live retention above the declared floor must be clean, got %+v", v)
	}
}

func TestCompareUnmeasuredIsUnverifiable(t *testing.T) {
	// the observation is config-intent, not measured — it proves nothing about the
	// live resource's own setting, so the declared control is unverifiable → unknown.
	v := Compare(
		map[string]any{"encryption.customerManagedKeys": true},
		[]provider.Observation{{Path: "encryption.customerManagedKeys", Value: true, Derivation: "config-intent"}},
		ddbControls)
	if v.Status != "unknown" || len(v.Unverifiable) != 1 {
		t.Fatalf("a non-measured observation must be unverifiable (fail-closed), got %+v", v)
	}
	if len(v.Missing) != 0 {
		t.Fatalf("unverifiable is not a confirmed miss, got %+v", v)
	}
}

func TestCompareAbsentObservationIsUnverifiable(t *testing.T) {
	v := Compare(
		map[string]any{"deletion.protection": true},
		nil, // observe emitted nothing for the path
		ddbControls)
	if v.Status != "unknown" || len(v.Unverifiable) != 1 {
		t.Fatalf("an unobserved declared control must be unverifiable, got %+v", v)
	}
}

func TestCompareKindMismatchIsUnverifiable(t *testing.T) {
	// declared bool, measured a string → incomparable, never a silent pass or false miss.
	v := Compare(
		map[string]any{"encryption.customerManagedKeys": true},
		[]provider.Observation{measured("encryption.customerManagedKeys", "yes")},
		ddbControls)
	if v.Status != "unknown" || len(v.Unverifiable) != 1 {
		t.Fatalf("a kind mismatch must be unverifiable (no coercion), got %+v", v)
	}
}

func TestComparePrecedenceImmutableDominates(t *testing.T) {
	// one immutable control missing AND one mutable-wired missing → failed dominates.
	v := Compare(
		map[string]any{"encryption.customerManagedKeys": true, "deletion.protection": true},
		[]provider.Observation{
			measured("encryption.customerManagedKeys", false),
			measured("deletion.protection", false),
		}, ddbControls)
	if v.Status != "failed" {
		t.Fatalf("an immutable miss must dominate a mutable one, got %+v", v)
	}
}

func TestCompareNoDeclaredControlsIsClean(t *testing.T) {
	// the candidate declares none of the adopt-critical controls → nothing to lie about.
	v := Compare(map[string]any{"location.region": "eu"}, nil, ddbControls)
	if v.Status != "clean" {
		t.Fatalf("no declared adopt-critical control must be clean, got %+v", v)
	}
}

func TestCompareSetUnordered(t *testing.T) {
	ctrl := []Control{{Path: "trust.principals", Direction: Set}} // immutable/unwired → failed on miss
	// same set, different order → clean (order must not cause a false mismatch).
	if v := Compare(
		map[string]any{"trust.principals": []any{"a", "b"}},
		[]provider.Observation{measured("trust.principals", []string{"b", "a"})},
		ctrl); v.Status != "clean" {
		t.Fatalf("same set different order must be clean, got %+v", v)
	}
	// broader live set (extra principal can assume) → dangerous → failed.
	if v := Compare(
		map[string]any{"trust.principals": []any{"a", "b"}},
		[]provider.Observation{measured("trust.principals", []string{"a", "b", "c"})},
		ctrl); v.Status != "failed" {
		t.Fatalf("a broader trust set must fail, got %+v", v)
	}
	// narrower live set (declared principal missing) → also a mismatch → failed.
	if v := Compare(
		map[string]any{"trust.principals": []any{"a", "b"}},
		[]provider.Observation{measured("trust.principals", []string{"a"})},
		ctrl); v.Status != "failed" {
		t.Fatalf("a narrower trust set must fail, got %+v", v)
	}
	// a non-list observation is unverifiable, never a silent pass.
	if v := Compare(
		map[string]any{"trust.principals": []any{"a"}},
		[]provider.Observation{measured("trust.principals", "a")},
		ctrl); v.Status != "unknown" || len(v.Unverifiable) != 1 {
		t.Fatalf("a non-list measured value must be unverifiable, got %+v", v)
	}
}

func TestCompareCeilingDuration(t *testing.T) {
	ctrl := []Control{{Path: "rotation.period", Direction: Ceiling}} // unwired → failed on miss
	// live rotation SHORTER than declared → more secure → clean.
	if v := Compare(
		map[string]any{"rotation.period": "90d"},
		[]provider.Observation{measured("rotation.period", "30d")},
		ctrl); v.Status != "clean" {
		t.Fatalf("a shorter rotation than declared must be clean, got %+v", v)
	}
	// equal → clean (lte includes equality).
	if v := Compare(
		map[string]any{"rotation.period": "90d"},
		[]provider.Observation{measured("rotation.period", "90d")},
		ctrl); v.Status != "clean" {
		t.Fatalf("an equal rotation must be clean, got %+v", v)
	}
	// mixed units, equal magnitude (365d == 8760h, the legacy default) → clean.
	if v := Compare(
		map[string]any{"rotation.period": "8760h"},
		[]provider.Observation{measured("rotation.period", "365d")},
		ctrl); v.Status != "clean" {
		t.Fatalf("365d must satisfy an 8760h ceiling (unit normalisation), got %+v", v)
	}
	// live rotation LONGER than declared → dangerous → failed (unwired).
	if v := Compare(
		map[string]any{"rotation.period": "90d"},
		[]provider.Observation{measured("rotation.period", "365d")},
		ctrl); v.Status != "failed" {
		t.Fatalf("a longer rotation than declared must fail, got %+v", v)
	}
	// a non-duration measured value is unverifiable, never a silent pass.
	if v := Compare(
		map[string]any{"rotation.period": "90d"},
		[]provider.Observation{measured("rotation.period", "yes")},
		ctrl); v.Status != "unknown" || len(v.Unverifiable) != 1 {
		t.Fatalf("a non-duration measured value must be unverifiable, got %+v", v)
	}
}

func TestCompareReasonNamesThePaths(t *testing.T) {
	v := Compare(
		map[string]any{"encryption.customerManagedKeys": true},
		[]provider.Observation{measured("encryption.customerManagedKeys", false)},
		ddbControls)
	if !strings.Contains(v.Reason, "encryption.customerManagedKeys") {
		t.Fatalf("the reason must name the missing control, got %q", v.Reason)
	}
}
