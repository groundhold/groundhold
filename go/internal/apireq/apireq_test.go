package apireq

import "testing"

// TestRegistryIntegrity enforces the shape rules that keep the catalog honest:
// closed provider set, no empty fields, unique GuardIDs, and a SinceDate/SourceURL
// on every entry (a requirement without a "when" and a "where" is folklore, not a
// catalogued fact).
func TestRegistryIntegrity(t *testing.T) {
	valid := map[string]bool{"aws": true, "gcp": true, "azure": true}
	seen := map[string]bool{}
	for _, r := range All() {
		if !valid[r.Provider] {
			t.Errorf("%s: provider %q outside the closed set aws|gcp|azure", r.GuardID, r.Provider)
		}
		if r.Service == "" || r.Operation == "" || r.Requirement == "" {
			t.Errorf("%s: service/operation/requirement must all be set", r.GuardID)
		}
		if r.SinceDate == "" {
			t.Errorf("%s: SinceDate must record when we learned the requirement", r.GuardID)
		}
		if len(r.SourceURL) == 0 {
			t.Errorf("%s: at least one SourceURL is required — no unsourced folklore", r.GuardID)
		}
		if r.GuardID == "" {
			t.Errorf("%s/%s: GuardID must be set (the guard keys off it)", r.Provider, r.Service)
		}
		if seen[r.GuardID] {
			t.Errorf("duplicate GuardID %q", r.GuardID)
		}
		seen[r.GuardID] = true
	}
}

// TestFirstEntryPresent pins the seed (D329): the AWS CloudFront-OAC dual-invoke
// requirement is present and correctly shaped. Its behavioural binding lives in
// the driver package (internal/aws/apireq_guard_test.go).
func TestFirstEntryPresent(t *testing.T) {
	r, ok := Get(GuardCloudFrontOACDualInvoke)
	if !ok {
		t.Fatalf("first entry %q missing", GuardCloudFrontOACDualInvoke)
	}
	if r.Provider != "aws" || r.Service != "lambda" {
		t.Fatalf("first entry mis-shaped: %+v", r)
	}
	if r.SinceDate != "2025-10" {
		t.Errorf("SinceDate = %q, want 2025-10", r.SinceDate)
	}
	if len(r.SourceURL) < 2 {
		t.Errorf("first entry should cite both known sources, got %v", r.SourceURL)
	}
}

// TestCanaryTargetsIsCatalog: the canary accessor exposes the whole catalog so a
// future functional canary iterates requirements as DATA (API-drift #3a).
func TestCanaryTargetsIsCatalog(t *testing.T) {
	if len(CanaryTargets()) != len(All()) {
		t.Fatalf("CanaryTargets (%d) must equal the full catalog (%d)", len(CanaryTargets()), len(All()))
	}
}
