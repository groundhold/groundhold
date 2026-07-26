package apply

import (
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/provider"
)

// D80: an action on an EXISTING resource (pinned targetProviderId) is checked
// against the resource surface (authoritative); a create against the project
// surface. Both denials aggregate.
func TestScopedPreflightResourceAndProject(t *testing.T) {
	fake := &provider.Fake{
		// authoritative resource-level denial for the delete's pre-read
		ResourceDenied: map[string]bool{"storage.buckets.get": true},
		// project-level denial for the create
		MissingPermissions: map[string]bool{"storage.buckets.create": true},
	}
	actions := []any{
		map[string]any{"operation": "create", "target": "gcp.gcs/new", "capability": "new"},
		map[string]any{"operation": "delete", "target": "gcp.gcs/old",
			"capability": "old", "targetProviderId": "gcs:p:b"},
	}
	denied, unatt, err := scopedPreflight(fake, fake, "proj", actions, "gcp", nil, &contract.Candidate{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(unatt) != 0 {
		t.Fatalf("no unattested expected, got %v", unatt)
	}
	got := map[string]bool{}
	for _, d := range denied {
		got[d] = true
	}
	if !got["storage.buckets.create"] {
		t.Errorf("project-level create denial missing: %v", denied)
	}
	if !got["storage.buckets.get"] {
		t.Errorf("authoritative resource-level delete denial missing: %v", denied)
	}
}

// A service with no resource surface (Cloud SQL) falls back to the project
// check, where its permissions are CRM-attested and a negative is authoritative.
func TestScopedPreflightNoSurfaceFallsBackToProject(t *testing.T) {
	fake := &provider.Fake{
		NoResourceSurface:  map[string]bool{"cloudsql": true},
		MissingPermissions: map[string]bool{"cloudsql.instances.delete": true},
	}
	actions := []any{
		map[string]any{"operation": "delete", "target": "gcp.cloudsql/db",
			"capability": "db", "targetProviderId": "p:region:db-1"},
	}
	denied, _, err := scopedPreflight(fake, fake, "proj", actions, "gcp", nil, &contract.Candidate{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range denied {
		if d == "cloudsql.instances.delete" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no-surface service must fall back to project denial, got %v", denied)
	}
}

// A resource surface that cannot be read makes those permissions INCONCLUSIVE
// (unattested), never denied — the resource may be gone (drift), not forbidden.
func TestScopedPreflightUnreadableResourceIsUnattested(t *testing.T) {
	fake := &provider.Fake{ResourcePreflightErr: true}
	actions := []any{
		map[string]any{"operation": "delete", "target": "gcp.gcs/old",
			"capability": "old", "targetProviderId": "gcs:p:b"},
	}
	denied, unatt, err := scopedPreflight(fake, fake, "proj", actions, "gcp", nil, &contract.Candidate{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(denied) != 0 {
		t.Fatalf("an unreadable resource must never be a denial, got %v", denied)
	}
	if len(unatt) == 0 {
		t.Fatal("an unreadable resource surface must be inconclusive (unattested)")
	}
}
