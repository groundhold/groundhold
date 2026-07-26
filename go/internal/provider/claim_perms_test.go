package provider

import (
	"sort"
	"testing"
)

// TestClaimPermissionsWired pins the D145 claim-breadth permission tables: a
// claimable service declares a non-empty, sorted, deduped claim footprint, and an
// honest-refuse service declares none (its claim never mutates, so there is
// nothing to preflight).
func TestClaimPermissionsWired(t *testing.T) {
	claimable := map[string][]string{
		"aws":   {"rds", "s3", "kms", "secretsmanager"},
		"gcp":   {"cloudsql", "gcs", "memorystore", "cloudrun"},
		"azure": {"flexpostgres", "blob", "cosmos", "keyvault"},
	}
	for prov, svcs := range claimable {
		for _, svc := range svcs {
			p := PermissionsFor(prov, svc, "claim", nil)
			if len(p) == 0 {
				t.Errorf("%s/%s must declare a claim permission footprint (D145)", prov, svc)
				continue
			}
			if !sort.StringsAreSorted(p) {
				t.Errorf("%s/%s claim perms not sorted: %v", prov, svc, p)
			}
			seen := map[string]bool{}
			for _, x := range p {
				if seen[x] {
					t.Errorf("%s/%s claim perms have a duplicate %q", prov, svc, x)
				}
				seen[x] = true
			}
		}
	}

	// honest-refuse services (marked by name/identity, not a tag/label) declare
	// no claim permissions — the claim refuses at the driver, never mutates.
	refuse := map[string]string{
		"aws":   "iam",
		"gcp":   "dashboard",
		"azure": "roleassignment",
	}
	for prov, svc := range refuse {
		if p := PermissionsFor(prov, svc, "claim", nil); len(p) != 0 {
			t.Errorf("%s/%s honest-refuses claim, so it must declare no claim perms, got %v", prov, svc, p)
		}
	}
}
