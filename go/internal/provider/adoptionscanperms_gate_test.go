package provider_test

import (
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// TestCreateAdoptionScanPermissionsAreDeclared pins D1013.
//
// Several drivers scan for an EXISTING resource carrying our ownership tags before a
// create, because the provider assigns the id (no idempotency token) and a blind create
// on a lost ledger mints a DUPLICATE. That scan is a READ on the create path, and its
// permission must be declared on the CREATE arm — otherwise an identity that can create
// but cannot scan passes the preflight, the scan 403s and (by deliberate design, so a
// genuine first deploy is not blocked) falls OPEN to the create, and a duplicate lands
// reported succeeded. kms (findKMSKeyByTags -> ListResourceTags) and eks
// (ensureEKSNodeGroup -> ListNodegroups) both escaped this; the eks UPDATE arm already
// carried its list (D848), the create arms did not.
//
// The permission is unconditional on the scan, so it must be present for EVERY attribute
// shape — the test drives an empty attrs map, which is the shape a plain create seals.
func TestCreateAdoptionScanPermissionsAreDeclared(t *testing.T) {
	cases := []struct {
		service string
		perm    string
		scan    string
	}{
		{"kms", "kms:ListResourceTags", "findKMSKeyByTags reads each key's tags"},
		{"eks", "eks:ListNodegroups", "ensureEKSNodeGroup lists the cluster's node groups"},
	}
	for _, c := range cases {
		for _, op := range []string{"create", "adopt"} {
			perms := provider.PermissionsFor("aws", c.service, op, map[string]any{})
			found := false
			for _, p := range perms {
				if p == c.perm {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s %s: %s on the create path needs %s, but it is not declared "+
					"(preflight passes, the scan 403s and falls open to a duplicate create) — got %s",
					c.service, op, c.scan, c.perm, strings.Join(perms, ", "))
			}
		}
	}
}
