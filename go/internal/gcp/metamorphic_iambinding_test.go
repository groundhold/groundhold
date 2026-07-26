package gcp

import (
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.authorization.grant on a GCP IAM binding. The stateful crmPolicyServer
// records the policy createIAMBinding writes and reflects it on observe; the test
// varies the ROLE and asserts observe reverse-maps the SAME role AND classifies its
// privilege honestly (a known privileged role -> true, a known read role -> false).
// A driver that granted the wrong role, or inverted the privilege classification,
// fails here with no fault injected.
func TestMetamorphicIAMBindingRoundTrip(t *testing.T) {
	cases := []struct {
		role       string
		privileged bool
	}{
		{"roles/storage.objectViewer", false},
		{"roles/owner", true},
	}
	for _, c := range cases {
		t.Run(c.role, func(t *testing.T) {
			srv := crmPolicyServer(t, "")
			defer srv.Close()
			d := authzDriver(t, srv)
			attrs := map[string]any{
				"grant.role":        c.role,
				"grant.principal":   "serviceAccount:runner@acme-prod.iam.gserviceaccount.com",
				"access.scope":      "account",
				"access.privileged": c.privileged,
				"service.managed":   true,
			}
			res := d.createIAMBinding("grantee", "prod", attrs, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeIAMBinding("grantee", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["grant.role"] != c.role {
				t.Errorf("role not reflected: %+v", got)
			}
			if got["access.privileged"] != c.privileged {
				t.Errorf("privilege %v not reflected/classified: %+v", c.privileged, got)
			}
		})
	}
}
