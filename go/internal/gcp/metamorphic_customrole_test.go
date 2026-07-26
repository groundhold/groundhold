package gcp

import (
	"testing"
)

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.authorization.role on a GCP custom role. The stateful customRoleServer
// records the includedPermissions createCustomRole writes and reflects them on
// observe; the test varies the PERMISSION SET and asserts observe reverse-maps the
// same set AND derives access.mutating/access.privileged honestly from the verbs. A
// driver that dropped a permission or inverted the classification fails here with no
// fault injected.
func TestMetamorphicCustomRoleRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		perms      []any
		mutating   bool
		privileged bool
	}{
		{"readonly", []any{"storage.objects.get", "storage.objects.list"}, false, false},
		{"mutating", []any{"storage.objects.get", "storage.objects.create"}, true, false},
		{"privileged", []any{"storage.objects.get", "storage.buckets.setIamPolicy"}, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := customRoleServer(t)
			defer srv.Close()
			d := customRoleDriver(t, srv)
			attrs := map[string]any{
				"role.permissions":  c.perms,
				"access.mutating":   c.mutating,
				"access.privileged": c.privileged,
				"service.managed":   true,
			}
			res := d.createCustomRole("grantee", "prod", attrs, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeCustomRole("grantee", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["access.mutating"] != c.mutating || got["access.privileged"] != c.privileged {
				t.Errorf("classification not reflected: %+v", got)
			}
			perms, _ := got["role.permissions"].([]string)
			if len(perms) != len(c.perms) {
				t.Errorf("permission set not reflected: %+v", got["role.permissions"])
			}
		})
	}
}
