package main

import (
	"sort"
	"testing"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
	"groundhold/internal/provider"
)

// D1175. The permission preflight refuses before mutating (D75), and it can only
// refuse over a NON-EMPTY required set: `apply` reaches the check through
// `if needed := requiredUnion(...); len(needed) > 0`. An empty set is not a pass and
// is not a denial — it is nothing happening, and until D1175 it happened silently,
// with `--require-preflight` returning success having verified nothing.
//
// The route to an empty set is the most ordinary one in this repository: add a service
// to a driver, forget its `PermissionsFor` case, and the switch falls through to
// `return nil`. Nothing anywhere held the map to the drivers' own service lists —
// measured when this was written: 145 services across three clouds, every one
// declaring, and held by care alone.
//
// `create` and `delete` are asserted rather than every operation on purpose. Those two
// are universal: a service this project can create it can also destroy, so a missing
// declaration is a gap and never a design choice. `update` is not universal — several
// services have no in-place update wired (`gcp/update.go` answers "in-place update is
// not wired yet" for nine of them) — and asserting it would enshrine declarations that
// may be describing an operation the driver refuses. That distinction is D1174's
// lesson: do not gate a set into place without asking whether it is right.
func TestEveryServedServiceDeclaresPermissions(t *testing.T) {
	type cloud struct {
		name string
		svcs map[string]string
	}
	clouds := []cloud{
		{"gcp", (&gcp.Driver{}).ServiceCapabilities()},
		{"aws", (&aws.Driver{}).ServiceCapabilities()},
		{"azure", (&azure.Driver{}).ServiceCapabilities()},
	}

	// The providers deliberately NOT swept, named here rather than left to be noticed.
	// `PermissionsFor` has no case for any of them and that is not an oversight: none
	// has an IAM permission model this preflight can ask about — k8s authorizes through
	// RBAC against the acting kubeconfig, and the other three through API tokens whose
	// scope is not enumerable. Their applies therefore reach the EMPTY-required-set
	// path, which is the path D1175 made loud: they now record `skipped` with a reason
	// and refuse under `--require-preflight`, instead of passing in silence.
	//
	// This list exists so the omission is a decision. If one of them grows a
	// permission model, delete its line and it joins the sweep above.
	noPermissionModel := map[string]string{
		"k8s":        "RBAC against the acting kubeconfig, not an IAM permission set",
		"upstash":    "API token; scope is not enumerable",
		"hetzner":    "API token; scope is not enumerable",
		"cloudflare": "API token; scope is not enumerable",
	}
	for name := range noPermissionModel {
		if len(provider.PermissionsFor(name, "any-service", "create", nil)) > 0 {
			t.Errorf("%s is listed as having no permission model, but PermissionsFor "+
				"answers for it — either it grew one (remove the line, and it joins "+
				"the sweep) or the list has drifted from the code", name)
		}
	}

	total := 0
	for _, c := range clouds {
		if len(c.svcs) == 0 {
			t.Fatalf("%s serves ZERO services — the scan lost its subject and this "+
				"gate would pass over anything (D328)", c.name)
		}
		total += len(c.svcs)

		names := make([]string, 0, len(c.svcs))
		for s := range c.svcs {
			names = append(names, s)
		}
		sort.Strings(names)

		for _, svc := range names {
			for _, op := range []string{"create", "delete"} {
				if len(provider.PermissionsFor(c.name, svc, op, nil)) == 0 {
					t.Errorf("%s/%s declares NO permissions for %s. The preflight only "+
						"runs over a non-empty set, so a plan touching this service "+
						"alone skips the check entirely — and a run that verified "+
						"nothing must never read as one that verified everything.",
						c.name, svc, op)
				}
			}
		}
	}

	// The floor that makes the sweep mean something: the three drivers between them
	// serve a known order of magnitude, and a registry that quietly shrank to a
	// handful would otherwise pass this gate having checked a handful.
	if total < 100 {
		t.Errorf("the three drivers serve %d services between them; this project has "+
			"shipped well over a hundred. Either the registries shrank or this gate is "+
			"reading a fraction of them.", total)
	}
}
