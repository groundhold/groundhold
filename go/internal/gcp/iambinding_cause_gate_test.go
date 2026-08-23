package gcp

import (
	"strings"
	"testing"
)

// D1225 established that a withheld `access.privileged` must not be explained by a
// cause nothing measured: the diagnostic called every unclassifiable role "custom",
// and in a real project 37 of 49 bindings hit that branch with ZERO custom roles.
//
// D1231 supersedes the mechanism those gates pinned — observe now reads the role
// DEFINITION instead of explaining why the id-pattern set missed. The value survives
// and is what these gates hold, alongside the new mechanism's own invariants.

func gcpBindingObserve(t *testing.T, role string) (map[string]any, string) {
	t.Helper()
	srv := crmPolicyServer(t, `{"bindings":[{"role":"`+role+`","members":[`+
		`"serviceAccount:runner@acme-prod.iam.gserviceaccount.com"]}],"etag":"BwXseed"}`)
	defer srv.Close()
	d := authzDriver(t, srv)
	o, diags, err := d.observeIAMBinding("grant",
		"gauth:acme-prod:"+role+":serviceAccount:runner@acme-prod.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("observe %s: %v", role, err)
	}
	obs := map[string]any{}
	for _, x := range o {
		obs[x.Path] = x.Value
	}
	for _, dg := range diags {
		if strings.HasPrefix(dg, "access.privileged") {
			return obs, dg
		}
	}
	return obs, ""
}

func withRolePerms(t *testing.T, perms string) {
	t.Helper()
	prev := gcpRoleFixturePerms
	gcpRoleFixturePerms = perms
	t.Cleanup(func() { gcpRoleFixturePerms = prev })
}

// The surviving D1225 value: a limit of OUR knowledge is attributed to us, never
// asserted as a property of the estate's role.
func TestWithheldPrivilegeBlamesGroundholdNotTheEstate(t *testing.T) {
	for _, role := range []string{
		"roles/iam.serviceAccountTokenCreator",       // predefined, outside the curated pattern set
		"projects/acme-prod/roles/bespokeOperator",   // genuinely custom
		"organizations/123456789012/roles/auditRead", // org-scoped custom
	} {
		obs, diag := gcpBindingObserve(t, role)
		if _, present := obs["access.privileged"]; present {
			t.Fatalf("%s: the fixture role includes no escalation permission, so privilege "+
				"must be withheld, got %v", role, obs["access.privileged"])
		}
		if !strings.Contains(diag, "groundhold's escalation") {
			t.Fatalf("%s: the limit must be attributed to groundhold's curated set: %q", role, diag)
		}
		if strings.Contains(strings.ToLower(diag), "is a custom role") {
			t.Fatalf("%s: a limit of our set must not be reported as a property of the "+
				"estate's role — it was false for 37 of 49 real bindings: %q", role, diag)
		}
	}
}

func TestWithheldPrivilegeDoesNotReadAsLeastPrivilege(t *testing.T) {
	_, diag := gcpBindingObserve(t, "projects/acme-prod/roles/bespokeOperator")
	if !strings.Contains(diag, "NOT proof of least privilege") {
		t.Fatalf("the diagnostic must say plainly that no match is not proof of least "+
			"privilege: %q", diag)
	}
}

// D1231 positive direction: a role whose definition CONTAINS escalation control is
// measured privileged, whatever its name suggests.
func TestPrivilegeIsMeasuredTrueFromTheRoleDefinition(t *testing.T) {
	for name, perms := range map[string]string{
		"a setIamPolicy permission": `"storage.buckets.setIamPolicy","storage.objects.get"`,
		"the iam. namespace":        `"iam.serviceAccounts.getAccessToken"`,
		"escalation in a long list": `"a.b.c","d.e.f","resourcemanager.projects.setIamPolicy"`,
	} {
		withRolePerms(t, perms)
		// a name that suggests read-only, to prove the DOCUMENT decides
		obs, _ := gcpBindingObserve(t, "projects/acme-prod/roles/companyViewer")
		if obs["access.privileged"] != true {
			t.Errorf("%s: must measure privileged=true from the definition, got %v",
				name, obs["access.privileged"])
		}
	}
}

// The withholding half, and the reason it is not `false`: the curated set misses real
// escalation paths, and this fixture contains one of them.
func TestNoEscalationPermissionWithholdsRatherThanClaimingLeastPrivilege(t *testing.T) {
	withRolePerms(t, `"storage.objects.get","cloudbuild.builds.create"`)
	obs, diag := gcpBindingObserve(t, "projects/acme-prod/roles/companyViewer")
	if v, present := obs["access.privileged"]; present {
		t.Fatalf("no match must WITHHOLD, not conclude %v — cloudbuild.builds.create in "+
			"this very fixture is an escalation path the curated set misses", v)
	}
	if diag == "" {
		t.Fatalf("withholding must be diagnosed")
	}
}

// One fetch per role per sweep, and a fresh sweep re-reads (the --at thesis).
func TestRoleDefinitionIsReadOncePerSweep(t *testing.T) {
	srv := crmPolicyServer(t, `{"bindings":[],"etag":"BwXseed"}`)
	defer srv.Close()
	d := authzDriver(t, srv)
	before := gcpRoleFixtureHits
	for i := 0; i < 3; i++ {
		if _, _, _ = d.bindingPrivilegeFromRole("projects/acme-prod/roles/x"); false {
			t.Fatal("unreachable")
		}
	}
	if got := gcpRoleFixtureHits - before; got != 1 {
		t.Fatalf("the same role definition must be fetched once per sweep, got %d", got)
	}
	d2 := authzDriver(t, srv)
	_, _, _ = d2.bindingPrivilegeFromRole("projects/acme-prod/roles/x")
	if got := gcpRoleFixtureHits - before; got != 2 {
		t.Fatalf("a new sweep must re-read the definition, got %d total", got)
	}
}

// The discriminator D1225 built is still load-bearing (D1228 uses it to decide whether
// a NAME may be read as evidence), so it keeps its gate.
func TestGCPRoleIsPredefinedDiscriminates(t *testing.T) {
	for role, want := range map[string]bool{
		"roles/owner":                            true,
		"roles/iam.serviceAccountTokenCreator":   true,
		"projects/acme-prod/roles/bespoke":       false,
		"organizations/123456789012/roles/audit": false,
	} {
		if got := gcpRoleIsPredefined(role); got != want {
			t.Fatalf("gcpRoleIsPredefined(%q) = %v, want %v", role, got, want)
		}
	}
}
