package gcp

import "testing"

// D1228, the GCP half. classifyGCPRole reads substrings of the role id ("admin", a
// viewer/reader suffix). Those are names GOOGLE chose for its predefined roles. A
// CUSTOM role's id ends in whatever its author typed, so
// `projects/p/roles/companyViewer` took the least-privilege branch and reported
// access.privileged=false over a role that can carry any permission in the project.
//
// A name only its author picked is not evidence about the permissions behind it.

func TestCustomRoleIsNeverClassifiedFromItsName(t *testing.T) {
	for _, role := range []string{
		"projects/acme-prod/roles/companyViewer",
		"projects/acme-prod/roles/auditReader",
		"organizations/123456789012/roles/breakGlassViewer",
		"projects/acme-prod/roles/legacyadminShim", // would have read as PRIVILEGED
		"projects/acme-prod/roles/objectviewerCompat",
	} {
		priv, known := classifyGCPRole(role)
		if known {
			t.Fatalf("%s is a CUSTOM role — its id was chosen by its author, so privilege "+
				"must be unknown, got privileged=%v", role, priv)
		}
	}
}

// The heuristic must still work where Google chose the name, or the fix has simply
// stopped classifying anything.
func TestPredefinedRoleIsStillClassifiedFromItsName(t *testing.T) {
	for role, wantPriv := range map[string]bool{
		"roles/owner":                true,
		"roles/editor":               true,
		"roles/viewer":               false,
		"roles/storage.admin":        true,
		"roles/storage.objectViewer": false,
	} {
		priv, known := classifyGCPRole(role)
		if !known {
			t.Fatalf("%s is predefined and matches the curated heuristic — it must stay classified", role)
		}
		if priv != wantPriv {
			t.Fatalf("%s: privileged=%v, want %v", role, priv, wantPriv)
		}
	}
}

// End to end: the binding observe must withhold rather than emit a least-privilege
// claim it derived from an author's chosen word.
func TestObserveWithholdsPrivilegeForACustomNamedViewerRole(t *testing.T) {
	const role = "projects/acme-prod/roles/companyViewer"
	srv := crmPolicyServer(t, `{"bindings":[{"role":"`+role+`","members":[`+
		`"serviceAccount:runner@acme-prod.iam.gserviceaccount.com"]}],"etag":"BwXseed"}`)
	defer srv.Close()
	d := authzDriver(t, srv)
	obs, diags, err := d.observeIAMBinding("grant",
		"gauth:acme-prod:"+role+":serviceAccount:runner@acme-prod.iam.gserviceaccount.com")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "access.privileged" {
			t.Fatalf("a custom-named role must not yield a measured least-privilege claim, got %v", o.Value)
		}
	}
	if len(diags) == 0 {
		t.Fatalf("withholding access.privileged must be diagnosed")
	}
}
