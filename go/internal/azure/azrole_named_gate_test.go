package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// D1225. `grant.role` is defined by the vocabulary as the NAMED role — "the grant's
// semantic identity" — and the driver used to fall back to the raw role-definition
// GUID for anything outside its four-entry curated table. That is not a weaker
// answer, it is a DIFFERENT NAMESPACE: a hard constraint written in names
// (`not-in: [..., "Key Vault Administrator"]`) reads SATISFIED over an assignment
// that IS Key Vault Administrator, because a GUID matches no name in the list.
// Found on a real subscription, where the estate's one unclassified role was a
// first-party built-in that the driver both mis-named and mis-explained.
//
// These gates assert the PROPERTY, not the wording: an observed grant.role is never
// a bare GUID, and the privilege diagnostic never asserts a cause ARM contradicts.

// azRoleServerWithDefinition answers the assignment GET as the shared harness does,
// and answers the roleDefinitions GET with the supplied name/type. A defStatus other
// than 200 makes the definition unreadable, which is the withholding path.
func azRoleServerWithDefinition(t *testing.T, roleGUID, roleName, roleType string, defStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" && strings.Contains(r.URL.Path, "/roleDefinitions/") {
				if defStatus != http.StatusOK {
					w.WriteHeader(defStatus)
					return
				}
				_, _ = w.Write([]byte(`{"properties":{"roleName":"` + roleName +
					`","type":"` + roleType + `"}}`))
				return
			}
			switch r.Method {
			case "PUT":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"properties":{` +
					`"roleDefinitionId":"/subscriptions/` + testSub +
					`/providers/Microsoft.Authorization/roleDefinitions/` + roleGUID + `",` +
					`"principalId":"` + testPrincipal + `"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func azObserveRoleFixture(t *testing.T, roleGUID, roleName, roleType string, defStatus int) (map[string]any, []string) {
	t.Helper()
	srv := azRoleServerWithDefinition(t, roleGUID, roleName, roleType, defStatus)
	defer srv.Close()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	pid := azureRoleProviderID(testSub, azAssignmentGUID("/subscriptions/"+testSub, testPrincipal, roleGUID))
	obs, diags, err := d.observeAzureRole("grant", pid)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	return got, diags
}

// The false-green itself: a role outside the curated table must be observed by NAME,
// so that a name-based constraint has something to match.
func TestObserveAzureRoleReportsTheRoleNameNotItsGUID(t *testing.T) {
	const guid = "00482a5a-887f-4fb3-b363-3b7fe8e74483" // Key Vault Administrator
	got, _ := azObserveRoleFixture(t, guid, "Key Vault Administrator", "BuiltInRole", http.StatusOK)
	if got["grant.role"] != "Key Vault Administrator" {
		t.Fatalf("grant.role must be the NAMED role ARM reports, got %v", got["grant.role"])
	}
	// The property, independent of which role this is: never a bare GUID.
	for path, v := range got {
		if s, ok := v.(string); ok && azGUIDOK.MatchString(s) && path == "grant.role" {
			t.Fatalf("%s must never be a bare role-definition GUID (it silently satisfies "+
				"name-based constraints), got %q", path, s)
		}
	}
}

// If the definition cannot be read, the attribute is WITHHELD. Falling back to the
// GUID is the defect; falling back to nothing makes a name constraint unknown, and
// unknown on a hard constraint blocks.
func TestObserveAzureRoleWithholdsRoleWhenDefinitionUnreadable(t *testing.T) {
	const guid = "00482a5a-887f-4fb3-b363-3b7fe8e74483"
	got, diags := azObserveRoleFixture(t, guid, "", "", http.StatusForbidden)
	if _, present := got["grant.role"]; present {
		t.Fatalf("grant.role must be withheld when the role definition is unreadable, got %v", got["grant.role"])
	}
	if !azDiagMentions(diags, "grant.role not observed") {
		t.Fatalf("withholding grant.role must be diagnosed, got %v", diags)
	}
}

// A curated role still resolves without an ARM round trip, and still reports privilege.
func TestObserveAzureRoleCuratedRoleStillNamedAndClassified(t *testing.T) {
	const owner = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
	got, _ := azObserveRoleFixture(t, owner, "SHOULD-NOT-BE-ASKED", "BuiltInRole", http.StatusInternalServerError)
	if got["grant.role"] != "Owner" {
		t.Fatalf("a curated role must be named from the table, got %v", got["grant.role"])
	}
	if got["access.privileged"] != true {
		t.Fatalf("Owner must be classified privileged, got %v", got["access.privileged"])
	}
}

// The diagnostic must not blame the estate for groundhold's own gap: ARM said
// BuiltInRole, so the message must not call the role custom.
func TestObserveAzureRoleDiagnosticDoesNotCallABuiltInRoleCustom(t *testing.T) {
	const guid = "00482a5a-887f-4fb3-b363-3b7fe8e74483"
	_, diags := azObserveRoleFixture(t, guid, "Key Vault Administrator", "BuiltInRole", http.StatusOK)
	d := azDiagFor(t, diags, "access.privileged")
	if strings.Contains(strings.ToLower(d), "custom") {
		t.Fatalf("ARM reported BuiltInRole — the diagnostic must not call it custom: %q", d)
	}
	if !strings.Contains(strings.ToLower(d), "built-in") {
		t.Fatalf("the diagnostic must name the cause ARM reported: %q", d)
	}
}

// ...and when it really IS custom, it says so.
func TestObserveAzureRoleDiagnosticNamesAGenuineCustomRole(t *testing.T) {
	const guid = "00000000-0000-0000-0000-0000000000ab"
	_, diags := azObserveRoleFixture(t, guid, "Bespoke Operator", "CustomRole", http.StatusOK)
	d := azDiagFor(t, diags, "access.privileged")
	if !strings.Contains(strings.ToLower(d), "custom") {
		t.Fatalf("a CustomRole must be named as custom: %q", d)
	}
}

func azDiagMentions(diags []string, substr string) bool {
	for _, d := range diags {
		if strings.Contains(d, substr) {
			return true
		}
	}
	return false
}

func azDiagFor(t *testing.T, diags []string, subject string) string {
	t.Helper()
	for _, d := range diags {
		if strings.HasPrefix(d, subject) {
			return d
		}
	}
	t.Fatalf("no diagnostic for %s in %v", subject, diags)
	return ""
}
