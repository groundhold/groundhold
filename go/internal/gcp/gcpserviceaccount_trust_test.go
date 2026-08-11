package gcp

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// gsaPolicyServer serves the account read AND its IAM policy, which is what `observe` now
// touches (D868). The policy body is given verbatim so each case can say exactly what
// Google returned.
func gsaPolicyServer(t *testing.T, policy string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			if policy == "" {
				w.WriteHeader(403)
				return
			}
			_, _ = w.Write([]byte(policy))
		case r.Method == "GET":
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/serviceAccounts/x",` +
				`"email":"x@acme-prod.iam.gserviceaccount.com","displayName":"runner",` +
				`"description":"groundhold:capability=runner;environment=prod"}`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func gsaTrust(t *testing.T, policy string) ([]string, bool, []string) {
	t.Helper()
	srv := gsaPolicyServer(t, policy)
	defer srv.Close()
	d := gsaDriver(t, srv)
	obs, diags, err := d.observeGServiceAccount("runner", gsaProviderID("acme-prod", "runner-prod-86900a4d"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "trust.principals" {
			v, ok := o.Value.([]string)
			if !ok {
				t.Fatalf("trust.principals is %T, not a list of strings", o.Value)
			}
			return v, true, diags
		}
	}
	return nil, false, diags
}

// TestGSATrustPrincipalsCarryTheirRoleAndCondition is the GCP half of D868, and it is not
// the AWS half translated: on AWS the trust document names an ACTION, here the binding
// names a ROLE, and three different roles let a principal end up acting as this identity.
// The role rides with the principal for the same reason the condition does on AWS — a set
// of bare members would compare a token-minter equal to someone who may merely ATTACH the
// account to a VM they create.
func TestGSATrustPrincipalsCarryTheirRoleAndCondition(t *testing.T) {
	got, ok, _ := gsaTrust(t, `{"bindings":[
	  {"role":"roles/iam.workloadIdentityUser",
	   "members":["serviceAccount:acme-prod.svc.id.goog[apps/runner]"]},
	  {"role":"roles/iam.serviceAccountTokenCreator","members":["user:ops@acme.example"],
	   "condition":{"title":"business hours","expression":"request.time.getHours() < 18"}},
	  {"role":"roles/viewer","members":["user:auditor@acme.example"]}]}`)
	if !ok {
		t.Fatal("a well-formed policy produced no trust.principals")
	}
	want := []string{
		"serviceAccount:acme-prod.svc.id.goog[apps/runner] via roles/iam.workloadIdentityUser",
		"user:ops@acme.example via roles/iam.serviceAccountTokenCreator if request.time.getHours() < 18",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("trust.principals = %q, want %q — roles/viewer is not assumption, and the "+
			"condition is what bounds the grant", got, want)
	}
}

// TestGSATrustIncludesServiceAccountUser: the role an audit forgets. It mints no token, so
// it reads as harmless; what it grants is the right to ATTACH this account to a resource,
// and the resource then runs AS the account. For a trust attribute the safe direction is
// to over-report, and leaving it out would under-report who ends up acting as the identity.
func TestGSATrustIncludesServiceAccountUser(t *testing.T) {
	got, ok, _ := gsaTrust(t, `{"bindings":[{"role":"roles/iam.serviceAccountUser",
	  "members":["user:dev@acme.example"]}]}`)
	if !ok || len(got) != 1 || !strings.HasPrefix(got[0], "user:dev@acme.example via") {
		t.Fatalf("trust.principals = %q — serviceAccountUser lets a principal attach this "+
			"account to a resource that then runs as it, which is assumption by another door", got)
	}
}

// TestAnUnreadableGSAPolicyIsNotAnEmptyTrust is D847's discipline in the GCP attribute:
// a 403 on the policy read must not become "nobody may assume this account", which is the
// safest-looking answer there is and would be asserted with derivation "measured".
func TestAnUnreadableGSAPolicyIsNotAnEmptyTrust(t *testing.T) {
	got, ok, diags := gsaTrust(t, "")
	if ok {
		t.Fatalf("a 403 on getIamPolicy produced trust.principals = %q", got)
	}
	var told bool
	for _, d := range diags {
		if strings.Contains(d, "trust.principals") {
			told = true
		}
	}
	if !told {
		t.Fatalf("the policy was unreadable and nothing said so: %q. Silence here is the "+
			"absence that reads as an answer (D847).", diags)
	}
}

// TestTheDiscoverySweepDoesNotReadEachAccountsPolicy pins the split. The sweep reuses the
// observe function, so the trust read would land once PER ACCOUNT in a crawl that already
// touches every account in the project — D141's pace budget spent on a question discovery
// does not ask. What it may not do is stay quiet about it.
func TestTheDiscoverySweepDoesNotReadEachAccountsPolicy(t *testing.T) {
	var policyReads int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			policyReads++
			_, _ = w.Write([]byte(`{"bindings":[]}`))
		case strings.HasSuffix(r.URL.Path, "/serviceAccounts"):
			_, _ = w.Write([]byte(`{"accounts":[{"name":"projects/acme-prod/serviceAccounts/app-runner",` +
				`"email":"app-runner@acme-prod.iam.gserviceaccount.com","displayName":"app runner",` +
				`"description":"groundhold:capability=app-runner;environment=prod"}]}`))
		default:
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/serviceAccounts/app-runner",` +
				`"email":"app-runner@acme-prod.iam.gserviceaccount.com","displayName":"app runner",` +
				`"description":"groundhold:capability=app-runner;environment=prod"}`))
		}
	}))
	defer srv.Close()
	d := gsaDriver(t, srv)

	found, diags, err := d.discoverServiceAccounts("europe-west1")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("the sweep found nothing — this test would then pass over an empty subject (D328)")
	}
	if policyReads != 0 {
		t.Fatalf("the sweep read %d IAM policies; discovery must not double its calls per "+
			"account (D141)", policyReads)
	}
	for _, f := range found {
		for _, o := range f.Observations {
			if o.Path == "trust.principals" {
				t.Fatalf("the sweep reported trust.principals=%v without reading a policy", o.Value)
			}
		}
	}
	var told bool
	for _, d := range diags {
		if strings.Contains(d, "trust.principals") {
			told = true
		}
	}
	if !told {
		t.Fatalf("the sweep skipped the trust read and said nothing: %q. An absent "+
			"trust.principals would then read as an empty one.", diags)
	}
}
