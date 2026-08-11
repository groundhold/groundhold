package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

const testIssuer = "https://westeurope.oic.prod-aks.azure.com/tenant/abc123/"

func aksWIAttrs() map[string]any {
	return map[string]any{
		"workload.namespace":      "payments",
		"workload.serviceAccount": "worker",
		"service.managed":         true,
	}
}

func aksWIImpl() map[string]any {
	return map[string]any{
		"resource_group": "rg1",
		"uamiName":       "id-runner",
		"oidcIssuer":     testIssuer,
	}
}

func TestBuildAKSWorkloadIdentityHonors(t *testing.T) {
	p, err := BuildAKSWorkloadIdentity(testSub, "prod", "runner", aksWIAttrs(), aksWIImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Namespace != "payments" || p.ServiceAccount != "worker" {
		t.Fatalf("identity = %+v", p)
	}
	if p.Subject() != "system:serviceaccount:payments:worker" {
		t.Fatalf("subject = %q", p.Subject())
	}
	if p.UAMIName != "id-runner" || p.ResourceGroup != "rg1" || p.OIDCIssuer != testIssuer {
		t.Fatalf("operands = %+v", p)
	}
	if !azNameOK.MatchString(p.CredentialName) || !strings.HasPrefix(p.CredentialName, "fic-runner-prod-") {
		t.Fatalf("credential name = %q", p.CredentialName)
	}
}

func TestBuildAKSWorkloadIdentityResourceIDForm(t *testing.T) {
	impl := map[string]any{
		"uamiResourceId": "/subscriptions/" + testSub + "/resourceGroups/rg9/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-x",
		"oidcIssuer":     testIssuer,
	}
	p, err := BuildAKSWorkloadIdentity(testSub, "prod", "runner", aksWIAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Subscription != testSub || p.ResourceGroup != "rg9" || p.UAMIName != "id-x" {
		t.Fatalf("uamiResourceId not parsed: %+v", p)
	}
}

func TestBuildAKSWorkloadIdentityRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"unmanaged":       {map[string]any{"service.managed": false}, aksWIImpl()},
		"unknown-attr":    {map[string]any{"identity.tier": "x"}, aksWIImpl()},
		"no-namespace":    {map[string]any{"workload.namespace": ""}, aksWIImpl()},
		"bad-namespace":   {map[string]any{"workload.namespace": "Bad_NS"}, aksWIImpl()},
		"no-uami":         {nil, map[string]any{"resource_group": "rg1", "oidcIssuer": testIssuer}},
		"no-rg":           {nil, map[string]any{"uamiName": "id-runner", "oidcIssuer": testIssuer}},
		"no-issuer":       {nil, map[string]any{"resource_group": "rg1", "uamiName": "id-runner"}},
		"bad-issuer":      {nil, map[string]any{"resource_group": "rg1", "uamiName": "id-runner", "oidcIssuer": "http://insecure"}},
		"bad-resource-id": {nil, map[string]any{"uamiResourceId": "/subscriptions/x/foo", "oidcIssuer": testIssuer}},
	}
	for name, c := range cases {
		a := aksWIAttrs()
		for k, v := range c.attrs {
			a[k] = v
		}
		if _, err := BuildAKSWorkloadIdentity(testSub, "prod", "runner", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestClassifyAKSWorkloadIdentityChange(t *testing.T) {
	// D831: this pinned "immutable", which is right for the EKS and GKE twins — their
	// providerId encodes the namespace and service account, so a change addresses a
	// different resource. Here it does not: the credential name is derived from
	// capability+environment, and the subject is a property Azure updates with a PUT on the
	// same credential. The old expectation pinned replacing a binding that never moved.
	for _, path := range []string{"workload.namespace", "workload.serviceAccount"} {
		if verb, why := classifyAKSWorkloadIdentityChange(path); verb != "unsupported" || why == "" {
			t.Errorf("%s should be unsupported with a reason, got %q/%q", path, verb, why)
		}
	}
	if verb, _ := classifyAKSWorkloadIdentityChange("cost.monthly"); verb != "unsupported" {
		t.Errorf("cost.monthly should be unsupported, got %q", verb)
	}
}

func TestAKSWIProviderIDRoundTrip(t *testing.T) {
	pid := aksWIProviderID(testSub, "rg1", "id-runner", "fic-runner-prod-abcd1234")
	sub, rg, uami, name, err := splitAKSWIProviderID(pid)
	if err != nil {
		t.Fatal(err)
	}
	if sub != testSub || rg != "rg1" || uami != "id-runner" || name != "fic-runner-prod-abcd1234" {
		t.Fatalf("roundtrip lost data: %s %s %s %s", sub, rg, uami, name)
	}
	if _, _, _, _, err := splitAKSWIProviderID("uami:x:y:z"); err == nil {
		t.Error("a non-aks-wi pid must be rejected")
	}
}

// ficServer is a stateful fake: PUT records the properties, GET reflects them,
// DELETE clears. capOverrideSubject lets a test inject a foreign subject.
func ficServer(t *testing.T, subject string) *httptest.Server {
	t.Helper()
	stored := ""
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				b, _ := io.ReadAll(r.Body)
				var body struct {
					Properties struct {
						Subject string `json:"subject"`
					} `json:"properties"`
				}
				_ = json.Unmarshal(b, &body)
				stored = body.Properties.Subject
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"issuer":"` + testIssuer + `","subject":"` + stored + `","audiences":["` + aksWIAudience + `"]}}`))
			case "GET":
				sub := stored
				if sub == "" {
					sub = subject
				}
				if sub == "__none__" {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write([]byte(`{"properties":{"issuer":"` + testIssuer + `","subject":"` + sub + `","audiences":["` + aksWIAudience + `"]}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func aksWIDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	d.AKSLROTimeout = 2 * time.Second // keep AKS long-poll timeout paths fast (D264 class)
	return d
}

func TestCreateObserveDeleteAKSWorkloadIdentity(t *testing.T) {
	srv := ficServer(t, "__none__") // absent until PUT stores
	defer srv.Close()
	d := aksWIDriver(t, srv)

	res := d.createAKSWorkloadIdentity("prod", "runner", aksWIAttrs(), aksWIImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "aks-wi:"+testSub+":rg1:id-runner:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAKSWorkloadIdentity("runner", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["workload.namespace"] != "payments" || got["workload.serviceAccount"] != "worker" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteAKSWorkloadIdentity("runner", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestCreateAKSWorkloadIdentityForeignRefused(t *testing.T) {
	// The name exists but its subject belongs to a different serviceAccount.
	srv := ficServer(t, "system:serviceaccount:other:sa")
	defer srv.Close()
	d := aksWIDriver(t, srv)
	res := d.createAKSWorkloadIdentity("prod", "runner", aksWIAttrs(), aksWIImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign credential must refuse create, got %+v", res)
	}
}

func TestObserveAKSWorkloadIdentityNotFound(t *testing.T) {
	srv := ficServer(t, "__none__")
	defer srv.Close()
	d := aksWIDriver(t, srv)
	pid := aksWIProviderID(testSub, "rg1", "id-runner", "fic-runner-prod-abcd1234")
	obs, diags, err := d.observeAKSWorkloadIdentity("runner", pid)
	if err != nil {
		t.Fatal(err)
	}
	// Corrected with D518: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if len(diags) == 0 || !absentMarked(obs) {
		t.Fatalf("absent credential must report %s=true with a diag, got obs=%v diags=%v",
			provider.ResourceAbsentPath, obs, diags)
	}
}

// TestFicContentMatches pins the ownership-by-content proof (D29/D87): with no
// tag marker on a federated credential, matching subject+issuer+the fixed AAD
// audience IS the ownership proof. Each mismatch axis is checked independently.
func TestFicContentMatches(t *testing.T) {
	plan := AKSWorkloadIdentityPlan{
		Namespace: "payments", ServiceAccount: "worker", OIDCIssuer: testIssuer,
	}
	ok := ficDoc{}
	ok.Properties.Subject = plan.Subject()
	ok.Properties.Issuer = plan.OIDCIssuer
	ok.Properties.Audiences = []string{aksWIAudience}
	if !ficContentMatches(ok, plan) {
		t.Fatal("matching subject/issuer/audience must report a match")
	}

	wrongSubject := ok
	wrongSubject.Properties.Subject = "system:serviceaccount:other:sa"
	if ficContentMatches(wrongSubject, plan) {
		t.Fatal("a different subject must not match")
	}

	wrongIssuer := ok
	wrongIssuer.Properties.Issuer = "https://not-the-issuer.example.com/"
	if ficContentMatches(wrongIssuer, plan) {
		t.Fatal("a different issuer must not match")
	}

	noAudience := ok
	noAudience.Properties.Audiences = []string{"some-other-audience"}
	if ficContentMatches(noAudience, plan) {
		t.Fatal("a credential missing the fixed AAD audience must not match")
	}

	emptyAudiences := ok
	emptyAudiences.Properties.Audiences = nil
	if ficContentMatches(emptyAudiences, plan) {
		t.Fatal("a credential with no audiences must not match")
	}
}

// TestFicURLBoundsInputs pins the D73 injection-boundary validation ficURL adds
// on top of armURL: an invalid UAMI name or federated-credential name is refused
// before either is interpolated into the ARM path.
func TestFicURLBoundsInputs(t *testing.T) {
	d := NewDriver(testSub)
	if _, err := d.ficURL("rg1", "Bad UAMI Name!", "fic-1"); err == nil {
		t.Fatal("an invalid uami name must be refused")
	}
	if _, err := d.ficURL("rg1", "id-runner", "Bad Name!"); err == nil {
		t.Fatal("an invalid federated credential name must be refused")
	}
	url, err := d.ficURL("rg1", "id-runner", "fic-1")
	if err != nil {
		t.Fatalf("a valid pair must resolve: %v", err)
	}
	if !strings.Contains(url, "userAssignedIdentities/id-runner/federatedIdentityCredentials/fic-1") {
		t.Fatalf("url = %q", url)
	}
}

// TestCreateAKSWorkloadIdentitySubscriptionMismatch pins the D73 boundary on the
// create path: a uamiResourceId whose subscription differs from the driver's
// pinned one is refused before any request is made.
func TestCreateAKSWorkloadIdentitySubscriptionMismatch(t *testing.T) {
	d := NewDriver(testSub)
	other := "11111111-1111-1111-1111-111111111111"
	impl := map[string]any{
		"uamiResourceId": "/subscriptions/" + other + "/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-x",
		"oidcIssuer":     testIssuer,
	}
	res := d.createAKSWorkloadIdentity("prod", "runner", aksWIAttrs(), impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "is not the driver's") {
		t.Fatalf("a cross-subscription uamiResourceId must refuse, got %+v", res)
	}
}

// TestCreateAKSWorkloadIdentityPreReadErrorUnknown: a pre-create ownership read
// that gives no answer (here: no bearer token at all) is `unknown`, never a
// fabricated success or a failure that discards the deterministic providerId.
func TestCreateAKSWorkloadIdentityPreReadErrorUnknown(t *testing.T) {
	d := NewDriver(testSub)
	d.token = "" // doARM refuses immediately — stands in for a transport failure
	res := d.createAKSWorkloadIdentity("prod", "runner", aksWIAttrs(), aksWIImpl(), 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable pre-create check must be unknown, got %+v", res)
	}
}

// TestCreateAKSWorkloadIdentityPUTOutcomes pins the four-valued PUT handling
// (D237/D29): a 5xx is unknown WITH the pid (may have landed), a clean 4xx is a
// clear failed.
func TestCreateAKSWorkloadIdentityPUTOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		putStatus  int
		wantStatus string
	}{
		{"server-error-unknown", 503, "unknown"},
		{"bad-request-failed", 400, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case "GET":
					w.WriteHeader(404) // absent — proceed to PUT
				case "PUT":
					w.WriteHeader(tc.putStatus)
				default:
					w.WriteHeader(404)
				}
			}))
			defer srv.Close()
			d := aksWIDriver(t, srv)
			res := d.createAKSWorkloadIdentity("prod", "runner", aksWIAttrs(), aksWIImpl(), 1)
			if res.Status != tc.wantStatus {
				t.Fatalf("PUT %d: status = %q, want %q (%+v)", tc.putStatus, res.Status, tc.wantStatus, res)
			}
			if tc.wantStatus == "unknown" && res.ProviderID == "" {
				t.Fatalf("an unknown outcome must carry the deterministic providerId, got %+v", res)
			}
		})
	}
}

// TestDeleteAKSWorkloadIdentitySubscriptionMismatch: the delete path re-derives
// the subscription from the providerId and refuses one that does not match a
// pinned driver.
func TestDeleteAKSWorkloadIdentitySubscriptionMismatch(t *testing.T) {
	d := NewDriver(testSub)
	other := "11111111-1111-1111-1111-111111111111"
	pid := aksWIProviderID(other, "rg1", "id-runner", "fic-runner-prod-abcd1234")
	res := d.deleteAKSWorkloadIdentity("runner", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "is not the driver's") {
		t.Fatalf("a cross-subscription providerId must refuse delete, got %+v", res)
	}
}

// TestDeleteAKSWorkloadIdentityPreReadErrorUnknown mirrors the create-side
// pre-read honesty on delete.
func TestDeleteAKSWorkloadIdentityPreReadErrorUnknown(t *testing.T) {
	d := NewDriver(testSub)
	d.token = ""
	pid := aksWIProviderID(testSub, "rg1", "id-runner", "fic-runner-prod-abcd1234")
	res := d.deleteAKSWorkloadIdentity("runner", "prod", pid)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable pre-delete check must be unknown, got %+v", res)
	}
}

// TestDeleteAKSWorkloadIdentityNonServiceAccountSubjectRefused: a credential
// that exists under the deterministic name but whose subject is not a
// system:serviceaccount binding is not something this driver's naming scheme
// ever produced — refuse rather than delete a foreign use of the credential.
func TestDeleteAKSWorkloadIdentityNonServiceAccountSubjectRefused(t *testing.T) {
	srv := ficServer(t, "not-a-service-account-subject")
	defer srv.Close()
	d := aksWIDriver(t, srv)
	pid := aksWIProviderID(testSub, "rg1", "id-runner", "fic-runner-prod-abcd1234")
	res := d.deleteAKSWorkloadIdentity("runner", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a non-serviceaccount subject must refuse delete, got %+v", res)
	}
}

// TestDiscoverAKSWorkloadIdentityListErrors pins the diagnostic (never
// fabricated-absence) behavior when the top-level UAMI list itself fails.
func TestDiscoverAKSWorkloadIdentityListErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	d := aksWIDriver(t, srv)
	if _, _, err := d.discoverAKSWorkloadIdentity("westeurope"); err == nil {
		t.Fatal("a failed UAMI list must be a hard error, not a fabricated empty result")
	}
}

// TestDiscoverAKSWorkloadIdentitySkipsUnreadableCredentialList: a UAMI whose own
// federatedIdentityCredentials list fails is skipped with a diagnostic — the
// sweep still completes and still reports the other (readable) UAMIs.
func TestDiscoverAKSWorkloadIdentitySkipsUnreadableCredentialList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/federatedIdentityCredentials"):
			w.WriteHeader(500) // this UAMI's credential list is unreadable
		case strings.HasSuffix(r.URL.Path, "/userAssignedIdentities"):
			_, _ = w.Write([]byte(`{"value":[{"id":"/subscriptions/` + testSub +
				`/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-runner",` +
				`"name":"id-runner","location":"westeurope"}]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := aksWIDriver(t, srv)
	found, diags, err := d.discoverAKSWorkloadIdentity("westeurope")
	if err != nil {
		t.Fatalf("a per-UAMI list failure must not abort the whole sweep: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("expected no discovered credentials, got %+v", found)
	}
	if len(diags) == 0 {
		t.Fatal("an unreadable per-UAMI credential list must be diagnosed")
	}
}

func TestDiscoverAKSWorkloadIdentity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "/federatedIdentityCredentials/"):
				// single-credential GET (observe reverse map)
				_, _ = w.Write([]byte(`{"properties":{"issuer":"` + testIssuer +
					`","subject":"system:serviceaccount:payments:worker","audiences":["` + aksWIAudience + `"]}}`))
			case strings.HasSuffix(r.URL.Path, "/federatedIdentityCredentials"):
				_, _ = w.Write([]byte(`{"value":[{"name":"fic-runner-prod-abcd1234"}]}`))
			case strings.HasSuffix(r.URL.Path, "/userAssignedIdentities"):
				_, _ = w.Write([]byte(`{"value":[{"id":"/subscriptions/` + testSub +
					`/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id-runner",` +
					`"name":"id-runner","location":"westeurope"}]}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := aksWIDriver(t, srv)
	found, _, err := d.discoverAKSWorkloadIdentity("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.identity.podidentity" {
		t.Fatalf("discover: %+v", found)
	}
	if !strings.HasPrefix(found[0].ProviderID, "aks-wi:"+testSub+":rg1:id-runner:") {
		t.Fatalf("discovered pid = %q", found[0].ProviderID)
	}
}
