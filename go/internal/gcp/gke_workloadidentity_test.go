package gcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const wiGSA = "wi-runner@acme-prod.iam.gserviceaccount.com"

func wiAttrs() map[string]any {
	return map[string]any{
		"workload.namespace":      "default",
		"workload.serviceAccount": "app-sa",
		"service.managed":         true,
	}
}

func wiImpl() map[string]any {
	return map[string]any{"gsaEmail": wiGSA}
}

// wiPID is the deterministic providerId a create/build yields for wiAttrs+wiImpl
// against the pinned project "acme-prod".
func wiPID() string {
	return gkeWIProviderID("acme-prod", wiGSA, "default", "app-sa")
}

// --- pure builder ---

func TestBuildGKEWorkloadIdentityHonors(t *testing.T) {
	p, err := BuildGKEWorkloadIdentity("acme-prod", "prod", "runner", wiAttrs(), wiImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Namespace != "default" || p.ServiceAccount != "app-sa" ||
		p.GSAEmail != wiGSA || p.PoolProject != "acme-prod" {
		t.Fatalf("plan = %+v", p)
	}
	if got := p.Member(); got != "serviceAccount:acme-prod.svc.id.goog[default/app-sa]" {
		t.Fatalf("member = %q", got)
	}
	// clusterProject overrides the pool project (cross-project WI).
	impl := wiImpl()
	impl["clusterProject"] = "other-cluster"
	p2, err := BuildGKEWorkloadIdentity("acme-prod", "prod", "runner", wiAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p2.PoolProject != "other-cluster" ||
		p2.Member() != "serviceAccount:other-cluster.svc.id.goog[default/app-sa]" {
		t.Fatalf("cross-project plan = %+v", p2)
	}
}

func TestBuildGKEWorkloadIdentityRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs, impl map[string]any
	}{
		"unmapped-attr":   {map[string]any{"workload.namespace": "default", "workload.serviceAccount": "app-sa", "addon.name": "x"}, wiImpl()},
		"missing-ns":      {map[string]any{"workload.serviceAccount": "app-sa"}, wiImpl()},
		"missing-sa":      {map[string]any{"workload.namespace": "default"}, wiImpl()},
		"unmanaged":       {map[string]any{"workload.namespace": "default", "workload.serviceAccount": "app-sa", "service.managed": false}, wiImpl()},
		"missing-gsa":     {wiAttrs(), map[string]any{}},
		"bad-gsa":         {wiAttrs(), map[string]any{"gsaEmail": "not-an-email"}},
		"gsa-path-inject": {wiAttrs(), map[string]any{"gsaEmail": "evil@acme-prod.iam.gserviceaccount.com/../../foo"}},
		"bad-ns":          {map[string]any{"workload.namespace": "Bad_NS", "workload.serviceAccount": "app-sa"}, wiImpl()},
	}
	for name, c := range cases {
		if _, err := BuildGKEWorkloadIdentity("acme-prod", "prod", "runner", c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestClassifyGKEWorkloadIdentityChange(t *testing.T) {
	for _, tc := range []struct {
		path, want string
	}{
		{"workload.namespace", "immutable"},
		{"workload.serviceAccount", "immutable"},
		{"service.managed", "unsupported"},
		{"cost.monthly", "unsupported"},
		{"anything.else", "unsupported"},
	} {
		got, reason := classifyGKEWorkloadIdentityChange(tc.path)
		if got != tc.want {
			t.Errorf("%s: class=%q want %q", tc.path, got, tc.want)
		}
		if reason == "" {
			t.Errorf("%s: empty reason", tc.path)
		}
	}
}

func TestGKEWIProviderIDRoundtrip(t *testing.T) {
	pid := wiPID()
	pool, gsa, ns, sa, err := splitGKEWIProviderID(pid)
	if err != nil {
		t.Fatal(err)
	}
	if pool != "acme-prod" || gsa != wiGSA || ns != "default" || sa != "app-sa" {
		t.Fatalf("roundtrip = %q %q %q %q", pool, gsa, ns, sa)
	}
	for _, bad := range []string{
		"gauth:acme-prod:roles/x:serviceAccount:y", // wrong scheme
		"gke-wi:acme-prod:not-an-email:default:app-sa",
		"gke-wi:acme-prod:" + wiGSA + ":Bad_NS:app-sa",
		"gke-wi:acme-prod:" + wiGSA + ":default", // too few parts
	} {
		if _, _, _, _, err := splitGKEWIProviderID(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// --- network shell (stateful fake GSA IAM policy) ---

// saPolicyServer is a STATEFUL fake GSA IAM policy: setIamPolicy records the written
// policy, getIamPolicy reflects it, and the serviceAccounts list returns wiGSA for
// discovery. conflict makes every setIamPolicy answer 409 (the etag-conflict path).
func saPolicyServer(t *testing.T, seed *iamPolicy, conflict bool) *httptest.Server {
	t.Helper()
	pol := iamPolicy{Etag: "BwXseed"}
	if seed != nil {
		pol = *seed
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				_ = json.NewEncoder(w).Encode(pol)
			case strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
				if conflict {
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":{"code":409,"message":"etag"}}`))
					return
				}
				var req struct {
					Policy iamPolicy `json:"policy"`
				}
				_ = json.NewDecoder(r.Body).Decode(&req)
				pol = req.Policy
				pol.Etag = "BwXnext"
				_ = json.NewEncoder(w).Encode(pol)
			case strings.HasSuffix(r.URL.Path, "/serviceAccounts"):
				_ = json.NewEncoder(w).Encode(map[string]any{
					"accounts": []map[string]string{{"email": wiGSA}},
				})
			default:
				w.WriteHeader(404)
			}
		}))
}

func wiDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.IAMBaseURL = srv.URL
	d.Now = time.Now
	// getIamPolicy now rides the bounded transient-retry (gcpGetRetry); keep the
	// inter-attempt sleep at ~0 so an all-503 pre-read test stays fast.
	d.PollInterval = time.Millisecond
	return d
}

func TestGKEWorkloadIdentityCreateObserveDelete(t *testing.T) {
	srv := saPolicyServer(t, nil, false)
	defer srv.Close()
	d := wiDriver(t, srv)

	res := d.createGKEWorkloadIdentity("runner", "prod", wiAttrs(), wiImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID != wiPID() {
		t.Fatalf("create: %+v", res)
	}

	obs, _, err := d.observeGKEWorkloadIdentity("runner", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["workload.namespace"] != "default" || got["workload.serviceAccount"] != "app-sa" || got["service.managed"] != true {
		t.Fatalf("observe = %+v", got)
	}

	del := d.deleteGKEWorkloadIdentity("runner", "prod", res.ProviderID)
	if del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	// after delete the binding is gone — observe finds nothing.
	obs2, diags, err := d.observeGKEWorkloadIdentity("runner", res.ProviderID)
	if err != nil || len(obs2) != 0 || len(diags) == 0 {
		t.Fatalf("post-delete observe: obs=%v diags=%v err=%v", obs2, diags, err)
	}
}

func TestGKEWorkloadIdentityCreateIdempotent(t *testing.T) {
	seed := &iamPolicy{Etag: "BwXseed", Bindings: []iamPolicyBinding{
		{Role: wiRole, Members: []string{wiMember("acme-prod", "default", "app-sa")}},
	}}
	srv := saPolicyServer(t, seed, false)
	defer srv.Close()
	d := wiDriver(t, srv)
	res := d.createGKEWorkloadIdentity("runner", "prod", wiAttrs(), wiImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID != wiPID() {
		t.Fatalf("idempotent create: %+v", res)
	}
}

func TestGKEWorkloadIdentityDeleteIdempotentAbsent(t *testing.T) {
	srv := saPolicyServer(t, nil, false)
	defer srv.Close()
	d := wiDriver(t, srv)
	res := d.deleteGKEWorkloadIdentity("runner", "prod", wiPID())
	if res.Status != "succeeded" {
		t.Fatalf("delete absent should be idempotent: %+v", res)
	}
}

// content-addressed ownership: delete removes ONLY our member, never a co-tenant's.
func TestGKEWorkloadIdentityDeleteLeavesForeignMember(t *testing.T) {
	foreign := "serviceAccount:other-proj.svc.id.goog[team/other-sa]"
	seed := &iamPolicy{Etag: "BwXseed", Bindings: []iamPolicyBinding{
		{Role: wiRole, Members: []string{wiMember("acme-prod", "default", "app-sa"), foreign}},
	}}
	srv := saPolicyServer(t, seed, false)
	defer srv.Close()
	d := wiDriver(t, srv)
	if res := d.deleteGKEWorkloadIdentity("runner", "prod", wiPID()); res.Status != "succeeded" {
		t.Fatalf("delete: %+v", res)
	}
	// the foreign member survives.
	pol, perr := d.saGetIamPolicy(wiGSA)
	if perr != nil {
		t.Fatalf("policy read gave no answer: %v", perr)
	}
	if !memberInRole(pol, wiRole, foreign) {
		t.Fatal("delete clobbered a foreign member — content-addressing violated")
	}
	if memberInRole(pol, wiRole, wiMember("acme-prod", "default", "app-sa")) {
		t.Fatal("our member was not removed")
	}
}

// an etag conflict on setIamPolicy is unknown WITH the pid (reconcile), never a
// blind retry and never a failure that would orphan a possibly-landed write.
func TestGKEWorkloadIdentityEtagConflictIsUnknown(t *testing.T) {
	srv := saPolicyServer(t, nil, true)
	defer srv.Close()
	d := wiDriver(t, srv)
	res := d.createGKEWorkloadIdentity("runner", "prod", wiAttrs(), wiImpl(), 1)
	if res.Status != "unknown" || res.ProviderID != wiPID() {
		t.Fatalf("etag conflict should be unknown+pid: %+v", res)
	}
	if !strings.Contains(res.Reason, "conflict") {
		t.Fatalf("reason = %q", res.Reason)
	}
}

// getIamPolicy unreadable on create is unknown WITH the pid (never a blind create).
func TestGKEWorkloadIdentityCreateUnreadableIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	d := wiDriver(t, srv)
	res := d.createGKEWorkloadIdentity("runner", "prod", wiAttrs(), wiImpl(), 1)
	if res.Status != "unknown" || res.ProviderID != wiPID() {
		t.Fatalf("unreadable pre-read should be unknown+pid: %+v", res)
	}
}

func TestDiscoverGKEWorkloadIdentity(t *testing.T) {
	seed := &iamPolicy{Etag: "BwXseed", Bindings: []iamPolicyBinding{
		{Role: wiRole, Members: []string{
			wiMember("acme-prod", "default", "app-sa"),
			"serviceAccount:acme-prod.iam.gserviceaccount.com", // a non-WI member — skipped
		}},
		{Role: "roles/viewer", Members: []string{"user:someone@example.com"}}, // not WI — ignored
	}}
	srv := saPolicyServer(t, seed, false)
	defer srv.Close()
	d := wiDriver(t, srv)
	found, _, err := d.discoverGKEWorkloadIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 WI binding discovered, got %d: %+v", len(found), found)
	}
	if found[0].ResourceType != "capability.identity.podidentity" || found[0].ProviderID != wiPID() {
		t.Fatalf("discovered = %+v", found[0])
	}
	if len(found[0].Observations) == 0 {
		t.Fatal("discovered binding carries no observations")
	}
}
