package gcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"groundhold/internal/provider"
)

// --- pure reverse map -------------------------------------------------------

func TestMapLoadBalancerExternalHTTPS(t *testing.T) {
	fr := lbForwardingRule{
		Name:                "public-https",
		LoadBalancingScheme: "EXTERNAL_MANAGED",
		Target:              "https://www.googleapis.com/compute/v1/projects/acme-prod/global/targetHttpsProxies/web-proxy",
	}
	got := observedMap(MapLoadBalancer(fr))
	if got["network.publicExposure"] != true {
		t.Errorf("EXTERNAL_MANAGED must be public, got %v", got["network.publicExposure"])
	}
	if got["encryption.inTransit"] != true {
		t.Errorf("targetHttpsProxies must terminate TLS, got %v", got["encryption.inTransit"])
	}
	if got["service.managed"] != true {
		t.Errorf("a GCP forwarding rule is always managed, got %v", got["service.managed"])
	}
}

func TestMapLoadBalancerInternalHTTP(t *testing.T) {
	fr := lbForwardingRule{
		Name:                "internal-http",
		LoadBalancingScheme: "INTERNAL_MANAGED",
		Target:              "https://www.googleapis.com/compute/v1/projects/acme-prod/regions/us-central1/targetHttpProxies/int-proxy",
	}
	got := observedMap(MapLoadBalancer(fr))
	if got["network.publicExposure"] != false {
		t.Errorf("INTERNAL_MANAGED must be private, got %v", got["network.publicExposure"])
	}
	if got["encryption.inTransit"] != false {
		t.Errorf("targetHttpProxies terminates no TLS, got %v", got["encryption.inTransit"])
	}
}

func TestMapLoadBalancerSSLProxyIsInTransit(t *testing.T) {
	fr := lbForwardingRule{LoadBalancingScheme: "EXTERNAL",
		Target: ".../global/targetSslProxies/ssl-proxy"}
	got := observedMap(MapLoadBalancer(fr))
	if got["encryption.inTransit"] != true {
		t.Errorf("targetSslProxies must terminate TLS, got %v", got["encryption.inTransit"])
	}
}

func TestMapLoadBalancerL4Passthrough(t *testing.T) {
	// A bare backendService (no target proxy) is an L4 passthrough — no TLS.
	fr := lbForwardingRule{LoadBalancingScheme: "INTERNAL",
		BackendService: ".../regions/us-central1/backendServices/db-lb"}
	got := observedMap(MapLoadBalancer(fr))
	if got["encryption.inTransit"] != false {
		t.Errorf("L4 passthrough terminates no TLS, got %v", got["encryption.inTransit"])
	}
	if got["network.publicExposure"] != false {
		t.Errorf("INTERNAL must be private, got %v", got["network.publicExposure"])
	}
}

func TestMapLoadBalancerUnknownSchemeSkips(t *testing.T) {
	_, diags := MapLoadBalancer(lbForwardingRule{LoadBalancingScheme: "WHAT"})
	if len(diags) == 0 {
		t.Fatal("an unknown loadBalancingScheme must produce a diagnostic, not a default")
	}
}

func observedMap(obs []Observed, _ []string) map[string]any {
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	return m
}

// --- golden httptest: observe + discover ------------------------------------

// lbServer is a compute double. It asserts the bearer on every request, serves
// two forwarding rules (a public HTTPS one under global/, an internal HTTP one
// under us-central1/) via forwardingRules.get, and the same two via
// aggregatedList.
func lbServer(t *testing.T) *httptest.Server {
	t.Helper()
	const publicHTTPS = `{"name":"public-https","loadBalancingScheme":"EXTERNAL_MANAGED",` +
		`"target":"https://www.googleapis.com/compute/v1/projects/acme-prod/global/targetHttpsProxies/web-proxy"}`
	const internalHTTP = `{"name":"internal-http","loadBalancingScheme":"INTERNAL_MANAGED",` +
		`"target":"https://www.googleapis.com/compute/v1/projects/acme-prod/regions/us-central1/targetHttpProxies/int-proxy"}`
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer test-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			switch {
			case strings.HasSuffix(r.URL.Path, "/aggregated/forwardingRules"):
				_, _ = w.Write([]byte(`{"items":{` +
					`"global":{"forwardingRules":[` + publicHTTPS + `]},` +
					`"regions/us-central1":{"forwardingRules":[` + internalHTTP + `]},` +
					`"regions/us-east1":{"warning":{"code":"NO_RESULTS_ON_PAGE"}}` +
					`}}`))
			case strings.HasSuffix(r.URL.Path, "/global/forwardingRules/public-https"):
				_, _ = w.Write([]byte(publicHTTPS))
			case strings.HasSuffix(r.URL.Path, "/regions/us-central1/forwardingRules/internal-http"):
				_, _ = w.Write([]byte(internalHTTP))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

func lbDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.ComputeBaseURL = srv.URL
	return d
}

func TestObserveLoadBalancerGolden(t *testing.T) {
	srv := lbServer(t)
	defer srv.Close()
	d := lbDriver(t, srv)

	pub, _, err := d.Observe("loadbalancer", "", lbProviderID("acme-prod", "global", "public-https"))
	if err != nil {
		t.Fatal(err)
	}
	pm := obsMap(pub)
	if pm["network.publicExposure"] != true || pm["encryption.inTransit"] != true {
		t.Fatalf("external HTTPS LB should be public+encrypted, got %+v", pm)
	}

	intl, _, err := d.Observe("loadbalancer", "", lbProviderID("acme-prod", "us-central1", "internal-http"))
	if err != nil {
		t.Fatal(err)
	}
	im := obsMap(intl)
	if im["network.publicExposure"] != false || im["encryption.inTransit"] != false {
		t.Fatalf("internal HTTP LB should be private+plaintext, got %+v", im)
	}
}

func TestDiscoverLoadBalancersGolden(t *testing.T) {
	srv := lbServer(t)
	defer srv.Close()
	d := lbDriver(t, srv)

	found, _, err := d.discoverLoadBalancers("")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 2 {
		t.Fatalf("expected 2 forwarding rules, got %d: %+v", len(found), found)
	}
	byID := map[string]map[string]any{}
	for _, f := range found {
		if f.ResourceType != "capability.network.loadbalancer" {
			t.Errorf("wrong resource type: %s", f.ResourceType)
		}
		byID[f.ProviderID] = obsMap(f.Observations)
	}
	pub := byID["lb:acme-prod:global:public-https"]
	if pub["network.publicExposure"] != true || pub["encryption.inTransit"] != true {
		t.Errorf("discovered public HTTPS LB wrong: %+v", pub)
	}
	intl := byID["lb:acme-prod:us-central1:internal-http"]
	if intl["network.publicExposure"] != false || intl["encryption.inTransit"] != false {
		t.Errorf("discovered internal HTTP LB wrong: %+v", intl)
	}
}

func TestDiscoverLoadBalancersRegionFilter(t *testing.T) {
	srv := lbServer(t)
	defer srv.Close()
	d := lbDriver(t, srv)

	found, _, err := d.discoverLoadBalancers("us-central1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ProviderID != "lb:acme-prod:us-central1:internal-http" {
		t.Fatalf("region filter should keep only the regional rule, got %+v", found)
	}
}

func obsMap(obs []provider.Observation) map[string]any {
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	return m
}

// --- full provisioning composite: create -> observe -> delete ---------------

// lbFake is a stateful compute/v1 double for the WHOLE HTTP(S) LB composite. It
// asserts the bearer on every request, records the insert ORDER (by collection),
// stores each inserted resource body (so a later GET/observe reads it back), and
// serves every global operation as DONE. failColl, when set, makes that
// collection's POST return failStatus (to exercise the partial->unknown path).
type lbFake struct {
	t          *testing.T
	mu         sync.Mutex
	store      map[string][]byte // resource path -> body
	order      []string          // collection segments, in insert order
	deletes    []string          // collection segments deleted, in order
	opN        int
	failColl   string
	failStatus int
}

func newLBFake(t *testing.T) *lbFake {
	return &lbFake{t: t, store: map[string][]byte{}}
}

func (f *lbFake) server() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// global operations always resolve DONE immediately.
		if strings.Contains(r.URL.Path, "/operations/") {
			_, _ = w.Write([]byte(`{"status":"DONE"}`))
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.Method {
		case http.MethodPost:
			coll := lastSeg(r.URL.Path)
			if f.failColl != "" && coll == f.failColl {
				w.WriteHeader(f.failStatus)
				_, _ = w.Write([]byte(`{"error":{"message":"injected failure"}}`))
				return
			}
			body, _ := io.ReadAll(r.Body)
			var doc struct {
				Name string `json:"name"`
			}
			_ = json.Unmarshal(body, &doc)
			// D429: GCP answers 409 when the name is taken. The fake used to overwrite
			// silently, so it could not describe an estate where the composite already
			// stands — and the create-adoption path had nothing to be tested against.
			if _, taken := f.store[r.URL.Path+"/"+doc.Name]; taken {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"error":{"code":409,"message":"already exists"}}`))
				return
			}
			f.store[r.URL.Path+"/"+doc.Name] = body
			f.order = append(f.order, coll)
			f.opN++
			_, _ = w.Write([]byte(fmt.Sprintf(`{"name":"op-%d"}`, f.opN)))
		case http.MethodGet:
			if b, ok := f.store[r.URL.Path]; ok {
				_, _ = w.Write(b)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		case http.MethodDelete:
			if _, ok := f.store[r.URL.Path]; !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			delete(f.store, r.URL.Path)
			// collection is the second-to-last segment of the resource path.
			segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
			if len(segs) >= 2 {
				f.deletes = append(f.deletes, segs[len(segs)-2])
			}
			f.opN++
			_, _ = w.Write([]byte(fmt.Sprintf(`{"name":"op-%d"}`, f.opN)))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
}

func lastSeg(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	return segs[len(segs)-1]
}

func lbProvisionDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.ComputeBaseURL = srv.URL
	return d
}

// The whole loop for the non-TLS external LB: create the composite in dependency
// order, observe the resulting forwarding rule (public + plaintext), then tear it
// down and assert every sub-resource is gone.
func TestLoadBalancerCreateObserveDeleteHTTP(t *testing.T) {
	fake := newLBFake(t)
	srv := fake.server()
	defer srv.Close()
	d := lbProvisionDriver(t, srv)

	attrs := map[string]any{"network.publicExposure": true, "service.managed": true}
	res := d.Create("loadbalancer", "capability.network.loadbalancer", "prod", attrs, nil, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create should succeed, got %+v", res)
	}
	names := lbComposeNames("acme-prod", "prod", "capability.network.loadbalancer", 1)
	wantPID := lbProviderID("acme-prod", "global", names.ForwardingRule)
	if res.ProviderID != wantPID {
		t.Fatalf("providerId = %q, want %q", res.ProviderID, wantPID)
	}

	// the create ORDER: dependency order, HTTP target proxy (not HTTPS).
	wantOrder := []string{"addresses", "healthChecks", "backendServices",
		"urlMaps", "targetHttpProxies", "forwardingRules"}
	if strings.Join(fake.order, ",") != strings.Join(wantOrder, ",") {
		t.Fatalf("create order = %v, want %v", fake.order, wantOrder)
	}

	// observe: public + plaintext.
	obs, _, err := d.Observe("loadbalancer", "", wantPID)
	if err != nil {
		t.Fatal(err)
	}
	om := obsMap(obs)
	if om["network.publicExposure"] != true || om["encryption.inTransit"] != false {
		t.Fatalf("observed HTTP LB should be public+plaintext, got %+v", om)
	}

	// delete: reverse order, forwarding rule first.
	del := d.Delete("loadbalancer", "capability.network.loadbalancer", "prod", wantPID, "k")
	if del.Status != "succeeded" {
		t.Fatalf("delete should succeed, got %+v", del)
	}
	if len(fake.deletes) == 0 || fake.deletes[0] != "forwardingRules" {
		t.Fatalf("delete must start with the forwarding rule, got %v", fake.deletes)
	}
	if len(fake.store) != 0 {
		t.Fatalf("delete left resources behind: %v", keysOf(fake.store))
	}
}

// The HTTPS composite consumes the sslCertificate operand: a targetHttpsProxies
// (not HTTP) carrying the referenced certificate, observed as public+encrypted.
func TestLoadBalancerCreateHTTPSWithCert(t *testing.T) {
	fake := newLBFake(t)
	srv := fake.server()
	defer srv.Close()
	d := lbProvisionDriver(t, srv)

	attrs := map[string]any{"network.publicExposure": true,
		"encryption.inTransit": true, "service.managed": true}
	impl := map[string]any{"sslCertificate": "my-cert"}
	res := d.Create("loadbalancer", "capability.network.loadbalancer", "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("HTTPS create should succeed, got %+v", res)
	}
	if !containsStr(fake.order, "targetHttpsProxies") || containsStr(fake.order, "targetHttpProxies") {
		t.Fatalf("HTTPS composite must build a targetHttpsProxies, got order %v", fake.order)
	}
	// the proxy body must carry the referenced certificate.
	names := lbComposeNames("acme-prod", "prod", "capability.network.loadbalancer", 1)
	pkey := "/projects/acme-prod/global/targetHttpsProxies/" + names.HTTPSProxy
	if !bytesContain(fake, pkey, "sslCertificates") || !bytesContain(fake, pkey, "my-cert") {
		t.Fatalf("HTTPS proxy body missing the sslCertificate operand")
	}
	obs, _, err := d.Observe("loadbalancer", "", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	om := obsMap(obs)
	if om["network.publicExposure"] != true || om["encryption.inTransit"] != true {
		t.Fatalf("observed HTTPS LB should be public+encrypted, got %+v", om)
	}
}

// A required operand that is missing (inTransit=true, no sslCertificate) is a
// REFUSAL at validate time — never a half-built HTTPS proxy with no cert.
func TestLoadBalancerMissingCertOperandRefuses(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	attrs := map[string]any{"network.publicExposure": true,
		"encryption.inTransit": true, "service.managed": true}
	err := d.Validate("loadbalancer", "capability.network.loadbalancer", "prod", attrs, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "sslCertificate") {
		t.Fatalf("inTransit without sslCertificate must refuse, got %v", err)
	}
}

// A partial composite (earlier sub-resources built, the forwarding rule fails) is
// `unknown` WITH the providerId — never a silent success, never a target-less rule.
func TestLoadBalancerPartialFailureIsUnknown(t *testing.T) {
	fake := newLBFake(t)
	fake.failColl, fake.failStatus = "forwardingRules", http.StatusBadRequest // hard 4xx, yet partial
	srv := fake.server()
	defer srv.Close()
	d := lbProvisionDriver(t, srv)

	attrs := map[string]any{"network.publicExposure": true, "service.managed": true}
	res := d.Create("loadbalancer", "capability.network.loadbalancer", "prod", attrs, nil, "k", 1)
	names := lbComposeNames("acme-prod", "prod", "capability.network.loadbalancer", 1)
	wantPID := lbProviderID("acme-prod", "global", names.ForwardingRule)
	if res.Status != "unknown" {
		t.Fatalf("a partial composite must be unknown, got %+v", res)
	}
	if res.ProviderID != wantPID {
		t.Fatalf("a partial composite must carry the providerId, got %q", res.ProviderID)
	}
	// the earlier plumbing DID get built — it must be reconcilable/retirable.
	if !containsStr(fake.order, "targetHttpProxies") {
		t.Fatalf("expected the proxy to have been built before the forwarding rule, got %v", fake.order)
	}
}

// Delete refuses a forwarding rule whose marker is FOREIGN — never deletes what
// is not ours, even under our deterministic name.
func TestLoadBalancerDeleteForeignRefuses(t *testing.T) {
	fake := newLBFake(t)
	srv := fake.server()
	defer srv.Close()
	d := lbProvisionDriver(t, srv)

	names := lbComposeNames("acme-prod", "prod", "capability.network.loadbalancer", 1)
	// seed a forwarding rule under our deterministic name but with a FOREIGN marker.
	fake.store["/projects/acme-prod/global/forwardingRules/"+names.ForwardingRule] =
		[]byte(`{"name":"` + names.ForwardingRule + `","description":"terraform-owned; not groundhold"}`)

	pid := lbProviderID("acme-prod", "global", names.ForwardingRule)
	del := d.Delete("loadbalancer", "capability.network.loadbalancer", "prod", pid, "k")
	if del.Status != "failed" || !strings.Contains(del.Reason, "not ours") {
		t.Fatalf("delete of a foreign-marked resource must refuse, got %+v", del)
	}
}

// Update is honestly not wired (scheme/inTransit are replacements).
func TestLoadBalancerUpdateNotWired(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	pid := lbProviderID("acme-prod", "global", "some-lb")
	r := d.Update("loadbalancer", "capability.network.loadbalancer", "prod", pid, nil, nil, nil, "k")
	if r.Status != "failed" || !strings.Contains(r.Reason, "not wired") {
		t.Fatalf("update should honestly refuse, got %+v", r)
	}
}

// ClassifyChange: exposure/in-transit are replacements; the health-check path is
// an operand handled outside the semantic change set.
func TestLoadBalancerClassifyChange(t *testing.T) {
	d := NewDriver("acme-prod")
	if k, _ := d.ClassifyChange("loadbalancer", "network.publicExposure", true, false, nil); k != "immutable" {
		t.Errorf("publicExposure must be a replacement, got %s", k)
	}
	if k, _ := d.ClassifyChange("loadbalancer", "encryption.inTransit", false, true, nil); k != "immutable" {
		t.Errorf("inTransit must be a replacement, got %s", k)
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func bytesContain(f *lbFake, path, want string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Contains(string(f.store[path]), want)
}

// --- read-only providerId validation ----------------------------------------

func TestLoadBalancerProviderIDRejectsInjection(t *testing.T) {
	if _, _, _, err := splitLBProviderID("lb:acme-prod:global:../../evil"); err == nil {
		t.Fatal("a providerId with path-traversal must be rejected")
	}
	if _, _, _, err := splitLBProviderID("lb:acme-prod:global"); err == nil {
		t.Fatal("a 3-part providerId must be rejected (scope is required)")
	}
}
