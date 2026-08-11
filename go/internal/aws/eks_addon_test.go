package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// fakeAddon is a stateful fake EKS addon (REST-JSON) endpoint. It records the
// ORDER of mutating actions, tracks the addon as it lands / updates / is torn
// down, and captures the CreateAddon and UpdateAddon bodies.
type fakeAddon struct {
	mu sync.Mutex

	cluster string
	addon   string

	exists     bool
	status     string
	version    string
	tags       map[string]string
	createBody string
	updateBody string

	order []string
}

func newFakeAddon() *fakeAddon {
	return &fakeAddon{
		cluster: "acme-prod",
		addon:   "aws-ebs-csi-driver",
		status:  "ACTIVE",
		version: "v1.29.0-eksbuild.1",
		tags:    map[string]string{},
	}
}

func (f *fakeAddon) handler(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	base := "/clusters/" + f.cluster + "/addons"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		if rec != nil {
			rec.record(r, body)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		p, m := r.URL.Path, r.Method
		switch {
		case p == base && m == http.MethodPost:
			f.order = append(f.order, "CreateAddon")
			f.exists = true
			f.createBody = body
			_, _ = w.Write([]byte(`{"addon":{"addonName":"` + f.addon + `","status":"` + f.status + `"}}`))
		case p == base+"/"+f.addon && m == http.MethodGet:
			if !f.exists {
				http.Error(w, `{"message":"No addon found"}`, http.StatusNotFound)
				return
			}
			cj, _ := json.Marshal(map[string]any{"addon": map[string]any{
				"addonName": f.addon, "addonVersion": f.version, "status": f.status, "tags": f.tags,
			}})
			_, _ = w.Write(cj)
		case p == base+"/"+f.addon+"/update" && m == http.MethodPost:
			f.order = append(f.order, "UpdateAddon")
			f.updateBody = body
			var ub map[string]any
			_ = json.Unmarshal(b, &ub)
			if v, ok := ub["addonVersion"].(string); ok {
				f.version = v
			}
			f.status = "ACTIVE"
			_, _ = w.Write([]byte(`{"update":{"id":"u1"}}`))
		case p == base+"/"+f.addon && m == http.MethodDelete:
			f.order = append(f.order, "DeleteAddon")
			f.exists = false
			_, _ = w.Write([]byte(`{}`))
		case p == base && m == http.MethodGet:
			if f.exists {
				_, _ = w.Write([]byte(`{"addons":["` + f.addon + `"]}`))
			} else {
				_, _ = w.Write([]byte(`{"addons":[]}`))
			}
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	}))
}

const eksAddonCap = "capability.cluster.addon"

func addonCandidate() (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region": "eu-central-1",
		"addon.name":      "aws-ebs-csi-driver",
		"addon.version":   "v1.30.0-eksbuild.1",
		"service.managed": true,
	}
	impl = map[string]any{
		"clusterName":    "acme-prod",
		"serviceRoleArn": "arn:aws:iam::000000000000:role/ebs-csi",
	}
	return
}

func addonPID() string {
	return eksAddonProviderID("eu-central-1", "acme-prod", "aws-ebs-csi-driver")
}

// TestEKSAddon_FullCreateSucceeds: DescribeAddon (404) -> CreateAddon -> poll
// ACTIVE -> succeeded WITH the pid. The CreateAddon body carries the addon name,
// version, service-account role and ownership tags. Every request is SigV4-signed.
func TestEKSAddon_FullCreateSucceeds(t *testing.T) {
	f := newFakeAddon()
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := addonCandidate()

	res := d.Create("eks-addon", eksAddonCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != addonPID() {
		t.Fatalf("create providerId = %q, want %q", res.ProviderID, addonPID())
	}
	if strings.Join(f.order, ",") != "CreateAddon" {
		t.Fatalf("create order = %v, want [CreateAddon]", f.order)
	}
	var cb map[string]any
	if err := json.Unmarshal([]byte(f.createBody), &cb); err != nil {
		t.Fatalf("CreateAddon body not JSON: %v", err)
	}
	if cb["addonName"] != "aws-ebs-csi-driver" {
		t.Fatalf("body addonName = %v", cb["addonName"])
	}
	if cb["addonVersion"] != "v1.30.0-eksbuild.1" {
		t.Fatalf("body addonVersion = %v", cb["addonVersion"])
	}
	if cb["serviceAccountRoleArn"] != "arn:aws:iam::000000000000:role/ebs-csi" {
		t.Fatalf("body serviceAccountRoleArn = %v", cb["serviceAccountRoleArn"])
	}
	tags, _ := cb["tags"].(map[string]any)
	if tags["groundhold-capability"] != sanitizeTag(eksAddonCap) || tags["groundhold-environment"] != sanitizeTag("prod") {
		t.Fatalf("ownership tags missing/wrong: %+v", tags)
	}
	if rec.unsign != 0 {
		t.Fatalf("every EKS request must be SigV4-signed; %d were not", rec.unsign)
	}
}

// TestEKSAddon_UpdateVersion: an in-place version bump POSTs UpdateAddon (carrying
// the new version), polls the addon back to ACTIVE, and succeeds — ownership tags
// gate the patch.
func TestEKSAddon_UpdateVersion(t *testing.T) {
	f := newFakeAddon()
	f.exists = true
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag(eksAddonCap), "groundhold-environment": sanitizeTag("prod")}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Update("eks-addon", eksAddonCap, "prod", addonPID(),
		map[string]any{"addon.version": "v1.31.0-eksbuild.1"}, nil, []string{"addon.version"}, "k")
	if res.Status != "succeeded" || res.ProviderID != addonPID() {
		t.Fatalf("version update must succeed with the pid, got %+v", res)
	}
	if !strings.Contains(f.updateBody, `"addonVersion":"v1.31.0-eksbuild.1"`) {
		t.Fatalf("UpdateAddon body must carry the version: %s", f.updateBody)
	}
	if strings.Join(f.order, ",") != "UpdateAddon" {
		t.Fatalf("update order = %v, want [UpdateAddon]", f.order)
	}
}

// TestEKSAddon_CreateForeignRefuses: an addon already at our name whose ownership
// tags are NOT ours must not be adopted — refuse (failed), issue no mutation.
func TestEKSAddon_CreateForeignRefuses(t *testing.T) {
	f := newFakeAddon()
	f.exists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := addonCandidate()

	res := d.Create("eks-addon", eksAddonCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign addon create must refuse, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("no mutation may touch a foreign addon; saw %v", f.order)
	}
}

// TestEKSAddon_ObserveReverseMap: observe reverse-maps the addon to
// capability.cluster.addon (name, version, service.managed).
func TestEKSAddon_ObserveReverseMap(t *testing.T) {
	f := newFakeAddon()
	f.exists = true
	f.version = "v1.29.0-eksbuild.1"
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	obs, _, err := d.Observe("eks-addon", eksAddonCap, addonPID())
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["addon.name"] != "aws-ebs-csi-driver" {
		t.Fatalf("addon.name = %v", m["addon.name"])
	}
	if m["addon.version"] != "v1.29.0-eksbuild.1" {
		t.Fatalf("addon.version = %v", m["addon.version"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed = %v, want true", m["service.managed"])
	}
	if m["location.region"] != "eu-central-1" {
		t.Fatalf("location.region = %v", m["location.region"])
	}
}

// TestEKSAddon_DeleteSucceeds: delete re-checks ownership then DeleteAddon and
// succeeds.
func TestEKSAddon_DeleteSucceeds(t *testing.T) {
	f := newFakeAddon()
	f.exists = true
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag(eksAddonCap), "groundhold-environment": sanitizeTag("prod")}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Delete("eks-addon", eksAddonCap, "prod", addonPID(), "k")
	if res.Status != "succeeded" {
		t.Fatalf("delete status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if strings.Join(f.order, ",") != "DeleteAddon" {
		t.Fatalf("delete order = %v, want [DeleteAddon]", f.order)
	}
}

// TestEKSAddon_DeleteForeignRefuses: a foreign addon (tags not ours) is refused,
// no DeleteAddon issued.
func TestEKSAddon_DeleteForeignRefuses(t *testing.T) {
	f := newFakeAddon()
	f.exists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Delete("eks-addon", eksAddonCap, "prod", addonPID(), "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign addon delete must refuse, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("no DeleteAddon may touch a foreign addon; saw %v", f.order)
	}
}

// TestEKSAddon_MissingOperandRefuses: refuse-BEFORE-mutate — a missing required
// operand (clusterName) and a missing required attribute (addon.version) are caught
// by the builder, before any EKS call, at BOTH Create and Validate.
func TestEKSAddon_MissingOperandRefuses(t *testing.T) {
	f := newFakeAddon()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	attrs, impl := addonCandidate()
	delete(impl, "clusterName")
	res := d.Create("eks-addon", eksAddonCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "clusterName") {
		t.Fatalf("missing clusterName must refuse with a clusterName reason, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("refuse-before-mutate must issue no EKS call; saw %v", f.order)
	}
	if err := d.Validate("eks-addon", eksAddonCap, "prod", attrs, impl, 1); err == nil {
		t.Fatal("Validate must refuse a candidate with no clusterName")
	}

	attrs2, impl2 := addonCandidate()
	delete(attrs2, "addon.version")
	if err := d.Validate("eks-addon", eksAddonCap, "prod", attrs2, impl2, 1); err == nil || !strings.Contains(err.Error(), "addon.version") {
		t.Fatalf("missing addon.version must refuse, got %v", err)
	}
}

// TestEKSAddon_UnmappedAttributeRefuses: an attribute with no cluster.addon
// mapping is REFUSED (never silently dropped).
func TestEKSAddon_UnmappedAttributeRefuses(t *testing.T) {
	attrs, impl := addonCandidate()
	attrs["network.apiExposure"] = "public" // not a cluster.addon attribute
	if _, err := BuildEKSAddon("prod", eksAddonCap, attrs, impl, 1); err == nil {
		t.Fatal("an unmapped attribute must be refused, not silently dropped")
	}
}

// TestEKSAddon_ClassifyChange: addon.version is mutable in place (UpdateAddon);
// addon.name is the identity (immutable); service.managed is unsupported. Every
// path carries a reason.
func TestEKSAddon_ClassifyChange(t *testing.T) {
	d := NewDriver("eu-central-1")
	want := map[string]string{
		"addon.version":   "mutable",
		"addon.name":      "immutable",
		"service.managed": "unsupported",
	}
	for p, w := range want {
		got, reason := d.ClassifyChange("eks-addon", p, nil, nil, nil)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// TestEKSAddon_Discover: ListClusters -> ListAddons per cluster -> per-addon
// reverse map, surfacing the addon as capability.cluster.addon for adoption.
func TestEKSAddon_Discover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clusters":
			_, _ = w.Write([]byte(`{"clusters":["acme-prod"]}`))
		case "/clusters/acme-prod/addons":
			_, _ = w.Write([]byte(`{"addons":["aws-ebs-csi-driver"]}`))
		case "/clusters/acme-prod/addons/aws-ebs-csi-driver":
			_, _ = w.Write([]byte(`{"addon":{"addonName":"aws-ebs-csi-driver","addonVersion":"v1.29.0-eksbuild.1","status":"ACTIVE"}}`))
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	d := eksDriver(t, srv)

	found, _, err := d.discoverEKSAddon("eu-central-1")
	if err != nil {
		t.Fatalf("discoverEKSAddon: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 discovered addon, got %d", len(found))
	}
	if found[0].ProviderID != addonPID() {
		t.Fatalf("providerId = %q, want %q", found[0].ProviderID, addonPID())
	}
	if found[0].ResourceType != "capability.cluster.addon" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
}

// flakyAddonServer serves an existing, ACTIVE, OWNED addon whose DescribeAddon GET
// returns a transient 503 for its first failN calls, then the real body. It models
// Acme's D260 crash: an all-healthy adopted world where one sibling's describe
// hiccups. With eksGet's bounded retry the adopt must ride it out to succeeded.
func flakyAddonServer(t *testing.T, failN int) *httptest.Server {
	t.Helper()
	base := "/clusters/acme-prod/addons/aws-ebs-csi-driver"
	var gets int
	var mu sync.Mutex
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == base {
			mu.Lock()
			gets++
			n := gets
			mu.Unlock()
			if n <= failN {
				http.Error(w, `{"message":"throttled"}`, http.StatusServiceUnavailable)
				return
			}
			cj, _ := json.Marshal(map[string]any{"addon": map[string]any{
				"addonName": "aws-ebs-csi-driver", "addonVersion": "v1.30.0-eksbuild.1", "status": "ACTIVE",
				"tags": map[string]string{
					"groundhold-capability":  sanitizeTag(eksAddonCap),
					"groundhold-environment": sanitizeTag("prod"),
				}}})
			_, _ = w.Write(cj)
			return
		}
		if r.Method == http.MethodPost {
			t.Errorf("adopt of an existing owned addon must not POST %s", r.URL.Path)
		}
		http.Error(w, `{"message":"unexpected"}`, http.StatusNotFound)
	}))
}

// TestEKSAddonAdoptRidesOutTransientRead pins D260: an existing owned ACTIVE addon
// whose DescribeAddon throttles on its first 3 calls (503) is still adopted
// (succeeded) because eksGet retries the transient read — no fatal "unknown", no
// aborted converge, no duplicate CreateAddon.
func TestEKSAddonAdoptRidesOutTransientRead(t *testing.T) {
	srv := flakyAddonServer(t, eksReadAttempts-1) // fail every attempt but the last
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := addonCandidate()
	res := d.Create("eks-addon", eksAddonCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" || res.ProviderID != addonPID() {
		t.Fatalf("transient DescribeAddon must be retried into a succeeded adopt, got %+v", res)
	}
}

// TestEKSAddonAdoptPersistentReadFailureIsActionable pins the honest tail: a
// DescribeAddon that stays 503 through the whole retry budget concludes unknown WITH
// the pid and an ACTIONABLE reason (permission / throttle) — never a silent hang and
// never a false success.
func TestEKSAddonAdoptPersistentReadFailureIsActionable(t *testing.T) {
	srv := flakyAddonServer(t, 1000) // never recovers
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := addonCandidate()
	res := d.Create("eks-addon", eksAddonCap, "prod", attrs, impl, "k", 1)
	if res.Status != "unknown" {
		t.Fatalf("a persistent read failure must be unknown, got %+v", res)
	}
	if !strings.Contains(res.Reason, "eks:DescribeAddon") {
		t.Fatalf("the reason must name the missing permission to be actionable, got %q", res.Reason)
	}
}

// TestAdoptsExistingEKSAddon enrols eks-addon in the D391 gate. An addon is identified
// by (cluster, addon name) and the foreign case already has a test; the OURS case — an
// addon we installed that is already there, which is what every re-converge meets —
// did not.
func TestAdoptsExistingEKSAddon(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	attrs, impl := addonCandidate()
	p := &certifynet.ExistingProbe{
		Name:     "aws/eks-addon",
		Classify: eksRole,
		ExistingServer: func() *httptest.Server {
			f := newFakeAddon()
			f.exists = true
			f.tags = map[string]string{
				"groundhold-capability":  sanitizeTag(eksAddonCap),
				"groundhold-environment": sanitizeTag("prod"),
			}
			return f.handler(t, nil)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.EKSBaseURL = happyURL
			d.EC2BaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.PollInterval = 0
			d.PollTimeout = 2 * time.Second
			d.EKSLROTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("eks-addon", eksAddonCap, "prod", attrs, impl, "k", 1)
		},
		PID: addonPID(),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
