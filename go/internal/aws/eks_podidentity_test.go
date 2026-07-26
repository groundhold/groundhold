package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakePodID is a stateful fake EKS pod-identity-association endpoint. The
// association is keyed by a server-generated id (resolved via the list filter); the
// fake records the ORDER of mutating actions and captures the create body.
type fakePodID struct {
	mu sync.Mutex

	cluster        string
	id             string
	namespace      string
	serviceAccount string
	roleArn        string

	exists     bool
	tags       map[string]string
	createBody string

	order []string
}

func newFakePodID() *fakePodID {
	return &fakePodID{
		cluster:        "acme-prod",
		id:             "a-1",
		namespace:      "kube-system",
		serviceAccount: "ebs-csi-controller-sa",
		roleArn:        "arn:aws:iam::000000000000:role/ebs-csi",
		tags:           map[string]string{},
	}
}

func (f *fakePodID) handler(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	base := "/clusters/" + f.cluster + "/pod-identity-associations"
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
			f.order = append(f.order, "CreatePodIdentityAssociation")
			f.exists = true
			f.createBody = body
			_, _ = w.Write([]byte(`{"association":{"associationId":"` + f.id + `","associationArn":"arn:aws:eks:eu-central-1:000000000000:podidentityassociation/` + f.id + `"}}`))
		case p == base && m == http.MethodGet:
			if f.exists {
				aj, _ := json.Marshal(map[string]any{"associations": []any{map[string]any{
					"associationId": f.id, "namespace": f.namespace, "serviceAccount": f.serviceAccount,
				}}})
				_, _ = w.Write(aj)
			} else {
				_, _ = w.Write([]byte(`{"associations":[]}`))
			}
		case p == base+"/"+f.id && m == http.MethodGet:
			if !f.exists {
				http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
				return
			}
			aj, _ := json.Marshal(map[string]any{"association": map[string]any{
				"associationId": f.id, "namespace": f.namespace, "serviceAccount": f.serviceAccount,
				"roleArn": f.roleArn, "tags": f.tags,
			}})
			_, _ = w.Write(aj)
		case p == base+"/"+f.id && m == http.MethodDelete:
			f.order = append(f.order, "DeletePodIdentityAssociation")
			f.exists = false
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	}))
}

const eksPodIDCap = "capability.identity.podidentity"

func podIDCandidate() (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region":         "eu-central-1",
		"workload.namespace":      "kube-system",
		"workload.serviceAccount": "ebs-csi-controller-sa",
		"service.managed":         true,
	}
	impl = map[string]any{
		"clusterName": "acme-prod",
		"roleArn":     "arn:aws:iam::000000000000:role/ebs-csi",
	}
	return
}

func podIDPID() string {
	return eksPodIdentityProviderID("eu-central-1", "acme-prod", "kube-system", "ebs-csi-controller-sa")
}

// TestEKSPodIdentity_CreateSucceeds: resolve (no existing) -> CreatePodIdentity-
// Association (synchronous) -> succeeded WITH the pid. The create body carries the
// namespace, serviceAccount, roleArn and ownership tags. Every request is
// SigV4-signed.
func TestEKSPodIdentity_CreateSucceeds(t *testing.T) {
	f := newFakePodID()
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := podIDCandidate()

	res := d.Create("eks-podidentity", eksPodIDCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != podIDPID() {
		t.Fatalf("create providerId = %q, want %q", res.ProviderID, podIDPID())
	}
	if strings.Join(f.order, ",") != "CreatePodIdentityAssociation" {
		t.Fatalf("create order = %v, want [CreatePodIdentityAssociation]", f.order)
	}
	var cb map[string]any
	if err := json.Unmarshal([]byte(f.createBody), &cb); err != nil {
		t.Fatalf("create body not JSON: %v", err)
	}
	if cb["namespace"] != "kube-system" || cb["serviceAccount"] != "ebs-csi-controller-sa" {
		t.Fatalf("create body ns/sa wrong: %+v", cb)
	}
	if cb["roleArn"] != "arn:aws:iam::000000000000:role/ebs-csi" {
		t.Fatalf("create body roleArn = %v", cb["roleArn"])
	}
	tags, _ := cb["tags"].(map[string]any)
	if tags["groundhold-capability"] != sanitizeTag(eksPodIDCap) || tags["groundhold-environment"] != sanitizeTag("prod") {
		t.Fatalf("ownership tags missing/wrong: %+v", tags)
	}
	if rec.unsign != 0 {
		t.Fatalf("every EKS request must be SigV4-signed; %d were not", rec.unsign)
	}
}

// TestEKSPodIdentity_CreateExistingOursIsRepair: an association already ours for
// our ns+sa is a repair (succeeded WITH the pid), never a second create.
func TestEKSPodIdentity_CreateExistingOursIsRepair(t *testing.T) {
	f := newFakePodID()
	f.exists = true
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag(eksPodIDCap), "groundhold-environment": sanitizeTag("prod")}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := podIDCandidate()

	res := d.Create("eks-podidentity", eksPodIDCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" || res.ProviderID != podIDPID() {
		t.Fatalf("ours-already must repair to succeeded with the pid, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("no create may be issued for an ours-already association; saw %v", f.order)
	}
}

// TestEKSPodIdentity_Observe: resolve id -> describe -> ns/sa reverse-mapped to
// capability.identity.podidentity.
func TestEKSPodIdentity_Observe(t *testing.T) {
	f := newFakePodID()
	f.exists = true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	obs, _, err := d.Observe("eks-podidentity", eksPodIDCap, podIDPID())
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["workload.namespace"] != "kube-system" {
		t.Fatalf("workload.namespace = %v", m["workload.namespace"])
	}
	if m["workload.serviceAccount"] != "ebs-csi-controller-sa" {
		t.Fatalf("workload.serviceAccount = %v", m["workload.serviceAccount"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed = %v, want true", m["service.managed"])
	}
	if m["location.region"] != "eu-central-1" {
		t.Fatalf("location.region = %v", m["location.region"])
	}
}

// TestEKSPodIdentity_CreateForeignRefuses: an association for our ns+sa whose tags
// are NOT ours must not be adopted — refuse (failed), issue no create.
func TestEKSPodIdentity_CreateForeignRefuses(t *testing.T) {
	f := newFakePodID()
	f.exists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := podIDCandidate()

	res := d.Create("eks-podidentity", eksPodIDCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign association create must refuse, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("no mutation may touch a foreign association; saw %v", f.order)
	}
}

// TestEKSPodIdentity_DeleteSucceeds: resolve id -> ownership re-check -> Delete-
// PodIdentityAssociation, succeeds.
func TestEKSPodIdentity_DeleteSucceeds(t *testing.T) {
	f := newFakePodID()
	f.exists = true
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag(eksPodIDCap), "groundhold-environment": sanitizeTag("prod")}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Delete("eks-podidentity", eksPodIDCap, "prod", podIDPID(), "k")
	if res.Status != "succeeded" {
		t.Fatalf("delete status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if strings.Join(f.order, ",") != "DeletePodIdentityAssociation" {
		t.Fatalf("delete order = %v, want [DeletePodIdentityAssociation]", f.order)
	}
}

// TestEKSPodIdentity_DeleteForeignRefuses: a foreign association (tags not ours) is
// refused, no delete issued.
func TestEKSPodIdentity_DeleteForeignRefuses(t *testing.T) {
	f := newFakePodID()
	f.exists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Delete("eks-podidentity", eksPodIDCap, "prod", podIDPID(), "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign association delete must refuse, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("no delete may touch a foreign association; saw %v", f.order)
	}
}

// TestEKSPodIdentity_MissingOperandRefuses: refuse-BEFORE-mutate — a missing
// required operand (roleArn) and a missing required attribute
// (workload.serviceAccount) are caught by the builder, before any EKS call, at BOTH
// Create and Validate.
func TestEKSPodIdentity_MissingOperandRefuses(t *testing.T) {
	f := newFakePodID()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	attrs, impl := podIDCandidate()
	delete(impl, "roleArn")
	res := d.Create("eks-podidentity", eksPodIDCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "roleArn") {
		t.Fatalf("missing roleArn must refuse with a roleArn reason, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("refuse-before-mutate must issue no EKS call; saw %v", f.order)
	}
	if err := d.Validate("eks-podidentity", eksPodIDCap, "prod", attrs, impl, 1); err == nil {
		t.Fatal("Validate must refuse a candidate with no roleArn")
	}

	attrs2, impl2 := podIDCandidate()
	delete(attrs2, "workload.serviceAccount")
	if err := d.Validate("eks-podidentity", eksPodIDCap, "prod", attrs2, impl2, 1); err == nil || !strings.Contains(err.Error(), "serviceAccount") {
		t.Fatalf("missing workload.serviceAccount must refuse, got %v", err)
	}
}

// TestEKSPodIdentity_UnmappedAttributeRefuses: an attribute with no
// identity.podidentity mapping is REFUSED (never silently dropped).
func TestEKSPodIdentity_UnmappedAttributeRefuses(t *testing.T) {
	attrs, impl := podIDCandidate()
	attrs["addon.name"] = "vpc-cni" // not an identity.podidentity attribute
	if _, err := BuildEKSPodIdentity("prod", eksPodIDCap, attrs, impl, 1); err == nil {
		t.Fatal("an unmapped attribute must be refused, not silently dropped")
	}
}

// TestEKSPodIdentity_ClassifyChange: namespace + serviceAccount are the identity
// (immutable); service.managed is unsupported. Every path carries a reason.
func TestEKSPodIdentity_ClassifyChange(t *testing.T) {
	d := NewDriver("eu-central-1")
	want := map[string]string{
		"workload.namespace":      "immutable",
		"workload.serviceAccount": "immutable",
		"service.managed":         "unsupported",
	}
	for p, w := range want {
		got, reason := d.ClassifyChange("eks-podidentity", p, nil, nil, nil)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// TestEKSPodIdentity_Discover: ListClusters -> ListPodIdentityAssociations per
// cluster -> per-association reverse map, surfacing the association as
// capability.identity.podidentity for adoption.
func TestEKSPodIdentity_Discover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clusters":
			_, _ = w.Write([]byte(`{"clusters":["acme-prod"]}`))
		case "/clusters/acme-prod/pod-identity-associations":
			_, _ = w.Write([]byte(`{"associations":[{"associationId":"a-1","namespace":"kube-system","serviceAccount":"ebs-csi-controller-sa"}]}`))
		case "/clusters/acme-prod/pod-identity-associations/a-1":
			_, _ = w.Write([]byte(`{"association":{"associationId":"a-1","namespace":"kube-system","serviceAccount":"ebs-csi-controller-sa","roleArn":"arn:aws:iam::000000000000:role/ebs-csi"}}`))
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	d := eksDriver(t, srv)

	found, _, err := d.discoverEKSPodIdentity("eu-central-1")
	if err != nil {
		t.Fatalf("discoverEKSPodIdentity: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 discovered association, got %d", len(found))
	}
	if found[0].ProviderID != podIDPID() {
		t.Fatalf("providerId = %q, want %q", found[0].ProviderID, podIDPID())
	}
	if found[0].ResourceType != "capability.identity.podidentity" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
}
