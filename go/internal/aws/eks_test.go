package aws

import (
	"encoding/json"
	"fmt"
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

// eksDriver points the EKS endpoint at a stub and supplies signing creds.
func eksDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.EKSBaseURL = srv.URL
	return d
}

func eksObsMap(t *testing.T, d *Driver, pid string) map[string]any {
	t.Helper()
	obs, _, err := d.observeEKS("", pid)
	if err != nil {
		t.Fatalf("observeEKS: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	return m
}

// TestObserveEKSReverseMap: a mixed-endpoint, secrets-encrypted cluster maps to the
// governed capability attributes — SigV4-signed DescribeCluster, EU residency.
func TestObserveEKSReverseMap(t *testing.T) {
	var sawSigV4 bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			sawSigV4 = true
		}
		if r.URL.Path != "/clusters/acme-prod" {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"cluster":{"version":"1.29",
		  "resourcesVpcConfig":{"endpointPublicAccess":true,"endpointPrivateAccess":true},
		  "encryptionConfig":[{"resources":["secrets"]}]}}`)
	}))
	defer srv.Close()
	d := eksDriver(t, srv)

	m := eksObsMap(t, d, "eks:eu-central-1:acme-prod")
	if !sawSigV4 {
		t.Fatal("DescribeCluster must be SigV4-signed")
	}
	if m["location.region"] != "eu-central-1" {
		t.Fatalf("region = %v, want eu-central-1 (EU residency)", m["location.region"])
	}
	if m["cluster.version"] != "1.29" {
		t.Fatalf("version = %v", m["cluster.version"])
	}
	if m["network.apiExposure"] != "mixed" {
		t.Fatalf("apiExposure = %v, want mixed (public+private)", m["network.apiExposure"])
	}
	if m["encryption.secrets"] != true {
		t.Fatalf("encryption.secrets = %v, want true", m["encryption.secrets"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed missing")
	}
}

// TestObserveEKSExposureVariants: the endpoint-access flags map to public/private.
func TestObserveEKSExposureVariants(t *testing.T) {
	for _, tc := range []struct {
		pub, priv bool
		want      string
	}{
		{true, false, "public"},
		{false, true, "private"},
		{true, true, "mixed"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, `{"cluster":{"version":"1.29","resourcesVpcConfig":{"endpointPublicAccess":%t,"endpointPrivateAccess":%t}}}`, tc.pub, tc.priv)
		}))
		d := eksDriver(t, srv)
		m := eksObsMap(t, d, "eks:eu-central-1:c")
		if m["network.apiExposure"] != tc.want {
			t.Errorf("pub=%t priv=%t -> %v, want %v", tc.pub, tc.priv, m["network.apiExposure"], tc.want)
		}
		if m["encryption.secrets"] != false {
			t.Errorf("no encryptionConfig must map to secrets=false, got %v", m["encryption.secrets"])
		}
		srv.Close()
	}
}

// TestObserveEKSUnreadableIsError: a transport/permission failure is unknown (an
// error), never a fabricated absence.
func TestObserveEKSUnreadableIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	d := eksDriver(t, srv)
	if _, _, err := d.observeEKS("", "eks:eu-central-1:c"); err == nil {
		t.Fatal("a 403 must be an error (unknown), never a fabricated absence")
	}
}

// TestDiscoverEKS: ListClusters -> per-cluster reverse map, surfacing the cluster
// as capability.cluster.kubernetes for adoption.
func TestDiscoverEKS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/clusters":
			fmt.Fprint(w, `{"clusters":["acme-prod"]}`)
		case "/clusters/acme-prod":
			fmt.Fprint(w, `{"cluster":{"version":"1.29","resourcesVpcConfig":{"endpointPrivateAccess":true}}}`)
		default:
			http.Error(w, "nf", http.StatusNotFound)
		}
	}))
	defer srv.Close()
	d := eksDriver(t, srv)

	found, _, err := d.discoverEKS("eu-central-1")
	if err != nil {
		t.Fatalf("discoverEKS: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 discovered cluster, got %d", len(found))
	}
	if found[0].ProviderID != "eks:eu-central-1:acme-prod" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.cluster.kubernetes" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
}

// --- PROVISIONING (slice 2, D147): the CLUSTER + one managed NODE GROUP composite ---

const eksCap = "capability.cluster.kubernetes"

var (
	eksTestName = eksCompositeName("prod", eksCap, 1)
	eksTestNG   = eksTestName + "-ng"
)

// fakeEKS is a stateful fake EKS (REST-JSON) endpoint that also answers EC2
// DescribeSubnets (so the same server backs both the EKS base and the EC2 base). It
// records the ORDER of mutating actions, tracks the cluster + node group as they
// land and are torn down, captures the CreateCluster body, and can inject a
// node-group status to exercise the partial-failure -> unknown path.
type fakeEKS struct {
	mu sync.Mutex

	name   string
	ngName string

	clusterExists bool
	ngExists      bool
	tags          map[string]string
	clusterStatus string
	ngStatus      string
	clusterBody   string // captured CreateCluster JSON
	roleErr400    int    // D281: first N CreateCluster calls answer the IAM-propagation 400

	ngSubnets  []string
	azBySubnet map[string]string

	order []string
}

func newFakeEKS() *fakeEKS {
	return &fakeEKS{
		name: eksTestName, ngName: eksTestNG,
		tags:          map[string]string{},
		clusterStatus: "ACTIVE",
		ngStatus:      "ACTIVE",
		azBySubnet:    map[string]string{},
	}
}

func (f *fakeEKS) handler(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
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
		case p == "/" && m == http.MethodPost: // EC2 DescribeSubnets (Query protocol)
			out := `<DescribeSubnetsResponse><subnetSet>`
			for _, s := range f.ngSubnets {
				out += `<item><subnetId>` + s + `</subnetId><availabilityZone>` + f.azBySubnet[s] + `</availabilityZone></item>`
			}
			out += `</subnetSet></DescribeSubnetsResponse>`
			_, _ = w.Write([]byte(out))
		case p == "/clusters" && m == http.MethodPost:
			if f.roleErr400 > 0 {
				f.roleErr400--
				f.order = append(f.order, "CreateCluster400")
				http.Error(w, `{"message":"Role with arn: arn:aws:iam::000000000000:role/acme-eks-cluster-role could not be assumed because it does not exist or the trusted entity is not correct"}`, http.StatusBadRequest)
				return
			}
			f.order = append(f.order, "CreateCluster")
			f.clusterExists = true
			f.clusterBody = body
			_, _ = w.Write([]byte(`{"cluster":{"name":"` + f.name + `","status":"` + f.clusterStatus + `"}}`))
		case p == "/clusters/"+f.name && m == http.MethodGet:
			if !f.clusterExists {
				http.Error(w, `{"message":"No cluster found"}`, http.StatusNotFound)
				return
			}
			cj, _ := json.Marshal(map[string]any{"cluster": map[string]any{
				"name":    f.name,
				"status":  f.clusterStatus,
				"version": "1.29",
				"resourcesVpcConfig": map[string]any{
					"endpointPublicAccess": true, "endpointPrivateAccess": true},
				"tags": f.tags,
			}})
			_, _ = w.Write(cj)
		case p == "/clusters/"+f.name && m == http.MethodDelete:
			f.order = append(f.order, "DeleteCluster")
			f.clusterExists = false
			_, _ = w.Write([]byte(`{}`))
		case p == "/clusters/"+f.name+"/node-groups" && m == http.MethodPost:
			f.order = append(f.order, "CreateNodegroup")
			f.ngExists = true
			_, _ = w.Write([]byte(`{"nodegroup":{"nodegroupName":"` + f.ngName + `","status":"` + f.ngStatus + `"}}`))
		case p == "/clusters/"+f.name+"/node-groups" && m == http.MethodGet:
			if f.ngExists {
				_, _ = w.Write([]byte(`{"nodegroups":["` + f.ngName + `"]}`))
			} else {
				_, _ = w.Write([]byte(`{"nodegroups":[]}`))
			}
		case p == "/clusters/"+f.name+"/node-groups/"+f.ngName && m == http.MethodGet:
			if !f.ngExists {
				http.Error(w, `{"message":"No node group found"}`, http.StatusNotFound)
				return
			}
			sub, _ := json.Marshal(f.ngSubnets)
			_, _ = w.Write([]byte(`{"nodegroup":{"status":"` + f.ngStatus + `","subnets":` + string(sub) + `}}`))
		case p == "/clusters/"+f.name+"/node-groups/"+f.ngName && m == http.MethodDelete:
			f.order = append(f.order, "DeleteNodegroup")
			f.ngExists = false
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	}))
}

func eksProvDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.EKSBaseURL = srv.URL
	d.EC2BaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = 0
	d.PollTimeout = 2 * time.Second
	d.EKSLROTimeout = 2 * time.Second // keep EKS long-poll timeout paths fast in tests (D264)
	return d
}

// eksCandidate: a mixed-exposure, secrets-encrypted cluster. The attributes drive
// the SHAPE; the impl block supplies the operands (roles, subnets, KMS key, node
// group). instanceTypes/sizes are float64 to mirror JSON-decoded candidates.
func eksCandidate() (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region":     "eu-central-1",
		"cluster.version":     "1.29",
		"network.apiExposure": "mixed",
		"encryption.secrets":  true,
		"service.managed":     true,
		"availability.class":  "regional",
	}
	impl = map[string]any{
		"clusterRoleArn":   "arn:aws:iam::000000000000:role/eks-cluster",
		"subnetIds":        []any{"subnet-aaa", "subnet-bbb"},
		"securityGroupIds": []any{"sg-123"},
		"kmsKeyArn":        "arn:aws:kms:eu-central-1:000000000000:key/abc-123",
		"nodeRoleArn":      "arn:aws:iam::000000000000:role/eks-node",
		"nodeGroup": map[string]any{
			"instanceTypes": []any{"t3.medium"},
			"minSize":       float64(1),
			"desiredSize":   float64(2),
			"maxSize":       float64(3),
		},
	}
	return
}

// TestEKSComposite_FullCreateSucceeds: CreateCluster -> poll ACTIVE -> CreateNodegroup
// -> poll ACTIVE -> succeeded WITH the pid. The CreateCluster body carries the
// version, the endpoint-exposure flags (mixed = both true), the secrets
// encryptionConfig, and the ownership tags. Every request is SigV4-signed.
func TestEKSComposite_FullCreateSucceeds(t *testing.T) {
	f := newFakeEKS()
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := eksCandidate()

	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != eksProviderID("eu-central-1", eksTestName) {
		t.Fatalf("create providerId = %q", res.ProviderID)
	}
	if strings.Join(f.order, ",") != "CreateCluster,CreateNodegroup" {
		t.Fatalf("create order = %v, want [CreateCluster CreateNodegroup]", f.order)
	}
	// CreateCluster body assertions.
	var cb map[string]any
	if err := json.Unmarshal([]byte(f.clusterBody), &cb); err != nil {
		t.Fatalf("CreateCluster body not JSON: %v", err)
	}
	if cb["version"] != "1.29" {
		t.Fatalf("body version = %v, want 1.29", cb["version"])
	}
	vpc, _ := cb["resourcesVpcConfig"].(map[string]any)
	if vpc["endpointPublicAccess"] != true || vpc["endpointPrivateAccess"] != true {
		t.Fatalf("mixed exposure must set both endpoint flags true, got %+v", vpc)
	}
	enc, ok := cb["encryptionConfig"].([]any)
	if !ok || len(enc) != 1 {
		t.Fatalf("encryption.secrets=true must emit one encryptionConfig entry, got %v", cb["encryptionConfig"])
	}
	tags, _ := cb["tags"].(map[string]any)
	if tags["groundhold-capability"] != sanitizeTag(eksCap) || tags["groundhold-environment"] != sanitizeTag("prod") {
		t.Fatalf("ownership tags missing/wrong: %+v", tags)
	}
	if rec.unsign != 0 {
		t.Fatalf("every EKS/EC2 request must be SigV4-signed; %d were not", rec.unsign)
	}
}

// TestEKSComposite_NodeGroupFailsIsPartialUnknown: the four-valued crux — the
// CLUSTER lands ACTIVE but the managed node group enters CREATE_FAILED. The result
// must be unknown WITH the providerId (a half-provisioned cluster to reconcile),
// never a bare "failed" that implies nothing was created.
func TestEKSComposite_NodeGroupFailsIsPartialUnknown(t *testing.T) {
	f := newFakeEKS()
	f.ngStatus = "CREATE_FAILED"
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := eksCandidate()

	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "unknown" {
		t.Fatalf("cluster ACTIVE + node group failed must be unknown, got %q (%s)", res.Status, res.Reason)
	}
	if res.ProviderID != eksProviderID("eu-central-1", eksTestName) {
		t.Fatalf("partial-failure unknown must carry the providerId, got %q", res.ProviderID)
	}
	if !f.clusterExists {
		t.Fatal("the cluster should have landed before the node-group failure")
	}
	// the cluster WAS created (never a 'failed' that hides it).
	sawCreateCluster := false
	for _, o := range f.order {
		if o == "CreateCluster" {
			sawCreateCluster = true
		}
	}
	if !sawCreateCluster {
		t.Fatalf("CreateCluster must have been issued; order = %v", f.order)
	}
}

// TestEKSComposite_DeleteReverseOrder: delete tears the composite down in REVERSE
// order — DeleteNodegroup (poll gone) then DeleteCluster (poll gone) — ownership-
// guarded, and succeeds.
func TestEKSComposite_DeleteReverseOrder(t *testing.T) {
	f := newFakeEKS()
	f.clusterExists = true
	f.ngExists = true
	f.tags = map[string]string{
		"groundhold-capability": sanitizeTag(eksCap), "groundhold-environment": sanitizeTag("prod")}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	res := d.Delete("eks", eksCap, "prod", eksProviderID("eu-central-1", eksTestName), "k")
	if res.Status != "succeeded" {
		t.Fatalf("delete status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if strings.Join(f.order, ",") != "DeleteNodegroup,DeleteCluster" {
		t.Fatalf("delete order = %v, want [DeleteNodegroup DeleteCluster] (reverse)", f.order)
	}
}

// TestEKSComposite_CreateForeignRefuses: a cluster already at our name whose
// ownership tags are NOT ours must not be adopted — refuse (failed), issue no
// mutation.
func TestEKSComposite_CreateForeignRefuses(t *testing.T) {
	f := newFakeEKS()
	f.clusterExists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := eksCandidate()

	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign cluster create must refuse, got %+v", res)
	}
	for _, o := range f.order {
		if strings.HasPrefix(o, "Create") || strings.HasPrefix(o, "Delete") {
			t.Fatalf("no mutation may touch a foreign cluster; saw %v", f.order)
		}
	}
}

// TestEKSCreate_MissingOperandRefuses: refuse-BEFORE-mutate — a missing required
// operand (nodeRoleArn) and the KMS key required by encryption.secrets are caught
// by the builder, before any EKS call, at BOTH Create and Validate.
func TestEKSCreate_MissingOperandRefuses(t *testing.T) {
	f := newFakeEKS()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	attrs, impl := eksCandidate()
	delete(impl, "nodeRoleArn")
	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "nodeRoleArn") {
		t.Fatalf("missing nodeRoleArn must refuse with a nodeRoleArn reason, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("refuse-before-mutate must issue no EKS call; saw %v", f.order)
	}
	if err := d.Validate("eks", eksCap, "prod", attrs, impl, 1); err == nil {
		t.Fatal("Validate must refuse a candidate with no nodeRoleArn")
	}

	// encryption.secrets=true with no kmsKeyArn -> refuse.
	attrs2, impl2 := eksCandidate()
	delete(impl2, "kmsKeyArn")
	if err := d.Validate("eks", eksCap, "prod", attrs2, impl2, 1); err == nil || !strings.Contains(err.Error(), "kmsKeyArn") {
		t.Fatalf("secrets encryption with no KMS key must refuse, got %v", err)
	}
}

// TestEKSBuild_UnmappedAttributeRefuses: an attribute with no cluster.kubernetes
// mapping is REFUSED (never silently dropped).
func TestEKSBuild_UnmappedAttributeRefuses(t *testing.T) {
	attrs, impl := eksCandidate()
	attrs["network.publicExposure"] = true // not a cluster.kubernetes attribute
	if _, err := BuildEKS("prod", eksCap, attrs, impl, 1); err == nil {
		t.Fatal("an unmapped attribute must be refused, not silently dropped")
	}
}

// TestEKSObserve_AvailabilityFromNodeGroupAZs: observe derives availability.class
// from the node group's subnet AZ spread — two distinct AZs -> "regional".
func TestEKSObserve_AvailabilityFromNodeGroupAZs(t *testing.T) {
	f := newFakeEKS()
	f.clusterExists = true
	f.ngExists = true
	f.ngSubnets = []string{"subnet-aaa", "subnet-bbb"}
	f.azBySubnet = map[string]string{"subnet-aaa": "eu-central-1a", "subnet-bbb": "eu-central-1b"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)

	obs, _, err := d.Observe("eks", eksCap, eksProviderID("eu-central-1", eksTestName))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["availability.class"] != "regional" {
		t.Fatalf("two-AZ node group must map to availability.class=regional, got %v", m["availability.class"])
	}
}

// TestEKSClassifyChange: version + apiExposure are MUTABLE in place (slice 3, LRO
// updates); encryption.secrets stays unsupported (enable is one-way, disable
// impossible — groundhold will not replace a stateful cluster). Every path carries a
// reason.
func TestEKSClassifyChange(t *testing.T) {
	d := NewDriver("eu-central-1")
	want := map[string]string{
		"cluster.version":     "mutable",
		"network.apiExposure": "mutable",
		"encryption.secrets":  "unsupported",
		"availability.class":  "unsupported",
	}
	for p, w := range want {
		got, reason := d.ClassifyChange("eks", p, nil, nil, nil)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// TestEKSUpdateVersion: an in-place version bump (slice 3) POSTs UpdateClusterVersion,
// polls the update to Successful, and succeeds — ownership tags gate the patch.
func TestEKSUpdateVersion(t *testing.T) {
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/updates/u1"):
			fmt.Fprint(w, `{"update":{"status":"Successful"}}`)
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/updates"):
			b, _ := io.ReadAll(r.Body)
			posted = string(b)
			fmt.Fprint(w, `{"update":{"id":"u1"}}`)
		case r.Method == "GET": // DescribeCluster — ownership pre-read
			fmt.Fprint(w, `{"cluster":{"status":"ACTIVE","version":"1.29","tags":{"groundhold-capability":"cluster","groundhold-environment":"production"}}}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := eksDriver(t, srv)
	d.PollInterval = 0

	cr := d.Update("eks", "cluster", "production", "eks:eu-central-1:acme-prod",
		map[string]any{"cluster.version": "1.30"}, nil, []string{"cluster.version"}, "k")
	if cr.Status != "succeeded" || cr.ProviderID != "eks:eu-central-1:acme-prod" {
		t.Fatalf("version update must succeed with the pid, got %+v", cr)
	}
	if !strings.Contains(posted, `"version":"1.30"`) {
		t.Fatalf("UpdateClusterVersion body must carry the version: %s", posted)
	}
}

// TestEKSUpgradeRollsNodegroup (D248): a control-plane version bump ALSO rolls the
// managed node group to the same version — control plane FIRST (polled to
// Successful), THEN UpdateNodegroupVersion, then poll. A node group already at the
// target is SKIPPED (idempotent, so a re-run after a partial roll converges).
func TestEKSUpgradeRollsNodegroup(t *testing.T) {
	var order []string
	var ngPosted string
	var ngRolled bool // D273: the node group reaches the target version AFTER the roll POST
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, m := r.URL.Path, r.Method
		switch {
		case m == "POST" && strings.HasSuffix(p, "/node-groups/acme-prod-ng/update-version"):
			order = append(order, "ng-update")
			b, _ := io.ReadAll(r.Body)
			ngPosted = string(b)
			ngRolled = true // the node group now transitions to the target version
			fmt.Fprint(w, `{"update":{"id":"ngu1"}}`)
		case m == "POST" && strings.HasSuffix(p, "/node-groups/acme-prod-ng2/update-version"):
			order = append(order, "ng2-update-SHOULD-NOT-HAPPEN")
			fmt.Fprint(w, `{"update":{"id":"ngu2"}}`)
		case m == "GET" && strings.HasSuffix(p, "/node-groups/acme-prod-ng"):
			// D273: the driver polls the NODE GROUP's observable version (not a nonexistent
			// /updates/<id> path). Stale 1.29 before the roll -> ACTIVE 1.30 after it.
			if ngRolled {
				fmt.Fprint(w, `{"nodegroup":{"status":"ACTIVE","version":"1.30"}}`)
			} else {
				fmt.Fprint(w, `{"nodegroup":{"status":"ACTIVE","version":"1.29"}}`)
			}
		case m == "GET" && strings.HasSuffix(p, "/node-groups/acme-prod-ng2"):
			fmt.Fprint(w, `{"nodegroup":{"status":"ACTIVE","version":"1.30"}}`) // current -> skip
		case m == "GET" && strings.HasSuffix(p, "/node-groups"):
			fmt.Fprint(w, `{"nodegroups":["acme-prod-ng","acme-prod-ng2"]}`)
		case m == "GET" && strings.HasSuffix(p, "/updates/u1"):
			fmt.Fprint(w, `{"update":{"status":"Successful"}}`) // control-plane update poll (real path)
		case m == "POST" && strings.HasSuffix(p, "/updates"):
			order = append(order, "cp-update")
			fmt.Fprint(w, `{"update":{"id":"u1"}}`)
		case m == "GET" && p == "/clusters/acme-prod": // DescribeCluster ownership pre-read
			fmt.Fprint(w, `{"cluster":{"status":"ACTIVE","version":"1.29","tags":{"groundhold-capability":"cluster","groundhold-environment":"production"}}}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := eksDriver(t, srv)
	d.PollInterval = 0
	d.EKSLROTimeout = 2 * time.Second // a poll that never terminates fails fast, never hangs the suite

	cr := d.Update("eks", "cluster", "production", "eks:eu-central-1:acme-prod",
		map[string]any{"cluster.version": "1.30"}, nil, []string{"cluster.version"}, "k")
	if cr.Status != "succeeded" || cr.ProviderID != "eks:eu-central-1:acme-prod" {
		t.Fatalf("upgrade must succeed with the pid, got %+v", cr)
	}
	// ordering: control plane bump strictly BEFORE the node-group roll.
	if len(order) < 2 || order[0] != "cp-update" || order[1] != "ng-update" {
		t.Fatalf("control plane must upgrade before the node group; order=%v", order)
	}
	// the already-current node group (ng2) must be skipped, never rolled.
	for _, o := range order {
		if strings.Contains(o, "SHOULD-NOT-HAPPEN") {
			t.Fatalf("a node group already at the target version must be skipped; order=%v", order)
		}
	}
	if !strings.Contains(ngPosted, `"version":"1.30"`) {
		t.Fatalf("UpdateNodegroupVersion must carry the target version: %s", ngPosted)
	}
}

// TestEKSUpgradeNodegroupPartialIsUnknown: if the control plane upgrades but a
// node-group roll fails, the result is unknown WITH the pid (a half-upgraded
// cluster to reconcile), never a bare success or failed.
func TestEKSUpgradeNodegroupPartialIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, m := r.URL.Path, r.Method
		switch {
		case m == "POST" && strings.HasSuffix(p, "/node-groups/acme-prod-ng/update-version"):
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"message":"nodegroup upgrade rejected"}`)
		case m == "GET" && strings.HasSuffix(p, "/node-groups/acme-prod-ng"):
			fmt.Fprint(w, `{"nodegroup":{"status":"ACTIVE","version":"1.29"}}`)
		case m == "GET" && strings.HasSuffix(p, "/node-groups"):
			fmt.Fprint(w, `{"nodegroups":["acme-prod-ng"]}`)
		case m == "GET" && strings.HasSuffix(p, "/updates/u1"):
			fmt.Fprint(w, `{"update":{"status":"Successful"}}`)
		case m == "POST" && strings.HasSuffix(p, "/updates"):
			fmt.Fprint(w, `{"update":{"id":"u1"}}`)
		case m == "GET" && p == "/clusters/acme-prod":
			fmt.Fprint(w, `{"cluster":{"status":"ACTIVE","version":"1.29","tags":{"groundhold-capability":"cluster","groundhold-environment":"production"}}}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := eksDriver(t, srv)
	d.PollInterval = 0

	cr := d.Update("eks", "cluster", "production", "eks:eu-central-1:acme-prod",
		map[string]any{"cluster.version": "1.30"}, nil, []string{"cluster.version"}, "k")
	if cr.Status != "unknown" || cr.ProviderID != "eks:eu-central-1:acme-prod" {
		t.Fatalf("a failed node-group roll after a control-plane bump must be unknown WITH the pid, got %+v", cr)
	}
}

// TestEKSUpdateForeignRefuses: an in-place update on a cluster whose tags are not
// ours is refused before any patch.
func TestEKSUpdateForeignRefuses(t *testing.T) {
	var mutated bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			mutated = true
		}
		fmt.Fprint(w, `{"cluster":{"status":"ACTIVE","version":"1.29","tags":{"team":"someone-else"}}}`)
	}))
	defer srv.Close()
	d := eksDriver(t, srv)
	d.PollInterval = 0

	cr := d.Update("eks", "cluster", "production", "eks:eu-central-1:acme-prod",
		map[string]any{"cluster.version": "1.30"}, nil, []string{"cluster.version"}, "k")
	if cr.Status != "failed" {
		t.Fatalf("a foreign cluster must refuse the update, got %+v", cr)
	}
	if mutated {
		t.Fatal("no update must be issued to a foreign cluster")
	}
}

// TestEKSAdoptExistingClusterBindsRealNodegroup pins D258: adopting an existing
// cluster whose real node group has a DIFFERENT name than the deterministic
// plan.NodeGroupName must LIST the real node groups, see one ACTIVE, and bind the
// composite — never poll the wrong name forever (the Acme hang) and never POST a
// duplicate node group.
func TestEKSAdoptExistingClusterBindsRealNodegroup(t *testing.T) {
	capTag := sanitizeTag(eksCap)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, m := r.URL.Path, r.Method
		switch {
		case m == "GET" && p == "/clusters/"+eksTestName: // ownership pre-read + wait ACTIVE
			fmt.Fprintf(w, `{"cluster":{"status":"ACTIVE","version":"1.29",`+
				`"tags":{"groundhold-capability":%q,"groundhold-environment":"prod"}}}`, capTag)
		case m == "GET" && p == "/clusters/"+eksTestName+"/node-groups": // LIST real names
			fmt.Fprint(w, `{"nodegroups":["acme-ng"]}`) // NOT the deterministic <cluster>-ng
		case m == "GET" && p == "/clusters/"+eksTestName+"/node-groups/acme-ng":
			fmt.Fprint(w, `{"nodegroup":{"status":"ACTIVE","version":"1.29"}}`)
		case m == "POST":
			t.Errorf("adopt must not POST %s — the cluster already has an ACTIVE node group (no duplicate)", p)
			w.WriteHeader(400)
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := eksCandidate()
	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" || res.ProviderID != eksProviderID("eu-central-1", eksTestName) {
		t.Fatalf("adopt must bind the existing cluster+node group (no hang, no duplicate), got %+v", res)
	}
}

// TestEKSAdoptNodegroupDescribeInconclusiveStillBinds pins D259: Acme's second hang.
// The cluster is ACTIVE + ours and ListNodegroups returns a real node group, but
// DescribeNodegroup never reports ACTIVE (here a 404 — an inconclusive describe of a
// genuinely running node group). The adopt path must BIND on existence in a single
// pass (succeeded WITH the pid), never spin to the poll timeout. With PollTimeout=2s
// a reintroduced loop would return unknown here — so asserting succeeded guards the
// regression.
func TestEKSAdoptNodegroupDescribeInconclusiveStillBinds(t *testing.T) {
	capTag := sanitizeTag(eksCap)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, m := r.URL.Path, r.Method
		switch {
		case m == "GET" && p == "/clusters/"+eksTestName:
			fmt.Fprintf(w, `{"cluster":{"status":"ACTIVE","version":"1.33",`+
				`"tags":{"groundhold-capability":%q,"groundhold-environment":"prod"}}}`, capTag)
		case m == "GET" && p == "/clusters/"+eksTestName+"/node-groups":
			fmt.Fprint(w, `{"nodegroups":["acme-ng"]}`)
		case m == "GET" && p == "/clusters/"+eksTestName+"/node-groups/acme-ng":
			w.WriteHeader(http.StatusNotFound) // describe never confirms ACTIVE
		case m == "POST":
			t.Errorf("adopt must not POST %s — the cluster already has a node group (no duplicate)", p)
			w.WriteHeader(400)
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := eksCandidate()
	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" || res.ProviderID != eksProviderID("eu-central-1", eksTestName) {
		t.Fatalf("adopt must bind on existence when describe is inconclusive (no hang), got %+v", res)
	}
}

// TestEKSAdoptNodegroupDegradedIsUnknown pins the honest downgrade: an adopted
// cluster whose node group is positively DEGRADED (and none ACTIVE) binds the pid but
// concludes unknown for reconcile — never a false success, and still never a hang.
func TestEKSAdoptNodegroupDegradedIsUnknown(t *testing.T) {
	capTag := sanitizeTag(eksCap)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, m := r.URL.Path, r.Method
		switch {
		case m == "GET" && p == "/clusters/"+eksTestName:
			fmt.Fprintf(w, `{"cluster":{"status":"ACTIVE","version":"1.33",`+
				`"tags":{"groundhold-capability":%q,"groundhold-environment":"prod"}}}`, capTag)
		case m == "GET" && p == "/clusters/"+eksTestName+"/node-groups":
			fmt.Fprint(w, `{"nodegroups":["acme-ng"]}`)
		case m == "GET" && p == "/clusters/"+eksTestName+"/node-groups/acme-ng":
			fmt.Fprint(w, `{"nodegroup":{"status":"DEGRADED","version":"1.33"}}`)
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := eksCandidate()
	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "unknown" || res.ProviderID != eksProviderID("eu-central-1", eksTestName) {
		t.Fatalf("a positively DEGRADED adopted node group must be unknown WITH the pid, got %+v", res)
	}
}

// TestDriverProgressHook pins D257: the intra-action heartbeat sink is called when
// set and is a safe no-op when nil (the executor sets/clears it per action).
func TestDriverProgressHook(t *testing.T) {
	d := NewDriver("eu-central-1")
	var got []string
	d.SetProgress(func(phase string) { got = append(got, phase) })
	d.progress("cluster upgrading")
	if len(got) != 1 || got[0] != "cluster upgrading" {
		t.Fatalf("progress sink not invoked: %v", got)
	}
	d.SetProgress(nil)
	d.progress("should be dropped") // must not panic, must not append
	if len(got) != 1 {
		t.Fatalf("a nil sink must be a no-op, got %v", got)
	}
}

// --- D261: adopt-by-explicit-name (the real Acme duplicate bug) ---

// fakeEKSNamed is a fake serving a cluster under an arbitrary CUSTOM name (e.g.
// "acme"), like a brownfield eksctl cluster that does NOT carry the deterministic
// eks-prod-<hash> name.
func newFakeEKSNamed(name string, exists, owned bool) *fakeEKS {
	f := newFakeEKS()
	f.name = name
	f.ngName = name + "-ng"
	f.clusterExists = exists
	f.ngExists = exists
	if owned {
		f.tags = map[string]string{
			"groundhold-capability":  sanitizeTag(eksCap),
			"groundhold-environment": sanitizeTag("prod"),
		}
	}
	return f
}

// adoptByNameCandidate: a MINIMAL adopt candidate — clusterName operand + the governed
// version, NO create operands (role/subnets/nodeGroup). This is what a brownfield
// adopt looks like.
func adoptByNameCandidate(name string) (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region": "eu-central-1",
		"cluster.version": "1.29",
		"service.managed": true,
	}
	impl = map[string]any{"clusterName": name}
	return
}

// TestBuildEKSAdoptByNameMakesOperandsOptional pins D261: an explicit clusterName
// builds with AdoptByName=true and needs none of the create operands.
func TestBuildEKSAdoptByNameMakesOperandsOptional(t *testing.T) {
	attrs, impl := adoptByNameCandidate("acme")
	p, err := BuildEKS("prod", eksCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("minimal adopt candidate must build, got %v", err)
	}
	if !p.AdoptByName || p.Name != "acme" {
		t.Fatalf("plan = %+v (want AdoptByName, Name=acme)", p)
	}
	// a GREENFIELD candidate (no clusterName) still requires the operands.
	if _, err := BuildEKS("prod", eksCap, map[string]any{
		"location.region": "eu-central-1", "cluster.version": "1.29", "service.managed": true,
	}, nil, 1); err == nil {
		t.Fatal("a greenfield build with no operands must still refuse")
	}
}

// TestEKSAdoptByNameBindsExistingOwned pins the happy adopt: an existing owned
// custom-named cluster is BOUND by its real name (no CreateCluster, no duplicate).
func TestEKSAdoptByNameBindsExistingOwned(t *testing.T) {
	f := newFakeEKSNamed("acme", true, true)
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := adoptByNameCandidate("acme")
	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" || res.ProviderID != eksProviderID("eu-central-1", "acme") {
		t.Fatalf("adopt by name must bind eks:eu-central-1:acme, got %+v", res)
	}
	for _, a := range f.order {
		if a == "CreateCluster" {
			t.Fatalf("adopt by name must NEVER CreateCluster (the duplicate bug), order=%v", f.order)
		}
	}
}

// TestEKSAdoptByNameAbsentRefusesNeverDuplicates is the anti-duplicate core: an
// explicit adopt name that resolves to NO cluster must REFUSE, never create one.
func TestEKSAdoptByNameAbsentRefusesNeverDuplicates(t *testing.T) {
	f := newFakeEKSNamed("acme", false, false) // named cluster does not exist
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := adoptByNameCandidate("acme")
	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "adoption name") {
		t.Fatalf("an absent adopt name must refuse (never create), got %+v", res)
	}
	for _, a := range f.order {
		if a == "CreateCluster" {
			t.Fatalf("refusing an absent adopt name must NOT CreateCluster, order=%v", f.order)
		}
	}
}

// TestEKSAdoptByNameForeignRefused: an existing custom-named cluster that is NOT ours
// is refused (never adopted silently, never duplicated), pointing at the adopt flow.
func TestEKSAdoptByNameForeignRefused(t *testing.T) {
	f := newFakeEKSNamed("acme", true, false) // exists but not our tags
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	attrs, impl := adoptByNameCandidate("acme")
	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign named cluster must refuse, got %+v", res)
	}
}

// TestEKSLROTimeoutExceedsPollTimeout pins D264: the EKS long-running-operation
// ceiling must be well above the generic 20-min PollTimeout, because a real
// control-plane minor-version upgrade (1.33->1.34) routinely runs 20-40 min — a
// shorter ceiling would trip on a HEALTHY, still-progressing upgrade and report a
// false unknown (exit 4, converge DIED). Also pins the zero-value fallback.
func TestEKSLROTimeoutExceedsPollTimeout(t *testing.T) {
	d := NewDriver("eu-central-1")
	if d.EKSLROTimeout < 45*time.Minute {
		t.Fatalf("EKS LRO timeout must be >=45m for a 20-40m control-plane upgrade, got %v", d.EKSLROTimeout)
	}
	if d.eksLROTimeout() <= d.PollTimeout {
		t.Fatalf("eksLROTimeout() (%v) must exceed the generic PollTimeout (%v)", d.eksLROTimeout(), d.PollTimeout)
	}
	// zero EKSLROTimeout falls back to PollTimeout (the test-fast path).
	d.EKSLROTimeout = 0
	if d.eksLROTimeout() != d.PollTimeout {
		t.Fatalf("unset EKSLROTimeout must fall back to PollTimeout, got %v", d.eksLROTimeout())
	}
}

// eksRole classifies EKS REST-JSON requests structurally for the honesty harness: a
// GET is a read, everything else a mutation.
func eksRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestReadStormEKS enrolls EKS in the cross-driver read-retry gate (D266): a greenfield
// create whose first reads throttle must still succeed, because eksGet retries the
// transient class. A regression dropping the retry fails here.
func TestReadStormEKS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	attrs, impl := eksCandidate()
	p := &certifynet.Probe{
		AssertTransient: true, // D237 sweep
		Name:            "aws/eks",
		Classify:        eksRole,
		// F-LC3 (D523): hand-wired.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("eks", eksCap, eksProviderID("eu-central-1", eksTestName))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000"
			d.EKSBaseURL = happyURL
			d.EC2BaseURL = happyURL
			d.PollInterval = 0
			d.PollTimeout = 2 * time.Second
			d.EKSLROTimeout = 2 * time.Second
			return d
		},
		Ops: []certifynet.Op{{
			Name:  "create",
			Happy: func() *httptest.Server { return newFakeEKS().handler(t, nil) },
			Run: func(pr provider.Provider) provider.CreateResult {
				return pr.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
			},
		}},
	}
	certifynet.CertifyReadRetry(t, p)
}

// TestBoundedPollEKS enrolls EKS in the bounded-poll gate (D266): a cluster that never
// leaves CREATING must conclude unknown-with-pid within the LRO budget, never hang.
func TestBoundedPollEKS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	attrs, impl := eksCandidate()
	p := &certifynet.LifecycleProbe{
		Name: "aws/eks",
		StuckServer: func() *httptest.Server {
			f := newFakeEKS()
			f.clusterStatus = "CREATING" // never reaches ACTIVE
			return f.handler(t, nil)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000"
			d.EKSBaseURL = happyURL
			d.EC2BaseURL = happyURL
			d.PollInterval = 0
			d.PollTimeout = time.Second
			d.EKSLROTimeout = time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
		},
		PID: eksProviderID("eu-central-1", eksTestName),
	}
	certifynet.CertifyBoundedPoll(t, p)
}

// TestNoDuplicateEKS enrolls EKS in the no-duplicate gate (D267): a candidate that
// names a cluster to adopt (implementation.clusterName) which does NOT exist must
// refuse, sending zero mutations — never a duplicate (the Acme D261 root cause).
func TestNoDuplicateEKS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	attrs, impl := adoptByNameCandidate("acme")
	p := &certifynet.DuplicateProbe{
		Name:         "aws/eks",
		Classify:     eksRole,
		AbsentServer: func() *httptest.Server { return newFakeEKSNamed("acme", false, false).handler(t, nil) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000"
			d.EKSBaseURL = happyURL
			d.EC2BaseURL = happyURL
			d.PollInterval = 0
			d.PollTimeout = time.Second
			d.EKSLROTimeout = time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
		},
	}
	certifynet.CertifyNoDuplicate(t, p)
}

// TestApplyEKSUpdateRetriesTransient409 pins D270: a 409 "update in progress" (the
// transient post-update settling lock) is RETRIED into a successful update, not a DIED.
func TestApplyEKSUpdateRetriesTransient409(t *testing.T) {
	var posts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts++
			if posts <= 2 {
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"message":"Cluster is already undergoing an update"}`))
				return
			}
			_, _ = w.Write([]byte(`{"update":{"id":"u1"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"update":{"id":"u1","status":"Successful"}}`)) // GET poll
	}))
	defer srv.Close()
	d := eksProvDriver(t, srv)
	res := d.applyEKSUpdate("eu-central-1", eksProviderID("eu-central-1", "c"), "c", "/clusters/c/updates", []byte("{}"))
	if res != nil {
		t.Fatalf("a transient 409 must retry into a successful update (nil), got %+v", *res)
	}
	if posts < 3 {
		t.Fatalf("the 409 must be retried (>=3 posts), got %d", posts)
	}
}

// TestApplyEKSUpdatePersistent409IsUnknown: a 409 that never clears concludes unknown
// (reconcilable) at the LRO deadline, never a false success and never an infinite retry.
func TestApplyEKSUpdatePersistent409IsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"message":"Cluster is already undergoing an update"}`))
	}))
	defer srv.Close()
	d := eksProvDriver(t, srv)
	d.PollInterval = 10 * time.Millisecond // avoid a tight spin during the 2s deadline
	res := d.applyEKSUpdate("eu-central-1", eksProviderID("eu-central-1", "c"), "c", "/clusters/c/updates", []byte("{}"))
	if res == nil || res.Status != "unknown" {
		t.Fatalf("a persistent 409 must be unknown at the deadline, got %+v", res)
	}
}

// TestWaitEKSNodegroupUpdatePollsObservableState pins D273 (the real F29 root cause): the
// node-group version poll watches the NODE GROUP's observable Version+Status via a real
// endpoint, NOT the nonexistent /node-groups/<ng>/updates/<id> path the old code polled
// (which never returned "Successful" and spun to the LRO timeout even after AWS finished
// the roll — Acme's live hang). A request to any /updates/ path here is a regression.
func TestWaitEKSNodegroupUpdatePollsObservableState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/updates/") {
			t.Errorf("driver polled a nonexistent nodegroup-update endpoint %q — the D273 wrong-path bug", r.URL.Path)
		}
		if strings.HasSuffix(r.URL.Path, "/node-groups/ng") {
			fmt.Fprint(w, `{"nodegroup":{"status":"ACTIVE","version":"1.30"}}`) // rolled to target
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	d := eksProvDriver(t, srv)
	if res := d.waitEKSNodegroupUpdate("eu-central-1", "eks:eu-central-1:c", "c", "ng", "1.30"); res != nil {
		t.Fatalf("a node group ACTIVE at the target version must conclude done (nil), got %+v", *res)
	}
}

// TestWaitEKSNodegroupUpdateNeverReachesVersionIsUnknown: a node group that never rolls to
// the target concludes unknown at the (short, test) LRO timeout — bounded, never a hang.
func TestWaitEKSNodegroupUpdateNeverReachesVersionIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"nodegroup":{"status":"ACTIVE","version":"1.29"}}`) // never reaches 1.30
	}))
	defer srv.Close()
	d := eksProvDriver(t, srv) // EKSLROTimeout = 2s
	res := d.waitEKSNodegroupUpdate("eu-central-1", "eks:eu-central-1:c", "c", "ng", "1.30")
	if res == nil || res.Status != "unknown" {
		t.Fatalf("a node group that never reaches the target must be unknown at the timeout, got %+v", res)
	}
}

// D281: a role created in the SAME plan may not be visible to EKS yet (IAM is
// eventually consistent) — the role-assumption 400 retries within a bounded
// window and the create then lands; a role that never appears fails with the
// provider's own message, never an endless loop.
func TestCreateEKSRetriesIAMPropagation400(t *testing.T) {
	f := newFakeEKS()
	f.roleErr400 = 2
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	d.PollInterval = 0
	attrs, impl := eksCandidate()

	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create after transient role-400s = %q (%s), want succeeded", res.Status, res.Reason)
	}
	got := strings.Join(f.order, ",")
	if !strings.HasPrefix(got, "CreateCluster400,CreateCluster400,CreateCluster") {
		t.Fatalf("order = %v, want two retried 400s then the landing create", f.order)
	}
}

func TestCreateEKSPersistentRole400FailsBounded(t *testing.T) {
	f := newFakeEKS()
	f.roleErr400 = 1 << 30
	srv := f.handler(t, nil)
	defer srv.Close()
	d := eksProvDriver(t, srv)
	d.PollInterval = 0
	// a stepping clock: every Now() call advances 40s, so the 90s propagation
	// window is crossed after a few retries — bounded, no wall-clock sleep.
	base := time.Now()
	n := 0
	d.Now = func() time.Time { n++; return base.Add(time.Duration(n) * 40 * time.Second) }
	attrs, impl := eksCandidate()

	res := d.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "could not be assumed") {
		t.Fatalf("persistent role-400 must fail with AWS's message, got %q (%s)", res.Status, res.Reason)
	}
	if f.clusterExists {
		t.Fatal("no cluster may exist after a persistent role refusal")
	}
}

// TestAdoptsExistingEKS enrols EKS in the D391 gate — the driver at the centre of the
// whole Acme saga (D258/D259/D261). An existing ACTIVE cluster carrying our tags, with
// a node group under a name that is NOT the deterministic one, must be bound whole:
// zero mutations, and the cluster's own pid. That is the shape D253 called adoption and
// D261 called the root cause when it was missing.
func TestAdoptsExistingEKS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	capTag := sanitizeTag(eksCap)
	attrs, impl := eksCandidate()
	p := &certifynet.ExistingProbe{
		Name:     "aws/eks",
		Classify: eksRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pth, m := r.URL.Path, r.Method
				switch {
				case m == "GET" && pth == "/clusters/"+eksTestName:
					fmt.Fprintf(w, `{"cluster":{"status":"ACTIVE","version":"1.29",`+
						`"tags":{"groundhold-capability":%q,"groundhold-environment":"prod"}}}`, capTag)
				case m == "GET" && pth == "/clusters/"+eksTestName+"/node-groups":
					fmt.Fprint(w, `{"nodegroups":["acme-ng"]}`)
				case m == "GET" && pth == "/clusters/"+eksTestName+"/node-groups/acme-ng":
					fmt.Fprint(w, `{"nodegroup":{"status":"ACTIVE","version":"1.29"}}`)
				default:
					w.WriteHeader(400)
				}
			}))
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
			return pr.Create("eks", eksCap, "prod", attrs, impl, "k", 1)
		},
		PID: eksProviderID("eu-central-1", eksTestName),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
