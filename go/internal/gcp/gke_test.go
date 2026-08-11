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
	"time"
)

const gkeCap = "capability.cluster.kubernetes"

// gkeCandidate: a mixed-exposure, secrets-encrypted, regional cluster. Attributes
// drive the SHAPE; the impl block supplies the operands (network, subnetwork, CMEK
// key, node pool). Numeric operands are float64 to mirror JSON-decoded candidates.
func gkeCandidate() (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region":     "europe-west1",
		"cluster.version":     "1.29",
		"network.apiExposure": "mixed",
		"encryption.secrets":  true,
		"service.managed":     true,
		"availability.class":  "regional",
	}
	impl = map[string]any{
		"network":               "projects/proj/global/networks/main",
		"subnetwork":            "projects/proj/regions/europe-west1/subnetworks/main",
		"kmsKeyName":            "projects/proj/locations/europe-west1/keyRings/r/cryptoKeys/k",
		"masterAuthorizedCidrs": []any{"10.0.0.0/8"},
		"nodePool": map[string]any{
			"machineType": "e2-standard-4",
			"minNodes":    float64(1),
			"maxNodes":    float64(3),
			"autoscaling": true,
		},
	}
	return
}

// --- pure builder ---

func TestBuildGKE_MixedComposite(t *testing.T) {
	attrs, impl := gkeCandidate()
	plan, err := BuildGKE("test-proj", "prod", gkeCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("BuildGKE: %v", err)
	}
	if plan.Location != "europe-west1" {
		t.Fatalf("regional cluster location = %q, want the region", plan.Location)
	}
	body := plan.createClusterBody(gkeCap, "prod")
	cl, _ := body["cluster"].(map[string]any)
	if cl["initialClusterVersion"] != "1.29" {
		t.Fatalf("version = %v", cl["initialClusterVersion"])
	}
	if cl["network"] != impl["network"] || cl["subnetwork"] != impl["subnetwork"] {
		t.Fatalf("network/subnetwork operands not carried: %+v", cl)
	}
	nps, _ := cl["nodePools"].([]any)
	if len(nps) != 1 {
		t.Fatalf("want one node pool, got %v", cl["nodePools"])
	}
	np, _ := nps[0].(map[string]any)
	as, _ := np["autoscaling"].(map[string]any)
	if as["enabled"] != true || as["maxNodeCount"] != 3 {
		t.Fatalf("node pool autoscaling wrong: %+v", np)
	}
	// mixed -> private nodes, public (non-private) endpoint, authorized networks on.
	pcc, _ := cl["privateClusterConfig"].(map[string]any)
	if pcc["enablePrivateNodes"] != true || pcc["enablePrivateEndpoint"] != false {
		t.Fatalf("mixed exposure private config wrong: %+v", pcc)
	}
	man, _ := cl["masterAuthorizedNetworksConfig"].(map[string]any)
	if man["enabled"] != true {
		t.Fatalf("mixed exposure must enable authorized networks: %+v", man)
	}
	dbe, _ := cl["databaseEncryption"].(map[string]any)
	if dbe["state"] != "ENCRYPTED" || dbe["keyName"] != impl["kmsKeyName"] {
		t.Fatalf("secrets encryption must set databaseEncryption with the CMEK key: %+v", dbe)
	}
	labels, _ := cl["resourceLabels"].(map[string]any)
	if labels["groundhold-capability"] != sanitizeLabel(gkeCap) || labels["groundhold-environment"] != sanitizeLabel("prod") {
		t.Fatalf("ownership labels missing/wrong: %+v", labels)
	}
}

func TestBuildGKE_ZonalDefaultZone(t *testing.T) {
	attrs, impl := gkeCandidate()
	attrs["availability.class"] = "zonal"
	plan, err := BuildGKE("test-proj", "prod", gkeCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("BuildGKE zonal: %v", err)
	}
	if plan.Location != "europe-west1-a" {
		t.Fatalf("zonal cluster with no impl.zone must default to <region>-a, got %q", plan.Location)
	}
}

func TestBuildGKE_Refusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(attrs, impl map[string]any)
		frag string
	}{
		{"unmapped attribute", func(a, i map[string]any) { a["replicas.minimum"] = float64(1) }, "no GKE cluster mapping"},
		{"multi-regional", func(a, i map[string]any) { a["availability.class"] = "multi-regional" }, "multi-regional"},
		{"missing network", func(a, i map[string]any) { delete(i, "network") }, "network is required"},
		{"secrets no key", func(a, i map[string]any) { delete(i, "kmsKeyName") }, "kmsKeyName"},
		{"key no secrets", func(a, i map[string]any) { a["encryption.secrets"] = false }, "ambiguous shape"},
		{"mixed no cidrs", func(a, i map[string]any) { delete(i, "masterAuthorizedCidrs") }, "masterAuthorizedCidrs"},
		{"public with cidrs", func(a, i map[string]any) { a["network.apiExposure"] = "public" }, "ambiguous shape"},
		{"missing version", func(a, i map[string]any) { delete(a, "cluster.version") }, "cluster.version is required"},
		{"missing nodePool", func(a, i map[string]any) { delete(i, "nodePool") }, "nodePool is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := gkeCandidate()
			tc.mut(attrs, impl)
			_, err := BuildGKE("test-proj", "prod", gkeCap, attrs, impl, 1)
			if err == nil || !strings.Contains(err.Error(), tc.frag) {
				t.Fatalf("want refusal containing %q, got %v", tc.frag, err)
			}
		})
	}
}

func TestClassifyGKEChange(t *testing.T) {
	want := map[string]string{
		"cluster.version":     "mutable",
		"network.apiExposure": "mutable",
		"encryption.secrets":  "unsupported",
		"availability.class":  "immutable",
		"location.region":     "immutable",
		"service.managed":     "unsupported",
	}
	for p, w := range want {
		got, reason := classifyGKEChange(p)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// --- network shell: a stateful fake GKE (container v1) ---

type fakeGKE struct {
	mu sync.Mutex

	name string
	loc  string

	exists   bool
	labels   map[string]string
	status   string // RUNNING
	npStatus string // RUNNING
	opFail   bool

	// clusterGetFails: emit a 503 on this many INITIAL clusters.get reads before
	// serving the real cluster — a transient storm the bounded read-retry must ride
	// out (D260 class). Decremented per cluster GET.
	clusterGetFails int

	masterVersion         string
	enablePrivateEndpoint bool
	manEnabled            bool
	dbEncState            string

	createBody string
	updateBody string
	order      []string
}

func newFakeGKE(name, loc string) *fakeGKE {
	return &fakeGKE{
		name: name, loc: loc,
		labels: map[string]string{
			"groundhold-capability":  sanitizeLabel(gkeCap),
			"groundhold-environment": sanitizeLabel("prod"),
		},
		status:        "RUNNING",
		npStatus:      "RUNNING",
		masterVersion: "1.29.1-gke.1589020",
		manEnabled:    true,
		dbEncState:    "ENCRYPTED",
	}
}

func (f *fakeGKE) writeCluster(w http.ResponseWriter) {
	doc := map[string]any{
		"name":                           f.name,
		"status":                         f.status,
		"location":                       f.loc,
		"currentMasterVersion":           f.masterVersion,
		"resourceLabels":                 f.labels,
		"privateClusterConfig":           map[string]any{"enablePrivateEndpoint": f.enablePrivateEndpoint},
		"masterAuthorizedNetworksConfig": map[string]any{"enabled": f.manEnabled},
		"databaseEncryption":             map[string]any{"state": f.dbEncState},
		"nodePools":                      []any{map[string]any{"name": f.name + "-np", "status": f.npStatus}},
	}
	b, _ := json.Marshal(doc)
	_, _ = w.Write(b)
}

func (f *fakeGKE) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		p, m := r.URL.Path, r.Method
		coll := fmt.Sprintf("/projects/test-proj/locations/%s/clusters", f.loc)
		one := coll + "/" + f.name
		switch {
		case strings.Contains(p, "/operations/op-1") && m == http.MethodGet:
			if f.opFail {
				fmt.Fprint(w, `{"status":"DONE","statusMessage":"nodes failed to register"}`)
			} else {
				fmt.Fprint(w, `{"status":"DONE"}`)
			}
		case p == coll && m == http.MethodPost:
			f.order = append(f.order, "Create")
			f.exists = true
			f.createBody = string(b)
			fmt.Fprint(w, `{"name":"op-1"}`)
		case p == one && m == http.MethodGet:
			if f.clusterGetFails > 0 {
				f.clusterGetFails--
				http.Error(w, `{"error":{"code":503}}`, http.StatusServiceUnavailable)
				return
			}
			if !f.exists {
				http.Error(w, `{"error":{"code":404}}`, http.StatusNotFound)
				return
			}
			f.writeCluster(w)
		case p == one && m == http.MethodPut:
			f.order = append(f.order, "Update")
			f.updateBody = string(b)
			fmt.Fprint(w, `{"name":"op-1"}`)
		case p == one && m == http.MethodDelete:
			f.order = append(f.order, "Delete")
			f.exists = false
			fmt.Fprint(w, `{"name":"op-1"}`)
		case p == "/projects/test-proj/locations/-/clusters" && m == http.MethodGet:
			if f.exists {
				fmt.Fprintf(w, `{"clusters":[{"name":%q,"location":%q}]}`, f.name, f.loc)
			} else {
				fmt.Fprint(w, `{"clusters":[]}`)
			}
		default:
			http.Error(w, "nf "+m+" "+p, http.StatusNotFound)
		}
	}
}

func gkeTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "tok")
	d := NewDriver("test-proj")
	gkeBaseURLOverride = srv.URL
	t.Cleanup(func() { gkeBaseURLOverride = "" })
	d.PollInterval = 0
	d.PollTimeout = 2 * time.Second
	d.GKELROTimeout = 2 * time.Second // keep the GKE LRO poll fast (default is 60m)
	return d
}

func gkePlanName(t *testing.T) string {
	t.Helper()
	attrs, impl := gkeCandidate()
	plan, err := BuildGKE("test-proj", "prod", gkeCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("BuildGKE: %v", err)
	}
	return plan.Name
}

func gkeObsMap(t *testing.T, d *Driver, pid string) map[string]any {
	t.Helper()
	obs, _, err := d.observeGKE("", pid)
	if err != nil {
		t.Fatalf("observeGKE: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	return m
}

func TestObserveGKE_ReverseMap(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	m := gkeObsMap(t, d, gkeProviderID("test-proj", "europe-west1", name))
	if m["location.region"] != "europe-west1" {
		t.Fatalf("region = %v (EU residency)", m["location.region"])
	}
	if m["cluster.version"] != "1.29" {
		t.Fatalf("version = %v, want the governed minor 1.29 (from 1.29.1-gke...)", m["cluster.version"])
	}
	if m["network.apiExposure"] != "mixed" {
		t.Fatalf("apiExposure = %v, want mixed (public endpoint + authorized networks)", m["network.apiExposure"])
	}
	if m["encryption.secrets"] != true {
		t.Fatalf("encryption.secrets = %v, want true", m["encryption.secrets"])
	}
	if m["availability.class"] != "regional" {
		t.Fatalf("availability.class = %v, want regional (region location)", m["availability.class"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed missing")
	}
}

func TestObserveGKE_ExposureVariants(t *testing.T) {
	name := gkePlanName(t)
	for _, tc := range []struct {
		priv, man bool
		want      string
	}{
		{true, true, "private"},  // private endpoint wins
		{false, true, "mixed"},   // public endpoint restricted
		{false, false, "public"}, // public unrestricted
	} {
		f := newFakeGKE(name, "europe-west1")
		f.exists = true
		f.enablePrivateEndpoint = tc.priv
		f.manEnabled = tc.man
		srv := httptest.NewServer(f.handler())
		d := gkeTestDriver(t, srv)
		m := gkeObsMap(t, d, gkeProviderID("test-proj", "europe-west1", name))
		if m["network.apiExposure"] != tc.want {
			t.Errorf("priv=%t man=%t -> %v, want %v", tc.priv, tc.man, m["network.apiExposure"], tc.want)
		}
		srv.Close()
	}
}

func TestObserveGKE_ZonalFromLocation(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1-b")
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	m := gkeObsMap(t, d, gkeProviderID("test-proj", "europe-west1-b", name))
	if m["availability.class"] != "zonal" {
		t.Fatalf("a zone location must map to zonal, got %v", m["availability.class"])
	}
	if m["location.region"] != "europe-west1" {
		t.Fatalf("a zonal cluster's residency region is the zone's region, got %v", m["location.region"])
	}
}

func TestObserveGKE_UnreadableIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	if _, _, err := d.observeGKE("", gkeProviderID("test-proj", "europe-west1", "c")); err == nil {
		t.Fatal("a 403 must be an error (unknown), never a fabricated absence")
	}
}

func TestCreateGKE_FullSucceeds(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	attrs, impl := gkeCandidate()

	res := d.createGKE("prod", gkeCap, attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != gkeProviderID("test-proj", "europe-west1", name) {
		t.Fatalf("create providerId = %q", res.ProviderID)
	}
	if strings.Join(f.order, ",") != "Create" {
		t.Fatalf("create order = %v, want one CreateCluster", f.order)
	}
	var cb map[string]any
	if err := json.Unmarshal([]byte(f.createBody), &cb); err != nil {
		t.Fatalf("CreateCluster body not JSON: %v", err)
	}
	cl, _ := cb["cluster"].(map[string]any)
	if cl["initialClusterVersion"] != "1.29" {
		t.Fatalf("body version = %v", cl["initialClusterVersion"])
	}
}

func TestCreateGKE_PartialUnknown(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.npStatus = "ERROR" // control plane RUNNING but the node pool fell over
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	attrs, impl := gkeCandidate()

	res := d.createGKE("prod", gkeCap, attrs, impl, 1)
	if res.Status != "unknown" {
		t.Fatalf("cluster up + node pool unhealthy must be unknown, got %q (%s)", res.Status, res.Reason)
	}
	if res.ProviderID != gkeProviderID("test-proj", "europe-west1", name) {
		t.Fatalf("partial-composite unknown must carry the providerId, got %q", res.ProviderID)
	}
}

func TestCreateGKE_OpFailedButClusterStandsIsUnknown(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.opFail = true // the LRO fails, but the cluster object stands
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	attrs, impl := gkeCandidate()

	res := d.createGKE("prod", gkeCap, attrs, impl, 1)
	if res.Status != "unknown" || res.ProviderID != gkeProviderID("test-proj", "europe-west1", name) {
		t.Fatalf("failed op with a standing cluster must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreateGKE_ForeignRefuses(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	f.labels = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	attrs, impl := gkeCandidate()

	res := d.createGKE("prod", gkeCap, attrs, impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign cluster at our name must refuse, got %+v", res)
	}
	for _, o := range f.order {
		if o == "Create" {
			t.Fatalf("no CreateCluster may touch a foreign cluster; order = %v", f.order)
		}
	}
}

func TestUpdateGKE_Version(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	pid := gkeProviderID("test-proj", "europe-west1", name)
	res := d.updateGKE(gkeCap, "prod", pid,
		map[string]any{"cluster.version": "1.30"}, nil, []string{"cluster.version"})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("version update must succeed with the pid, got %+v", res)
	}
	if !strings.Contains(f.updateBody, `"desiredMasterVersion":"1.30"`) {
		t.Fatalf("update body must carry desiredMasterVersion: %s", f.updateBody)
	}
}

func TestUpdateGKE_ForeignRefuses(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	f.labels = map[string]string{"team": "someone-else"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	pid := gkeProviderID("test-proj", "europe-west1", name)
	res := d.updateGKE(gkeCap, "prod", pid,
		map[string]any{"cluster.version": "1.30"}, nil, []string{"cluster.version"})
	if res.Status != "failed" {
		t.Fatalf("a foreign cluster must refuse the update, got %+v", res)
	}
	for _, o := range f.order {
		if o == "Update" {
			t.Fatal("no update must be issued to a foreign cluster")
		}
	}
}

func TestDeleteGKE_OwnershipGuardedSucceeds(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	pid := gkeProviderID("test-proj", "europe-west1", name)
	res := d.deleteGKE(gkeCap, "prod", pid)
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("delete must succeed with the pid, got %+v", res)
	}
	if strings.Join(f.order, ",") != "Delete" {
		t.Fatalf("delete order = %v", f.order)
	}
}

func TestDeleteGKE_ForeignRefuses(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	f.labels = map[string]string{"team": "someone-else"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	res := d.deleteGKE(gkeCap, "prod", gkeProviderID("test-proj", "europe-west1", name))
	if res.Status != "failed" {
		t.Fatalf("a foreign cluster must refuse delete, got %+v", res)
	}
	for _, o := range f.order {
		if o == "Delete" {
			t.Fatal("no delete may touch a foreign cluster")
		}
	}
}

func TestDeleteGKE_AlreadyGoneIdempotent(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1") // exists=false
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	pid := gkeProviderID("test-proj", "europe-west1", name)
	res := d.deleteGKE(gkeCap, "prod", pid)
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("delete of an already-gone cluster must be idempotent success, got %+v", res)
	}
}

func TestDiscoverGKE(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)

	found, _, err := d.discoverGKE("europe-west1")
	if err != nil {
		t.Fatalf("discoverGKE: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 discovered cluster, got %d", len(found))
	}
	if found[0].ProviderID != gkeProviderID("test-proj", "europe-west1", name) {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.cluster.kubernetes" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	// a region filter that does not match omits the cluster.
	other, _, err := d.discoverGKE("us-central1")
	if err != nil {
		t.Fatalf("discoverGKE filtered: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("region filter must exclude a europe cluster, got %d", len(other))
	}
}

// TestGKELROTimeoutIsGenerous pins the D264-class fix: a GKE long-running operation
// (control-plane create/upgrade) polls on a generous budget, never the terse generic
// PollTimeout. A default driver must expose a public LROTimeout() well above the
// 20-minute PollTimeout, and a 0 GKELROTimeout must fall back to PollTimeout.
func TestGKELROTimeoutIsGenerous(t *testing.T) {
	d := NewDriver("test-proj")
	if got := d.LROTimeout(); got < 45*time.Minute {
		t.Fatalf("default GKE LROTimeout = %v, want >= 45m (a control-plane upgrade can exceed 20m)", got)
	}
	if d.LROTimeout() <= d.PollTimeout {
		t.Fatalf("GKE LROTimeout (%v) must exceed the generic PollTimeout (%v)", d.LROTimeout(), d.PollTimeout)
	}
	// zero-value fallback: an unset GKELROTimeout falls back to PollTimeout.
	d.GKELROTimeout = 0
	if got := d.LROTimeout(); got != d.PollTimeout {
		t.Fatalf("GKELROTimeout=0 must fall back to PollTimeout (%v), got %v", d.PollTimeout, got)
	}
}

// --- ADOPT-BY-NAME (mirror AWS EKS D261): the custom-name brownfield duplicate bug ---

// newFakeGKENamed serves a cluster under an arbitrary CUSTOM name (e.g. "acme"),
// like a brownfield gcloud/TF cluster that does NOT carry the deterministic name.
// owned=false poisons the ownership labels (a foreign cluster at that name).
func newFakeGKENamed(name, loc string, exists, owned bool) *fakeGKE {
	f := newFakeGKE(name, loc)
	f.exists = exists
	if !owned {
		f.labels = map[string]string{
			"groundhold-capability":  "someone-else",
			"groundhold-environment": "prod",
		}
	}
	return f
}

// gkeAdoptByNameCandidate: a MINIMAL adopt candidate — the clusterName operand + the
// governed attributes, NO create operands (network/subnetwork/CMEK/nodePool). This is
// what a brownfield adopt looks like. Regional defaults keep Location == the region.
func gkeAdoptByNameCandidate(name string) (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region": "europe-west1",
		"cluster.version": "1.29",
		"service.managed": true,
	}
	impl = map[string]any{"clusterName": name}
	return
}

// TestBuildGKE_AdoptByNameMakesOperandsOptional pins the adopt build: an explicit
// clusterName builds with AdoptByName=true and needs none of the create operands,
// while a greenfield candidate (no clusterName) still refuses without them.
func TestBuildGKE_AdoptByNameMakesOperandsOptional(t *testing.T) {
	attrs, impl := gkeAdoptByNameCandidate("acme")
	p, err := BuildGKE("test-proj", "prod", gkeCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("minimal adopt candidate must build, got %v", err)
	}
	if !p.AdoptByName || p.Name != "acme" || p.Location != "europe-west1" {
		t.Fatalf("plan = %+v (want AdoptByName, Name=acme, Location=europe-west1)", p)
	}
	// a greenfield candidate (no clusterName) still requires the operands.
	if _, err := BuildGKE("test-proj", "prod", gkeCap, map[string]any{
		"location.region": "europe-west1", "cluster.version": "1.29", "service.managed": true,
	}, nil, 1); err == nil {
		t.Fatal("a greenfield build with no operands must still refuse")
	}
}

// TestCreateGKE_AdoptByNameBindsExistingOwned pins the happy adopt: an existing owned
// custom-named cluster is BOUND by its real name — no CreateCluster, no duplicate.
func TestCreateGKE_AdoptByNameBindsExistingOwned(t *testing.T) {
	f := newFakeGKENamed("acme", "europe-west1", true, true)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	attrs, impl := gkeAdoptByNameCandidate("acme")

	res := d.createGKE("prod", gkeCap, attrs, impl, 1)
	if res.Status != "succeeded" || res.ProviderID != gkeProviderID("test-proj", "europe-west1", "acme") {
		t.Fatalf("adopt by name must bind gke:test-proj:europe-west1:acme, got %+v", res)
	}
	for _, o := range f.order {
		if o == "Create" {
			t.Fatalf("adopt by name must NEVER CreateCluster (the duplicate bug), order=%v", f.order)
		}
	}
}

// TestCreateGKE_AdoptByNameAbsentRefusesNeverDuplicates is the anti-duplicate core: an
// explicit adopt name that resolves to NO cluster must REFUSE, never create one.
func TestCreateGKE_AdoptByNameAbsentRefusesNeverDuplicates(t *testing.T) {
	f := newFakeGKENamed("acme", "europe-west1", false, false) // named cluster does not exist
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	attrs, impl := gkeAdoptByNameCandidate("acme")

	res := d.createGKE("prod", gkeCap, attrs, impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "adoption name") {
		t.Fatalf("an absent adopt name must refuse (never create), got %+v", res)
	}
	for _, o := range f.order {
		if o == "Create" {
			t.Fatalf("refusing an absent adopt name must NOT CreateCluster, order=%v", f.order)
		}
	}
}

// TestCreateGKE_AdoptByNameForeignRefused: an existing custom-named cluster that is NOT
// ours is refused (never adopted silently, never duplicated).
func TestCreateGKE_AdoptByNameForeignRefused(t *testing.T) {
	f := newFakeGKENamed("acme", "europe-west1", true, false) // exists but not our labels
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	attrs, impl := gkeAdoptByNameCandidate("acme")

	res := d.createGKE("prod", gkeCap, attrs, impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign named cluster must refuse, got %+v", res)
	}
	for _, o := range f.order {
		if o == "Create" {
			t.Fatalf("no CreateCluster may touch a foreign cluster; order=%v", f.order)
		}
	}
}

// TestCreateGKE_RidesOutReadStorm pins the D260-class fix: the ownership pre-read is a
// single-shot clusters.get, and a momentary 503 storm must NOT become a fatal `unknown`
// that aborts the converge. Here the first three reads 503; the fourth returns the real
// ours-healthy cluster, so create concludes succeeded (idempotent adopt) — riding out
// the storm rather than misreporting it.
func TestCreateGKE_RidesOutReadStorm(t *testing.T) {
	name := gkePlanName(t)
	f := newFakeGKE(name, "europe-west1")
	f.exists = true
	f.clusterGetFails = 3 // 503 on the first 3 reads; gcpGetRetry (4 attempts) rides it out
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := gkeTestDriver(t, srv)
	attrs, impl := gkeCandidate()

	res := d.createGKE("prod", gkeCap, attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("a transient 503 storm on the pre-read must be ridden out, got %q (%s)", res.Status, res.Reason)
	}
	if res.ProviderID != gkeProviderID("test-proj", "europe-west1", name) {
		t.Fatalf("create providerId = %q", res.ProviderID)
	}
	if f.clusterGetFails != 0 {
		t.Fatalf("the read-retry must have consumed all 3 transient failures, %d left", f.clusterGetFails)
	}
	for _, o := range f.order {
		if o == "Create" {
			t.Fatalf("the storm must not trigger a fresh CreateCluster on an existing ours cluster; order = %v", f.order)
		}
	}
}

// D763. The refusals and the registry contradicted each other: the driver refuses
// `network.apiExposure: mixed` unless `implementation.masterAuthorizedCidrs` is supplied,
// and the compiler's silent-ignore guard refused that operand because the registry did
// not list it — with the sentence "is not an operand the gcp/gke driver reads", which was
// false. Two refusals pointing at each other and no declaration in between.
//
// This pins both ends: the driver READS them, and the registry DECLARES them. Either half
// alone leaves the loop closed.
func TestGKEOperandsTheDriverReadsAreDeclared(t *testing.T) {
	d := NewDriver("acme-prod")
	declared := map[string]bool{}
	for _, k := range d.ConsumedOperands("gke") {
		declared[k] = true
	}
	for _, k := range []string{"masterAuthorizedCidrs", "kmsKeyName"} {
		if !declared[k] {
			t.Errorf("%s is demanded by a refusal and not declared consumed — supplying it "+
				"is then refused as an unknown operand, and the capability cannot be "+
				"expressed at all (D763)", k)
		}
	}

	// And the driver really does read them, or declaring them would be the lie.
	attrs, impl := gkeCandidate()
	p, err := BuildGKE("test-proj", "prod", gkeCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("the declaration the refusals ask for must build: %v", err)
	}
	if len(p.MasterAuthorizedCidrs) != 1 || p.KmsKeyName == "" {
		t.Fatalf("operands declared and not read: %+v", p)
	}
}
