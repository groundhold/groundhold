package azure

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

const aksCap = "capability.cluster.kubernetes"

// aksCandidate: a mixed-exposure, secrets-encrypted, regional cluster. Attributes
// drive the SHAPE; the impl block supplies the operands (resource group, CMEK key,
// authorized ranges, node pool). Numeric operands are float64 to mirror JSON-decoded
// candidates.
func aksCandidate() (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region":     "westeurope",
		"cluster.version":     "1.29",
		"network.apiExposure": "mixed",
		"encryption.secrets":  true,
		"service.managed":     true,
		"availability.class":  "regional",
	}
	impl = map[string]any{
		"resource_group":     "rg1",
		"kmsKeyId":           "https://kv.vault.azure.net/keys/etcd/abc123",
		"authorizedIPRanges": []any{"10.0.0.0/8"},
		"nodePool": map[string]any{
			"vmSize":            "Standard_D4s_v5",
			"count":             float64(3),
			"min":               float64(3),
			"max":               float64(6),
			"enableAutoScaling": true,
		},
	}
	return
}

// --- pure builder ---

func TestBuildAKS_MixedComposite(t *testing.T) {
	attrs, impl := aksCandidate()
	plan, err := BuildAKS("prod", aksCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("BuildAKS: %v", err)
	}
	if plan.Region != "westeurope" || plan.Version != "1.29" || !plan.Regional {
		t.Fatalf("plan shape wrong: %+v", plan)
	}
	body := plan.createBody(map[string]any{"groundhold-capability": sanitizeAzTag(aksCap)})
	props, _ := body["properties"].(map[string]any)
	if props["kubernetesVersion"] != "1.29" {
		t.Fatalf("version = %v", props["kubernetesVersion"])
	}
	pools, _ := props["agentPoolProfiles"].([]any)
	if len(pools) != 1 {
		t.Fatalf("want one agent pool, got %v", props["agentPoolProfiles"])
	}
	pool, _ := pools[0].(map[string]any)
	if pool["vmSize"] != "Standard_D4s_v5" || pool["enableAutoScaling"] != true || pool["maxCount"] != 6 {
		t.Fatalf("agent pool wrong: %+v", pool)
	}
	zones, _ := pool["availabilityZones"].([]any)
	if len(zones) != 3 {
		t.Fatalf("regional pool must spread 3 zones, got %v", pool["availabilityZones"])
	}
	// mixed -> public API server restricted to authorized IP ranges (not private).
	ap, _ := props["apiServerAccessProfile"].(map[string]any)
	if ap["enablePrivateCluster"] != false {
		t.Fatalf("mixed must not be a private cluster: %+v", ap)
	}
	if r, _ := ap["authorizedIPRanges"].([]any); len(r) != 1 {
		t.Fatalf("mixed must carry the authorized ranges: %+v", ap)
	}
	sp, _ := props["securityProfile"].(map[string]any)
	kms, _ := sp["azureKeyVaultKms"].(map[string]any)
	if kms["enabled"] != true || kms["keyId"] != impl["kmsKeyId"] {
		t.Fatalf("secrets encryption must set azureKeyVaultKms with the CMEK key: %+v", sp)
	}
	id, _ := body["identity"].(map[string]any)
	if id["type"] != "SystemAssigned" {
		t.Fatalf("default identity must be SystemAssigned: %+v", id)
	}
}

func TestBuildAKS_ZonalNoZones(t *testing.T) {
	attrs, impl := aksCandidate()
	attrs["availability.class"] = "zonal"
	plan, err := BuildAKS("prod", aksCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("BuildAKS zonal: %v", err)
	}
	pool := plan.createBody(map[string]any{})["properties"].(map[string]any)["agentPoolProfiles"].([]any)[0].(map[string]any)
	if _, has := pool["availabilityZones"]; has {
		t.Fatalf("a zonal cluster must omit availabilityZones, got %+v", pool)
	}
}

func TestBuildAKS_UserAssignedIdentity(t *testing.T) {
	attrs, impl := aksCandidate()
	impl["identity"] = "userAssigned"
	impl["userAssignedIdentityId"] = "/subscriptions/s/resourceGroups/rg1/providers/Microsoft.ManagedIdentity/userAssignedIdentities/aks-id"
	plan, err := BuildAKS("prod", aksCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("BuildAKS userAssigned: %v", err)
	}
	id, _ := plan.createBody(map[string]any{})["identity"].(map[string]any)
	if id["type"] != "UserAssigned" {
		t.Fatalf("identity type = %v", id["type"])
	}
	uai, _ := id["userAssignedIdentities"].(map[string]any)
	if _, ok := uai[impl["userAssignedIdentityId"].(string)]; !ok {
		t.Fatalf("userAssigned identity id not carried: %+v", id)
	}
}

func TestBuildAKS_Refusals(t *testing.T) {
	cases := []struct {
		name string
		mut  func(attrs, impl map[string]any)
		frag string
	}{
		{"unmapped attribute", func(a, i map[string]any) { a["replicas.minimum"] = float64(1) }, "no AKS cluster mapping"},
		{"multi-regional", func(a, i map[string]any) { a["availability.class"] = "multi-regional" }, "multi-regional"},
		{"missing region", func(a, i map[string]any) { delete(a, "location.region") }, "location.region"},
		{"missing version", func(a, i map[string]any) { delete(a, "cluster.version") }, "cluster.version is required"},
		{"secrets no key", func(a, i map[string]any) { delete(i, "kmsKeyId") }, "kmsKeyId"},
		{"key no secrets", func(a, i map[string]any) { a["encryption.secrets"] = false }, "ambiguous shape"},
		{"mixed no ranges", func(a, i map[string]any) { delete(i, "authorizedIPRanges") }, "authorizedIPRanges"},
		{"public with ranges", func(a, i map[string]any) { a["network.apiExposure"] = "public" }, "ambiguous shape"},
		{"missing nodePool", func(a, i map[string]any) { delete(i, "nodePool") }, "nodePool is required"},
		{"userAssigned no id", func(a, i map[string]any) { i["identity"] = "userAssigned" }, "userAssignedIdentityId"},
		{"service.managed false", func(a, i map[string]any) { a["service.managed"] = false }, "service.managed=false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := aksCandidate()
			tc.mut(attrs, impl)
			_, err := BuildAKS("prod", aksCap, attrs, impl, 1)
			if err == nil || !strings.Contains(err.Error(), tc.frag) {
				t.Fatalf("want refusal containing %q, got %v", tc.frag, err)
			}
		})
	}
}

func TestClassifyAKSChange(t *testing.T) {
	want := map[string]string{
		"cluster.version":     "mutable",
		"network.apiExposure": "mutable",
		"encryption.secrets":  "unsupported",
		"availability.class":  "immutable",
		"location.region":     "immutable",
		"service.managed":     "unsupported",
	}
	for p, w := range want {
		got, reason := classifyAKSChange(p)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// --- network shell: a stateful fake AKS (ARM managedClusters) ---

type fakeAKS struct {
	mu sync.Mutex

	sub, rg, name string

	exists    bool
	tags      map[string]string
	provState string   // provisioningState of the control plane
	npState   string   // provisioningState of the agent pool
	zones     []string // agent pool availabilityZones
	version   string
	private   bool
	ipRanges  []string
	kms       bool

	putBody string
	order   []string
}

func newFakeAKS(sub, rg, name string) *fakeAKS {
	return &fakeAKS{
		sub: sub, rg: rg, name: name,
		tags: map[string]string{
			"groundhold-capability":  sanitizeAzTag(aksCap),
			"groundhold-environment": sanitizeAzTag("prod"),
		},
		provState: "Succeeded",
		npState:   "Succeeded",
		zones:     []string{"1", "2", "3"},
		version:   "1.29.2",
		ipRanges:  []string{"10.0.0.0/8"},
		kms:       true,
	}
}

func (f *fakeAKS) writeDoc(w http.ResponseWriter) {
	doc := map[string]any{
		"location": "westeurope",
		"tags":     f.tags,
		"properties": map[string]any{
			"provisioningState":        f.provState,
			"currentKubernetesVersion": f.version,
			"agentPoolProfiles": []any{map[string]any{
				"name":              aksAgentPoolName,
				"provisioningState": f.npState,
				"availabilityZones": f.zones,
			}},
			"apiServerAccessProfile": map[string]any{
				"enablePrivateCluster": f.private,
				"authorizedIPRanges":   f.ipRanges,
			},
			"securityProfile": map[string]any{
				"azureKeyVaultKms": map[string]any{"enabled": f.kms},
			},
		},
	}
	b, _ := json.Marshal(doc)
	_, _ = w.Write(b)
}

func (f *fakeAKS) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		p, m := r.URL.Path, r.Method
		item := "/subscriptions/" + f.sub + "/resourceGroups/" + f.rg +
			"/providers/Microsoft.ContainerService/managedClusters/" + f.name
		list := "/subscriptions/" + f.sub + "/providers/Microsoft.ContainerService/managedClusters"
		switch {
		case p == item && m == http.MethodPut:
			if f.exists {
				f.order = append(f.order, "Update")
			} else {
				f.order = append(f.order, "Create")
			}
			f.exists = true
			f.putBody = string(b)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Creating"}}`))
		case p == item && m == http.MethodGet:
			if !f.exists {
				http.Error(w, `{"error":{"code":"NotFound"}}`, http.StatusNotFound)
				return
			}
			f.writeDoc(w)
		case p == item && m == http.MethodDelete:
			f.order = append(f.order, "Delete")
			f.exists = false
			w.WriteHeader(http.StatusAccepted)
		case p == list && m == http.MethodGet:
			if f.exists {
				w.Write([]byte(`{"value":[{"id":"` + item + `","name":"` + f.name + `","location":"westeurope"}]}`))
			} else {
				w.Write([]byte(`{"value":[]}`))
			}
		default:
			http.Error(w, "nf "+m+" "+p, http.StatusNotFound)
		}
	}
}

func aksDriver(t *testing.T, srv *httptest.Server) *Driver {
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

func aksPlanName(t *testing.T) string {
	t.Helper()
	attrs, impl := aksCandidate()
	plan, err := BuildAKS("prod", aksCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("BuildAKS: %v", err)
	}
	return plan.Name
}

func aksObsMap(t *testing.T, d *Driver, pid string) map[string]any {
	t.Helper()
	obs, _, err := d.observeAKS("", pid)
	if err != nil {
		t.Fatalf("observeAKS: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	return m
}

func TestObserveAKS_ReverseMap(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)

	m := aksObsMap(t, d, aksProviderID(testSub, "rg1", name))
	if m["location.region"] != "westeurope" {
		t.Fatalf("region = %v (EU residency)", m["location.region"])
	}
	if m["cluster.version"] != "1.29" {
		t.Fatalf("version = %v, want the governed minor 1.29 (from 1.29.2)", m["cluster.version"])
	}
	if m["network.apiExposure"] != "mixed" {
		t.Fatalf("apiExposure = %v, want mixed (public API server + authorized ranges)", m["network.apiExposure"])
	}
	if m["encryption.secrets"] != true {
		t.Fatalf("encryption.secrets = %v, want true", m["encryption.secrets"])
	}
	if m["availability.class"] != "regional" {
		t.Fatalf("availability.class = %v, want regional (3-zone pool)", m["availability.class"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed missing")
	}
}

func TestObserveAKS_ExposureVariants(t *testing.T) {
	name := aksPlanName(t)
	for _, tc := range []struct {
		priv   bool
		ranges []string
		want   string
	}{
		{true, nil, "private"},                   // private cluster wins
		{false, []string{"1.2.3.0/24"}, "mixed"}, // public restricted
		{false, nil, "public"},                   // public unrestricted
	} {
		f := newFakeAKS(testSub, "rg1", name)
		f.exists = true
		f.private = tc.priv
		f.ipRanges = tc.ranges
		srv := httptest.NewServer(f.handler())
		d := aksDriver(t, srv)
		m := aksObsMap(t, d, aksProviderID(testSub, "rg1", name))
		if m["network.apiExposure"] != tc.want {
			t.Errorf("priv=%t ranges=%v -> %v, want %v", tc.priv, tc.ranges, m["network.apiExposure"], tc.want)
		}
		srv.Close()
	}
}

func TestObserveAKS_ZonalFromPool(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.exists = true
	f.zones = []string{"1"} // single zone -> zonal
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)
	m := aksObsMap(t, d, aksProviderID(testSub, "rg1", name))
	if m["availability.class"] != "zonal" {
		t.Fatalf("a single-zone pool must map to zonal, got %v", m["availability.class"])
	}
}

func TestObserveAKS_UnreadableIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	d := aksDriver(t, srv)
	if _, _, err := d.observeAKS("", aksProviderID(testSub, "rg1", "pv-aks-c-00000000")); err == nil {
		t.Fatal("a 403 must be an error (unknown), never a fabricated absence")
	}
}

func TestCreateAKS_Succeeds(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name) // exists=false
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)
	attrs, impl := aksCandidate()

	res := d.createAKS("prod", aksCap, attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != aksProviderID(testSub, "rg1", name) {
		t.Fatalf("create providerId = %q", res.ProviderID)
	}
	if strings.Join(f.order, ",") != "Create" {
		t.Fatalf("create order = %v, want one managedClusters PUT", f.order)
	}
	var cb map[string]any
	if err := json.Unmarshal([]byte(f.putBody), &cb); err != nil {
		t.Fatalf("PUT body not JSON: %v", err)
	}
	props, _ := cb["properties"].(map[string]any)
	if props["kubernetesVersion"] != "1.29" {
		t.Fatalf("body version = %v", props["kubernetesVersion"])
	}
	tags, _ := cb["tags"].(map[string]any)
	if tags["groundhold-capability"] != sanitizeAzTag(aksCap) {
		t.Fatalf("ownership tags missing: %+v", tags)
	}
}

func TestCreateAKS_PartialUnknown(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.npState = "Failed" // control plane Succeeded but the agent pool fell over
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)
	attrs, impl := aksCandidate()

	res := d.createAKS("prod", aksCap, attrs, impl, 1)
	if res.Status != "unknown" {
		t.Fatalf("control plane up + agent pool failed must be unknown, got %q (%s)", res.Status, res.Reason)
	}
	if res.ProviderID != aksProviderID(testSub, "rg1", name) {
		t.Fatalf("partial-composite unknown must carry the providerId, got %q", res.ProviderID)
	}
}

func TestCreateAKS_FailedStandsIsUnknown(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.provState = "Failed" // the cluster object stands in Failed
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)
	attrs, impl := aksCandidate()

	res := d.createAKS("prod", aksCap, attrs, impl, 1)
	if res.Status != "unknown" || res.ProviderID != aksProviderID(testSub, "rg1", name) {
		t.Fatalf("a Failed cluster that stands must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreateAKS_ForeignRefuses(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.exists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)
	attrs, impl := aksCandidate()

	res := d.createAKS("prod", aksCap, attrs, impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign cluster at our name must refuse, got %+v", res)
	}
	for _, o := range f.order {
		if o == "Create" || o == "Update" {
			t.Fatalf("no PUT may touch a foreign cluster; order = %v", f.order)
		}
	}
}

func TestUpdateAKS_Version(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)

	pid := aksProviderID(testSub, "rg1", name)
	res := d.updateAKS(aksCap, "prod", pid,
		map[string]any{"cluster.version": "1.30"}, nil, []string{"cluster.version"})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("version update must succeed with the pid, got %+v", res)
	}
	if !strings.Contains(f.putBody, `"kubernetesVersion":"1.30"`) {
		t.Fatalf("update body must carry kubernetesVersion 1.30: %s", f.putBody)
	}
}

func TestUpdateAKS_PrivateToggleRefused(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.exists = true
	f.private = true // a private cluster
	f.ipRanges = nil
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)

	pid := aksProviderID(testSub, "rg1", name)
	res := d.updateAKS(aksCap, "prod", pid,
		map[string]any{"network.apiExposure": "public"}, nil, []string{"network.apiExposure"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "immutable") {
		t.Fatalf("a public<->private conversion must refuse (enablePrivateCluster immutable), got %+v", res)
	}
}

func TestUpdateAKS_ForeignRefuses(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.exists = true
	f.tags = map[string]string{"team": "someone-else"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)

	pid := aksProviderID(testSub, "rg1", name)
	res := d.updateAKS(aksCap, "prod", pid,
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

func TestDeleteAKS_OwnershipGuardedSucceeds(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)

	pid := aksProviderID(testSub, "rg1", name)
	res := d.deleteAKS(aksCap, "prod", pid)
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("delete must succeed with the pid, got %+v", res)
	}
	if strings.Join(f.order, ",") != "Delete" {
		t.Fatalf("delete order = %v", f.order)
	}
}

func TestDeleteAKS_ForeignRefuses(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.exists = true
	f.tags = map[string]string{"team": "someone-else"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)

	res := d.deleteAKS(aksCap, "prod", aksProviderID(testSub, "rg1", name))
	if res.Status != "failed" {
		t.Fatalf("a foreign cluster must refuse delete, got %+v", res)
	}
	for _, o := range f.order {
		if o == "Delete" {
			t.Fatal("no delete may touch a foreign cluster")
		}
	}
}

func TestDeleteAKS_AlreadyGoneIdempotent(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name) // exists=false
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)

	pid := aksProviderID(testSub, "rg1", name)
	res := d.deleteAKS(aksCap, "prod", pid)
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("delete of an already-gone cluster must be idempotent success, got %+v", res)
	}
}

func TestDiscoverAKS(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name)
	f.exists = true
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)

	found, _, err := d.discoverAKS("westeurope")
	if err != nil {
		t.Fatalf("discoverAKS: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 discovered cluster, got %d", len(found))
	}
	if found[0].ProviderID != aksProviderID(testSub, "rg1", name) {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.cluster.kubernetes" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	// a region filter that does not match omits the cluster.
	other, _, err := d.discoverAKS("eastus")
	if err != nil {
		t.Fatalf("discoverAKS filtered: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("region filter must exclude a westeurope cluster, got %d", len(other))
	}
}

// TestAKSLROTimeoutExceedsPollTimeout pins the D264 class for Azure: the AKS
// long-running-operation ceiling must exceed the generic 20-min PollTimeout (a real
// control-plane upgrade runs 20-40 min), and the public LROBudgeter method must
// report it. Zero falls back to PollTimeout so tests keep their fast timeout paths.
func TestAKSLROTimeoutExceedsPollTimeout(t *testing.T) {
	d := NewDriver(testSub)
	if d.AKSLROTimeout < 45*time.Minute {
		t.Fatalf("AKS LRO timeout must be >=45m for a 20-40m control-plane upgrade, got %v", d.AKSLROTimeout)
	}
	if d.LROTimeout() < 45*time.Minute {
		t.Fatalf("LROTimeout() must be >=45m, got %v", d.LROTimeout())
	}
	if d.aksLROTimeout() <= d.PollTimeout {
		t.Fatalf("aksLROTimeout() (%v) must exceed the generic PollTimeout (%v)", d.aksLROTimeout(), d.PollTimeout)
	}
	// zero AKSLROTimeout falls back to PollTimeout (the test-fast path).
	d.AKSLROTimeout = 0
	if d.aksLROTimeout() != d.PollTimeout {
		t.Fatalf("unset AKSLROTimeout must fall back to PollTimeout, got %v", d.aksLROTimeout())
	}
	if d.LROTimeout() != d.PollTimeout {
		t.Fatalf("LROTimeout() zero-fallback must equal PollTimeout, got %v", d.LROTimeout())
	}
}

// TestCreateAKS_RidesOutTransientReads pins the D260 class for Azure: a momentary
// 503 on the ownership pre-read must NOT abort the create. getAKS goes through armGet,
// which retries a bounded number of times on a transient (503/429/transport); three
// 503s followed by the real cluster still converge to a succeeded create.
func TestCreateAKS_RidesOutTransientReads(t *testing.T) {
	name := aksPlanName(t)
	f := newFakeAKS(testSub, "rg1", name) // exists=false
	inner := f.handler()
	var mu sync.Mutex
	getReads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			mu.Lock()
			getReads++
			n := getReads
			mu.Unlock()
			if n <= 3 { // the first three reads are a transient blip
				http.Error(w, `{"error":{"code":"TooBusy"}}`, http.StatusServiceUnavailable)
				return
			}
		}
		inner(w, r)
	}))
	defer srv.Close()
	d := aksDriver(t, srv)
	attrs, impl := aksCandidate()

	res := d.createAKS("prod", aksCap, attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded despite 3 transient 503 reads", res.Status, res.Reason)
	}
	if res.ProviderID != aksProviderID(testSub, "rg1", name) {
		t.Fatalf("create providerId = %q", res.ProviderID)
	}
}

// aksRole classifies Azure ARM requests structurally for the honesty harness: a GET
// is a read, every other method (PUT/DELETE/PATCH/POST) an opaque mutation (ARM
// success is status + provisioningState, never a parsed id).
func aksRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestReadStormAKS enrolls AKS in the cross-driver read-retry gate (D266), mirroring
// the EKS enrollment: a greenfield create whose first reads throttle must still
// succeed, because getAKS goes through armGet, which retries the transient class. A
// regression dropping the retry turns a healthy converge into a false unknown (the
// Acme D260 class) and fails HERE, in CI.
func TestReadStormAKS(t *testing.T) {
	name := aksPlanName(t)
	attrs, impl := aksCandidate()
	p := &certifynet.Probe{
		AssertTransient: true, // D237 sweep
		Name:            "azure/aks",
		Classify:        aksRole,
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.BaseURL = happyURL
			d.HTTP = &http.Client{Transport: rt}
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			d.AKSLROTimeout = 2 * time.Second
			return d
		},
		Ops: []certifynet.Op{{
			Name: "create",
			Happy: func() *httptest.Server {
				return httptest.NewServer(newFakeAKS(testSub, "rg1", name).handler())
			},
			Run: func(pr provider.Provider) provider.CreateResult {
				return pr.Create("aks", aksCap, "prod", attrs, impl, "k", 1)
			},
		}},
	}
	certifynet.CertifyReadRetry(t, p)
}

// TestBoundedPollAKS enrolls AKS in the bounded-poll gate (D266): a cluster whose
// control plane never leaves a non-terminal provisioningState must conclude
// unknown-with-pid within the AKS LRO budget, never hang. The StuckServer's PUT
// succeeds but the provisioningState poll never reaches Succeeded (nor a terminal
// Failed/Canceled).
func TestBoundedPollAKS(t *testing.T) {
	name := aksPlanName(t)
	attrs, impl := aksCandidate()
	p := &certifynet.LifecycleProbe{
		Name: "azure/aks",
		StuckServer: func() *httptest.Server {
			f := newFakeAKS(testSub, "rg1", name)
			f.provState = "Creating" // control plane never reaches Succeeded (nor Failed/Canceled)
			return httptest.NewServer(f.handler())
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.BaseURL = happyURL
			d.HTTP = &http.Client{Transport: rt}
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = time.Second
			d.AKSLROTimeout = time.Second // bound the stuck poll to ~1s, not 60m
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("aks", aksCap, "prod", attrs, impl, "k", 1)
		},
		PID: aksProviderID(testSub, "rg1", name),
	}
	certifynet.CertifyBoundedPoll(t, p)
}

// --- D261: adopt-by-explicit-name (the real Acme duplicate bug), mirrored from EKS ---

// aksAdoptByNameCandidate: a MINIMAL adopt candidate — clusterName + resource_group
// operands and the governed attrs (region, version, service.managed), NO create
// operands (nodePool/CMEK/identity/ranges). This is what a brownfield adopt looks like.
func aksAdoptByNameCandidate(name string) (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region": "westeurope",
		"cluster.version": "1.29",
		"service.managed": true,
	}
	impl = map[string]any{"resource_group": "rg1", "clusterName": name}
	return
}

// TestBuildAKSAdoptByNameMakesOperandsOptional pins D261: an explicit clusterName
// builds with AdoptByName=true and needs none of the create operands.
func TestBuildAKSAdoptByNameMakesOperandsOptional(t *testing.T) {
	attrs, impl := aksAdoptByNameCandidate("acme")
	p, err := BuildAKS("prod", aksCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("minimal adopt candidate must build, got %v", err)
	}
	if !p.AdoptByName || p.Name != "acme" {
		t.Fatalf("plan = %+v (want AdoptByName, Name=acme)", p)
	}
	// a GREENFIELD candidate (no clusterName) still requires the operands (nodePool).
	if _, err := BuildAKS("prod", aksCap, map[string]any{
		"location.region": "westeurope", "cluster.version": "1.29", "service.managed": true,
	}, map[string]any{"resource_group": "rg1"}, 1); err == nil {
		t.Fatal("a greenfield build with no operands must still refuse")
	}
}

// TestAKSAdoptByNameBindsExistingOwned pins the happy adopt: an existing owned
// custom-named cluster is BOUND by its real name (no PUT, no duplicate).
func TestAKSAdoptByNameBindsExistingOwned(t *testing.T) {
	f := newFakeAKS(testSub, "rg1", "acme")
	f.exists = true // owned (default tags) + healthy (default states)
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)
	attrs, impl := aksAdoptByNameCandidate("acme")

	res := d.createAKS("prod", aksCap, attrs, impl, 1)
	if res.Status != "succeeded" || res.ProviderID != aksProviderID(testSub, "rg1", "acme") {
		t.Fatalf("adopt by name must bind aks:...:acme, got %+v", res)
	}
	for _, o := range f.order {
		if o == "Create" || o == "Update" {
			t.Fatalf("adopt by name must NEVER PUT (the duplicate bug), order=%v", f.order)
		}
	}
}

// TestAKSAdoptByNameAbsentRefusesNeverDuplicates is the anti-duplicate core: an
// explicit adopt name that resolves to NO cluster must REFUSE, never PUT one (an AKS
// PUT is an upsert — the refuse must beat the PUT).
func TestAKSAdoptByNameAbsentRefusesNeverDuplicates(t *testing.T) {
	f := newFakeAKS(testSub, "rg1", "acme") // exists=false — the named cluster is absent
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)
	attrs, impl := aksAdoptByNameCandidate("acme")

	res := d.createAKS("prod", aksCap, attrs, impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "adoption name") {
		t.Fatalf("an absent adopt name must refuse (never create), got %+v", res)
	}
	for _, o := range f.order {
		if o == "Create" || o == "Update" {
			t.Fatalf("refusing an absent adopt name must NOT PUT, order=%v", f.order)
		}
	}
}

// TestAKSAdoptByNameForeignRefused: an existing custom-named cluster that is NOT ours
// is refused (never adopted silently, never duplicated), pointing at the adopt flow.
func TestAKSAdoptByNameForeignRefused(t *testing.T) {
	f := newFakeAKS(testSub, "rg1", "acme")
	f.exists = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := aksDriver(t, srv)
	attrs, impl := aksAdoptByNameCandidate("acme")

	res := d.createAKS("prod", aksCap, attrs, impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign named cluster must refuse, got %+v", res)
	}
	for _, o := range f.order {
		if o == "Create" || o == "Update" {
			t.Fatalf("no PUT may touch a foreign cluster; order=%v", f.order)
		}
	}
}

// TestNoDuplicateAKS enrolls AKS in the no-duplicate gate (D267), mirroring
// TestNoDuplicateEKS: a candidate that names a cluster to adopt
// (implementation.clusterName) which does NOT exist must refuse, sending zero
// mutations — never a duplicate (the Acme D261 root cause; and an AKS PUT is an
// upsert, so the refuse must beat it).
func TestNoDuplicateAKS(t *testing.T) {
	attrs, impl := aksAdoptByNameCandidate("acme")
	p := &certifynet.DuplicateProbe{
		Name:     "azure/aks",
		Classify: aksRole,
		AbsentServer: func() *httptest.Server {
			return httptest.NewServer(newFakeAKS(testSub, "rg1", "acme").handler()) // exists=false
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.BaseURL = happyURL
			d.HTTP = &http.Client{Transport: rt}
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = time.Second
			d.AKSLROTimeout = time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("aks", aksCap, "prod", attrs, impl, "k", 1)
		},
	}
	certifynet.CertifyNoDuplicate(t, p)
}
