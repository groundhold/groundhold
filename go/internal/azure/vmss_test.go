package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const azVMSSSubnet = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/app"

func vmssAttrs() map[string]any {
	return map[string]any{
		"location.region":        "swedencentral",
		"availability.class":     "regional",
		"replicas.minimum":       2,
		"replicas.maximum":       10,
		"autoscaling.enabled":    true,
		"network.publicExposure": false,
		"service.managed":        true,
	}
}

func vmssImpl() map[string]any {
	return map[string]any{
		"resource_group":         "rg",
		"vm_size":                "Standard_D2s_v5",
		"image_reference":        "Canonical:ubuntu-24_04-lts:server:latest",
		"subnet_id":              azVMSSSubnet,
		"admin_username":         "ops",
		"ssh_public_key":         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghijklmnop ops@example",
		"zones":                  []any{"1", "2"},
		"target_cpu_utilization": 60,
	}
}

func TestBuildVMSSGolden(t *testing.T) {
	p, err := BuildVMSS("production", "web-fleet", vmssAttrs(), vmssImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	body := p.createBody(map[string]any{"groundhold-capability": "web-fleet"})
	if body["location"] != "swedencentral" {
		t.Errorf("location = %v", body["location"])
	}
	sku, _ := body["sku"].(map[string]any)
	// sku.capacity starts the fleet at its FLOOR: starting above it bills for
	// machines nobody asked for.
	if sku["capacity"] != 2 || sku["name"] != "Standard_D2s_v5" {
		t.Errorf("sku = %v", sku)
	}
	zones, _ := body["zones"].([]any)
	if len(zones) != 2 {
		t.Errorf("zones = %v", body["zones"])
	}
	props, _ := body["properties"].(map[string]any)
	vmp, _ := props["virtualMachineProfile"].(map[string]any)
	os, _ := vmp["osProfile"].(map[string]any)
	lin, _ := os["linuxConfiguration"].(map[string]any)
	// The driver refuses a password operand, so advertising password login would
	// name a path nothing can use.
	if lin["disablePasswordAuthentication"] != true {
		t.Error("password authentication was not disabled")
	}
	// AUTHORED, not verified: the VM profile is inline, so a private fleet simply
	// carries no public-IP configuration.
	if strings.Contains(string(mustJSON(body)), "publicIPAddressConfiguration") {
		t.Error("a private fleet carried a public-IP configuration")
	}
}

// The difference from both twins: on AWS and GCP exposure lives in a template the
// driver must READ; here the VM profile is inline, so the driver BUILDS it.
func TestBuildVMSSAuthorsPublicExposure(t *testing.T) {
	attrs := vmssAttrs()
	attrs["network.publicExposure"] = true
	p, err := BuildVMSS("production", "web-fleet", attrs, vmssImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(string(mustJSON(p.createBody(nil))), "publicIPAddressConfiguration") {
		t.Error("a public fleet carried no public-IP configuration — the contract asked " +
			"for exposure and the profile is the driver's to write")
	}
}

func TestVMSSAutoscaleBody(t *testing.T) {
	p, err := BuildVMSS("production", "web-fleet", vmssAttrs(), vmssImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	body := p.autoscaleBody("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/x", nil)
	props, _ := body["properties"].(map[string]any)
	if props["enabled"] != true {
		t.Error("the autoscale setting was created disabled")
	}
	profiles, _ := props["profiles"].([]any)
	prof, _ := profiles[0].(map[string]any)
	capacity, _ := prof["capacity"].(map[string]any)
	if capacity["minimum"] != "2" || capacity["maximum"] != "10" {
		t.Errorf("capacity = %v", capacity)
	}
	// The default starts at the FLOOR, for the same reason sku.capacity does.
	if capacity["default"] != "2" {
		t.Errorf("default capacity = %v, want the floor", capacity["default"])
	}
	if !strings.Contains(string(mustJSON(body)), `"threshold":60`) {
		t.Error("the operator's target did not reach the rules")
	}
}

// Both directions, the same shape the managed disk uses for its SKU (D369).
func TestVMSSClassMustMatchTheZonesBothWays(t *testing.T) {
	t.Run("regional declared, one zone", func(t *testing.T) {
		impl := vmssImpl()
		impl["zones"] = []any{"1"}
		_, err := BuildVMSS("production", "web-fleet", vmssAttrs(), impl, 0)
		if err == nil || !strings.Contains(err.Error(), "does not survive losing it") {
			t.Errorf("refusal = %v", err)
		}
	})
	t.Run("zonal declared, several zones", func(t *testing.T) {
		attrs := vmssAttrs()
		attrs["availability.class"] = "zonal"
		_, err := BuildVMSS("production", "web-fleet", attrs, vmssImpl(), 0)
		if err == nil || !strings.Contains(err.Error(), "can never resolve") {
			t.Errorf("refusal = %v", err)
		}
	})
}

func TestBuildVMSSRefusals(t *testing.T) {
	cases := []struct {
		name  string
		mutA  func(map[string]any)
		mutI  func(map[string]any)
		wants string
	}{
		{
			// On a fleet a written-down credential reaches every machine the group
			// ever creates, including the ones it creates next year.
			name:  "a password operand",
			mutI:  func(i map[string]any) { i["admin_password"] = "hunter2" },
			wants: "every machine the group ever creates",
		},
		{"no capacity envelope", func(a map[string]any) { delete(a, "replicas.minimum") }, nil, "both required"},
		{"a floor above the ceiling", func(a map[string]any) {
			a["replicas.minimum"] = 10
			a["replicas.maximum"] = 2
		}, nil, "exceeds replicas.maximum"},
		{"a fixed fleet with a range", func(a map[string]any) { a["autoscaling.enabled"] = false }, func(i map[string]any) {
			delete(i, "target_cpu_utilization")
		}, "could never be satisfied"},
		{"an unknown availability class", func(a map[string]any) { a["availability.class"] = "multi-regional" }, nil, "has no scale-set mapping"},
		{"an attribute the driver cannot map", func(a map[string]any) { a["encryption.atRest"] = true }, nil, "refusing rather than silently dropping it"},
		{"an unmanaged fleet is an adoption", func(a map[string]any) { a["service.managed"] = false }, nil, "adoption, not a create"},
		{"no region", func(a map[string]any) { delete(a, "location.region") }, nil, "location.region is required"},
		{"no vm size", nil, func(i map[string]any) { delete(i, "vm_size") }, "implementation.vm_size is required"},
		{"no image", nil, func(i map[string]any) { delete(i, "image_reference") }, "implementation.image_reference is required"},
		{"an image that is neither form", nil, func(i map[string]any) { i["image_reference"] = "ubuntu" }, "publisher:offer:sku:version"},
		{"no subnet", nil, func(i map[string]any) { delete(i, "subnet_id") }, "implementation.subnet_id is required"},
		{"a subnet that is not a resource id", nil, func(i map[string]any) { i["subnet_id"] = "app" }, "is not an ARM resource id"},
		{"no ssh key", nil, func(i map[string]any) { delete(i, "ssh_public_key") }, "must be an OpenSSH PUBLIC key"},
		{"a PRIVATE key where a public one belongs", nil, func(i map[string]any) {
			i["ssh_public_key"] = "-----BEGIN OPENSSH PRIVATE KEY-----"
		}, "must be an OpenSSH PUBLIC key"},
		{"a zone that is not an Azure zone", nil, func(i map[string]any) { i["zones"] = []any{"1", "swedencentral-2"} }, "is not an Azure availability zone"},
		{"the same zone twice", nil, func(i map[string]any) { i["zones"] = []any{"1", "1"} }, "twice"},
		{"zones that are not a list", nil, func(i map[string]any) { i["zones"] = "1,2" }, "must be a list"},
		{"autoscaling wanted with no target", nil, func(i map[string]any) { delete(i, "target_cpu_utilization") }, "the driver does not invent one"},
		{"a target with no setting to carry it", func(a map[string]any) {
			a["autoscaling.enabled"] = false
			a["replicas.maximum"] = 2
		}, nil, "the fleet would stay fixed-size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := vmssAttrs(), vmssImpl()
			if tc.mutA != nil {
				tc.mutA(attrs)
			}
			if tc.mutI != nil {
				tc.mutI(impl)
			}
			_, err := BuildVMSS("production", "web-fleet", attrs, impl, 0)
			if err == nil {
				t.Fatalf("build succeeded; want a refusal mentioning %q", tc.wants)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refusal = %q, want it to mention %q", err, tc.wants)
			}
		})
	}
}

func TestVMSSNameIsDeterministicAndScoped(t *testing.T) {
	a, _ := BuildVMSS("production", "web-fleet", vmssAttrs(), vmssImpl(), 0)
	b, _ := BuildVMSS("production", "web-fleet", vmssAttrs(), vmssImpl(), 0)
	if a.Name == "" || a.Name != b.Name {
		t.Errorf("name is not deterministic: %q vs %q", a.Name, b.Name)
	}
	for _, o := range []struct {
		env, cap string
		gen      int
	}{{"staging", "web-fleet", 0}, {"production", "batch-fleet", 0}, {"production", "web-fleet", 2}} {
		got, _ := BuildVMSS(o.env, o.cap, vmssAttrs(), vmssImpl(), o.gen)
		if got.Name == a.Name {
			t.Errorf("%s/%s/g%d shares the name %q", o.env, o.cap, o.gen, a.Name)
		}
	}
}

// publicExposure is CAVEATED here and immutable on both twins — because on Azure
// the profile is inline and CAN be patched, but patching it re-addresses machines
// the fleet is already running.
func TestClassifyVMSSChange(t *testing.T) {
	for _, path := range []string{"replicas.minimum", "replicas.maximum", "autoscaling.enabled"} {
		if class, why := classifyVMSSChange(path); class != "mutable" || why == "" {
			t.Errorf("%s classified %q/%q, want mutable", path, class, why)
		}
	}
	if class, why := classifyVMSSChange("network.publicExposure"); class != "caveated" ||
		!strings.Contains(why, "already running") {
		t.Errorf("network.publicExposure classified %q/%q, want caveated with the live-fleet reason", class, why)
	}
	// D822: availability.class was pinned "immutable" here. Microsoft documents in-place
	// zone EXPANSION on a live scale set ("only add zones"), so the safe direction is an
	// update and the old expectation pinned a claim Azure contradicts.
	if class, why := classifyVMSSChange("availability.class"); class != "unsupported" || why == "" {
		t.Errorf("availability.class classified %q/%q, want unsupported with a reason", class, why)
	}
	for _, path := range []string{"location.region"} {
		if class, why := classifyVMSSChange(path); class != "immutable" || why == "" {
			t.Errorf("%s classified %q/%q, want immutable", path, class, why)
		}
	}
	if class, _ := classifyVMSSChange("service.managed"); class != "unsupported" {
		t.Errorf("service.managed classified %q", class)
	}
	if class, why := classifyVMSSChange("something.invented"); class != "" || why != "" {
		t.Errorf("an unknown path classified %q/%q", class, why)
	}
}

// --- network shell ---

type vmssServer struct {
	getStatus  int
	getBody    string
	autoStatus int
	autoBody   string
	putStatus  int
	delStatus  int
	paths      []string
	methods    []string
}

func (s *vmssServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.paths = append(s.paths, r.URL.Path)
		s.methods = append(s.methods, r.Method)
		isAuto := strings.Contains(r.URL.Path, "autoscalesettings")
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(s.putStatus)
			_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
		case http.MethodDelete:
			w.WriteHeader(s.delStatus)
			_, _ = w.Write([]byte(`{}`))
		default:
			if isAuto {
				w.WriteHeader(s.autoStatus)
				_, _ = w.Write([]byte(s.autoBody))
				return
			}
			w.WriteHeader(s.getStatus)
			_, _ = w.Write([]byte(s.getBody))
		}
	}
}

func vmssDriver(t *testing.T, s *vmssServer) (*Driver, func()) {
	t.Helper()
	srv := httptest.NewServer(s.handler())
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 50 * time.Millisecond
	return d, srv.Close
}

func vmssDoc(cap string, zones int, public bool) string {
	z := `["1"]`
	if zones > 1 {
		z = `["1","2"]`
	}
	ip := `{"properties":{}}`
	if public {
		ip = `{"properties":{"publicIPAddressConfiguration":{"name":"pip"}}}`
	}
	return `{"id":"/subscriptions/` + testSub + `/resourceGroups/rg/providers/Microsoft.Compute/virtualMachineScaleSets/pv-vmss-x",
"location":"swedencentral","zones":` + z + `,"sku":{"capacity":3},
"tags":{"groundhold-capability":"` + cap + `","groundhold-environment":"production"},
"properties":{"provisioningState":"Succeeded","virtualMachineProfile":{"networkProfile":{
"networkInterfaceConfigurations":[{"properties":{"ipConfigurations":[` + ip + `]}}]}}}}`
}

// D944: the create tags the autoscale setting, and retire now reads those tags to
// confirm ownership before deleting it — so the fake must carry them (the real shape).
const vmssAutoscaleDoc = `{"tags":{"groundhold-capability":"web-fleet","groundhold-environment":"production"},"properties":{"enabled":true,"profiles":[{"capacity":{"minimum":"2","maximum":"10"}}]}}`

func vmssHappyServer() *vmssServer {
	return &vmssServer{getStatus: 200, getBody: vmssDoc("web-fleet", 2, false),
		autoStatus: 200, autoBody: vmssAutoscaleDoc, putStatus: 200, delStatus: 200}
}

func TestObserveAzureVMSSWithAutoscaleSetting(t *testing.T) {
	s := vmssHappyServer()
	d, done := vmssDriver(t, s)
	defer done()

	obs, unread, err := d.observeAzureVMSS("web-fleet", azureVMSSProviderID(testSub, "rg", "pv-vmss-x"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(unread) != 0 {
		t.Errorf("unread = %v on a fully readable fleet", unread)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	want := map[string]any{
		"location.region":        "swedencentral",
		"availability.class":     "regional",
		"replicas.minimum":       2,
		"replicas.maximum":       10,
		"autoscaling.enabled":    true,
		"network.publicExposure": false,
		"service.managed":        true,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

// Without a setting the fleet has ONE size, and it is both bounds.
func TestObserveAzureVMSSWithoutSettingReadsBothBoundsFromCapacity(t *testing.T) {
	s := vmssHappyServer()
	s.autoStatus, s.autoBody = 404, `{}`
	d, done := vmssDriver(t, s)
	defer done()

	obs, _, err := d.observeAzureVMSS("web-fleet", azureVMSSProviderID(testSub, "rg", "pv-vmss-x"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["autoscaling.enabled"] != false {
		t.Errorf("autoscaling.enabled = %v, want false", got["autoscaling.enabled"])
	}
	if got["replicas.minimum"] != 3 || got["replicas.maximum"] != 3 {
		t.Errorf("envelope = %v..%v, want the single sku.capacity on both bounds",
			got["replicas.minimum"], got["replicas.maximum"])
	}
}

// A DISABLED setting is not a scaling fleet: the resource exists but the control
// loop does not run.
func TestObserveAzureVMSSDisabledSettingIsNotScaling(t *testing.T) {
	s := vmssHappyServer()
	s.autoBody = `{"properties":{"enabled":false,"profiles":[{"capacity":{"minimum":"2","maximum":"10"}}]}}`
	d, done := vmssDriver(t, s)
	defer done()

	obs, _, err := d.observeAzureVMSS("web-fleet", azureVMSSProviderID(testSub, "rg", "pv-vmss-x"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "autoscaling.enabled" && o.Value != false {
			t.Errorf("a disabled setting was reported as scaling (%v)", o.Value)
		}
	}
}

func TestObserveAzureVMSSUnreadableSettingIsUnreadNotFalse(t *testing.T) {
	s := vmssHappyServer()
	s.autoStatus, s.autoBody = 500, `{}`
	d, done := vmssDriver(t, s)
	defer done()

	obs, unread, err := d.observeAzureVMSS("web-fleet", azureVMSSProviderID(testSub, "rg", "pv-vmss-x"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		switch o.Path {
		case "autoscaling.enabled", "replicas.minimum", "replicas.maximum":
			t.Errorf("%s was observed as %v from an unreadable setting", o.Path, o.Value)
		}
	}
	var said bool
	for _, u := range unread {
		if strings.Contains(u, "autoscalesettings.get") {
			said = true
		}
	}
	if !said {
		t.Errorf("diagnostics %v do not name the call that failed", unread)
	}
}

func TestDeleteAzureVMSS(t *testing.T) {
	pid := azureVMSSProviderID(testSub, "rg", "pv-vmss-x")

	// A setting whose target has gone is an orphan that keeps evaluating.
	t.Run("removes the autoscale setting before the fleet", func(t *testing.T) {
		s := vmssHappyServer()
		d, done := vmssDriver(t, s)
		defer done()
		if res := d.deleteAzureVMSS("web-fleet", "production", pid); res.Status != "succeeded" {
			t.Fatalf("status = %q (%s)", res.Status, res.Reason)
		}
		var settingFirst bool
		for i, p := range s.paths {
			if s.methods[i] != http.MethodDelete {
				continue
			}
			if strings.Contains(p, "autoscalesettings") {
				settingFirst = true
				continue
			}
			if !settingFirst {
				t.Error("the fleet was deleted before its autoscale setting — the setting " +
					"would be left evaluating against a target that no longer exists")
			}
			break
		}
		if !settingFirst {
			t.Error("the autoscale setting was never deleted")
		}
	})
	// D944: a brownfield-adopted fleet has an arbitrary name, so `<name>-cpu` could be a
	// FOREIGN autoscale setting. Retire must read its tags and never delete one not ours.
	t.Run("leaves a foreign autoscale setting untouched", func(t *testing.T) {
		s := vmssHappyServer()
		s.autoBody = `{"tags":{"owner":"someone-else"},"properties":{"enabled":true,` +
			`"profiles":[{"capacity":{"minimum":"2","maximum":"10"}}]}}`
		d, done := vmssDriver(t, s)
		defer done()
		if res := d.deleteAzureVMSS("web-fleet", "production", pid); res.Status != "succeeded" {
			t.Fatalf("status = %q (%s)", res.Status, res.Reason)
		}
		for i, p := range s.paths {
			if s.methods[i] == http.MethodDelete && strings.Contains(p, "autoscalesettings") {
				t.Errorf("D944 FOREIGN-DELETE: a foreign autoscale setting was deleted — paths=%v", s.paths)
			}
		}
	})
	t.Run("refuses a fleet that is not ours", func(t *testing.T) {
		s := vmssHappyServer()
		s.getBody = vmssDoc("someone-elses-fleet", 2, false)
		d, done := vmssDriver(t, s)
		defer done()
		if res := d.deleteAzureVMSS("web-fleet", "production", pid); res.Status != "failed" {
			t.Fatalf("status = %q, want failed", res.Status)
		}
		for i, p := range s.paths {
			if s.methods[i] == http.MethodDelete && !strings.Contains(p, "autoscalesettings") {
				t.Fatal("a foreign fleet was terminated")
			}
		}
	})
	t.Run("an absent fleet is already deleted", func(t *testing.T) {
		s := vmssHappyServer()
		s.getStatus, s.getBody = 404, `{}`
		d, done := vmssDriver(t, s)
		defer done()
		if res := d.deleteAzureVMSS("web-fleet", "production", pid); res.Status != "succeeded" {
			t.Errorf("status = %q, want succeeded (idempotent)", res.Status)
		}
	})
	t.Run("an unreadable pre-delete read is unknown, never a delete", func(t *testing.T) {
		s := vmssHappyServer()
		s.getStatus, s.getBody = 500, `{}`
		d, done := vmssDriver(t, s)
		defer done()
		if res := d.deleteAzureVMSS("web-fleet", "production", pid); res.Status != "unknown" {
			t.Errorf("status = %q, want unknown", res.Status)
		}
		for i, p := range s.paths {
			if s.methods[i] == http.MethodDelete && !strings.Contains(p, "autoscalesettings") {
				t.Fatal("a fleet was terminated without a successful ownership read")
			}
		}
	})
}

func TestCreateAzureVMSSRefusesBeforeTheNetwork(t *testing.T) {
	s := vmssHappyServer()
	d, done := vmssDriver(t, s)
	defer done()

	impl := vmssImpl()
	delete(impl, "vm_size")
	res := d.createAzureVMSS("production", "web-fleet", vmssAttrs(), impl, 0)
	if res.Status != "failed" {
		t.Errorf("status = %q, want failed", res.Status)
	}
	if len(s.paths) != 0 {
		t.Errorf("the driver called %v before refusing", s.paths)
	}
}

func TestSplitAzureVMSSProviderID(t *testing.T) {
	pid := azureVMSSProviderID(testSub, "rg", "pv-vmss-x")
	sub, rg, name, err := splitAzureVMSSProviderID(pid)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if sub != testSub || rg != "rg" || name != "pv-vmss-x" {
		t.Errorf("split = %q/%q/%q", sub, rg, name)
	}
	for _, bad := range []string{
		"azvm:" + testSub + ":rg:pv-vmss-x",
		"azvmss::rg:x",
		"azvmss:" + testSub + ":rg:",
		"azvmss:" + testSub + ":rg",
	} {
		if _, _, _, err := splitAzureVMSSProviderID(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}
