package azure

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const (
	azVMNIC = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic0"
	azVMDES = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des0"
)

func azVMAttrs() map[string]any {
	return map[string]any{
		"location.region":                "swedencentral",
		"availability.class":             "zonal",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": false,
		"service.managed":                true,
	}
}

func azVMImpl() map[string]any {
	return map[string]any{
		"resource_group":       "rg",
		"vm_size":              "Standard_D2s_v5",
		"image_reference":      "Canonical:ubuntu-24_04-lts:server:latest",
		"network_interface_id": azVMNIC,
		"admin_username":       "ops",
		"ssh_public_key":       "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghijklmnop ops@example",
	}
}

func TestBuildAzureVMGolden(t *testing.T) {
	p, err := BuildAzureVM("production", "web", azVMAttrs(), azVMImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	body := p.createBody(map[string]any{"groundhold-capability": "web"})
	if body["location"] != "swedencentral" {
		t.Errorf("location = %v", body["location"])
	}
	props := body["properties"].(map[string]any)
	if got := props["hardwareProfile"].(map[string]any)["vmSize"]; got != "Standard_D2s_v5" {
		t.Errorf("vmSize = %v", got)
	}
	img := props["storageProfile"].(map[string]any)["imageReference"].(map[string]any)
	if img["publisher"] != "Canonical" || img["sku"] != "server" || img["version"] != "latest" {
		t.Errorf("imageReference not split correctly: %v", img)
	}
	osDisk := props["storageProfile"].(map[string]any)["osDisk"].(map[string]any)
	if _, present := osDisk["managedDisk"].(map[string]any)["diskEncryptionSet"]; present {
		t.Error("a disk-encryption set appeared although customerManagedKeys is false")
	}
	// D941: the create implicitly provisions this OS disk; without deleteOption:Delete
	// Azure's Detach default leaves it billing after the VM is gone (D920 residue).
	if osDisk["deleteOption"] != "Delete" {
		t.Errorf("osDisk.deleteOption = %v, want Delete — the OS disk must cascade with the VM", osDisk["deleteOption"])
	}
	// Password authentication must be structurally off, not merely undeclared.
	lin := props["osProfile"].(map[string]any)["linuxConfiguration"].(map[string]any)
	if lin["disablePasswordAuthentication"] != true {
		t.Error("password authentication is enabled — the driver refuses password operands, " +
			"so leaving this path open would permit a credential nobody declared")
	}
	nics := props["networkProfile"].(map[string]any)["networkInterfaces"].([]any)
	if nics[0].(map[string]any)["id"] != azVMNIC {
		t.Errorf("network interface = %v", nics[0])
	}
}

// ARM PUT is idempotent by name, so the name is what makes a lost create
// recoverable rather than duplicated.
func TestAzureVMNameIsDeterministic(t *testing.T) {
	a := azureVMName("production", "web", 0)
	if a != azureVMName("production", "web", 0) {
		t.Error("name is not deterministic")
	}
	if a == azureVMName("production", "web", 2) {
		t.Error("generation 2 reused the original's name — a replacement would upsert over " +
			"the machine it replaces instead of coexisting with it (D48)")
	}
	if len(a) > 64 {
		t.Errorf("name %q exceeds the Azure VM name limit", a)
	}
}

func TestBuildAzureVMRefusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(attrs, impl map[string]any)
		want   string
	}{
		// A candidate is a reviewed, stored document. Accepting a password "just
		// this once" is how secrets end up in git.
		{"a password operand", func(_, i map[string]any) {
			i["admin_password"] = "hunter2"
		}, "wrong place for a credential"},
		{"a private key pasted as the public one", func(_, i map[string]any) {
			i["ssh_public_key"] = "-----BEGIN OPENSSH PRIVATE KEY-----"
		}, "must be an OpenSSH PUBLIC key"},
		{"unencrypted disks", func(a, _ map[string]any) {
			a["encryption.atRest"] = false
		}, "no way to disable it"},
		{"regional placement", func(a, _ map[string]any) {
			a["availability.class"] = "regional"
		}, "scale set"},
		{"unmapped attribute", func(a, _ map[string]any) {
			a["replicas.minimum"] = 3
		}, "has no Azure VM mapping"},
		{"cmk without a disk-encryption set", func(a, i map[string]any) {
			a["encryption.customerManagedKeys"] = true
			delete(i, "disk_encryption_set_id")
		}, "requires implementation.disk_encryption_set_id"},
		{"no vm size", func(_, i map[string]any) {
			delete(i, "vm_size")
		}, "vm_size is required"},
		{"no image", func(_, i map[string]any) {
			delete(i, "image_reference")
		}, "image_reference is required"},
		{"malformed image", func(_, i map[string]any) {
			i["image_reference"] = "ubuntu:latest"
		}, "publisher:offer:sku:version"},
		{"no network interface", func(_, i map[string]any) {
			delete(i, "network_interface_id")
		}, "network_interface_id is required"},
		{"bogus network interface", func(_, i map[string]any) {
			i["network_interface_id"] = "nic0"
		}, "not a network-interface resource id"},
		{"no admin user", func(_, i map[string]any) {
			delete(i, "admin_username")
		}, "admin_username is required"},
		{"fractional disk", func(_, i map[string]any) {
			i["os_disk_size_gb"] = 63.5
		}, "positive whole number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := azVMAttrs(), azVMImpl()
			tc.mutate(attrs, impl)
			_, err := BuildAzureVM("production", "web", attrs, impl, 0)
			if err == nil {
				t.Fatal("expected a refusal, got a plan")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refusal does not explain itself:\n got: %v\nwant substring: %q", err, tc.want)
			}
		})
	}
}

func TestClassifyAzureVMChange(t *testing.T) {
	for path, want := range map[string]string{
		"location.region":    "immutable",
		"availability.class": "immutable",
		// D825: Azure attaches a disk encryption set to an EXISTING disk with the VM
		// stopped, so this never needed a new machine.
		"encryption.customerManagedKeys": "unsupported",
		"encryption.atRest":              "unsupported",
		"service.managed":                "unsupported",
		// Azure differs from both twins here: the address belongs to the interface,
		// a resource this driver does not own, so it is not the machine's to change.
		"network.publicExposure": "unsupported",
	} {
		got, reason := classifyAzureVMChange(path)
		if got != want {
			t.Errorf("%s classified %q, want %q", path, got, want)
		}
		if reason == "" {
			t.Errorf("%s carries no reason", path)
		}
	}
}

// --- network shell ---

type azVMServer struct {
	vmStatus  int
	vmBody    string
	nicStatus int
	nicBody   string
	delStatus int
	calls     []string
}

func (s *azVMServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "networkInterfaces"):
			s.calls = append(s.calls, "nic")
			w.WriteHeader(s.nicStatus)
			_, _ = w.Write([]byte(s.nicBody))
		case r.Method == http.MethodDelete:
			s.calls = append(s.calls, "delete")
			w.WriteHeader(s.delStatus)
			_, _ = w.Write([]byte(`{}`))
		default:
			s.calls = append(s.calls, "vm")
			w.WriteHeader(s.vmStatus)
			_, _ = w.Write([]byte(s.vmBody))
		}
	}
}

func azVMDriver(t *testing.T, s *azVMServer) (*Driver, func()) {
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

func azVMDoc(t *testing.T, cap string, des bool) string {
	t.Helper()
	doc := map[string]any{
		"location": "swedencentral",
		"tags": map[string]any{
			"groundhold-capability": cap, "groundhold-environment": "production",
		},
		"properties": map[string]any{
			"provisioningState": "Succeeded",
			"networkProfile": map[string]any{
				"networkInterfaces": []any{map[string]any{"id": azVMNIC}},
			},
			"storageProfile": map[string]any{"osDisk": map[string]any{
				"managedDisk": map[string]any{},
			}},
		},
	}
	if des {
		doc["properties"].(map[string]any)["storageProfile"].(map[string]any)["osDisk"].(map[string]any)["managedDisk"] =
			map[string]any{"diskEncryptionSet": map[string]any{"id": azVMDES}}
	}
	b, _ := json.Marshal(doc)
	return string(b)
}

func TestObserveAzureVM(t *testing.T) {
	pid := azureVMProviderID(testSub, "rg", "pv-vm-abc123456789")

	t.Run("a private machine with a customer key", func(t *testing.T) {
		s := &azVMServer{vmStatus: 200, vmBody: azVMDoc(t, "web", true),
			nicStatus: 200, nicBody: `{"properties":{"ipConfigurations":[{"properties":{}}]}}`}
		d, done := azVMDriver(t, s)
		defer done()
		obs, unread, err := d.observeAzureVM("web", pid)
		if err != nil {
			t.Fatalf("observe: %v", err)
		}
		if len(unread) != 0 {
			t.Errorf("unexpected unread notes: %v", unread)
		}
		got := map[string]any{}
		for _, o := range obs {
			got[o.Path] = o.Value
		}
		for path, want := range map[string]any{
			"location.region":                "swedencentral",
			"network.publicExposure":         false,
			"encryption.atRest":              true,
			"encryption.customerManagedKeys": true,
		} {
			if got[path] != want {
				t.Errorf("%s = %v, want %v", path, got[path], want)
			}
		}
	})

	t.Run("a public address on the interface makes it public", func(t *testing.T) {
		s := &azVMServer{vmStatus: 200, vmBody: azVMDoc(t, "web", false), nicStatus: 200,
			nicBody: `{"properties":{"ipConfigurations":[{"properties":{"publicIPAddress":{"id":"/subscriptions/x/pip"}}}]}}`}
		d, done := azVMDriver(t, s)
		defer done()
		obs, _, err := d.observeAzureVM("web", pid)
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range obs {
			if o.Path == "network.publicExposure" && o.Value != true {
				t.Error("a machine whose interface carries a public address was reported private")
			}
		}
	})

	// The dangerous default: a silent false would pass an "is it private?"
	// constraint on a machine that may be on the internet.
	t.Run("an unreadable interface leaves exposure unread, never false", func(t *testing.T) {
		s := &azVMServer{vmStatus: 200, vmBody: azVMDoc(t, "web", false), nicStatus: 500, nicBody: `{}`}
		d, done := azVMDriver(t, s)
		defer done()
		obs, unread, err := d.observeAzureVM("web", pid)
		if err != nil {
			t.Fatal(err)
		}
		if len(unread) == 0 {
			t.Fatal("an unreadable interface produced no unread note")
		}
		for _, o := range obs {
			if o.Path == "network.publicExposure" {
				t.Errorf("exposure was reported as %v although the interface could not be read", o.Value)
			}
		}
	})
}

func TestDeleteAzureVM(t *testing.T) {
	pid := azureVMProviderID(testSub, "rg", "pv-vm-abc123456789")

	t.Run("deletes our own machine", func(t *testing.T) {
		s := &azVMServer{vmStatus: 200, vmBody: azVMDoc(t, "web", false), delStatus: 200}
		d, done := azVMDriver(t, s)
		defer done()
		res := d.deleteAzureVM("web", "production", pid)
		if res.Status != "succeeded" {
			t.Errorf("status = %q (%s), want succeeded", res.Status, res.Reason)
		}
	})

	t.Run("refuses a machine that is not ours", func(t *testing.T) {
		s := &azVMServer{vmStatus: 200, vmBody: azVMDoc(t, "someone-else", false)}
		d, done := azVMDriver(t, s)
		defer done()
		res := d.deleteAzureVM("web", "production", pid)
		if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
			t.Errorf("status = %q (%s), want a refusal", res.Status, res.Reason)
		}
		for _, c := range s.calls {
			if c == "delete" {
				t.Fatal("a foreign machine was deleted")
			}
		}
	})

	t.Run("an already-gone machine is idempotently succeeded", func(t *testing.T) {
		s := &azVMServer{vmStatus: 404, vmBody: `{}`}
		d, done := azVMDriver(t, s)
		defer done()
		res := d.deleteAzureVM("web", "production", pid)
		if res.Status != "succeeded" {
			t.Errorf("status = %q, want succeeded (delete is idempotent)", res.Status)
		}
	})

	t.Run("an unreadable pre-delete state is unknown, never a delete", func(t *testing.T) {
		s := &azVMServer{vmStatus: 500, vmBody: `{}`}
		d, done := azVMDriver(t, s)
		defer done()
		res := d.deleteAzureVM("web", "production", pid)
		if res.Status != "unknown" {
			t.Errorf("status = %q, want unknown", res.Status)
		}
		for _, c := range s.calls {
			if c == "delete" {
				t.Fatal("deleted a machine whose ownership was never established")
			}
		}
	})
}

func TestSplitAzureVMProviderID(t *testing.T) {
	for _, bad := range []string{
		"azvm:not-a-guid:rg:name",
		"azvm:" + testSub + ":rg",
		"aisearch:" + testSub + ":rg:name",
	} {
		if _, _, _, err := splitAzureVMProviderID(bad); err == nil {
			t.Errorf("%q was accepted as a provider id", bad)
		}
	}
	sub, rg, name, err := splitAzureVMProviderID(azureVMProviderID(testSub, "rg", "pv-vm-1"))
	if err != nil || sub != testSub || rg != "rg" || name != "pv-vm-1" {
		t.Errorf("round trip failed: %q %q %q %v", sub, rg, name, err)
	}
}
