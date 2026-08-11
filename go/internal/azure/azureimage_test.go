package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

type azImageServer struct {
	getStatus int
	getBody   string
	calls     []string
}

func (s *azImageServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.calls = append(s.calls, r.Method)
		w.WriteHeader(s.getStatus)
		_, _ = w.Write([]byte(s.getBody))
	}
}

func azImageDriver(t *testing.T, s *azImageServer) (*Driver, func()) {
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

const azImageJSON = `{"location":"swedencentral","properties":{"provisioningState":"Succeeded",
"storageProfile":{"osDisk":{"diskEncryptionSet":{"id":"` + azDiskDES + `"}}}}}`

// The witness predicate is the design decision, and BOTH halves matter: too broad
// and groundhold silently creates nothing on Azure at all.
func TestAzureWitnessPredicateIsPerServiceAndNarrow(t *testing.T) {
	if provider.CanAuthor("azure", "azimage") {
		t.Error("azure/azimage reports as authorable — the compiler would emit a create " +
			"the driver refuses, the exact lie D177 exists to prevent")
	}
	for _, svc := range []string{"azvm", "azdisk", "vnet", "blob", "keyvault", "aks"} {
		if !provider.CanAuthor("azure", svc) {
			t.Errorf("azure/%s stopped being authorable — the predicate is too broad", svc)
		}
	}
}

func TestObserveAzureImage(t *testing.T) {
	s := &azImageServer{getStatus: 200, getBody: azImageJSON}
	d, done := azImageDriver(t, s)
	defer done()

	obs, unread, err := d.observeAzureImage("base-image",
		azureImageProviderID(testSub, "rg", "base-2026-07"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	deriv := map[string]string{}
	for _, o := range obs {
		got[o.Path] = o.Value
		deriv[o.Path] = o.Derivation
	}
	want := map[string]any{
		"location.region":                "swedencentral",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	// The distinction the derivations exist for: a managed image has NO sharing
	// setting, so `measured` would claim the driver read one and found it off.
	if deriv["network.publicExposure"] != "config-intent" {
		t.Errorf("network.publicExposure derivation = %q, want config-intent — a managed "+
			"image cannot be shared outside its subscription, so `false` is a fact about "+
			"the platform and not a reading", deriv["network.publicExposure"])
	}
	if deriv["encryption.customerManagedKeys"] != "measured" {
		t.Errorf("customerManagedKeys derivation = %q, want measured — this one IS read "+
			"off the resource", deriv["encryption.customerManagedKeys"])
	}
	var said bool
	for _, u := range unread {
		if strings.Contains(u, "sourceProvenance") {
			said = true
		}
	}
	if !said {
		t.Error("sourceProvenance is neither observed nor reported unread")
	}
	if _, ok := got["sourceProvenance"]; ok {
		t.Error("sourceProvenance was observed — a managed image carries no readable attestation")
	}
}

func TestObserveAzureImageWithoutCustomerKey(t *testing.T) {
	s := &azImageServer{getStatus: 200,
		getBody: `{"location":"swedencentral","properties":{"storageProfile":{"osDisk":{}}}}`}
	d, done := azImageDriver(t, s)
	defer done()

	obs, _, err := d.observeAzureImage("base-image",
		azureImageProviderID(testSub, "rg", "base-2026-07"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "encryption.customerManagedKeys" && o.Value != false {
			t.Errorf("a platform-key image was reported customer-managed (%v)", o.Value)
		}
	}
}

func TestObserveAzureImageMissingIsNotAnError(t *testing.T) {
	s := &azImageServer{getStatus: 404, getBody: `{}`}
	d, done := azImageDriver(t, s)
	defer done()
	obs, unread, err := d.observeAzureImage("base-image",
		azureImageProviderID(testSub, "rg", "base-2026-07"))
	if err != nil {
		t.Fatalf("an absent image produced an error: %v", err)
	}
	// Corrected with D518: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if len(unread) == 0 || !absentMarked(obs) {
		t.Errorf("obs = %v, unread = %v", obs, unread)
	}
}

func TestObserveAzureImageUnreadableIsAnError(t *testing.T) {
	s := &azImageServer{getStatus: 500, getBody: `{}`}
	d, done := azImageDriver(t, s)
	defer done()
	obs, _, err := d.observeAzureImage("base-image",
		azureImageProviderID(testSub, "rg", "base-2026-07"))
	if err == nil {
		t.Fatal("a 500 produced no error")
	}
	if len(obs) != 0 {
		t.Errorf("observations %v despite the failed read", obs)
	}
	if !strings.Contains(err.Error(), "images.get") {
		t.Errorf("diagnostic %q does not name the call", err)
	}
}

func TestDiscoverAzureImages(t *testing.T) {
	list := `{"value":[
{"id":"/subscriptions/` + testSub + `/resourceGroups/rg/providers/Microsoft.Compute/images/i1",
 "name":"i1","location":"swedencentral"},
{"id":"/subscriptions/` + testSub + `/resourceGroups/rg/providers/Microsoft.Compute/images/i2",
 "name":"i2","location":"westeurope"}]}`
	s := &azImageServer{getStatus: 200, getBody: list}
	d, done := azImageDriver(t, s)
	defer done()

	got, _, err := d.discoverAzureImages("swedencentral")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	var sawI1 bool
	for _, g := range got {
		if strings.HasSuffix(g.ProviderID, ":i1") {
			sawI1 = true
		}
		if strings.HasSuffix(g.ProviderID, ":i2") {
			t.Errorf("an image from another region was discovered: %q", g.ProviderID)
		}
		if g.ResourceType != "capability.compute.image" {
			t.Errorf("resourceType = %q", g.ResourceType)
		}
	}
	if !sawI1 {
		t.Fatalf("the in-region image was not discovered: %+v", got)
	}
}

func TestAzureImageRefusesEveryAuthoringPath(t *testing.T) {
	s := &azImageServer{getStatus: 200, getBody: azImageJSON}
	d, done := azImageDriver(t, s)
	defer done()

	if err := d.Validate("azimage", "base-image", "production", nil, nil, 1); err == nil {
		t.Error("Validate accepted a create for a witness service")
	} else if !strings.Contains(err.Error(), "WITNESS") {
		t.Errorf("Validate refusal = %q", err)
	}
	create := d.Create("azimage", "base-image", "production", nil, nil, "k", 1)
	if create.Status != "failed" || !strings.Contains(create.Reason, "WITNESS") {
		t.Errorf("Create = %q/%q", create.Status, create.Reason)
	}
	del := d.Delete("azimage", "base-image", "production",
		azureImageProviderID(testSub, "rg", "base-2026-07"), "k")
	if del.Status != "failed" || !strings.Contains(del.Reason, "WITNESS") {
		t.Errorf("Delete = %q/%q", del.Status, del.Reason)
	}
}

func TestClassifyAzureImageChange(t *testing.T) {
	for _, path := range []string{"location.region", "network.publicExposure",
		"encryption.atRest", "encryption.customerManagedKeys", "sourceProvenance", "service.managed"} {
		class, why := classifyAzureImageChange(path)
		if class != "unsupported" || !strings.Contains(why, "witnessed") {
			t.Errorf("%s classified %q/%q", path, class, why)
		}
	}
	if class, _ := classifyAzureImageChange("something.invented"); class != "" {
		t.Errorf("an unknown path classified %q", class)
	}
}

func TestSplitAzureImageProviderID(t *testing.T) {
	pid := azureImageProviderID(testSub, "rg", "base-2026-07")
	sub, rg, name, err := splitAzureImageProviderID(pid)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if sub != testSub || rg != "rg" || name != "base-2026-07" {
		t.Errorf("split = %q/%q/%q", sub, rg, name)
	}
	for _, bad := range []string{
		"azvm:" + testSub + ":rg:base",
		"azimage::rg:base",
		"azimage:" + testSub + ":rg:",
		"azimage:" + testSub + ":rg",
	} {
		if _, _, _, err := splitAzureImageProviderID(bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
}

// absentMarked reports whether an observation set carries the F-LC3 marker set
// true — the one way a driver says a BOUND resource is authoritatively gone.
func absentMarked(obs []provider.Observation) bool {
	for _, o := range obs {
		if o.Path == provider.ResourceAbsentPath {
			gone, _ := o.Value.(bool)
			return gone
		}
	}
	return false
}
