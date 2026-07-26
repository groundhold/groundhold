package azure

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const azDiskDES = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Compute/diskEncryptionSets/des0"
const azDiskSnap = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg/providers/Microsoft.Compute/snapshots/nightly"

func azDiskAttrs() map[string]any {
	return map[string]any{
		"location.region":                "swedencentral",
		"availability.class":             "zonal",
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": false,
		"service.managed":                true,
	}
}

func azDiskImpl() map[string]any {
	return map[string]any{
		"resource_group": "rg",
		"disk_sku":       "Premium_LRS",
		"size_gb":        100,
	}
}

func TestBuildAzureDiskGoldenZonal(t *testing.T) {
	p, err := BuildAzureDisk("production", "orders-data", azDiskAttrs(), azDiskImpl(), 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if p.Regional {
		t.Error("a _LRS SKU produced a regional plan")
	}
	body := p.createBody(map[string]any{"groundhold-capability": "orders-data"})
	if body["location"] != "swedencentral" {
		t.Errorf("location = %v", body["location"])
	}
	sku, _ := body["sku"].(map[string]any)
	if sku["name"] != "Premium_LRS" {
		t.Errorf("sku = %v", body["sku"])
	}
	props, _ := body["properties"].(map[string]any)
	if props["diskSizeGB"] != 100 {
		t.Errorf("diskSizeGB = %v", props["diskSizeGB"])
	}
	creation, _ := props["creationData"].(map[string]any)
	if creation["createOption"] != "Empty" {
		t.Errorf("createOption = %v, want Empty", creation["createOption"])
	}
	if _, ok := props["encryption"]; ok {
		t.Error("a disk with no declared CMK carried an encryption block — the platform " +
			"key is the default and naming it would claim a control the customer does not have")
	}
	if _, ok := body["zones"]; ok {
		t.Error("a disk with no pinned zone carried a zones array")
	}
}

// The SKU is where Azure keeps the durability guarantee: _ZRS spans zones. Three
// clouds, three mechanisms (EBS refuses, GCP uses regionDisks, Azure uses a
// suffix), one attribute.
func TestBuildAzureDiskGoldenRegional(t *testing.T) {
	attrs := azDiskAttrs()
	attrs["availability.class"] = "regional"
	impl := azDiskImpl()
	impl["disk_sku"] = "Premium_ZRS"

	p, err := BuildAzureDisk("production", "orders-data", attrs, impl, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !p.Regional {
		t.Fatal("a _ZRS SKU produced a zonal plan — the durability guarantee was lost")
	}
	sku, _ := p.createBody(nil)["sku"].(map[string]any)
	if sku["name"] != "Premium_ZRS" {
		t.Errorf("sku = %v", sku)
	}
}

// The cross-check runs in BOTH directions, and the reasons differ. An over-claim
// certifies a guarantee that does not exist. An under-claim leaves observed and
// declared disagreeing, so a converge that should be a no-op reports a violation
// that can never be resolved.
func TestAzureDiskClassMustMatchTheSKUBothWays(t *testing.T) {
	t.Run("regional declared, locally-redundant SKU", func(t *testing.T) {
		attrs := azDiskAttrs()
		attrs["availability.class"] = "regional"
		_, err := BuildAzureDisk("production", "orders-data", attrs, azDiskImpl(), 0)
		if err == nil {
			t.Fatal("a _LRS disk was accepted for a regional contract — that certifies " +
				"zone survivability the disk does not have")
		}
		if !strings.Contains(err.Error(), "does not survive losing a zone") {
			t.Errorf("refusal = %q", err)
		}
	})
	t.Run("zonal declared, zone-redundant SKU", func(t *testing.T) {
		impl := azDiskImpl()
		impl["disk_sku"] = "Premium_ZRS"
		_, err := BuildAzureDisk("production", "orders-data", azDiskAttrs(), impl, 0)
		if err == nil {
			t.Fatal("a _ZRS disk was accepted for a zonal contract — the disk observed " +
				"back would be regional and the contract would report a violation forever")
		}
		if !strings.Contains(err.Error(), "can never resolve") {
			t.Errorf("refusal = %q", err)
		}
	})
}

func TestBuildAzureDiskCustomerManagedKey(t *testing.T) {
	attrs := azDiskAttrs()
	attrs["encryption.customerManagedKeys"] = true
	impl := azDiskImpl()
	impl["disk_encryption_set_id"] = azDiskDES

	p, err := BuildAzureDisk("production", "orders-data", attrs, impl, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	props, _ := p.createBody(nil)["properties"].(map[string]any)
	enc, _ := props["encryption"].(map[string]any)
	if enc["type"] != "EncryptionAtRestWithCustomerKey" || enc["diskEncryptionSetId"] != azDiskDES {
		t.Errorf("encryption = %v", enc)
	}
}

func TestAzureDiskSizeMayComeFromACopySource(t *testing.T) {
	impl := map[string]any{"resource_group": "rg", "disk_sku": "Premium_LRS",
		"source_resource_id": azDiskSnap}
	p, err := BuildAzureDisk("production", "orders-data", azDiskAttrs(), impl, 0)
	if err != nil {
		t.Fatalf("a copy with no explicit size was refused: %v", err)
	}
	props, _ := p.createBody(nil)["properties"].(map[string]any)
	creation, _ := props["creationData"].(map[string]any)
	if creation["createOption"] != "Copy" || creation["sourceResourceId"] != azDiskSnap {
		t.Errorf("creationData = %v", creation)
	}
	if _, ok := props["diskSizeGB"]; ok {
		t.Errorf("diskSizeGB = %v was sent for a copy that declared none", props["diskSizeGB"])
	}
}

func TestBuildAzureDiskPinnedZone(t *testing.T) {
	impl := azDiskImpl()
	impl["zone"] = "2"
	p, err := BuildAzureDisk("production", "orders-data", azDiskAttrs(), impl, 0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	zones, _ := p.createBody(nil)["zones"].([]any)
	if len(zones) != 1 || zones[0] != "2" {
		t.Errorf("zones = %v", zones)
	}
}

func TestBuildAzureDiskRefusals(t *testing.T) {
	cases := []struct {
		name  string
		mutA  func(map[string]any)
		mutI  func(map[string]any)
		wants string
	}{
		{
			name:  "unencrypted is not something Azure can do",
			mutA:  func(a map[string]any) { a["encryption.atRest"] = false },
			wants: "always encrypted at rest",
		},
		{
			name:  "an unknown availability class",
			mutA:  func(a map[string]any) { a["availability.class"] = "multi-regional" },
			wants: "has no managed-disk mapping (zonal or regional)",
		},
		{
			name:  "an attribute the driver cannot map",
			mutA:  func(a map[string]any) { a["network.publicExposure"] = false },
			wants: "refusing rather than silently dropping it",
		},
		{
			name:  "no region",
			mutA:  func(a map[string]any) { delete(a, "location.region") },
			wants: "location.region is required",
		},
		{
			name:  "a customer key with nowhere to get it",
			mutA:  func(a map[string]any) { a["encryption.customerManagedKeys"] = true },
			wants: "requires implementation.disk_encryption_set_id",
		},
		{
			name:  "a disk-encryption set that is not a resource id",
			mutA:  func(a map[string]any) { a["encryption.customerManagedKeys"] = true },
			mutI:  func(i map[string]any) { i["disk_encryption_set_id"] = "des0" },
			wants: "is not an ARM resource id",
		},
		{
			name:  "an unmanaged disk is an adoption, not a create",
			mutA:  func(a map[string]any) { a["service.managed"] = false },
			wants: "adoption, not a create",
		},
		{
			// The SKU carries a GOVERNED fact, so it must not come from a default —
			// unlike the EBS volume type, which carries nothing the contract sees.
			name:  "no SKU",
			mutI:  func(i map[string]any) { delete(i, "disk_sku") },
			wants: "implementation.disk_sku is required",
		},
		{
			name:  "a SKU that is not one",
			mutI:  func(i map[string]any) { i["disk_sku"] = "SuperFast" },
			wants: "is not a managed-disk SKU",
		},
		{
			name:  "no size and nothing to copy",
			mutI:  func(i map[string]any) { delete(i, "size_gb") },
			wants: "implementation.size_gb is required",
		},
		{
			name:  "a size that is not a size",
			mutI:  func(i map[string]any) { i["size_gb"] = 0 },
			wants: "positive whole number of GiB",
		},
		{
			name:  "a zone that is not an Azure zone",
			mutI:  func(i map[string]any) { i["zone"] = "swedencentral-1" },
			wants: "is not an Azure availability zone",
		},
		{
			// Pinning a zone on a zone-redundant disk contradicts the redundancy.
			name: "a pinned zone on a zone-redundant SKU",
			mutA: func(a map[string]any) { a["availability.class"] = "regional" },
			mutI: func(i map[string]any) {
				i["disk_sku"] = "Premium_ZRS"
				i["zone"] = "2"
			},
			wants: "spans zones and pinning one contradicts that",
		},
		{
			name:  "a copy source that is not a resource id",
			mutI:  func(i map[string]any) { i["source_resource_id"] = "nightly" },
			wants: "is not an ARM resource id",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs, impl := azDiskAttrs(), azDiskImpl()
			if tc.mutA != nil {
				tc.mutA(attrs)
			}
			if tc.mutI != nil {
				tc.mutI(impl)
			}
			_, err := BuildAzureDisk("production", "orders-data", attrs, impl, 0)
			if err == nil {
				t.Fatalf("build succeeded; want a refusal mentioning %q", tc.wants)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("refusal = %q, want it to mention %q", err, tc.wants)
			}
		})
	}
}

func TestAzureDiskNameIsDeterministicAndScoped(t *testing.T) {
	a, _ := BuildAzureDisk("production", "orders-data", azDiskAttrs(), azDiskImpl(), 0)
	b, _ := BuildAzureDisk("production", "orders-data", azDiskAttrs(), azDiskImpl(), 0)
	if a.Name == "" || a.Name != b.Name {
		t.Errorf("name is not deterministic: %q vs %q", a.Name, b.Name)
	}
	for _, other := range []struct {
		env, cap   string
		generation int
	}{
		{"staging", "orders-data", 0},
		{"production", "audit-data", 0},
		{"production", "orders-data", 2},
	} {
		o, _ := BuildAzureDisk(other.env, other.cap, azDiskAttrs(), azDiskImpl(), other.generation)
		if o.Name == a.Name {
			t.Errorf("%s/%s/g%d shares the name %q", other.env, other.cap, other.generation, a.Name)
		}
	}
}

func TestClassifyAzureDiskChange(t *testing.T) {
	for _, path := range []string{
		"location.region", "availability.class",
		"encryption.atRest", "encryption.customerManagedKeys",
	} {
		class, why := classifyAzureDiskChange(path)
		if class != "immutable" {
			t.Errorf("%s classified %q, want immutable", path, class)
		}
		if why == "" {
			t.Errorf("%s gave no reason", path)
		}
	}
	if class, _ := classifyAzureDiskChange("service.managed"); class != "unsupported" {
		t.Errorf("service.managed classified %q, want unsupported", class)
	}
	if class, why := classifyAzureDiskChange("something.invented"); class != "" || why != "" {
		t.Errorf("an unknown path classified %q/%q, want the empty answer", class, why)
	}
}

// --- network shell ---

type azDiskServer struct {
	getStatus int
	getBody   string
	putStatus int
	putBody   string
	delStatus int
	calls     []string
	bodies    []string
}

func (s *azDiskServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			b := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(b)
			s.bodies = append(s.bodies, string(b))
			s.calls = append(s.calls, "put")
			w.WriteHeader(s.putStatus)
			_, _ = w.Write([]byte(s.putBody))
		case http.MethodDelete:
			s.calls = append(s.calls, "delete")
			w.WriteHeader(s.delStatus)
			_, _ = w.Write([]byte(`{}`))
		default:
			s.calls = append(s.calls, "get")
			w.WriteHeader(s.getStatus)
			_, _ = w.Write([]byte(s.getBody))
		}
	}
}

func azDiskDriver(t *testing.T, s *azDiskServer) (*Driver, func()) {
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

func azDiskDoc(t *testing.T, cap, sku string, des bool) string {
	t.Helper()
	props := map[string]any{"provisioningState": "Succeeded"}
	if des {
		props["encryption"] = map[string]any{
			"type": "EncryptionAtRestWithCustomerKey", "diskEncryptionSetId": azDiskDES}
	}
	doc := map[string]any{
		"location": "swedencentral",
		"sku":      map[string]any{"name": sku},
		"tags": map[string]any{
			"groundhold-capability": cap, "groundhold-environment": "production",
		},
		"properties": props,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func TestObserveAzureDisk(t *testing.T) {
	s := &azDiskServer{getStatus: 200, getBody: azDiskDoc(t, "orders-data", "Premium_LRS", true)}
	d, done := azDiskDriver(t, s)
	defer done()

	obs, unread, err := d.observeAzureDisk("orders-data",
		azureDiskProviderID(testSub, "rg", "pv-disk-orders-data-production-abcd1234"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(unread) != 0 {
		t.Errorf("unread = %v on a fully readable disk", unread)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	want := map[string]any{
		"location.region":                "swedencentral",
		"availability.class":             "zonal",
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestObserveAzureDiskReadsTheClassFromTheSKU(t *testing.T) {
	s := &azDiskServer{getStatus: 200, getBody: azDiskDoc(t, "orders-data", "Premium_ZRS", false)}
	d, done := azDiskDriver(t, s)
	defer done()

	obs, _, err := d.observeAzureDisk("orders-data",
		azureDiskProviderID(testSub, "rg", "pv-disk-x"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "availability.class" && o.Value != "regional" {
			t.Errorf("a _ZRS disk was observed as %v", o.Value)
		}
		// A platform key is not a customer key.
		if o.Path == "encryption.customerManagedKeys" && o.Value != false {
			t.Errorf("a platform-key disk was reported customer-managed (%v)", o.Value)
		}
	}
}

// An unreadable SKU is an unknown durability guarantee. Defaulting to zonal would
// pass a "must survive a zone failure" constraint the disk may violate;
// defaulting to regional would fail one it may satisfy. Neither is a reading.
func TestObserveAzureDiskReportsAnUnreadableSKURatherThanDefaultingIt(t *testing.T) {
	s := &azDiskServer{getStatus: 200, getBody: `{"location":"swedencentral","properties":{}}`}
	d, done := azDiskDriver(t, s)
	defer done()

	obs, unread, err := d.observeAzureDisk("orders-data",
		azureDiskProviderID(testSub, "rg", "pv-disk-x"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "availability.class" {
			t.Errorf("availability.class was observed as %v from a disk with no SKU", o.Value)
		}
	}
	if len(unread) == 0 {
		t.Error("no diagnostic — the caller cannot tell an unread SKU from a zonal disk")
	}
}

func TestObserveAzureDiskUnreadableIsAnError(t *testing.T) {
	s := &azDiskServer{getStatus: 500, getBody: `{}`}
	d, done := azDiskDriver(t, s)
	defer done()

	obs, _, err := d.observeAzureDisk("orders-data",
		azureDiskProviderID(testSub, "rg", "pv-disk-x"))
	if err == nil {
		t.Fatal("a 500 produced no error — the caller cannot tell an unreadable disk from an unencrypted one")
	}
	if len(obs) != 0 {
		t.Errorf("observations %v were emitted despite the failed read", obs)
	}
	if !strings.Contains(err.Error(), "disks.get") {
		t.Errorf("diagnostic %q does not name the call that failed", err)
	}
}

func TestDeleteAzureDisk(t *testing.T) {
	pid := azureDiskProviderID(testSub, "rg", "pv-disk-x")

	t.Run("deletes what it owns", func(t *testing.T) {
		s := &azDiskServer{getStatus: 200, getBody: azDiskDoc(t, "orders-data", "Premium_LRS", false),
			delStatus: 200}
		d, done := azDiskDriver(t, s)
		defer done()
		if got := d.deleteAzureDisk("orders-data", "production", pid); got.Status != "succeeded" {
			t.Fatalf("status = %q (%s)", got.Status, got.Reason)
		}
	})

	// The check that matters most on a stateful capability: someone else's disk
	// holds someone else's data.
	t.Run("refuses a disk that is not ours", func(t *testing.T) {
		s := &azDiskServer{getStatus: 200,
			getBody: azDiskDoc(t, "someone-elses-database", "Premium_LRS", false), delStatus: 200}
		d, done := azDiskDriver(t, s)
		defer done()
		if got := d.deleteAzureDisk("orders-data", "production", pid); got.Status != "failed" {
			t.Fatalf("status = %q, want failed", got.Status)
		}
		for _, c := range s.calls {
			if c == "delete" {
				t.Fatal("DELETE was issued against a disk with foreign tags")
			}
		}
	})

	t.Run("an absent disk is already deleted", func(t *testing.T) {
		s := &azDiskServer{getStatus: 404, getBody: `{}`}
		d, done := azDiskDriver(t, s)
		defer done()
		if got := d.deleteAzureDisk("orders-data", "production", pid); got.Status != "succeeded" {
			t.Errorf("status = %q, want succeeded (idempotent)", got.Status)
		}
	})

	t.Run("an unreadable pre-delete read is unknown, never a delete", func(t *testing.T) {
		s := &azDiskServer{getStatus: 500, getBody: `{}`}
		d, done := azDiskDriver(t, s)
		defer done()
		got := d.deleteAzureDisk("orders-data", "production", pid)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
		for _, c := range s.calls {
			if c == "delete" {
				t.Fatal("DELETE was issued without a successful ownership read")
			}
		}
	})

	t.Run("5xx on the delete is unknown", func(t *testing.T) {
		s := &azDiskServer{getStatus: 200, getBody: azDiskDoc(t, "orders-data", "Premium_LRS", false),
			delStatus: 503}
		d, done := azDiskDriver(t, s)
		defer done()
		if got := d.deleteAzureDisk("orders-data", "production", pid); got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
	})
}

func TestCreateAzureDiskRefusesBeforeTheNetwork(t *testing.T) {
	s := &azDiskServer{putStatus: 200, putBody: `{}`}
	d, done := azDiskDriver(t, s)
	defer done()

	impl := azDiskImpl()
	delete(impl, "disk_sku")
	got := d.createAzureDisk("production", "orders-data", azDiskAttrs(), impl, 0)
	if got.Status != "failed" {
		t.Errorf("status = %q, want failed", got.Status)
	}
	if len(s.calls) != 0 {
		t.Errorf("the driver called %v before refusing", s.calls)
	}
}

func TestCreateAzureDiskRefusesWithoutAResourceGroup(t *testing.T) {
	s := &azDiskServer{putStatus: 200, putBody: `{}`}
	d, done := azDiskDriver(t, s)
	defer done()

	impl := azDiskImpl()
	delete(impl, "resource_group")
	got := d.createAzureDisk("production", "orders-data", azDiskAttrs(), impl, 0)
	if got.Status != "failed" || !strings.Contains(got.Reason, "resource_group") {
		t.Errorf("status = %q reason = %q", got.Status, got.Reason)
	}
	if len(s.calls) != 0 {
		t.Errorf("the driver called %v before refusing", s.calls)
	}
}

func TestDiscoverAzureDisks(t *testing.T) {
	list := `{"value":[
{"id":"/subscriptions/` + testSub + `/resourceGroups/rg/providers/Microsoft.Compute/disks/d1",
 "name":"d1","location":"swedencentral"},
{"id":"/subscriptions/` + testSub + `/resourceGroups/rg/providers/Microsoft.Compute/disks/d2",
 "name":"d2","location":"westeurope"}]}`
	s := &azDiskServer{getStatus: 200, getBody: list}
	d, done := azDiskDriver(t, s)
	defer done()

	got, _, err := d.discoverAzureDisks("swedencentral")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	// A test that only checks what is ABSENT passes when discovery returns
	// nothing at all, so the positive assertion comes first.
	var sawD1 bool
	for _, g := range got {
		if strings.HasSuffix(g.ProviderID, ":d1") {
			sawD1 = true
		}
	}
	if !sawD1 {
		t.Fatalf("the in-region disk was not discovered: %+v", got)
	}
	for _, g := range got {
		if strings.HasSuffix(g.ProviderID, ":d2") {
			t.Errorf("a disk from another region was discovered: %q", g.ProviderID)
		}
		if g.ResourceType != "capability.storage.block" {
			t.Errorf("resourceType = %q", g.ResourceType)
		}
	}
}

func TestSplitAzureDiskProviderID(t *testing.T) {
	pid := azureDiskProviderID(testSub, "rg", "pv-disk-x")
	sub, rg, name, err := splitAzureDiskProviderID(pid)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if sub != testSub || rg != "rg" || name != "pv-disk-x" {
		t.Errorf("split = %q/%q/%q", sub, rg, name)
	}
	for _, bad := range []string{
		"azvm:" + testSub + ":rg:pv-disk-x", // another service's id
		"azdisk::rg:pv-disk-x",              // no subscription
		"azdisk:" + testSub + ":rg:",        // no name
		"azdisk:" + testSub + ":rg",         // truncated
	} {
		if _, _, _, err := splitAzureDiskProviderID(bad); err == nil {
			t.Errorf("%q was accepted as a managed-disk providerId", bad)
		}
	}
}
