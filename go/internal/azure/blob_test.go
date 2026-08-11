package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func blobAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eastus",
		"durability.class":       "regional",
		"versioning.enabled":     true,
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"retention.minimum":      "30d",
		"service.managed":        true,
	}
}

func TestBuildBlobHonors(t *testing.T) {
	p, err := BuildBlob("prod", "assets", blobAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.SKU != "Standard_ZRS" || !p.Versioning || p.Public || p.RetentionMinDays != 30 {
		t.Fatalf("plan = %+v", p)
	}
	if !storageNameOK.MatchString(p.Account) {
		t.Fatalf("account name %q invalid", p.Account)
	}
}

func TestBuildBlobRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "eastus", "encryption.atRest": true, "service.managed": true}
	}
	cases := map[string]map[string]any{}
	for k, v := range map[string]any{
		"encryption.atRest": false, "durability.class": "nonsense",
		"service.managed": false,
	} {
		a := base()
		a[k] = v
		cases[k] = a
	}
	// CMK without keys
	cmk := base()
	cmk["encryption.customerManagedKeys"] = true
	cases["cmk-no-keys"] = cmk
	// locked without minimum
	lk := base()
	lk["retention.locked"] = true
	cases["locked-no-min"] = lk
	// sub-day retention
	sd := base()
	sd["retention.minimum"] = "6h"
	cases["sub-day"] = sd
	// missing region
	cases["no-region"] = map[string]any{"encryption.atRest": true, "service.managed": true}
	// unknown attr
	uk := base()
	uk["autoscaling.enabled"] = true
	cases["unknown"] = uk

	for name, a := range cases {
		if _, err := BuildBlob("prod", "assets", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func replImpl() map[string]any {
	return map[string]any{
		"resource_group":                     "rg1",
		"replication_destination_account_id": "/subscriptions/" + testSub + "/resourceGroups/rg2/providers/Microsoft.Storage/storageAccounts/pvdestacct0000000000",
		"replication_destination_container":  "replica",
	}
}

func replAttrs() map[string]any {
	return map[string]any{
		"location.region":               "eastus",
		"durability.class":              "regional",
		"versioning.enabled":            true,
		"network.publicExposure":        false,
		"encryption.atRest":             true,
		"replication.enabled":           true,
		"replication.destinationRegion": "eastus2",
		"service.managed":               true,
	}
}

func TestBuildBlobReplicationHonors(t *testing.T) {
	p, err := BuildBlob("prod", "assets", replAttrs(), replImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Replication || p.ReplicationDestContainer != "replica" ||
		!storageAccountIDOK.MatchString(p.ReplicationDestAccountID) {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildBlobReplicationRefusals(t *testing.T) {
	// no versioning -> refuse (presupposition)
	noVer := replAttrs()
	noVer["versioning.enabled"] = false
	if _, err := BuildBlob("prod", "assets", noVer, replImpl(), 1); err == nil {
		t.Error("replication without versioning must refuse")
	}
	// no operands -> refuse
	if _, err := BuildBlob("prod", "assets", replAttrs(), map[string]any{"resource_group": "rg1"}, 1); err == nil {
		t.Error("replication without destination operands must refuse")
	}
	// bad destination account id -> refuse
	badID := replImpl()
	badID["replication_destination_account_id"] = "not-a-resource-id"
	if _, err := BuildBlob("prod", "assets", replAttrs(), badID, 1); err == nil {
		t.Error("replication with a non-resource-id destination must refuse")
	}
}

func TestCreateObserveBlobReplication(t *testing.T) {
	srcAcct := azStorageName("prod", "assets", 1)
	destAcctID := "/subscriptions/" + testSub + "/resourceGroups/rg2/providers/Microsoft.Storage/storageAccounts/pvdestacct0000000000"
	policyID := "11111111-1111-1111-1111-111111111111"
	ruleID := "22222222-2222-2222-2222-222222222222"
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case r.Method == "PUT" && strings.HasSuffix(p, "/objectReplicationPolicies/default"):
				_, _ = w.Write([]byte(`{"properties":{"policyId":"` + policyID + `","rules":[{"ruleId":"` + ruleID + `"}]}}`))
			case r.Method == "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"etag":"W/\"abc\"","properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "GET" && strings.HasSuffix(p, "/objectReplicationPolicies"):
				_, _ = w.Write([]byte(`{"value":[{"properties":{"sourceAccount":"` + srcAcct +
					`","destinationAccount":"` + destAcctID + `"}}]}`))
			case r.Method == "GET" && strings.HasSuffix(p, "/immutabilityPolicies/default"):
				w.WriteHeader(404)
			case r.Method == "GET" && strings.HasSuffix(p, destAcctID):
				_, _ = w.Write([]byte(`{"location":"East US 2"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"Standard_ZRS"},` +
					`"tags":{"groundhold-capability":"assets","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"Disabled"}}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	res := d.createBlob("prod", "assets", replAttrs(), replImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeBlob("assets", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["replication.enabled"] != true || got["replication.destinationRegion"] != "eastus2" {
		t.Fatalf("replication observe = %+v", got)
	}
}

func blobArmFake(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT", "POST":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"etag":"W/\"abc\"","properties":{"provisioningState":"Succeeded"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"Standard_ZRS"},` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"Disabled"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestCreateObserveDeleteBlob(t *testing.T) {
	srv := blobArmFake(t, "assets")
	defer srv.Close()
	d := vnetTestDriver(t, srv) // reuse: same driver setup (sub, token, poll)
	impl := map[string]any{"resource_group": "rg1"}

	res := d.createBlob("prod", "assets", blobAttrs(), impl, 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeBlob("assets", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eastus" || got["durability.class"] != "regional" ||
		got["network.publicExposure"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteBlob("assets", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// TestClassifyBlobChange pins every branch of the pure classifier: WORM/
// replacement paths, and the default "unsupported" fallback for anything else.
func TestClassifyBlobChange(t *testing.T) {
	cases := map[string]string{
		"location.region": "immutable",
		// D824: Microsoft publishes "Change how a storage account is replicated" — the
		// redundancy is editable, so a replacement destroys every blob for nothing.
		"durability.class": "unsupported",
		// D824: an unlocked policy can be shortened or lengthened, a locked one extended.
		"retention.minimum": "unsupported",
		"retention.locked":  "immutable",
		// D824: object replication is a policy Azure applies to accounts that already
		// exist, so replacing a stateful account was never what it needed.
		"replication.enabled":           "unsupported",
		"replication.destinationRegion": "unsupported",
		"versioning.enabled":            "unsupported",
		"cost.monthly":                  "unsupported",
	}
	for path, want := range cases {
		if got, reason := classifyBlobChange(path); got != want {
			t.Errorf("classifyBlobChange(%q) = (%q, %q), want verb %q", path, got, reason, want)
		}
	}
}

// TestSplitBlobProviderIDRejectsMalformed pins the parse guard: wrong prefix,
// wrong arity, and an invalid component (account/container) all refuse.
func TestSplitBlobProviderIDRejectsMalformed(t *testing.T) {
	valid := blobProviderID(testSub, "rg1", "pvacct000000000000000", "container1")
	if _, _, _, _, err := splitBlobProviderID(valid); err != nil {
		t.Fatalf("a well-formed pid must parse, got %v", err)
	}
	cases := map[string]string{
		"wrong-prefix":  "notblob:" + testSub + ":rg1:pvacct000000000000000:container1",
		"too-few-parts": "blob:" + testSub + ":rg1:pvacct000000000000000",
		"bad-sub":       "blob:not-a-guid:rg1:pvacct000000000000000:container1",
		"bad-account":   "blob:" + testSub + ":rg1:UPPER-not-valid:container1",
	}
	for name, pid := range cases {
		if _, _, _, _, err := splitBlobProviderID(pid); err == nil {
			t.Errorf("%s: expected a parse refusal for %q, got none", name, pid)
		}
	}
}

// TestJsonEtag pins the etag-extraction helper the WORM lock POST needs: present,
// absent, and unparseable bodies.
func TestJsonEtag(t *testing.T) {
	if got := jsonEtag([]byte(`{"etag":"W/\"abc\""}`)); got != `W/"abc"` {
		t.Errorf("jsonEtag with an etag = %q", got)
	}
	if got := jsonEtag([]byte(`{"properties":{}}`)); got != "" {
		t.Errorf("jsonEtag with no etag field = %q, want empty", got)
	}
	if got := jsonEtag([]byte(`not json`)); got != "" {
		t.Errorf("jsonEtag on unparseable body = %q, want empty", got)
	}
}

// TestManagementPolicyBody pins the shape of the lifecycle (retention.maximum)
// policy body: scoped to THIS container's prefix, blockBlob only, a delete
// action gated on the configured day count.
func TestManagementPolicyBody(t *testing.T) {
	body := managementPolicyBody("mycontainer", 90)
	props, _ := body["properties"].(map[string]any)
	policy, _ := props["policy"].(map[string]any)
	rules, _ := policy["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("expected exactly one rule, got %+v", rules)
	}
	rule, _ := rules[0].(map[string]any)
	if rule["enabled"] != true || rule["type"] != "Lifecycle" {
		t.Fatalf("rule = %+v", rule)
	}
	def, _ := rule["definition"].(map[string]any)
	filters, _ := def["filters"].(map[string]any)
	prefixes, _ := filters["prefixMatch"].([]any)
	if len(prefixes) != 1 || prefixes[0] != "mycontainer/" {
		t.Fatalf("prefixMatch = %+v, want [\"mycontainer/\"]", prefixes)
	}
	blobTypes, _ := filters["blobTypes"].([]any)
	if len(blobTypes) != 1 || blobTypes[0] != "blockBlob" {
		t.Fatalf("blobTypes = %+v", blobTypes)
	}
	actions, _ := def["actions"].(map[string]any)
	baseBlob, _ := actions["baseBlob"].(map[string]any)
	del, _ := baseBlob["delete"].(map[string]any)
	if del["daysAfterModificationGreaterThan"] != int64(90) {
		t.Fatalf("delete action = %+v, want 90 days", del)
	}
}

// TestCreateBlobRetentionLockedExercisesWORMLock proves the WORM-lock branch
// end to end: an immutability policy is PUT, its etag is used as an If-Match CAS
// on the lock POST (doARMIfMatch) — never applied without the etag from the
// immediately-preceding PUT.
func TestCreateBlobRetentionLockedExercisesWORMLock(t *testing.T) {
	var sawIfMatch string
	var lockCalled bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST" && strings.Contains(r.URL.Path, "/immutabilityPolicies/default/lock"):
			lockCalled = true
			sawIfMatch = r.Header.Get("If-Match")
			w.WriteHeader(200)
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/immutabilityPolicies/default"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"etag":"W/\"lockme\"","properties":{"immutabilityPeriodSinceCreationInDays":30}}`))
		case r.Method == "GET":
			// the account pre-existence/ownership read refuseForeignUpsert issues
			// before the account PUT — must carry OUR tags or the create refuses.
			_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"Standard_ZRS"},` +
				`"tags":{"groundhold-capability":"assets","groundhold-environment":"prod"},` +
				`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"Disabled"}}`))
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"etag":"W/\"abc\"","properties":{"provisioningState":"Succeeded"}}`))
		}
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	a := blobAttrs()
	a["retention.minimum"] = "30d"
	a["retention.locked"] = true
	impl := map[string]any{"resource_group": "rg1"}
	res := d.createBlob("prod", "assets", a, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create with a WORM lock: %+v", res)
	}
	if !lockCalled {
		t.Fatal("a locked retention.minimum must POST the immutability lock")
	}
	if sawIfMatch != `W/"lockme"` {
		t.Fatalf("the lock POST must carry the policy's own etag as If-Match, got %q", sawIfMatch)
	}
}

// TestCreateBlobRetentionLockedNoEtagIsUnknown: a locked policy whose PUT answers
// with NO etag cannot be safely CAS-locked — surfaced as unknown (reconcile),
// never silently skipped or forced without the CAS guard.
func TestCreateBlobRetentionLockedNoEtagIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "PUT" && strings.Contains(r.URL.Path, "/immutabilityPolicies/default"):
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"properties":{"immutabilityPeriodSinceCreationInDays":30}}`)) // no etag
		case r.Method == "GET":
			_, _ = w.Write([]byte(`{"location":"eastus","sku":{"name":"Standard_ZRS"},` +
				`"tags":{"groundhold-capability":"assets","groundhold-environment":"prod"},` +
				`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"Disabled"}}`))
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"etag":"W/\"abc\"","properties":{"provisioningState":"Succeeded"}}`))
		}
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	a := blobAttrs()
	a["retention.minimum"] = "30d"
	a["retention.locked"] = true
	impl := map[string]any{"resource_group": "rg1"}
	res := d.createBlob("prod", "assets", a, impl, 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "no etag") {
		t.Fatalf("a lock with no etag must be unknown, got %+v", res)
	}
}

func TestDeleteBlobForeignRefused(t *testing.T) {
	srv := blobArmFake(t, "someone-else")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := blobProviderID(testSub, "rg1", azStorageName("prod", "assets", 1), blobContainerName("prod", "assets", 1))
	res := d.deleteBlob("assets", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign account must refuse delete, got %+v", res)
	}
}

func TestDeleteBlobWORMLockedBlocked(t *testing.T) {
	// a 409 on the account delete = a WORM-locked container; retirement is blocked,
	// never forced.
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"assets","groundhold-environment":"prod"},"properties":{"provisioningState":"Succeeded"}}`))
				return
			}
			if r.Method == "DELETE" {
				w.WriteHeader(409)
				return
			}
			w.WriteHeader(404)
		}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := blobProviderID(testSub, "rg1", azStorageName("prod", "assets", 1), blobContainerName("prod", "assets", 1))
	res := d.deleteBlob("assets", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "WORM-locked") {
		t.Fatalf("a WORM-locked account delete must be a clear failed, got %+v", res)
	}
}
