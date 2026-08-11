package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// a Log Analytics workspace resource id under testSub — the destination operand a
// contract declares (a separate capability the operator owns).
const testWorkspaceDest = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/Microsoft.OperationalInsights/workspaces/pvlaw01"
const testStorageDest = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/pvstore01"
const testEventHubDest = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/Microsoft.EventHub/namespaces/pvhubns01/authorizationRules/RootManageSharedAccessKey"

func activityLogAttrs() map[string]any {
	return map[string]any{
		"scope.multiRegion": true,
		"delivery.assured":  true,
		"service.managed":   true,
	}
}

func activityLogImpl() map[string]any {
	return map[string]any{"destination": testWorkspaceDest}
}

func TestBuildActivityLogHonors(t *testing.T) {
	p, err := BuildActivityLog(testSub, "prod", "audit", activityLogAttrs(), activityLogImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.DestField != "workspaceId" || p.Destination != testWorkspaceDest {
		t.Fatalf("destination routing = %q/%q", p.DestField, p.Destination)
	}
	if !p.Deliver {
		t.Fatalf("delivery.assured should default/honor true")
	}
	if len(p.Categories) != len(activityLogCategories) {
		t.Fatalf("categories = %v", p.Categories)
	}
	if !strings.HasPrefix(p.Name, "pv-al-") {
		t.Fatalf("name = %q", p.Name)
	}
	// the body carries every category with enabled reflecting delivery.assured.
	body := p.createBody()
	props := body["properties"].(map[string]any)
	if props["workspaceId"] != testWorkspaceDest {
		t.Fatalf("body workspaceId = %v", props["workspaceId"])
	}
	logs := props["logs"].([]any)
	if len(logs) != len(activityLogCategories) {
		t.Fatalf("body logs = %v", logs)
	}
	if logs[0].(map[string]any)["enabled"] != true {
		t.Fatalf("category enabled should be true")
	}
}

// delivery.assured=false flips every category enabled flag off (the in-place-mutable knob).
func TestBuildActivityLogDeliveryFalse(t *testing.T) {
	attrs := activityLogAttrs()
	attrs["delivery.assured"] = false
	p, err := BuildActivityLog(testSub, "prod", "audit", attrs, activityLogImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	logs := p.createBody()["properties"].(map[string]any)["logs"].([]any)
	if logs[0].(map[string]any)["enabled"] != false {
		t.Fatalf("delivery.assured=false must disable categories")
	}
}

// storage and event-hub destinations route to their own body fields.
func TestBuildActivityLogDestinationRouting(t *testing.T) {
	for dest, field := range map[string]string{
		testStorageDest:  "storageAccountId",
		testEventHubDest: "eventHubAuthorizationRuleId",
	} {
		p, err := BuildActivityLog(testSub, "prod", "audit", activityLogAttrs(), map[string]any{"destination": dest}, 1)
		if err != nil {
			t.Fatalf("%s: %v", dest, err)
		}
		if p.DestField != field {
			t.Fatalf("dest %q routed to %q, want %q", dest, p.DestField, field)
		}
	}
}

// a log_categories operand restricts the exported set, preserving canonical order.
func TestBuildActivityLogCategorySubset(t *testing.T) {
	impl := activityLogImpl()
	impl["log_categories"] = []any{"Security", "Administrative"}
	p, err := BuildActivityLog(testSub, "prod", "audit", activityLogAttrs(), impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Categories) != 2 || p.Categories[0] != "Administrative" || p.Categories[1] != "Security" {
		t.Fatalf("category subset (canonical order) = %v", p.Categories)
	}
}

// CMK is a destination property: true requires the key REFERENCE, carried not sent.
func TestBuildActivityLogCMK(t *testing.T) {
	attrs := activityLogAttrs()
	attrs["encryption.customerManagedKeys"] = true
	impl := activityLogImpl()
	impl["kms_key_name"] = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg1/providers/Microsoft.KeyVault/vaults/pvkv01/keys/auditkey"
	p, err := BuildActivityLog(testSub, "prod", "audit", attrs, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.CMK || p.KmsKeyName == "" {
		t.Fatalf("CMK reference not carried: %+v", p)
	}
	// the key reference must NOT enter the setting body (it lives on the destination).
	props := p.createBody()["properties"].(map[string]any)
	for k := range props {
		if strings.Contains(strings.ToLower(k), "key") {
			t.Fatalf("CMK key must not appear in the setting body, found %q", k)
		}
	}
}

func TestBuildActivityLogRefusals(t *testing.T) {
	base := func() (map[string]any, map[string]any) {
		a := activityLogAttrs()
		i := activityLogImpl()
		return a, i
	}
	type tc struct {
		mut func(a, i map[string]any)
	}
	cases := map[string]tc{
		"integrity-true":        {func(a, i map[string]any) { a["integrity.logValidation"] = true }},
		"integrity-not-bool":    {func(a, i map[string]any) { a["integrity.logValidation"] = "yes" }},
		"scope-false":           {func(a, i map[string]any) { a["scope.multiRegion"] = false }},
		"scope-not-bool":        {func(a, i map[string]any) { a["scope.multiRegion"] = "y" }},
		"managed-false":         {func(a, i map[string]any) { a["service.managed"] = false }},
		"delivery-not-bool":     {func(a, i map[string]any) { a["delivery.assured"] = "y" }},
		"unknown-attr":          {func(a, i map[string]any) { a["network.publicExposure"] = true }},
		"missing-destination":   {func(a, i map[string]any) { delete(i, "destination") }},
		"bad-destination":       {func(a, i map[string]any) { i["destination"] = "/subscriptions/x/not-a-dest" }},
		"cmk-without-key":       {func(a, i map[string]any) { a["encryption.customerManagedKeys"] = true }},
		"key-without-cmk":       {func(a, i map[string]any) { i["kms_key_name"] = testWorkspaceDest }},
		"bad-region":            {func(a, i map[string]any) { a["location.region"] = "bad/region!" }},
		"empty-categories":      {func(a, i map[string]any) { i["log_categories"] = []any{} }},
		"unknown-category":      {func(a, i map[string]any) { i["log_categories"] = []any{"NotACategory"} }},
		"categories-not-a-list": {func(a, i map[string]any) { i["log_categories"] = "Security" }},
		"bad-setting-name":      {func(a, i map[string]any) { i["diagnosticSettingName"] = "bad/name?" }},
	}
	for name, c := range cases {
		a, i := base()
		c.mut(a, i)
		if _, err := BuildActivityLog(testSub, "prod", "audit", a, i, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// location.region is accepted (a declared residency assertion) but never enters the body.
func TestBuildActivityLogRegionCarriedNotSent(t *testing.T) {
	attrs := activityLogAttrs()
	attrs["location.region"] = "West Europe"
	p, err := BuildActivityLog(testSub, "prod", "audit", attrs, activityLogImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "West Europe" {
		t.Fatalf("region not carried: %q", p.Region)
	}
	props := p.createBody()["properties"].(map[string]any)
	if _, ok := props["region"]; ok {
		t.Fatalf("region must not enter the setting body")
	}
}

// activityLogArmFake serves the diagnostic-setting PUT/GET/DELETE + the LIST, asserting
// the bearer header and the Insights path, and echoing an all-enabled setting on GET.
func activityLogArmFake(t *testing.T, wantField, wantDest string, seeded bool) *httptest.Server {
	t.Helper()
	// D804: the create READS before writing, and adoption means "what stands here is
	// exactly what this contract describes". So the fake serves the canonical category
	// set the plan writes, not a two-entry sketch of it — a fixture that serves less
	// than the driver writes makes its own resource look like a stranger's.
	settingDoc := func(name string) string {
		logs := make([]string, 0, len(activityLogCategories))
		for _, c := range activityLogCategories {
			// ARM echoes a retentionPolicy inside every log entry that this driver
			// never writes (D804) — the fake says so, because a comparison that cannot
			// survive it would call our own setting foreign.
			logs = append(logs, `{"category":"`+c+`","enabled":true,`+
				`"retentionPolicy":{"days":0,"enabled":false}}`)
		}
		return `{"name":"` + name + `","properties":{"` + wantField + `":"` + wantDest + `",` +
			`"logs":[` + strings.Join(logs, ",") + `]}}`
	}
	// D804: ARM answers 404 until something is PUT there, and the create now READS
	// before writing. A fake that serves the setting from the first GET makes every
	// create look like an overwrite of a stranger's resource.
	stored := seeded
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
				t.Errorf("missing/wrong bearer: %q", got)
			}
			if !strings.Contains(r.URL.Path, "/providers/Microsoft.Insights/diagnosticSettings") {
				t.Errorf("unexpected path %q", r.URL.Path)
			}
			// LIST: the path ends at diagnosticSettings (no trailing name).
			if strings.HasSuffix(r.URL.Path, "/diagnosticSettings") && r.Method == "GET" {
				_, _ = w.Write([]byte(`{"value":[` + settingDoc("pv-al-audit-prod-deadbeef") + `]}`))
				return
			}
			parts := strings.Split(strings.TrimRight(r.URL.Path, "/"), "/")
			name := parts[len(parts)-1]
			switch r.Method {
			case "PUT":
				stored = true
				var body struct {
					Properties map[string]any `json:"properties"`
				}
				raw, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(raw, &body); err != nil {
					t.Fatalf("bad PUT body: %v", err)
				}
				if body.Properties[wantField] != wantDest {
					t.Errorf("PUT %s = %v (want %q)", wantField, body.Properties[wantField], wantDest)
				}
				if _, ok := body.Properties["logs"]; !ok {
					t.Errorf("PUT body missing logs")
				}
				w.WriteHeader(200)
				_, _ = w.Write([]byte(settingDoc(name)))
			case "GET":
				if !stored {
					w.WriteHeader(404)
					return
				}
				_, _ = w.Write([]byte(settingDoc(name)))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestCreateObserveDeleteActivityLog(t *testing.T) {
	srv := activityLogArmFake(t, "workspaceId", testWorkspaceDest, false)
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	res := d.createActivityLog("prod", "audit", activityLogAttrs(), activityLogImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	if !strings.HasPrefix(res.ProviderID, "activitylog:"+testSub+":pv-al-") {
		t.Fatalf("providerId = %q", res.ProviderID)
	}

	obs, diags, err := d.observeActivityLog("audit", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["scope.multiRegion"] != true {
		t.Fatalf("observe scope.multiRegion = %v", got["scope.multiRegion"])
	}
	if got["delivery.assured"] != true {
		t.Fatalf("observe delivery.assured = %v", got["delivery.assured"])
	}
	if got["service.managed"] != true {
		t.Fatalf("observe service.managed = %v", got["service.managed"])
	}
	// honesty: integrity, region and CMK are OMITTED with diagnostics, never fabricated.
	if _, ok := got["integrity.logValidation"]; ok {
		t.Fatalf("integrity.logValidation must never be observed")
	}
	if _, ok := got["location.region"]; ok {
		t.Fatalf("location.region must never be observed from the setting")
	}
	if len(diags) != 3 {
		t.Fatalf("expected 3 honesty diagnostics, got %v", diags)
	}
	joined := strings.Join(diags, "|")
	for _, want := range []string{"location.region omitted", "integrity.logValidation omitted", "encryption.customerManagedKeys omitted"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing diagnostic %q in %v", want, diags)
		}
	}

	if del := d.deleteActivityLog("audit", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// delivery.assured is the ONE in-place-mutable attribute; the updater is wired.
func TestUpdateActivityLogDelivery(t *testing.T) {
	srv := activityLogArmFake(t, "workspaceId", testWorkspaceDest, true)
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	pid := activityLogProviderID(testSub, activityLogName("prod", "audit", 1))
	attrs := activityLogAttrs()
	attrs["delivery.assured"] = false
	res := d.updateActivityLog("audit", "prod", pid, attrs, activityLogImpl(), []string{"delivery.assured"})
	if res.Status != "succeeded" {
		t.Fatalf("update delivery.assured: %+v", res)
	}
	// a non-delivery change is refused (immutable/unsupported, never a silent no-op).
	res = d.updateActivityLog("audit", "prod", pid, activityLogAttrs(), activityLogImpl(), []string{"location.region"})
	if res.Status != "failed" {
		t.Fatalf("non-delivery update must refuse, got %+v", res)
	}
}

// a live setting with all categories disabled reads delivery.assured=false — measured,
// not assumed.
func TestObserveActivityLogDeliveryFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"name":"pv-al-audit-prod-x","properties":{"workspaceId":"` + testWorkspaceDest +
				`","logs":[{"category":"Administrative","enabled":false},{"category":"Security","enabled":false}]}}`))
		}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := activityLogProviderID(testSub, activityLogName("prod", "audit", 1))
	obs, _, err := d.observeActivityLog("audit", pid)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "delivery.assured" && o.Value != false {
			t.Fatalf("delivery.assured should read false when all categories disabled, got %v", o.Value)
		}
	}
}

func TestDiscoverActivityLog(t *testing.T) {
	srv := activityLogArmFake(t, "workspaceId", testWorkspaceDest, true)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	found, _, err := d.discoverActivityLog("westeurope")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.audit.trail" {
		t.Fatalf("discover = %+v", found)
	}
	if !strings.HasPrefix(found[0].ProviderID, "activitylog:"+testSub+":") {
		t.Fatalf("discovered providerId = %q", found[0].ProviderID)
	}
}

func TestDeleteActivityLogForeignSubscriptionRefused(t *testing.T) {
	srv := activityLogArmFake(t, "workspaceId", testWorkspaceDest, true)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	foreign := activityLogProviderID("00000000-0000-0000-0000-0000000000ff", activityLogName("prod", "audit", 1))
	res := d.deleteActivityLog("audit", "prod", foreign)
	if res.Status != "failed" || !strings.Contains(res.Reason, "across subscriptions") {
		t.Fatalf("foreign subscription must refuse delete, got %+v", res)
	}
}

func TestProviderIDRoundTripActivityLog(t *testing.T) {
	pid := activityLogProviderID(testSub, "pv-al-audit-prod-deadbeef")
	sub, name, err := splitActivityLogProviderID(pid)
	if err != nil || sub != testSub || name != "pv-al-audit-prod-deadbeef" {
		t.Fatalf("round-trip = %q/%q err=%v", sub, name, err)
	}
	for _, bad := range []string{"auditlogs:x:y", "activitylog:not-a-guid:name", "activitylog:" + testSub + ":bad/name"} {
		if _, _, err := splitActivityLogProviderID(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestClassifyActivityLogChange(t *testing.T) {
	cases := map[string]string{
		"delivery.assured":               "mutable",
		"location.region":                "immutable",
		"encryption.customerManagedKeys": "immutable",
		"scope.multiRegion":              "unsupported",
		"integrity.logValidation":        "unsupported",
		"service.managed":                "unsupported",
		"cost.monthly":                   "unsupported",
		"something.else":                 "unsupported",
	}
	for path, want := range cases {
		got, _ := classifyActivityLogChange(path)
		if got != want {
			t.Errorf("classify %q = %q, want %q", path, got, want)
		}
	}
}
