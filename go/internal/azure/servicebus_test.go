package azure

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func sbQueueAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eastus",
		"delivery.guarantee":     "exactly-once",
		"ordering.enabled":       true,
		"retention.minimum":      "7d",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

func TestBuildServiceBusQueueHonors(t *testing.T) {
	p, err := BuildServiceBusQueue("prod", "orders", sbQueueAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Dedup || !p.Session || p.TTLDays != 7 || p.Public {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildServiceBusRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "eastus", "encryption.atRest": true, "service.managed": true}
	}
	q := map[string]map[string]any{
		"bad-delivery": {"delivery.guarantee": "nonsense"},
		"cmk":          {"encryption.customerManagedKeys": true},
		"atRest-false": {"encryption.atRest": false},
		"unmanaged":    {"service.managed": false},
		"unknown":      {"durability.class": "regional"},
	}
	for name, extra := range q {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildServiceBusQueue("prod", "orders", a, nil, 1); err == nil {
			t.Errorf("queue %s: expected refusal", name)
		}
	}
	// topic refuses CMK too; missing region refuses
	tcmk := base()
	tcmk["encryption.customerManagedKeys"] = true
	if _, err := BuildServiceBusTopic("prod", "events", tcmk, nil, 1); err == nil {
		t.Error("topic CMK must refuse")
	}
	if _, err := BuildServiceBusTopic("prod", "events", map[string]any{"encryption.atRest": true, "service.managed": true}, nil, 1); err == nil {
		t.Error("topic missing region must refuse")
	}
}

func TestBuildServiceBusQueueDeadLetter(t *testing.T) {
	a := sbQueueAttrs()
	a["reliability.deadLetter"] = true
	p, err := BuildServiceBusQueue("prod", "orders", a, map[string]any{"max_delivery_count": 7}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.DeadLetter || p.MaxDelivery != 7 {
		t.Fatalf("dead-letter not honored: %+v", p)
	}
	// false = Azure default, no operand required
	a["reliability.deadLetter"] = false
	p, err = BuildServiceBusQueue("prod", "orders", a, nil, 1)
	if err != nil || p.DeadLetter || p.MaxDelivery != 0 {
		t.Fatalf("deadLetter=false must not require an operand: %+v err=%v", p, err)
	}
}

func TestBuildServiceBusQueueDeadLetterRefusals(t *testing.T) {
	base := func() map[string]any {
		a := sbQueueAttrs()
		a["reliability.deadLetter"] = true
		return a
	}
	// missing operand
	if _, err := BuildServiceBusQueue("prod", "orders", base(), nil, 1); err == nil {
		t.Error("deadLetter=true without max_delivery_count must refuse")
	}
	// out of envelope (1..2000)
	for _, bad := range []int{0, 2001} {
		if _, err := BuildServiceBusQueue("prod", "orders", base(),
			map[string]any{"max_delivery_count": bad}, 1); err == nil {
			t.Errorf("max_delivery_count %d must refuse", bad)
		}
	}
	// non-whole-number operand
	if _, err := BuildServiceBusQueue("prod", "orders", base(),
		map[string]any{"max_delivery_count": 3.5}, 1); err == nil {
		t.Error("fractional max_delivery_count must refuse")
	}
}

func TestClassifyServiceBusQueueChange(t *testing.T) {
	cases := map[string]string{
		"reliability.deadLetter": "mutable",
		"retention.minimum":      "mutable",
		"delivery.guarantee":     "immutable",
		"ordering.enabled":       "immutable",
		"location.region":        "immutable",
		"network.publicExposure": "unsupported",
		"service.managed":        "unsupported",
	}
	for path, want := range cases {
		if got, _ := classifyServiceBusQueueChange(path); got != want {
			t.Errorf("classify %q = %q, want %q", path, got, want)
		}
	}
}

func TestUpdateServiceBusQueueDeadLetter(t *testing.T) {
	var lastQueuePUT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isQueue := strings.Contains(r.URL.Path, "/queues/")
		if r.Method == "PUT" && isQueue {
			b, _ := io.ReadAll(r.Body)
			lastQueuePUT = string(b)
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"properties":{}}`))
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := sbProviderID("sbq", testSub, "rg1", serviceBusNamespace("prod", "orders", 1), azResourceName("q", "prod", "orders", 1))
	a := sbQueueAttrs()
	a["reliability.deadLetter"] = true
	res := d.updateServiceBus("orders", "prod", pid, a,
		map[string]any{"resource_group": "rg1", "max_delivery_count": 9}, []string{"reliability.deadLetter"})
	if res.Status != "succeeded" {
		t.Fatalf("update: %+v", res)
	}
	if !strings.Contains(lastQueuePUT, `"maxDeliveryCount":9`) ||
		!strings.Contains(lastQueuePUT, `"deadLetteringOnMessageExpiration":true`) {
		t.Fatalf("update PUT body missing dead-letter properties: %s", lastQueuePUT)
	}
	// an immutable path in the change-set must refuse before mutating
	res = d.updateServiceBus("orders", "prod", pid, a,
		map[string]any{"resource_group": "rg1"}, []string{"delivery.guarantee"})
	if res.Status != "failed" {
		t.Fatalf("immutable change must refuse, got %+v", res)
	}
	// a topic providerId carries no mutable vocabulary
	tpid := sbProviderID("sbt", testSub, "rg1", serviceBusNamespace("prod", "orders", 1), azResourceName("t", "prod", "orders", 1))
	if res := d.updateServiceBus("orders", "prod", tpid, a, nil, []string{"reliability.deadLetter"}); res.Status != "failed" {
		t.Fatalf("topic update must refuse, got %+v", res)
	}
}

func TestObserveServiceBusQueueDeadLetter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/queues/") {
			_, _ = w.Write([]byte(`{"properties":{"requiresDuplicateDetection":false,"requiresSession":false,` +
				`"maxDeliveryCount":9,"deadLetteringOnMessageExpiration":true}}`))
			return
		}
		_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"orders","groundhold-environment":"prod"},` +
			`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"Disabled"}}`))
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := sbProviderID("sbq", testSub, "rg1", serviceBusNamespace("prod", "orders", 1), azResourceName("q", "prod", "orders", 1))
	obs, _, err := d.sbObserve("orders", pid)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["reliability.deadLetter"] != true {
		t.Fatalf("observe: reliability.deadLetter = %v, want true (deadLetteringOnMessageExpiration set)", got["reliability.deadLetter"])
	}
}

func sbArmFake(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			isEntity := strings.Contains(r.URL.Path, "/queues/") || strings.Contains(r.URL.Path, "/topics/")
			switch {
			case r.Method == "PUT" && !isEntity: // namespace
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"properties":{"provisioningState":"Succeeded"}}`))
			case r.Method == "PUT": // entity
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"properties":{}}`))
			case r.Method == "GET" && isEntity:
				_, _ = w.Write([]byte(`{"properties":{"requiresDuplicateDetection":true,"requiresSession":true,"defaultMessageTimeToLive":"P7D"}}`))
			case r.Method == "GET": // namespace
				_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"provisioningState":"Succeeded","publicNetworkAccess":"Disabled"}}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestCreateObserveDeleteServiceBusQueue(t *testing.T) {
	srv := sbArmFake(t, "orders")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	res := d.createServiceBusQueue("prod", "orders", sbQueueAttrs(), map[string]any{"resource_group": "rg1"}, 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.sbObserve("orders", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["delivery.guarantee"] != "exactly-once" || got["ordering.enabled"] != true ||
		got["network.publicExposure"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.sbDelete("orders", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestCreateDeleteServiceBusTopic(t *testing.T) {
	srv := sbArmFake(t, "events")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	attrs := map[string]any{"location.region": "eastus", "network.publicExposure": false, "encryption.atRest": true, "service.managed": true}
	res := d.createServiceBusTopic("prod", "events", attrs, map[string]any{"resource_group": "rg1"}, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "sbt:") {
		t.Fatalf("create: %+v", res)
	}
	if del := d.sbDelete("events", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteServiceBusForeignRefused(t *testing.T) {
	srv := sbArmFake(t, "someone-else")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := sbProviderID("sbq", testSub, "rg1", serviceBusNamespace("prod", "orders", 1), azResourceName("q", "prod", "orders", 1))
	res := d.sbDelete("orders", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign namespace must refuse delete, got %+v", res)
	}
}
