package azure

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const azDNSRecordCap = "capability.dns.record"

func azDNSRecordAttrs() map[string]any {
	return map[string]any{
		"dns.type":        "CNAME",
		"dns.target":      "origin.example.net",
		"service.managed": true,
	}
}

func azDNSRecordImpl() map[string]any {
	return map[string]any{"zone": "example.com", "resourceGroup": "rg1", "record_name": "connect"}
}

func TestBuildAzureDNSRecordHonors(t *testing.T) {
	p, err := BuildAzureDNSRecord("prod", azDNSRecordCap, azDNSRecordAttrs(), azDNSRecordImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Zone != "example.com" || p.ResourceGroup != "rg1" || p.Name != "connect" || p.Type != "CNAME" || p.Target != "origin.example.net" {
		t.Fatalf("plan = %+v", p)
	}
	if p.childPath() != "Microsoft.Network/dnsZones/example.com/CNAME/connect" {
		t.Fatalf("childPath = %s", p.childPath())
	}
	props := p.recordProperties()
	if _, ok := props["CNAMERecord"]; !ok {
		t.Fatalf("CNAME must carry CNAMERecord: %+v", props)
	}
	// each type maps to its own recordset property key
	for _, tc := range []struct {
		typ, target, key string
	}{
		{"A", "1.2.3.4", "ARecords"},
		{"AAAA", "2001:db8::1", "AAAARecords"},
		{"TXT", "v=spf1 -all", "TXTRecords"},
		{"MX", "10 mail.example.com", "MXRecords"},
	} {
		a := map[string]any{"dns.type": tc.typ, "dns.target": tc.target, "service.managed": true}
		pp, err := BuildAzureDNSRecord("prod", azDNSRecordCap, a, azDNSRecordImpl(), 1)
		if err != nil {
			t.Fatalf("%s: %v", tc.typ, err)
		}
		if _, ok := pp.recordProperties()[tc.key]; !ok {
			t.Fatalf("%s must carry %s: %+v", tc.typ, tc.key, pp.recordProperties())
		}
	}
}

func TestBuildAzureDNSRecordRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"proxied-is-cloudflare-only": {
			map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "dns.proxied": true, "service.managed": true},
			azDNSRecordImpl()},
		"unmanaged":       {map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "service.managed": false}, azDNSRecordImpl()},
		"bad-type":        {map[string]any{"dns.type": "WIDGET", "dns.target": "x", "service.managed": true}, azDNSRecordImpl()},
		"missing-type":    {map[string]any{"dns.target": "1.2.3.4", "service.managed": true}, azDNSRecordImpl()},
		"missing-target":  {map[string]any{"dns.type": "A", "service.managed": true}, azDNSRecordImpl()},
		"missing-zone":    {azDNSRecordAttrs(), map[string]any{"resourceGroup": "rg1", "record_name": "connect"}},
		"missing-rg":      {azDNSRecordAttrs(), map[string]any{"zone": "example.com", "record_name": "connect"}},
		"missing-name":    {azDNSRecordAttrs(), map[string]any{"zone": "example.com", "resourceGroup": "rg1"}},
		"record-noise":    {map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "dns.ttl": 60, "service.managed": true}, azDNSRecordImpl()},
		"bad-record-name": {azDNSRecordAttrs(), map[string]any{"zone": "example.com", "resourceGroup": "rg1", "record_name": "bad name/slash"}},
	}
	for name, c := range cases {
		if _, err := BuildAzureDNSRecord("prod", azDNSRecordCap, c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// azDNSRecordServer fakes the ARM endpoints a record driver touches: the parent
// zone GET (ownership gate) and the record child PUT/GET/DELETE. The parent zone
// path has ONE segment after /dnsZones/ (the zone); a record child has THREE
// (zone/TYPE/name).
func azDNSRecordServer(t *testing.T, tagCap string, capturedPath *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := strings.Index(r.URL.Path, "/dnsZones/")
		if idx < 0 {
			w.WriteHeader(404)
			return
		}
		rest := r.URL.Path[idx+len("/dnsZones/"):]
		isChild := strings.Count(rest, "/") >= 2
		switch {
		case r.Method == "GET" && !isChild:
			// parent zone GET — ownership tags
			_, _ = w.Write([]byte(`{"location":"global",` +
				`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
				`"properties":{"provisioningState":"Succeeded"}}`))
		case r.Method == "PUT" && isChild:
			if capturedPath != nil {
				*capturedPath = r.URL.Path
			}
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"properties":{"CNAMERecord":{"cname":"origin.example.net"},"TTL":300}}`))
		case r.Method == "GET" && isChild:
			_, _ = w.Write([]byte(`{"properties":{"CNAMERecord":{"cname":"origin.example.net"},"TTL":300}}`))
		case r.Method == "DELETE" && isChild:
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestCreateObserveDeleteAzureDNSRecord(t *testing.T) {
	var path string
	srv := azDNSRecordServer(t, sanitizeAzTag(azDNSRecordCap), &path)
	defer srv.Close()
	d := azDNSDriver(t, srv)

	res := d.createAzureDNSRecord("prod", azDNSRecordCap, azDNSRecordAttrs(), azDNSRecordImpl(), 1)
	wantPID := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("create: %+v (want pid %s)", res, wantPID)
	}
	if !strings.Contains(path, "/dnsZones/example.com/CNAME/connect") {
		t.Fatalf("record PUT must address the child, got %s", path)
	}
	obs, diags, err := d.observeAzureDNSRecord(azDNSRecordCap, res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["dns.type"] != "CNAME" || got["dns.target"] != "origin.example.net" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if _, ok := got["dns.proxied"]; ok {
		t.Fatalf("dns.proxied must be OMITTED on Azure DNS, got %v", got["dns.proxied"])
	}
	if len(diags) == 0 || !strings.Contains(strings.Join(diags, " "), "dns.proxied") {
		t.Fatalf("observe must diagnose the omitted dns.proxied, diags=%v", diags)
	}
	if del := d.deleteAzureDNSRecord(azDNSRecordCap, "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// TestClassifyAzureDNSRecordChange pins how each attribute reconciles: repointing
// (dns.target) is in-place; the record kind (dns.type) is a replacement; edge/
// projection properties are unsupported.
func TestClassifyAzureDNSRecordChange(t *testing.T) {
	cases := map[string]string{
		"dns.target":      "mutable",
		"dns.type":        "immutable",
		"dns.proxied":     "unsupported",
		"service.managed": "unsupported",
		"cost.monthly":    "unsupported",
		"dns.ttl":         "unsupported",
	}
	for path, want := range cases {
		if got, _ := classifyAzureDNSRecordChange(path); got != want {
			t.Errorf("classify %s = %q, want %q", path, got, want)
		}
	}
}

// TestUpdateAzureDNSRecordRepoints proves a repoint is an in-place PUT of the new
// target to the SAME record child — no delete+recreate.
func TestUpdateAzureDNSRecordRepoints(t *testing.T) {
	var path string
	srv := azDNSRecordServer(t, sanitizeAzTag(azDNSRecordCap), &path)
	defer srv.Close()
	d := azDNSDriver(t, srv)

	pid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	repointed := map[string]any{
		"dns.type": "CNAME", "dns.target": "new-origin.example.net", "service.managed": true,
	}
	res := d.updateAzureDNSRecord(azDNSRecordCap, "prod", pid, repointed, azDNSRecordImpl(), []string{"dns.target"})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("repoint: %+v (want succeeded, pid %s)", res, pid)
	}
	if !strings.Contains(path, "/dnsZones/example.com/CNAME/connect") {
		t.Fatalf("repoint PUT must address the same child, got %s", path)
	}

	// an immutable path may not reach the updater — it is a replacement, not an update.
	if bad := d.updateAzureDNSRecord(azDNSRecordCap, "prod", pid, repointed, azDNSRecordImpl(),
		[]string{"dns.type"}); bad.Status != "failed" || !strings.Contains(bad.Reason, "does not honor") {
		t.Fatalf("a dns.type change must be refused by the updater, got %+v", bad)
	}
}

// TestUpdateAzureDNSRecordForeignZoneRefused pins the ownership boundary on the update
// path too: a repoint into a zone that is not ours is refused before the PUT.
func TestUpdateAzureDNSRecordForeignZoneRefused(t *testing.T) {
	srv := azDNSRecordServer(t, "someone-else", nil)
	defer srv.Close()
	d := azDNSDriver(t, srv)
	pid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	repointed := map[string]any{"dns.type": "CNAME", "dns.target": "new-origin.example.net", "service.managed": true}
	res := d.updateAzureDNSRecord(azDNSRecordCap, "prod", pid, repointed, azDNSRecordImpl(), []string{"dns.target"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign parent zone must refuse the repoint, got %+v", res)
	}
}

// TestRecordTarget pins the reverse-mapping recordTarget performs for EVERY
// wired record type (inverting recordProperties) — including the "no value" case
// for a type with an empty value block, which must yield "" (never a panic on a
// nil/empty slice index).
func TestRecordTarget(t *testing.T) {
	mkDoc := func(raw string) (doc azureDNSRecordDoc) {
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("bad test fixture json: %v", err)
		}
		return doc
	}
	cases := []struct {
		recordType, json, want string
	}{
		{"A", `{"properties":{"ARecords":[{"ipv4Address":"1.2.3.4"}]}}`, "1.2.3.4"},
		{"A", `{"properties":{}}`, ""},
		{"AAAA", `{"properties":{"AAAARecords":[{"ipv6Address":"2001:db8::1"}]}}`, "2001:db8::1"},
		{"AAAA", `{"properties":{}}`, ""},
		{"CNAME", `{"properties":{"CNAMERecord":{"cname":"origin.example.net"}}}`, "origin.example.net"},
		{"CNAME", `{"properties":{}}`, ""},
		{"TXT", `{"properties":{"TXTRecords":[{"value":["v=spf1 -all"]}]}}`, "v=spf1 -all"},
		{"TXT", `{"properties":{"TXTRecords":[{"value":[]}]}}`, ""},
		{"TXT", `{"properties":{}}`, ""},
		{"MX", `{"properties":{"MXRecords":[{"preference":10,"exchange":"mail.example.com"}]}}`, "10 mail.example.com"},
		{"MX", `{"properties":{}}`, ""},
		{"WIDGET", `{"properties":{}}`, ""},
	}
	for _, c := range cases {
		if got := recordTarget(c.recordType, mkDoc(c.json)); got != c.want {
			t.Errorf("recordTarget(%q, %s) = %q, want %q", c.recordType, c.json, got, c.want)
		}
	}
}

// TestSplitAzureDNSRecordProviderIDRejectsMalformed pins every parse guard: the
// wrong kind prefix, a bad sub/rg, an invalid zone, an unrecognized record type,
// and an invalid record name are all refused (never a partial/garbage parse).
func TestSplitAzureDNSRecordProviderIDRejectsMalformed(t *testing.T) {
	valid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	if _, _, _, _, _, err := splitAzureDNSRecordProviderID(valid); err != nil {
		t.Fatalf("a well-formed pid must parse, got %v", err)
	}
	cases := map[string]string{
		"wrong-prefix":    "notadnsrec:" + testSub + ":rg1:example.com:CNAME:connect",
		"too-few-parts":   "adnsrec:" + testSub + ":rg1:example.com:CNAME",
		"bad-sub":         "adnsrec:not-a-guid:rg1:example.com:CNAME:connect",
		"bad-zone":        "adnsrec:" + testSub + ":rg1:not a zone:CNAME:connect",
		"bad-type":        "adnsrec:" + testSub + ":rg1:example.com:WIDGET:connect",
		"bad-record-name": "adnsrec:" + testSub + ":rg1:example.com:CNAME:bad name",
	}
	for name, pid := range cases {
		if _, _, _, _, _, err := splitAzureDNSRecordProviderID(pid); err == nil {
			t.Errorf("%s: expected a parse refusal for %q, got none", name, pid)
		}
	}
}

// TestDNSZoneOwnedByUsScopeErrorIsFalseNotError pins the specific "scope" cause
// coming back from a malformed sub/rg: it is treated as a DEFINITIVE non-owned
// (false, nil), never surfaced as a transient error a caller might retry into a
// false "unknown" — the malformation itself will never resolve on retry.
func TestDNSZoneOwnedByUsScopeErrorIsFalseNotError(t *testing.T) {
	d := NewDriver("not-a-guid")
	owned, err := d.dnsZoneOwnedByUs("rg1", "example.com", "cap", "prod")
	if err != nil {
		t.Fatalf("a scope (malformed sub) error must not surface as an error, got %v", err)
	}
	if owned {
		t.Fatal("a malformed scope must never report owned=true")
	}
}

// TestDNSZoneOwnedByUsTransientReadIsError: a non-scope read failure (server
// error) DOES surface as an error — never silently treated as not-owned (which
// would fail OPEN on a permission/availability blip and let a caller believe
// they may safely write outside their own zone... or refuse a legitimate owner).
func TestDNSZoneOwnedByUsTransientReadIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	d := azDNSDriver(t, srv)
	if _, err := d.dnsZoneOwnedByUs("rg1", "example.com", "cap", "prod"); err == nil {
		t.Fatal("a transient (5xx) parent-zone read must surface as an error, not a silent false")
	}
}

// TestCreateAzureDNSRecordZoneReadErrorUnknown: when the parent-zone ownership
// read itself gives no answer, create is `unknown` — never a fabricated success
// or a "not ours" refusal that could be permanently wrong.
func TestCreateAzureDNSRecordZoneReadErrorUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	d := azDNSDriver(t, srv)
	res := d.createAzureDNSRecord("prod", azDNSRecordCap, azDNSRecordAttrs(), azDNSRecordImpl(), 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable parent-zone check must be unknown, got %+v", res)
	}
}

// TestCreateAzureDNSRecordPUTOutcomes pins the four-valued record PUT handling:
// a 5xx is unknown WITH the pid, a clean 4xx is a clear failed.
func TestCreateAzureDNSRecordPUTOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		putStatus  int
		wantStatus string
	}{
		{"server-error-unknown", 503, "unknown"},
		{"bad-request-failed", 400, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				idx := strings.Index(r.URL.Path, "/dnsZones/")
				rest := r.URL.Path[idx+len("/dnsZones/"):]
				isChild := strings.Count(rest, "/") >= 2
				switch {
				case r.Method == "GET" && !isChild:
					_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + sanitizeAzTag(azDNSRecordCap) +
						`","groundhold-environment":"prod"}}`))
				case r.Method == "PUT" && isChild:
					w.WriteHeader(tc.putStatus)
				default:
					w.WriteHeader(404)
				}
			}))
			defer srv.Close()
			d := azDNSDriver(t, srv)
			res := d.createAzureDNSRecord("prod", azDNSRecordCap, azDNSRecordAttrs(), azDNSRecordImpl(), 1)
			if res.Status != tc.wantStatus {
				t.Fatalf("PUT %d: status = %q, want %q (%+v)", tc.putStatus, res.Status, tc.wantStatus, res)
			}
			if tc.wantStatus == "unknown" && res.ProviderID == "" {
				t.Fatalf("an unknown outcome must carry the deterministic providerId, got %+v", res)
			}
		})
	}
}

// TestDeleteAzureDNSRecordServerErrorUnknown / TestDeleteAzureDNSRecordAlreadyGone
// pin the remaining delete outcomes: a 5xx on the DELETE is unknown WITH the pid
// (reconcile), and a 404 is idempotently succeeded (already gone).
func TestDeleteAzureDNSRecordServerErrorUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := strings.Index(r.URL.Path, "/dnsZones/")
		rest := r.URL.Path[idx+len("/dnsZones/"):]
		isChild := strings.Count(rest, "/") >= 2
		switch {
		case r.Method == "GET" && !isChild:
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + sanitizeAzTag(azDNSRecordCap) +
				`","groundhold-environment":"prod"}}`))
		case r.Method == "DELETE" && isChild:
			w.WriteHeader(503)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := azDNSDriver(t, srv)
	pid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	res := d.deleteAzureDNSRecord(azDNSRecordCap, "prod", pid)
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("a 5xx delete must be unknown WITH the pid, got %+v", res)
	}
}

func TestDeleteAzureDNSRecordAlreadyGoneIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idx := strings.Index(r.URL.Path, "/dnsZones/")
		rest := r.URL.Path[idx+len("/dnsZones/"):]
		isChild := strings.Count(rest, "/") >= 2
		switch {
		case r.Method == "GET" && !isChild:
			_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + sanitizeAzTag(azDNSRecordCap) +
				`","groundhold-environment":"prod"}}`))
		case r.Method == "DELETE" && isChild:
			w.WriteHeader(404)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := azDNSDriver(t, srv)
	pid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	if res := d.deleteAzureDNSRecord(azDNSRecordCap, "prod", pid); res.Status != "succeeded" {
		t.Fatalf("a 404 delete must be idempotently succeeded, got %+v", res)
	}
}

// TestUpdateAzureDNSRecordSubscriptionMismatch: a providerId from a different
// subscription is refused before any zone read or write.
func TestUpdateAzureDNSRecordSubscriptionMismatch(t *testing.T) {
	d := NewDriver(testSub)
	other := "11111111-1111-1111-1111-111111111111"
	pid := azureDNSRecordProviderID(other, "rg1", "example.com", "CNAME", "connect")
	res := d.updateAzureDNSRecord(azDNSRecordCap, "prod", pid, azDNSRecordAttrs(), azDNSRecordImpl(), []string{"dns.target"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "is not the driver's") {
		t.Fatalf("a cross-subscription providerId must refuse the update, got %+v", res)
	}
}

// TestUpdateAzureDNSRecordBuildRefusalPropagates: an invalid desired shape (the
// pure builder refuses) surfaces as a clean failed, never a partial write attempt.
func TestUpdateAzureDNSRecordBuildRefusalPropagates(t *testing.T) {
	d := NewDriver(testSub)
	pid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	bad := map[string]any{"dns.type": "WIDGET", "dns.target": "x", "service.managed": true}
	res := d.updateAzureDNSRecord(azDNSRecordCap, "prod", pid, bad, azDNSRecordImpl(), []string{"dns.target"})
	if res.Status != "failed" {
		t.Fatalf("an invalid desired record must refuse, got %+v", res)
	}
}

// TestUpdateAzureDNSRecordIdentityDriftRefused: a desired record whose
// zone/type/name differs from the BOUND providerId is a different record
// entirely — a replacement, never something the in-place updater may repoint.
func TestUpdateAzureDNSRecordIdentityDriftRefused(t *testing.T) {
	d := NewDriver(testSub)
	pid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	// desired record has a DIFFERENT type (A, not CNAME) from the bound identity.
	desired := map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "service.managed": true}
	res := d.updateAzureDNSRecord(azDNSRecordCap, "prod", pid, desired, azDNSRecordImpl(), []string{"dns.target"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "replacement") {
		t.Fatalf("an identity drift must refuse as a replacement, got %+v", res)
	}
}

// TestUpdateAzureDNSRecordZoneReadErrorUnknown mirrors the create-path honesty:
// an unreadable parent-zone ownership check is unknown, not a fabricated outcome.
func TestUpdateAzureDNSRecordZoneReadErrorUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	d := azDNSDriver(t, srv)
	pid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	repointed := map[string]any{"dns.type": "CNAME", "dns.target": "new-origin.example.net", "service.managed": true}
	res := d.updateAzureDNSRecord(azDNSRecordCap, "prod", pid, repointed, azDNSRecordImpl(), []string{"dns.target"})
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable parent-zone check must be unknown, got %+v", res)
	}
}

// TestUpdateAzureDNSRecordPUTOutcomes pins the four-valued repoint PUT handling.
func TestUpdateAzureDNSRecordPUTOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name       string
		putStatus  int
		wantStatus string
	}{
		{"server-error-unknown", 503, "unknown"},
		{"bad-request-failed", 400, "failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				idx := strings.Index(r.URL.Path, "/dnsZones/")
				rest := r.URL.Path[idx+len("/dnsZones/"):]
				isChild := strings.Count(rest, "/") >= 2
				switch {
				case r.Method == "GET" && !isChild:
					_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + sanitizeAzTag(azDNSRecordCap) +
						`","groundhold-environment":"prod"}}`))
				case r.Method == "PUT" && isChild:
					w.WriteHeader(tc.putStatus)
				default:
					w.WriteHeader(404)
				}
			}))
			defer srv.Close()
			d := azDNSDriver(t, srv)
			pid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
			repointed := map[string]any{"dns.type": "CNAME", "dns.target": "new-origin.example.net", "service.managed": true}
			res := d.updateAzureDNSRecord(azDNSRecordCap, "prod", pid, repointed, azDNSRecordImpl(), []string{"dns.target"})
			if res.Status != tc.wantStatus {
				t.Fatalf("PUT %d: status = %q, want %q (%+v)", tc.putStatus, res.Status, tc.wantStatus, res)
			}
		})
	}
}

// TestObserveAzureDNSRecordSubscriptionMismatch / GetError / NonOKStatus pin the
// remaining observe branches: a providerId from another subscription is
// refused, a transport failure is an error (never a fabricated absence), and a
// non-200/non-404 status is an error too.
func TestObserveAzureDNSRecordSubscriptionMismatch(t *testing.T) {
	d := NewDriver(testSub)
	other := "11111111-1111-1111-1111-111111111111"
	pid := azureDNSRecordProviderID(other, "rg1", "example.com", "CNAME", "connect")
	if _, _, err := d.observeAzureDNSRecord(azDNSRecordCap, pid); err == nil {
		t.Fatal("a cross-subscription providerId must error")
	}
}

func TestObserveAzureDNSRecordNonOKStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	d := azDNSDriver(t, srv)
	pid := azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")
	if _, _, err := d.observeAzureDNSRecord(azDNSRecordCap, pid); err == nil {
		t.Fatal("a 500 read must be an error, never a fabricated observation")
	}
}

// TestDeleteAzureDNSRecordSubscriptionMismatch mirrors the same guard on delete.
func TestDeleteAzureDNSRecordSubscriptionMismatch(t *testing.T) {
	d := NewDriver(testSub)
	other := "11111111-1111-1111-1111-111111111111"
	pid := azureDNSRecordProviderID(other, "rg1", "example.com", "CNAME", "connect")
	res := d.deleteAzureDNSRecord(azDNSRecordCap, "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "is not the driver's") {
		t.Fatalf("a cross-subscription providerId must refuse the delete, got %+v", res)
	}
}

// TestCreateAzureDNSRecordForeignZoneRefused pins the ownership boundary: a record
// whose PARENT ZONE is not ours (tags mismatch) is refused — never written into a
// zone we do not own.
func TestCreateAzureDNSRecordForeignZoneRefused(t *testing.T) {
	srv := azDNSRecordServer(t, "someone-else", nil)
	defer srv.Close()
	d := azDNSDriver(t, srv)
	res := d.createAzureDNSRecord("prod", azDNSRecordCap, azDNSRecordAttrs(), azDNSRecordImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign parent zone must refuse the record write, got %+v", res)
	}
	if del := d.deleteAzureDNSRecord(azDNSRecordCap, "prod",
		azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")); del.Status != "failed" ||
		!strings.Contains(del.Reason, "not ours") {
		t.Fatalf("a foreign parent zone must refuse the record delete, got %+v", del)
	}
}
