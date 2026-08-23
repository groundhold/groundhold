package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const dnsRecordCap = "capability.dns.record"

func dnsRecordAttrs() map[string]any {
	return map[string]any{
		"dns.type":        "CNAME",
		"dns.target":      "origin.example.net",
		"service.managed": true,
	}
}

func dnsRecordImpl() map[string]any {
	return map[string]any{"zone": "example-com", "record_name": "connect.example.com"}
}

func TestBuildCloudDNSRecordHonors(t *testing.T) {
	p, err := BuildCloudDNSRecord("acme-prod", "prod", dnsRecordCap, dnsRecordAttrs(), dnsRecordImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Zone != "example-com" || p.Name != "connect.example.com." || p.Type != "CNAME" || p.Target != "origin.example.net" {
		t.Fatalf("plan = %+v", p)
	}
	rr := p.rrset()
	if rr["name"] != "connect.example.com." || rr["type"] != "CNAME" || rr["ttl"] != 300 {
		t.Fatalf("rrset = %+v", rr)
	}
	if rd := rr["rrdatas"].([]any); len(rd) != 1 || rd[0] != "origin.example.net" {
		t.Fatalf("rrdatas = %+v", rr["rrdatas"])
	}
	// a TXT target is quoted on the wire, unquoted on read.
	txt, err := BuildCloudDNSRecord("acme-prod", "prod", dnsRecordCap,
		map[string]any{"dns.type": "TXT", "dns.target": "v=spf1 -all", "service.managed": true}, dnsRecordImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if rd := txt.rrset()["rrdatas"].([]any); rd[0] != `"v=spf1 -all"` {
		t.Fatalf("TXT must be quoted: %v", rd[0])
	}
}

func TestBuildCloudDNSRecordRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"proxied-is-cloudflare-only": {
			map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "dns.proxied": true, "service.managed": true},
			dnsRecordImpl()},
		"unmanaged":      {map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "service.managed": false}, dnsRecordImpl()},
		"bad-type":       {map[string]any{"dns.type": "WIDGET", "dns.target": "x", "service.managed": true}, dnsRecordImpl()},
		"missing-type":   {map[string]any{"dns.target": "1.2.3.4", "service.managed": true}, dnsRecordImpl()},
		"missing-target": {map[string]any{"dns.type": "A", "service.managed": true}, dnsRecordImpl()},
		"missing-zone":   {dnsRecordAttrs(), map[string]any{"record_name": "connect.example.com"}},
		"missing-name":   {dnsRecordAttrs(), map[string]any{"zone": "example-com"}},
		"record-noise":   {map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "dns.ttl": 60, "service.managed": true}, dnsRecordImpl()},
	}
	for name, c := range cases {
		if _, err := BuildCloudDNSRecord("acme-prod", "prod", dnsRecordCap, c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// dnsRecordServer fakes the Cloud DNS endpoints a record driver touches: the parent
// managed zone (ownership gate, via managedZones.get), the rrsets list, and the
// changes POST (additions/deletions).
func dnsRecordServer(t *testing.T, zoneCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrsets"):
			_, _ = w.Write([]byte(`{"rrsets":[{"name":"connect.example.com.","type":"CNAME","ttl":300,` +
				`"rrdatas":["origin.example.net"]}]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","dnsName":"example.com.","visibility":"public",` +
				`"labels":{"groundhold-capability":"` + zoneCap + `","groundhold-environment":"prod"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/changes"):
			_, _ = w.Write([]byte(`{"id":"1","status":"pending"}`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestCreateObserveDeleteCloudDNSRecord(t *testing.T) {
	srv := dnsRecordServer(t, sanitizeLabel(dnsRecordCap))
	defer srv.Close()
	d := dnsDriver(t, srv)

	res := d.createCloudDNSRecord("prod", dnsRecordCap, dnsRecordAttrs(), dnsRecordImpl(), 1)
	wantPID := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("create: %+v (want pid %s)", res, wantPID)
	}

	obs, diags, err := d.observeCloudDNSRecord(dnsRecordCap, res.ProviderID)
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
		t.Fatalf("dns.proxied must be OMITTED on Cloud DNS, got %v", got["dns.proxied"])
	}
	if len(diags) == 0 || !strings.Contains(strings.Join(diags, " "), "dns.proxied") {
		t.Fatalf("observe must diagnose the omitted dns.proxied, diags=%v", diags)
	}

	if del := d.deleteCloudDNSRecord(dnsRecordCap, "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestClassifyCloudDNSRecordChange(t *testing.T) {
	cases := map[string]string{
		"dns.target":      "mutable",
		"dns.type":        "immutable",
		"service.managed": "unsupported",
		"dns.proxied":     "unsupported",
		"cost.monthly":    "unsupported",
		"whatever.else":   "unsupported",
	}
	for path, want := range cases {
		got, _ := classifyCloudDNSRecordChange(path)
		if got != want {
			t.Errorf("classify %s = %q, want %q", path, got, want)
		}
	}
	// wired through the ClassifyChange dispatch too.
	d := NewDriver("acme-prod")
	if got, _ := d.ClassifyChange("clouddnsrecord", "dns.target", "a", "b", nil); got != "mutable" {
		t.Fatalf("dispatch classify dns.target = %q, want mutable", got)
	}
}

// TestUpdateCloudDNSRecordRepoints pins the repoint: changing dns.target is an atomic
// managedZones.changes carrying BOTH the deletion of the current rrset and the addition
// of the new target — a patch, not a delete+recreate.
func TestUpdateCloudDNSRecordRepoints(t *testing.T) {
	var changeBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrsets"):
			_, _ = w.Write([]byte(`{"rrsets":[{"name":"connect.example.com.","type":"CNAME","ttl":300,` +
				`"rrdatas":["origin.example.net"]}]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","dnsName":"example.com.","visibility":"public",` +
				`"labels":{"groundhold-capability":"` + sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/changes"):
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &changeBody)
			_, _ = w.Write([]byte(`{"id":"1","status":"pending"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)

	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	newAttrs := map[string]any{"dns.type": "CNAME", "dns.target": "origin2.example.net", "service.managed": true}
	res := d.updateCloudDNSRecord(dnsRecordCap, "prod", pid, newAttrs, []string{"dns.target"})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("repoint: %+v (want pid %s)", res, pid)
	}
	// the change must be ATOMIC: delete the current rrset AND add the new one.
	dels, _ := changeBody["deletions"].([]any)
	adds, _ := changeBody["additions"].([]any)
	if len(dels) != 1 || len(adds) != 1 {
		t.Fatalf("repoint must carry exactly one deletion and one addition, got %+v", changeBody)
	}
	del0 := dels[0].(map[string]any)
	if rd := del0["rrdatas"].([]any); rd[0] != "origin.example.net" {
		t.Fatalf("deletion must match the CURRENT rrset, got %+v", del0)
	}
	add0 := adds[0].(map[string]any)
	if rd := add0["rrdatas"].([]any); rd[0] != "origin2.example.net" {
		t.Fatalf("addition must carry the NEW target, got %+v", add0)
	}
}

// TestUpdateCloudDNSRecordForeignZoneRefused pins the ownership boundary on the update
// path: repointing a record whose PARENT ZONE is not ours is refused.
func TestUpdateCloudDNSRecordForeignZoneRefused(t *testing.T) {
	srv := dnsRecordServer(t, "someone-else")
	defer srv.Close()
	d := dnsDriver(t, srv)
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.updateCloudDNSRecord(dnsRecordCap, "prod",
		pid, map[string]any{"dns.target": "origin2.example.net"}, []string{"dns.target"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign parent zone must refuse the repoint, got %+v", res)
	}
}

// TestCreateCloudDNSRecordForeignZoneRefused pins the ownership boundary: a record
// whose PARENT ZONE is not ours (labels mismatch) is refused — never written into a
// zone we do not own.
func TestCreateCloudDNSRecordForeignZoneRefused(t *testing.T) {
	srv := dnsRecordServer(t, "someone-else")
	defer srv.Close()
	d := dnsDriver(t, srv)
	res := d.createCloudDNSRecord("prod", dnsRecordCap, dnsRecordAttrs(), dnsRecordImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign parent zone must refuse the record write, got %+v", res)
	}
}

// D1237, the GCP witness. `dns.target` is one string and a Cloud DNS rrset holds a
// LIST — the vocabulary discloses that ("rrdatas[0] — the first value only") where an
// implementer reads it, not where an operator does. A record answering with two
// addresses reported one, as measured, in silence: `dns.target equals <first>` then
// read SATISFIED while the name also resolved to the second.
func TestCloudDNSMultiValueRecordIsDisclosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"rrsets":[{"name":"www.example.com.","type":"A","ttl":300,` +
			`"rrdatas":["10.0.0.5","203.0.113.9"]}]}`))
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	obs, diags, err := d.observeCloudDNSRecord(dnsRecordCap,
		"gdnsrec:acme-prod:example-zone:A:www.example.com.")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	var target any
	for _, o := range obs {
		if o.Path == "dns.target" {
			target = o.Value
		}
	}
	if target != "10.0.0.5" {
		t.Fatalf("the first value is what the spec reports, got %v", target)
	}
	var told bool
	for _, dg := range diags {
		if strings.Contains(dg, "FIRST of 2 values") {
			told = true
		}
	}
	if !told {
		t.Fatalf("the operator must be told the record holds more than the attribute can "+
			"carry, got %v", diags)
	}
}
