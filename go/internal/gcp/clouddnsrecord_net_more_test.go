package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file extends clouddnsrecord_test.go, which pins the happy create/
// observe/delete/update loop and the ownership-refusal boundary. These tests
// pin the remaining branches: splitGDNSRecProviderID's validation ladder,
// rrsetTarget's TXT-unquote edge cases, recordZoneOwnedByUs/getRecordSet's
// error branches, and the transport/5xx/transient paths of create/update/delete.

// --- splitGDNSRecProviderID -------------------------------------------------

func TestSplitGDNSRecProviderID(t *testing.T) {
	if _, _, _, _, err := splitGDNSRecProviderID(gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	cases := []string{
		"proj:zone:type:name",              // wrong prefix
		"gdnsrec:zone:type",                // too few parts
		"gdnsrec:BAD PROJECT:z:CNAME:name", // invalid project
		"gdnsrec:acme-prod:BAD ZONE:CNAME:name",
		"gdnsrec:acme-prod:example-com:WIDGET:name", // unknown record type
		"gdnsrec:acme-prod:example-com:CNAME:",      // empty name
	}
	for _, c := range cases {
		if _, _, _, _, err := splitGDNSRecProviderID(c); err == nil {
			t.Errorf("accepted malformed gdnsrec id %q", c)
		}
	}
}

// --- rrsetTarget -------------------------------------------------------

func TestRrsetTarget(t *testing.T) {
	if got := rrsetTarget(dnsRRSet{Rrdatas: nil}); got != "" {
		t.Errorf("no rrdatas must yield empty target, got %q", got)
	}
	if got := rrsetTarget(dnsRRSet{Type: "A", Rrdatas: []string{"1.2.3.4"}}); got != "1.2.3.4" {
		t.Errorf("A record target = %q", got)
	}
	if got := rrsetTarget(dnsRRSet{Type: "TXT", Rrdatas: []string{`"v=spf1 -all"`}}); got != "v=spf1 -all" {
		t.Errorf("TXT unquote = %q", got)
	}
	// an escaped inner quote must unescape too.
	if got := rrsetTarget(dnsRRSet{Type: "TXT", Rrdatas: []string{`"a\"b"`}}); got != `a"b` {
		t.Errorf("TXT escaped-quote unquote = %q", got)
	}
}

// --- recordZoneOwnedByUs / getRecordSet error branches ----------------------

func TestRecordZoneOwnedByUsErrorBranches(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := dnsDriver(t, srv)
		srv.Close()
		if _, err := d.recordZoneOwnedByUs("acme-prod", "example-com", "assets", "prod"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("zone gone is not owned, not an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		d := dnsDriver(t, srv)
		owned, err := d.recordZoneOwnedByUs("acme-prod", "example-com", "assets", "prod")
		if err != nil || owned {
			t.Fatalf("a gone zone must be owned=false, err=nil, got owned=%v err=%v", owned, err)
		}
	})
}

func TestGetRecordSetErrorBranches(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := dnsDriver(t, srv)
		srv.Close()
		if _, _, err := d.getRecordSet("acme-prod", "example-com", "connect.example.com.", "CNAME"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := dnsDriver(t, srv)
		if _, _, err := d.getRecordSet("acme-prod", "example-com", "connect.example.com.", "CNAME"); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("expected an HTTP 403 error, got %v", err)
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := dnsDriver(t, srv)
		if _, _, err := d.getRecordSet("acme-prod", "example-com", "connect.example.com.", "CNAME"); err == nil {
			t.Fatal("expected a body-parse error")
		}
	})
	t.Run("404 is a clean absence", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		d := dnsDriver(t, srv)
		_, found, err := d.getRecordSet("acme-prod", "example-com", "connect.example.com.", "CNAME")
		if err != nil || found {
			t.Fatalf("a 404 must be found=false, err=nil, got found=%v err=%v", found, err)
		}
	})
	t.Run("no exact name+type match in a filtered list", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"rrsets":[{"name":"other.example.com.","type":"CNAME","rrdatas":["x"]}]}`))
		}))
		defer srv.Close()
		d := dnsDriver(t, srv)
		_, found, err := d.getRecordSet("acme-prod", "example-com", "connect.example.com.", "CNAME")
		if err != nil || found {
			t.Fatalf("a sibling-only list must be found=false, got found=%v err=%v", found, err)
		}
	})
}

// --- createCloudDNSRecord transport/5xx/conflict branches -------------------

func TestCreateCloudDNSRecordTransportErrorIsUnknown(t *testing.T) {
	srv := dnsRecordServer(t, sanitizeLabel(dnsRecordCap))
	d := dnsDriver(t, srv)
	// keep the zone read reachable but kill the changes POST: point the driver
	// at a closed server entirely, so the ownership read itself is lost.
	srv.Close()
	res := d.createCloudDNSRecord("prod", dnsRecordCap, dnsRecordAttrs(), dnsRecordImpl(), 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("a lost zone-ownership read must be unknown, got %+v", res)
	}
}

func TestCreateCloudDNSRecordChangesPOST5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","labels":{"groundhold-capability":"` +
				sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/changes"):
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	res := d.createCloudDNSRecord("prod", dnsRecordCap, dnsRecordAttrs(), dnsRecordImpl(), 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 on the changes POST must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreateCloudDNSRecordChangesPOSTTerminalRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","labels":{"groundhold-capability":"` +
				sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/changes"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"malformed change"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	res := d.createCloudDNSRecord("prod", dnsRecordCap, dnsRecordAttrs(), dnsRecordImpl(), 1)
	if res.Status != "failed" {
		t.Fatalf("a clean 400 on the changes POST must be a terminal failed, got %+v", res)
	}
}

// --- updateCloudDNSRecord additional branches -------------------------------

func TestUpdateCloudDNSRecordUnsupportedPathRefuses(t *testing.T) {
	d := dnsDriver(t, dnsRecordServer(t, sanitizeLabel(dnsRecordCap)))
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.updateCloudDNSRecord(dnsRecordCap, "prod", pid,
		map[string]any{"dns.type": "A"}, []string{"dns.type"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not repointable") {
		t.Fatalf("an unsupported path must refuse, got %+v", res)
	}
}

func TestUpdateCloudDNSRecordEmptyTargetRefuses(t *testing.T) {
	d := dnsDriver(t, dnsRecordServer(t, sanitizeLabel(dnsRecordCap)))
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.updateCloudDNSRecord(dnsRecordCap, "prod", pid,
		map[string]any{"dns.target": "   "}, []string{"dns.target"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "non-empty") {
		t.Fatalf("a blank target must refuse, got %+v", res)
	}
}

func TestUpdateCloudDNSRecordZoneReadTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := dnsDriver(t, srv)
	srv.Close()
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.updateCloudDNSRecord(dnsRecordCap, "prod", pid,
		map[string]any{"dns.target": "origin2.example.net"}, []string{"dns.target"})
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("a lost zone-ownership read must be unknown, got %+v", res)
	}
}

func TestUpdateCloudDNSRecordCurrentRecordGoneIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrsets"):
			_, _ = w.Write([]byte(`{"rrsets":[]}`)) // vanished
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","labels":{"groundhold-capability":"` +
				sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.updateCloudDNSRecord(dnsRecordCap, "prod", pid,
		map[string]any{"dns.target": "origin2.example.net"}, []string{"dns.target"})
	if res.Status != "unknown" || !strings.Contains(res.Reason, "not present") {
		t.Fatalf("a vanished current record must be unknown, got %+v", res)
	}
}

func TestUpdateCloudDNSRecordChangesPOST5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrsets"):
			_, _ = w.Write([]byte(`{"rrsets":[{"name":"connect.example.com.","type":"CNAME","ttl":300,"rrdatas":["origin.example.net"]}]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","labels":{"groundhold-capability":"` +
				sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/changes"):
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.updateCloudDNSRecord(dnsRecordCap, "prod", pid,
		map[string]any{"dns.target": "origin2.example.net"}, []string{"dns.target"})
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("a 503 on the repoint POST must be unknown WITH the pid, got %+v", res)
	}
}

func TestUpdateCloudDNSRecordChangesPOSTTerminalRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrsets"):
			_, _ = w.Write([]byte(`{"rrsets":[{"name":"connect.example.com.","type":"CNAME","ttl":300,"rrdatas":["origin.example.net"]}]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","labels":{"groundhold-capability":"` +
				sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/changes"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"bad change"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.updateCloudDNSRecord(dnsRecordCap, "prod", pid,
		map[string]any{"dns.target": "origin2.example.net"}, []string{"dns.target"})
	if res.Status != "failed" {
		t.Fatalf("a clean 400 on the repoint POST must be a terminal failed, got %+v", res)
	}
}

// --- deleteCloudDNSRecord additional branches -------------------------------

func TestDeleteCloudDNSRecordZoneReadTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := dnsDriver(t, srv)
	srv.Close()
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.deleteCloudDNSRecord(dnsRecordCap, "prod", pid)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("a lost zone-ownership read must be unknown, got %+v", res)
	}
}

func TestDeleteCloudDNSRecordForeignZoneRefused(t *testing.T) {
	srv := dnsRecordServer(t, "someone-else")
	defer srv.Close()
	d := dnsDriver(t, srv)
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.deleteCloudDNSRecord(dnsRecordCap, "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign zone must refuse the delete, got %+v", res)
	}
}

func TestDeleteCloudDNSRecordCurrentRecordReadErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrsets"):
			w.WriteHeader(http.StatusForbidden)
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","labels":{"groundhold-capability":"` +
				sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.deleteCloudDNSRecord(dnsRecordCap, "prod", pid)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable current-record check must be unknown, got %+v", res)
	}
}

func TestDeleteCloudDNSRecordAlreadyGoneIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrsets"):
			_, _ = w.Write([]byte(`{"rrsets":[]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","labels":{"groundhold-capability":"` +
				sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.deleteCloudDNSRecord(dnsRecordCap, "prod", pid)
	if res.Status != "succeeded" {
		t.Fatalf("deleting an already-gone record must be idempotent success, got %+v", res)
	}
}

func TestDeleteCloudDNSRecordChangesPOST5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrsets"):
			_, _ = w.Write([]byte(`{"rrsets":[{"name":"connect.example.com.","type":"CNAME","ttl":300,"rrdatas":["origin.example.net"]}]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","labels":{"groundhold-capability":"` +
				sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/changes"):
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.deleteCloudDNSRecord(dnsRecordCap, "prod", pid)
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("a 503 on the delete-changes POST must be unknown WITH the pid, got %+v", res)
	}
}

func TestDeleteCloudDNSRecordChangesPOSTTerminalRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrsets"):
			_, _ = w.Write([]byte(`{"rrsets":[{"name":"connect.example.com.","type":"CNAME","ttl":300,"rrdatas":["origin.example.net"]}]}`))
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/managedZones/"):
			_, _ = w.Write([]byte(`{"name":"example-com","labels":{"groundhold-capability":"` +
				sanitizeLabel(dnsRecordCap) + `","groundhold-environment":"prod"}}`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/changes"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"bad delete change"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := dnsDriver(t, srv)
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	res := d.deleteCloudDNSRecord(dnsRecordCap, "prod", pid)
	if res.Status != "failed" {
		t.Fatalf("a clean 400 on the delete-changes POST must be a terminal failed, got %+v", res)
	}
}

// --- observeCloudDNSRecord error branch --------------------------------

func TestObserveCloudDNSRecordTransportErrorIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := dnsDriver(t, srv)
	srv.Close()
	pid := gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com.")
	if _, _, err := d.observeCloudDNSRecord(dnsRecordCap, pid); err == nil {
		t.Fatal("expected a transport error")
	}
}

func TestObserveCloudDNSRecordCrossProjectRefused(t *testing.T) {
	d := dnsDriver(t, dnsRecordServer(t, sanitizeLabel(dnsRecordCap)))
	pid := gdnsrecProviderID("other-proj", "example-com", "CNAME", "connect.example.com.")
	if _, _, err := d.observeCloudDNSRecord(dnsRecordCap, pid); err == nil || !strings.Contains(err.Error(), "cross-project") {
		t.Fatalf("a cross-project pid must refuse, got %v", err)
	}
}
