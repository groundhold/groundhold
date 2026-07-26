package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const r53RecordCap = "capability.dns.record"

func r53RecordAttrs() map[string]any {
	return map[string]any{
		"dns.type":        "CNAME",
		"dns.target":      "origin.example.net",
		"service.managed": true,
	}
}

func r53RecordImpl() map[string]any {
	return map[string]any{"zone_id": "Z123ABC", "record_name": "connect.example.com"}
}

func TestBuildRoute53RecordHonors(t *testing.T) {
	p, err := BuildRoute53Record("prod", r53RecordCap, r53RecordAttrs(), r53RecordImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.ZoneID != "Z123ABC" || p.Name != "connect.example.com." || p.Type != "CNAME" || p.Target != "origin.example.net" {
		t.Fatalf("plan = %+v", p)
	}
	xml := p.changeXML("UPSERT")
	if !strings.Contains(xml, "<Action>UPSERT</Action>") ||
		!strings.Contains(xml, "<Type>CNAME</Type>") ||
		!strings.Contains(xml, "<Name>connect.example.com.</Name>") ||
		!strings.Contains(xml, "<Value>origin.example.net</Value>") {
		t.Fatalf("xml = %s", xml)
	}
	// a TXT target is quoted on the wire, unquoted on read.
	txt, _ := BuildRoute53Record("prod", r53RecordCap,
		map[string]any{"dns.type": "TXT", "dns.target": "v=spf1 -all", "service.managed": true}, r53RecordImpl(), 1)
	if !strings.Contains(txt.changeXML("UPSERT"), `<Value>"v=spf1 -all"</Value>`) {
		t.Fatalf("TXT must be quoted: %s", txt.changeXML("UPSERT"))
	}
}

func TestBuildRoute53RecordRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"proxied-is-cloudflare-only": {
			map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "dns.proxied": true, "service.managed": true},
			r53RecordImpl()},
		"unmanaged":      {map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "service.managed": false}, r53RecordImpl()},
		"bad-type":       {map[string]any{"dns.type": "WIDGET", "dns.target": "x", "service.managed": true}, r53RecordImpl()},
		"missing-type":   {map[string]any{"dns.target": "1.2.3.4", "service.managed": true}, r53RecordImpl()},
		"missing-target": {map[string]any{"dns.type": "A", "service.managed": true}, r53RecordImpl()},
		"missing-zone":   {r53RecordAttrs(), map[string]any{"record_name": "connect.example.com"}},
		"bad-zone":       {r53RecordAttrs(), map[string]any{"zone_id": "not-a-zone", "record_name": "connect.example.com"}},
		"missing-name":   {r53RecordAttrs(), map[string]any{"zone_id": "Z123ABC"}},
		"record-noise":   {map[string]any{"dns.type": "A", "dns.target": "1.2.3.4", "dns.ttl": 60, "service.managed": true}, r53RecordImpl()},
	}
	for name, c := range cases {
		if _, err := BuildRoute53Record("prod", r53RecordCap, c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// r53RecordServer fakes the Route 53 endpoints a record driver touches: the parent
// zone's tags (ownership gate), the rrset UPSERT/DELETE, and the rrset list.
func r53RecordServer(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/2013-04-01/tags/hostedzone/"):
			_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ResourceTagSet><Tags>` +
				`<Tag><Key>groundhold-capability</Key><Value>` + tagCap + `</Value></Tag>` +
				`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
				`</Tags></ResourceTagSet></ListTagsForResourceResponse>`))
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/rrset"):
			_, _ = w.Write([]byte(`<ListResourceRecordSetsResponse><ResourceRecordSets><ResourceRecordSet>` +
				`<Name>connect.example.com.</Name><Type>CNAME</Type><TTL>300</TTL>` +
				`<ResourceRecords><ResourceRecord><Value>origin.example.net</Value></ResourceRecord></ResourceRecords>` +
				`</ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>`))
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/rrset"):
			_, _ = w.Write([]byte(`<ChangeResourceRecordSetsResponse><ChangeInfo><Status>PENDING</Status></ChangeInfo></ChangeResourceRecordSetsResponse>`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestCreateObserveDeleteRoute53Record(t *testing.T) {
	srv := r53RecordServer(t, sanitizeTag(r53RecordCap))
	defer srv.Close()
	d := r53Driver(t, srv)

	res := d.createRoute53Record("prod", r53RecordCap, r53RecordAttrs(), r53RecordImpl(), 1)
	wantPID := r53RecordProviderID("Z123ABC", "CNAME", "connect.example.com.")
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("create: %+v (want pid %s)", res, wantPID)
	}
	obs, diags, err := d.observeRoute53Record(r53RecordCap, res.ProviderID)
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
		t.Fatalf("dns.proxied must be OMITTED on Route 53, got %v", got["dns.proxied"])
	}
	if len(diags) == 0 || !strings.Contains(strings.Join(diags, " "), "dns.proxied") {
		t.Fatalf("observe must diagnose the omitted dns.proxied, diags=%v", diags)
	}
	if del := d.deleteRoute53Record(r53RecordCap, "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// TestClassifyRoute53RecordChange pins the mutable/immutable/unsupported arms: a
// target repoint is an in-place UPSERT (no delete+recreate resolution gap), a type
// change is a replacement (the record's identity), and platform/edge paths are
// unsupported — never a silent "mutable".
func TestClassifyRoute53RecordChange(t *testing.T) {
	cases := map[string]string{
		"dns.target":      "mutable",
		"dns.type":        "immutable",
		"service.managed": "unsupported",
		"dns.proxied":     "unsupported",
		"cost.monthly":    "unsupported",
		"dns.ttl":         "unsupported", // unknown path is refused, never mutable
	}
	for path, want := range cases {
		got, note := classifyRoute53RecordChange(path, nil, nil)
		if got != want {
			t.Errorf("classify %s = %q, want %q", path, got, want)
		}
		if got != "mutable" && note == "" {
			t.Errorf("classify %s: a non-mutable class must carry a reason", path)
		}
	}
}

// TestUpdateRoute53RecordRepointsTarget pins the thesis of this slice: changing
// dns.target is a PATCH (one UPSERT into the owned zone), not a delete+recreate.
func TestUpdateRoute53RecordRepointsTarget(t *testing.T) {
	srv := r53RecordServer(t, sanitizeTag(r53RecordCap))
	defer srv.Close()
	d := r53Driver(t, srv)

	pid := r53RecordProviderID("Z123ABC", "CNAME", "connect.example.com.")
	repointed := r53RecordAttrs()
	repointed["dns.target"] = "new-origin.example.net" // repoint
	res := d.updateRoute53Record(r53RecordCap, "prod", pid, repointed, r53RecordImpl(), []string{"dns.target"})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("repoint: %+v (want succeeded, pid %s)", res, pid)
	}
}

// TestUpdateRoute53RecordForeignZoneRefused pins the ownership boundary on the
// update path too: repointing a record in a zone that is not ours is refused.
func TestUpdateRoute53RecordForeignZoneRefused(t *testing.T) {
	srv := r53RecordServer(t, "someone-else")
	defer srv.Close()
	d := r53Driver(t, srv)

	pid := r53RecordProviderID("Z123ABC", "CNAME", "connect.example.com.")
	res := d.updateRoute53Record(r53RecordCap, "prod", pid, r53RecordAttrs(), r53RecordImpl(), []string{"dns.target"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign parent zone must refuse the repoint, got %+v", res)
	}
}

// TestCreateRoute53RecordForeignZoneRefused pins the ownership boundary: a record
// whose PARENT ZONE is not ours (tags mismatch) is refused — never written into a
// zone we do not own.
func TestCreateRoute53RecordForeignZoneRefused(t *testing.T) {
	srv := r53RecordServer(t, "someone-else")
	defer srv.Close()
	d := r53Driver(t, srv)
	res := d.createRoute53Record("prod", r53RecordCap, r53RecordAttrs(), r53RecordImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign parent zone must refuse the record write, got %+v", res)
	}
}
