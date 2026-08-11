package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

func auditAttrs() map[string]any {
	return map[string]any{
		"location.region":                "europe-west1",
		"scope.multiRegion":              true,
		"integrity.logValidation":        false,
		"encryption.customerManagedKeys": false,
		"delivery.assured":               true,
		"service.managed":                true,
	}
}

func auditImpl() map[string]any {
	return map[string]any{"destination": "storage.googleapis.com/acme-audit-logs"}
}

func TestBuildAuditSinkHonors(t *testing.T) {
	p, err := BuildAuditSink("acme-prod", "prod", "capability.audit.trail", auditAttrs(), auditImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Destination != "storage.googleapis.com/acme-audit-logs" {
		t.Fatalf("destination = %q", p.Destination)
	}
	if p.Disabled {
		t.Fatalf("delivery.assured=true must leave the sink enabled (disabled=false)")
	}
	if p.Name != AuditSinkName("acme-prod", "prod", "capability.audit.trail", 1) {
		t.Fatalf("sink name not deterministic: %q", p.Name)
	}
	body := p.createBody()
	if body["destination"] != p.Destination {
		t.Fatalf("body destination = %v", body["destination"])
	}
	if !strings.Contains(body["filter"].(string), "cloudaudit.googleapis.com") {
		t.Fatalf("filter must select audit logs: %v", body["filter"])
	}
	if body["disabled"] != false {
		t.Fatalf("body disabled = %v", body["disabled"])
	}
	if body["description"] != auditSinkDescription("capability.audit.trail", "prod") {
		t.Fatalf("body description marker = %v", body["description"])
	}
}

// delivery.assured=false is honored as a disabled sink (the StopLogging analog).
func TestBuildAuditSinkDeliveryDisabled(t *testing.T) {
	a := auditAttrs()
	a["delivery.assured"] = false
	p, err := BuildAuditSink("acme-prod", "prod", "capability.audit.trail", a, auditImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Disabled {
		t.Fatalf("delivery.assured=false must disable the sink")
	}
}

// CMEK is a declared assertion about the destination — true requires the operand key.
func TestBuildAuditSinkCMEK(t *testing.T) {
	a := auditAttrs()
	a["encryption.customerManagedKeys"] = true
	impl := map[string]any{
		"destination":  "storage.googleapis.com/acme-audit-logs",
		"kms_key_name": "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k",
	}
	p, err := BuildAuditSink("acme-prod", "prod", "capability.audit.trail", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.CMK || p.KmsKeyName == "" {
		t.Fatalf("plan = %+v", p)
	}
	// the CMEK never enters the sink body — it lives on the destination operand.
	if _, ok := p.createBody()["kmsKeyName"]; ok {
		t.Fatalf("CMEK must not be sent to the sink API")
	}
}

// The load-bearing honesty: integrity.logValidation=true has NO GCP analog and MUST be
// refused, never faked into the plan.
func TestBuildAuditSinkRefusesLogValidation(t *testing.T) {
	a := auditAttrs()
	a["integrity.logValidation"] = true
	_, err := BuildAuditSink("acme-prod", "prod", "capability.audit.trail", a, auditImpl(), 1)
	if err == nil || !strings.Contains(err.Error(), "NO GCP equivalent") {
		t.Fatalf("integrity.logValidation=true must refuse honestly, got err=%v", err)
	}
}

func TestBuildAuditSinkRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"single-region-scope": {map[string]any{"scope.multiRegion": false}, auditImpl()},
		"unmanaged":           {map[string]any{"service.managed": false}, auditImpl()},
		"unknown-attr":        {map[string]any{"retention.days": 90}, auditImpl()},
		"bad-region":          {map[string]any{"location.region": "not a region!"}, auditImpl()},
		"missing-destination": {nil, map[string]any{}},
		"bad-destination":     {nil, map[string]any{"destination": "s3://bucket"}},
		"cmk-without-key":     {map[string]any{"encryption.customerManagedKeys": true}, auditImpl()},
		"key-without-cmk": {nil, map[string]any{
			"destination":  "storage.googleapis.com/acme-audit-logs",
			"kms_key_name": "projects/p/locations/l/keyRings/r/cryptoKeys/k"}},
		"bad-sink-name": {nil, map[string]any{
			"destination": "storage.googleapis.com/acme-audit-logs", "sinkName": "1-bad/name"}},
	}
	for name, tc := range cases {
		a := auditAttrs()
		for k, v := range tc.attrs {
			a[k] = v
		}
		if _, err := BuildAuditSink("acme-prod", "prod", "capability.audit.trail", a, tc.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestClassifyAuditLogsChange(t *testing.T) {
	want := map[string]string{
		"delivery.assured":               "mutable",
		"location.region":                "unsupported",
		"encryption.customerManagedKeys": "unsupported",
		"scope.multiRegion":              "unsupported",
		"integrity.logValidation":        "unsupported",
		"service.managed":                "unsupported",
		"cost.monthly":                   "unsupported",
	}
	// D825: residency and CMEK belong to the sink's DESTINATION, which is what the reason
	// always said — and the neighbouring cases answer unsupported for exactly that.
	for path, w := range want {
		got, _ := classifyAuditLogsChange(path)
		if got != w {
			t.Errorf("classify(%s) = %q, want %q", path, got, w)
		}
	}
}

// auditSinkServer is a fake Logging sinks endpoint. disabled is what a GET reports.
func auditSinkServer(t *testing.T, disabled bool) (*httptest.Server, *[]string, *int) {
	t.Helper()
	var sawAuth []string
	patches := 0
	desc := auditSinkDescription("capability.audit.trail", "prod")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			sawAuth = append(sawAuth, r.Header.Get("Authorization"))
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/sinks"):
				var got map[string]any
				raw, _ := io.ReadAll(r.Body)
				if json.Unmarshal(raw, &got) != nil || got["destination"] == nil {
					w.WriteHeader(400)
					return
				}
				_, _ = w.Write([]byte(`{"name":"` + got["name"].(string) + `","writerIdentity":"serviceAccount:x@y"}`))
			case r.Method == "PATCH":
				patches++
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"name":"x"}`))
			case r.Method == "GET":
				dis := "false"
				if disabled {
					dis = "true"
				}
				_, _ = w.Write([]byte(`{"name":"x","destination":"storage.googleapis.com/acme-audit-logs",` +
					`"filter":"logName:\"cloudaudit.googleapis.com\"","description":"` + desc + `","disabled":` + dis + `}`))
			case r.Method == "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
	return srv, &sawAuth, &patches
}

func auditDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	auditLogsBaseURLOverride = srv.URL
	t.Cleanup(func() { auditLogsBaseURLOverride = "" })
	return NewDriver("acme-prod")
}

func TestCreateObserveDeleteAuditLogs(t *testing.T) {
	srv, sawAuth, _ := auditSinkServer(t, false)
	defer srv.Close()
	d := auditDriver(t, srv)

	res := d.createAuditLogs("capability.audit.trail", "prod", auditAttrs(), auditImpl(), 1)
	wantPID := "auditlogs:acme-prod:" + AuditSinkName("acme-prod", "prod", "capability.audit.trail", 1)
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("create: %+v (want pid %q)", res, wantPID)
	}
	if len(*sawAuth) == 0 || (*sawAuth)[0] != "Bearer test-token" {
		t.Fatalf("missing/incorrect bearer: %v", *sawAuth)
	}

	obs, diags, err := d.observeAuditLogs("capability.audit.trail", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
		// D738: `delivery.assured` is config-intent, deliberately. It reads the sink's
		// own `disabled` flag, and this driver creates the sink with its own writer
		// identity whose grant on the DESTINATION nothing here verifies — so a sink
		// that delivers nothing reports the same as one that delivers. This assertion
		// demanded `measured` for every path, which is why the over-claim was pinned
		// rather than caught. Everything else here must still be measured.
		if o.Path == "delivery.assured" {
			if o.Derivation != "config-intent" {
				t.Fatalf("delivery.assured derivation = %q — reading the sink's own flag "+
					"is not a measurement that anything arrives", o.Derivation)
			}
			continue
		}
		if o.Derivation != "measured" {
			t.Fatalf("observation %s derivation = %q, want measured", o.Path, o.Derivation)
		}
	}
	if got["delivery.assured"] != true || got["service.managed"] != true || got["scope.multiRegion"] != true {
		t.Fatalf("observe: %+v", got)
	}
	// HONESTY: integrity.logValidation, location.region and CMEK are NEVER observed —
	// only omitted with diagnostics.
	for _, unfaked := range []string{"integrity.logValidation", "location.region", "encryption.customerManagedKeys"} {
		if _, present := got[unfaked]; present {
			t.Fatalf("%s must NOT be observed (no honest GCP analog on the sink)", unfaked)
		}
	}
	// D738: four now — the fourth says why delivery.assured is config-intent. A count
	// is a weak assertion (it cannot tell WHICH diagnostic), so the substance is checked
	// too: the one a reader most needs is the one about the grant nobody verified.
	if len(diags) != 4 {
		t.Fatalf("expected 4 honesty diagnostics, got %v", diags)
	}
	var saidWhy bool
	for _, dg := range diags {
		if strings.Contains(dg, "write access on the destination") {
			saidWhy = true
		}
	}
	if !saidWhy {
		t.Fatalf("the diagnostics do not say that the destination grant is unverified: %v", diags)
	}

	if del := d.deleteAuditLogs("capability.audit.trail", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// delivery.assured is the only in-place-mutable attribute — a toggle is one sinks.patch.
func TestUpdateAuditLogsDeliveryToggle(t *testing.T) {
	srv, _, patches := auditSinkServer(t, false)
	defer srv.Close()
	d := auditDriver(t, srv)
	pid := "auditlogs:acme-prod:" + AuditSinkName("acme-prod", "prod", "capability.audit.trail", 1)

	a := auditAttrs()
	a["delivery.assured"] = false // stop delivering
	res := d.updateAuditLogs("capability.audit.trail", "prod", pid, a, auditImpl(), []string{"delivery.assured"})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("update: %+v", res)
	}
	if *patches != 1 {
		t.Fatalf("expected exactly one sinks.patch, got %d", *patches)
	}

	// a non-delivery path must NOT be silently patched — it refuses.
	if r := d.updateAuditLogs("capability.audit.trail", "prod", pid, a, auditImpl(),
		[]string{"integrity.logValidation"}); r.Status != "failed" {
		t.Fatalf("a non-mutable change must refuse, got %+v", r)
	}
}

// A sink at our name with a FOREIGN description is refused, never adopted.
func TestCreateAuditLogsConflictForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST":
				w.WriteHeader(http.StatusConflict)
			case "GET":
				_, _ = w.Write([]byte(`{"name":"x","description":"someone elses sink"}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := auditDriver(t, srv)
	res := d.createAuditLogs("capability.audit.trail", "prod", auditAttrs(), auditImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign conflict must refuse, got %+v", res)
	}
}

// A conflict on OUR sink (description marker matches) is an idempotent success.
func TestCreateAuditLogsConflictOursIdempotent(t *testing.T) {
	desc := auditSinkDescription("capability.audit.trail", "prod")
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST":
				w.WriteHeader(http.StatusConflict)
			case "GET":
				_, _ = w.Write([]byte(`{"name":"x","description":"` + desc + `"}`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := auditDriver(t, srv)
	res := d.createAuditLogs("capability.audit.trail", "prod", auditAttrs(), auditImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("ours-conflict must be idempotent success, got %+v", res)
	}
}

func TestObserveAuditLogsNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer srv.Close()
	d := auditDriver(t, srv)
	pid := "auditlogs:acme-prod:" + AuditSinkName("acme-prod", "prod", "capability.audit.trail", 1)
	obs, diags, err := d.observeAuditLogs("capability.audit.trail", pid)
	if err != nil {
		t.Fatal(err)
	}
	// Corrected with D519: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if !absentMarked(obs) || len(diags) == 0 {
		t.Fatalf("a missing sink must report %s=true with a diagnostic, got obs=%v diags=%v",
			provider.ResourceAbsentPath, obs, diags)
	}
}

func TestSplitAuditLogsProviderID(t *testing.T) {
	if _, _, err := splitAuditLogsProviderID("auditlogs:acme-prod:pv-sink"); err != nil {
		t.Fatalf("valid pid rejected: %v", err)
	}
	for _, bad := range []string{"assetfeed:p:s", "auditlogs:p", "auditlogs:BAD PROJECT:s", "auditlogs:acme-prod:1bad/name"} {
		if _, _, err := splitAuditLogsProviderID(bad); err == nil {
			t.Errorf("bad pid %q accepted", bad)
		}
	}
}
