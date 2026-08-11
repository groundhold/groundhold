package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func flexAttrs() map[string]any {
	return map[string]any{
		"engine.protocol":        "postgresql/16",
		"location.region":        "eastus",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"encryption.inTransit":   true,
		"availability.class":     "regional",
		"service.managed":        true,
	}
}

func flexImpl() map[string]any {
	// D942: availability.class=regional (HA) is not supported on the Burstable default,
	// so the HA fixture must bring a GeneralPurpose sku — the real-world valid shape.
	return map[string]any{"admin_username": "pgadmin", "admin_password": "S3cret!pw",
		"resource_group": "rg1", "sku": "Standard_D2s_v3"}
}

func TestBuildFlexServerHonors(t *testing.T) {
	p, err := BuildFlexServer("prod", "db", flexAttrs(), flexImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != "16" || p.PublicAccess || !p.ZoneRedundant {
		t.Fatalf("plan = %+v", p)
	}
	if p.AdminUser != "pgadmin" {
		t.Fatalf("admin = %+v", p)
	}
}

func TestBuildFlexServerRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"engine.protocol": "postgresql/16", "location.region": "eastus", "service.managed": true}
	}
	// admin missing
	if _, err := BuildFlexServer("prod", "db", base(), map[string]any{"resource_group": "rg1"}, 1); err == nil {
		t.Error("missing admin creds must refuse")
	}
	cases := map[string]map[string]any{
		"mysql":           {"engine.protocol": "mysql/8.0"},
		"atRest-false":    {"encryption.atRest": false},
		"inTransit-false": {"encryption.inTransit": false},
		"rpo-too-long":    {"recovery.rpo": "60d"},
		"multi-regional":  {"availability.class": "multi-regional"},
		"unknown":         {"versioning.enabled": true},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildFlexServer("prod", "db", a, flexImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// CMK without keys
	cmk := base()
	cmk["encryption.customerManagedKeys"] = true
	if _, err := BuildFlexServer("prod", "db", cmk, flexImpl(), 1); err == nil {
		t.Error("CMK without keys must refuse")
	}
	// missing engine
	if _, err := BuildFlexServer("prod", "db", map[string]any{"location.region": "eastus", "service.managed": true}, flexImpl(), 1); err == nil {
		t.Error("missing engine.protocol must refuse")
	}
}

// flexSecureTransport is the value the fake's configurations endpoint reports (D761).
var flexSecureTransport = "on"

func flexArmFake(t *testing.T, tagCap string) *httptest.Server {
	t.Helper()
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// once deleted, the server is GONE — the ARM delete's 202 poll-to-absence
			// (D971) must be able to confirm a 404, or a delete could never conclude.
			if deleted && r.Method == "GET" {
				w.WriteHeader(404)
				return
			}
			switch r.Method {
			case "PUT":
				w.WriteHeader(202)
				_, _ = w.Write([]byte(`{"properties":{"state":"Creating"}}`))
			case "GET":
				// D761: the server PARAMETER that decides whether plaintext is accepted.
				// The fake served no configurations endpoint at all, so the driver's
				// assertion could never be contradicted by a test.
				if strings.Contains(r.URL.Path, "/configurations/require_secure_transport") {
					_, _ = w.Write([]byte(`{"properties":{"value":"` + flexSecureTransport + `"}}`))
					return
				}
				_, _ = w.Write([]byte(`{"location":"eastus",` +
					`"tags":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"properties":{"state":"Ready","version":"16",` +
					`"network":{"publicNetworkAccess":"Disabled"},` +
					`"backup":{"backupRetentionDays":7},"highAvailability":{"mode":"ZoneRedundant"}}}`))
			case "DELETE":
				deleted = true
				w.WriteHeader(202)
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestCreateObserveDeleteFlexServer(t *testing.T) {
	srv := flexArmFake(t, "db")
	defer srv.Close()
	d := vnetTestDriver(t, srv)

	res := d.createFlexServer("prod", "db", flexAttrs(), flexImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID == "" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeFlexServer("db", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["engine.protocol"] != "postgresql/16" || got["network.publicExposure"] != false ||
		got["availability.class"] != "regional" || got["encryption.inTransit"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteFlexServer("db", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteFlexServerForeignRefused(t *testing.T) {
	srv := flexArmFake(t, "someone-else")
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	pid := flexProviderID(testSub, "rg1", flexServerName("prod", "db", 1))
	res := d.deleteFlexServer("db", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign server must refuse delete, got %+v", res)
	}
}

// TestCreateFlexServerAdoptsExistingSkipsPUT pins D256: an existing OURS flexible
// server is ADOPTED (bound) without a re-PUT — the create body carries the admin
// password, so a re-PUT on a lost-ledger self-adopt would RESET it. Any mutation
// is a test failure.
func TestCreateFlexServerAdoptsExistingSkipsPUT(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"db","groundhold-environment":"prod"},"properties":{"state":"Ready"}}`))
			return
		}
		t.Errorf("adopt must not %s — bind the existing server without re-PUTting (a re-PUT resets the admin password)", r.Method)
		w.WriteHeader(400)
	}))
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	res := d.createFlexServer("prod", "db", flexAttrs(), flexImpl(), 1)
	want := flexProviderID(testSub, "rg1", flexServerName("prod", "db", 1))
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("must adopt the existing owned server (no PUT), got %+v", res)
	}
}

// D761. `encryption.inTransit: true` was asserted with the comment "TLS is enforced by
// DEFAULT on Flexible Server" — and a default is not a guarantee. require_secure_transport
// is a server parameter an operator can turn off, and then the server accepts plaintext
// while the contract's transit-encryption constraint reads satisfied.
//
// Found by D760's question — is this true of EVERY instance? — asked of an asserted
// constant. It was the one answer that was no.
func TestFlexTransitEncryptionComesFromTheServerParameter(t *testing.T) {
	for _, c := range []struct {
		name  string
		value string
		want  any
		diag  string
	}{
		{"require_secure_transport on", "on", true, ""},
		{"turned OFF — the server accepts plaintext", "off", false, ""},
		{"a value we cannot read is not a value we can vouch for", "sometimes", nil,
			"could not be read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			old := flexSecureTransport
			flexSecureTransport = c.value
			defer func() { flexSecureTransport = old }()

			srv := flexArmFake(t, "db")
			defer srv.Close()
			d := vnetTestDriver(t, srv)

			obs, diags, err := d.observeFlexServer("db",
				flexProviderID(testSub, "rg1", flexServerName("prod", "db", 1)))
			if err != nil {
				t.Fatal(err)
			}
			var got any
			for _, o := range obs {
				if o.Path == "encryption.inTransit" {
					got = o.Value
				}
			}
			if got != c.want {
				t.Fatalf("encryption.inTransit = %v, want %v — a server that accepts "+
					"plaintext must not read as encrypted transit (D761)", got, c.want)
			}
			if c.diag != "" {
				found := false
				for _, dg := range diags {
					if strings.Contains(dg, c.diag) {
						found = true
					}
				}
				if !found {
					t.Fatalf("withheld the value and said nothing: %v", diags)
				}
			}
		})
	}
}

// D796. Two halves of one defect, pinned on both sides.
//
// The write half was the dangerous one: BuildFlexServer divided the requested RPO into
// DAYS and wrote it to backupRetentionDays, so a contract asking for a 15-minute
// data-loss window set backup retention to its floor of ONE DAY. Asking for better
// recovery made the estate's recoverability worse, silently, on a real server.
//
// The read half made it invisible: observe echoed those retention days back as the RPO,
// so the loop closed and every round-trip test agreed with itself.
func TestFlexServerRefusesRPOInsteadOfWritingItToRetention(t *testing.T) {
	attrs := flexAttrs()
	attrs["recovery.rpo"] = "15m"
	_, err := BuildFlexServer("prod", "db", attrs, flexImpl(), 1)
	if err == nil {
		t.Fatal("a 15-minute RPO was accepted — it can only have landed in a day-granular field")
	}
	for _, want := range []string{"backupRetentionDays", "how far BACK", "measured"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not teach the difference (missing %q): %v", want, err)
		}
	}
}

func TestFlexServerObserveDoesNotCallRetentionAnRPO(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold.io/managed":"true",` +
			`"groundhold.io/environment":"prod","groundhold.io/capability":"db"},` +
			`"properties":{"state":"Ready","version":"16",` +
			`"network":{"publicNetworkAccess":"Disabled"},` +
			`"backup":{"backupRetentionDays":7},"highAvailability":{"mode":"ZoneRedundant"}}}`))
	}))
	defer srv.Close()
	d := metamorphicDriver(t, srv.URL)
	obs, diags, err := d.observeFlexServer("db", flexProviderID(d.Subscription, "rg1", "pv-pg-prod-db-g1"))
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "recovery.rpo" {
			t.Fatalf("retention reported as a data-loss window: %+v", o)
		}
	}
	// Silence alone would be the D513 mistake — the read happened and has a result, so
	// the run says what it saw and why that is not the answer.
	joined := strings.Join(diags, " | ")
	if !strings.Contains(joined, "recovery.rpo not observed") || !strings.Contains(joined, "7 day") {
		t.Errorf("the withheld attribute is not explained: %v", diags)
	}
}

// D942: the tier is derived from the sku family, never the constant "Burstable".
// Field-proven — Standard_D2s_v3 with the correct GeneralPurpose tier reaches Ready,
// but the identical body with tier:Burstable rolls back. An unrecognized sku family
// refuses rather than guess a wrong (rolling-back) tier.
func TestFlexServerTierDerivedFromSkuFamily(t *testing.T) {
	for sku, wantTier := range map[string]string{
		"Standard_B1ms":   "Burstable",
		"Standard_D2s_v3": "GeneralPurpose",
		"Standard_E2s_v3": "MemoryOptimized",
	} {
		a := flexAttrs()
		im := map[string]any{"admin_username": "pgadmin", "admin_password": "S3cret!pw",
			"resource_group": "rg1", "sku": sku}
		p, err := BuildFlexServer("prod", "db", a, im, 1)
		if err != nil {
			t.Fatalf("sku %s: %v", sku, err)
		}
		if p.Tier != wantTier {
			t.Errorf("sku %s -> tier %q, want %q", sku, p.Tier, wantTier)
		}
	}
	// an unrecognized sku family must refuse rather than send a wrong tier
	a := flexAttrs()
	im := map[string]any{"admin_username": "pgadmin", "admin_password": "S3cret!pw",
		"resource_group": "rg1", "sku": "Standard_Q9weird"}
	if _, err := BuildFlexServer("prod", "db", a, im, 1); err == nil {
		t.Error("an unrecognized sku family must refuse rather than send a wrong tier")
	}
}

// D947: availability.class=regional maps to ZoneRedundant HA, which Azure accepts then
// rolls back ~20 min later in a region/subscription where it is Disabled. The create
// preflights the region's capabilities and refuses up front. Skip-loudly: an
// inconclusive capabilities read must NOT block (the plain flexserver tests, whose fake
// serves no /capabilities, already exercise that proceed path).
func TestCreateFlexServerRefusesUnsupportedZoneRedundantHA(t *testing.T) {
	for _, c := range []struct {
		name       string
		flag       string
		wantRefuse bool
	}{
		{"Disabled refuses up front", "Disabled", true},
		{"Enabled is not refused by the preflight", "Enabled", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.Contains(r.URL.Path, "/capabilities") {
					_, _ = w.Write([]byte(`{"value":[{"zoneRedundantHaSupported":"` + c.flag + `"}]}`))
					return
				}
				if r.Method == "PUT" {
					w.WriteHeader(202)
					_, _ = w.Write([]byte(`{"properties":{"state":"Creating"}}`))
					return
				}
				w.WriteHeader(404) // server pre-read/poll: absent
			}))
			defer srv.Close()
			d := vnetTestDriver(t, srv)
			res := d.createFlexServer("prod", "db", flexAttrs(), flexImpl(), 1)
			refusedForHA := res.Status == "failed" && strings.Contains(res.Reason, "zoneRedundantHaSupported=Disabled")
			if c.wantRefuse && !refusedForHA {
				t.Errorf("unsupported zone-redundant HA must refuse up front, got %+v", res)
			}
			if !c.wantRefuse && refusedForHA {
				t.Errorf("a region that supports zone-redundant HA must NOT be preflight-refused: %+v", res)
			}
		})
	}
}
