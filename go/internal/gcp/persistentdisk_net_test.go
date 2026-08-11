package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pdServer answers the calls this driver makes, routed by method+path so a test
// states what the API does rather than how the driver phrases the question. It
// records the paths, because ZONAL AND REGIONAL DISKS LIVE AT DIFFERENT URLS and
// hitting the wrong one is the failure mode this driver has that its EBS twin
// does not.
type pdServer struct {
	insertStatus int
	insertBody   string
	getStatus    int
	getBody      string
	opBody       string
	deleteStatus int
	deleteBody   string
	calls        []string
	paths        []string
}

func (s *pdServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		s.paths = append(s.paths, p)
		switch {
		case strings.Contains(p, "/operations/"):
			s.calls = append(s.calls, "operation")
			_, _ = w.Write([]byte(s.opBody))
		case strings.Contains(p, "/aggregated/disks"):
			s.calls = append(s.calls, "aggregatedList")
			w.WriteHeader(s.getStatus)
			_, _ = w.Write([]byte(s.getBody))
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/disks"):
			s.calls = append(s.calls, "insert")
			w.WriteHeader(s.insertStatus)
			_, _ = w.Write([]byte(s.insertBody))
		case r.Method == http.MethodDelete:
			s.calls = append(s.calls, "delete")
			w.WriteHeader(s.deleteStatus)
			_, _ = w.Write([]byte(s.deleteBody))
		case r.Method == http.MethodGet:
			s.calls = append(s.calls, "get")
			w.WriteHeader(s.getStatus)
			_, _ = w.Write([]byte(s.getBody))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func pdDriver(t *testing.T, s *pdServer) (*Driver, func()) {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	srv := httptest.NewServer(s.handler())
	d := NewDriver("acme-prod")
	d.ComputeBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 50 * time.Millisecond
	return d, srv.Close
}

const pdOpDone = `{"name":"op-1","status":"DONE"}`

// ownedDisk is a zonal disk carrying OUR labels.
const ownedDisk = `{"name":"orders-data-production-abc12345","status":"READY",
"labels":{"groundhold-capability":"orders-data","groundhold-environment":"production"},
"diskEncryptionKey":{"kmsKeyName":"projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k"}}`

// ownedRegionalDisk carries replicaZones, which is what makes it regional.
const ownedRegionalDisk = `{"name":"orders-data-production-abc12345","status":"READY",
"labels":{"groundhold-capability":"orders-data","groundhold-environment":"production"},
"replicaZones":["https://x/zones/europe-west1-b","https://x/zones/europe-west1-c"]}`

func TestCreatePDZonalHitsTheZonalEndpoint(t *testing.T) {
	s := &pdServer{insertStatus: 200, insertBody: `{"name":"op-1"}`, opBody: pdOpDone}
	d, done := pdDriver(t, s)
	defer done()

	res := d.createPD("orders-data", "production", pdAttrs(), pdImpl(), 0)
	if res.Status != "succeeded" {
		t.Fatalf("status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if !strings.HasPrefix(res.ProviderID, "pd:acme-prod:europe-west1-b:") {
		t.Errorf("providerId = %q, want a zone-scoped id", res.ProviderID)
	}
	if !strings.Contains(s.paths[0], "/zones/europe-west1-b/disks") {
		t.Errorf("insert path = %q, want the zonal collection", s.paths[0])
	}
}

// The one thing this driver can get wrong that EBS cannot: creating a regional
// disk against the zonal endpoint. The API would accept a zonal disk and the
// contract would report `regional` for it — a durability guarantee that does not
// exist.
func TestCreatePDRegionalHitsTheRegionalEndpoint(t *testing.T) {
	attrs := pdAttrs()
	attrs["availability.class"] = "regional"
	impl := map[string]any{"size_gb": 200,
		"replica_zones": []any{"europe-west1-b", "europe-west1-c"}}

	s := &pdServer{insertStatus: 200, insertBody: `{"name":"op-1"}`, opBody: pdOpDone}
	d, done := pdDriver(t, s)
	defer done()

	res := d.createPD("orders-data", "production", attrs, impl, 0)
	if res.Status != "succeeded" {
		t.Fatalf("status = %q (%s)", res.Status, res.Reason)
	}
	if !strings.HasPrefix(res.ProviderID, "pd:acme-prod:europe-west1:") {
		t.Errorf("providerId = %q, want a region-scoped id", res.ProviderID)
	}
	if !strings.Contains(s.paths[0], "/regions/europe-west1/disks") {
		t.Errorf("insert path = %q, want the REGIONAL collection — a regional contract "+
			"served by the zonal endpoint yields a zonal disk the contract calls regional",
			s.paths[0])
	}
	// The operation must be polled in the matching scope, or the poll 404s and a
	// perfectly good create reports unknown forever.
	var polled string
	for _, p := range s.paths {
		if strings.Contains(p, "/operations/") {
			polled = p
		}
	}
	if polled != "" && !strings.Contains(polled, "/regions/europe-west1/") {
		t.Errorf("operation polled at %q, want the regional scope", polled)
	}
}

func TestCreatePDMutationHonesty(t *testing.T) {
	t.Run("5xx is unknown, never failed", func(t *testing.T) {
		s := &pdServer{insertStatus: 503, insertBody: `{}`}
		d, done := pdDriver(t, s)
		defer done()
		res := d.createPD("orders-data", "production", pdAttrs(), pdImpl(), 0)
		if res.Status != "unknown" {
			t.Errorf("status = %q, want unknown (a 503 can front a disk that exists)", res.Status)
		}
		if res.ProviderID == "" {
			t.Error("an unknown create carried no providerId — the name is deterministic, " +
				"so the disk is findable and must be named for the reconcile")
		}
	})
	t.Run("a name conflict with our labels is the create succeeding twice", func(t *testing.T) {
		s := &pdServer{insertStatus: 409, insertBody: `{}`, getStatus: 200, getBody: ownedDisk}
		d, done := pdDriver(t, s)
		defer done()
		res := d.createPD("orders-data", "production", pdAttrs(), pdImpl(), 0)
		if res.Status != "succeeded" {
			t.Errorf("status = %q (%s), want succeeded — the deterministic name IS the "+
				"idempotency mechanism", res.Status, res.Reason)
		}
	})
	// The check that matters on a stateful capability: binding a stranger's disk
	// would put their DATA under our contract, and our delete gate over it.
	t.Run("a name conflict with foreign labels refuses to bind", func(t *testing.T) {
		foreign := strings.Replace(ownedDisk, `"groundhold-capability":"orders-data"`,
			`"groundhold-capability":"someone-elses-database"`, 1)
		s := &pdServer{insertStatus: 409, insertBody: `{}`, getStatus: 200, getBody: foreign}
		d, done := pdDriver(t, s)
		defer done()
		res := d.createPD("orders-data", "production", pdAttrs(), pdImpl(), 0)
		if res.Status != "failed" {
			t.Errorf("status = %q, want failed", res.Status)
		}
		if res.ProviderID != "" {
			t.Errorf("bound providerId %q — that is a stranger's data", res.ProviderID)
		}
	})
	t.Run("a conflict whose disk cannot be read is unknown", func(t *testing.T) {
		s := &pdServer{insertStatus: 409, insertBody: `{}`, getStatus: 500, getBody: `{}`}
		d, done := pdDriver(t, s)
		defer done()
		res := d.createPD("orders-data", "production", pdAttrs(), pdImpl(), 0)
		if res.Status != "unknown" {
			t.Errorf("status = %q, want unknown", res.Status)
		}
	})
	t.Run("a create that never reaches the network is failed", func(t *testing.T) {
		s := &pdServer{insertStatus: 200, insertBody: `{"name":"op-1"}`, opBody: pdOpDone}
		d, done := pdDriver(t, s)
		defer done()
		impl := map[string]any{"zone": "europe-west1-b"} // no size, nothing to restore
		res := d.createPD("orders-data", "production", pdAttrs(), impl, 0)
		if res.Status != "failed" {
			t.Errorf("status = %q, want failed", res.Status)
		}
		if len(s.calls) != 0 {
			t.Errorf("the driver called %v before refusing — a refusal must happen before any mutation", s.calls)
		}
	})
}

func TestObservePD(t *testing.T) {
	s := &pdServer{getStatus: 200, getBody: ownedDisk}
	d, done := pdDriver(t, s)
	defer done()

	obs, unread, err := d.observePD("orders-data",
		"pd:acme-prod:europe-west1-b:orders-data-production-abc12345")
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
		"location.region":                "europe-west1",
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
	// atRest is a fact about the PLATFORM, not a reading of this disk, and saying
	// so is what keeps `measured` meaning something. D759 gave that sentence its own
	// label — it was written here long before the set had a value for it, which is as
	// good an argument for the third value as the count of 65 was.
	for _, o := range obs {
		if o.Path == "encryption.atRest" && o.Derivation != "platform-invariant" {
			t.Errorf("encryption.atRest derivation = %q, want platform-invariant", o.Derivation)
		}
	}
}

// availability.class is read from the RESOURCE, not inferred from where we
// looked. A disk observed through a region-scoped id that carries no replicaZones
// would otherwise be reported regional on the strength of the lookup path alone.
func TestObservePDReadsTheClassFromTheDiskNotTheScope(t *testing.T) {
	s := &pdServer{getStatus: 200, getBody: ownedRegionalDisk}
	d, done := pdDriver(t, s)
	defer done()

	obs, _, err := d.observePD("orders-data",
		"pd:acme-prod:europe-west1:orders-data-production-abc12345")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "availability.class" && o.Value != "regional" {
			t.Errorf("availability.class = %v, want regional", o.Value)
		}
		if o.Path == "location.region" && o.Value != "europe-west1" {
			t.Errorf("location.region = %v", o.Value)
		}
	}
	if !strings.Contains(s.paths[0], "/regions/europe-west1/disks/") {
		t.Errorf("read path = %q, want the regional collection", s.paths[0])
	}
}

func TestObservePDUnreadableIsAnError(t *testing.T) {
	s := &pdServer{getStatus: 500, getBody: `{}`}
	d, done := pdDriver(t, s)
	defer done()

	obs, _, err := d.observePD("orders-data",
		"pd:acme-prod:europe-west1-b:orders-data-production-abc12345")
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

func TestDeletePD(t *testing.T) {
	t.Run("deletes what it owns", func(t *testing.T) {
		s := &pdServer{getStatus: 200, getBody: ownedDisk, deleteStatus: 200,
			deleteBody: `{"name":"op-1"}`, opBody: pdOpDone}
		d, done := pdDriver(t, s)
		defer done()
		res := d.deletePD("orders-data", "production",
			"pd:acme-prod:europe-west1-b:orders-data-production-abc12345")
		if res.Status != "succeeded" {
			t.Fatalf("status = %q (%s)", res.Status, res.Reason)
		}
	})

	t.Run("refuses a disk that is not ours", func(t *testing.T) {
		foreign := strings.Replace(ownedDisk, `"groundhold-capability":"orders-data"`,
			`"groundhold-capability":"someone-elses-database"`, 1)
		s := &pdServer{getStatus: 200, getBody: foreign, deleteStatus: 200}
		d, done := pdDriver(t, s)
		defer done()
		res := d.deletePD("orders-data", "production",
			"pd:acme-prod:europe-west1-b:orders-data-production-abc12345")
		if res.Status != "failed" {
			t.Fatalf("status = %q, want failed", res.Status)
		}
		for _, c := range s.calls {
			if c == "delete" {
				t.Fatal("DELETE was issued against a disk with foreign labels")
			}
		}
	})

	t.Run("an absent disk is already deleted", func(t *testing.T) {
		s := &pdServer{getStatus: 404, getBody: `{}`}
		d, done := pdDriver(t, s)
		defer done()
		res := d.deletePD("orders-data", "production",
			"pd:acme-prod:europe-west1-b:orders-data-production-abc12345")
		if res.Status != "succeeded" {
			t.Errorf("status = %q, want succeeded (idempotent)", res.Status)
		}
	})

	t.Run("an unreadable pre-delete read is unknown, never a delete", func(t *testing.T) {
		s := &pdServer{getStatus: 500, getBody: `{}`}
		d, done := pdDriver(t, s)
		defer done()
		res := d.deletePD("orders-data", "production",
			"pd:acme-prod:europe-west1-b:orders-data-production-abc12345")
		if res.Status != "unknown" {
			t.Errorf("status = %q, want unknown", res.Status)
		}
		for _, c := range s.calls {
			if c == "delete" {
				t.Fatal("DELETE was issued without a successful ownership read")
			}
		}
	})
}

// A sweep that enumerated zones only would silently miss every regional disk and
// report the account as clean.
func TestDiscoverPDFindsBothScopes(t *testing.T) {
	s := &pdServer{getStatus: 200, getBody: `{"items":{
"zones/europe-west1-b":{"disks":[{"name":"zonal-one"}]},
"regions/europe-west1":{"disks":[{"name":"regional-one"}]},
"zones/us-central1-a":{"disks":[{"name":"elsewhere"}]}}}`}
	d, done := pdDriver(t, s)
	defer done()

	got, _, err := d.discoverPD("europe-west1")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	ids := map[string]bool{}
	for _, g := range got {
		ids[g.ProviderID] = true
		if g.ResourceType != "capability.storage.block" {
			t.Errorf("resourceType = %q", g.ResourceType)
		}
	}
	if !ids["pd:acme-prod:europe-west1-b:zonal-one"] {
		t.Errorf("the zonal disk was not discovered: %v", ids)
	}
	if !ids["pd:acme-prod:europe-west1:regional-one"] {
		t.Errorf("the REGIONAL disk was not discovered: %v", ids)
	}
	if ids["pd:acme-prod:us-central1-a:elsewhere"] {
		t.Errorf("a disk from another region was discovered: %v", ids)
	}
}

func TestSplitPDProviderID(t *testing.T) {
	for _, tc := range []struct {
		pid, scope string
		regional   bool
	}{
		{"pd:acme-prod:europe-west1-b:orders", "europe-west1-b", false},
		{"pd:acme-prod:europe-west1:orders", "europe-west1", true},
	} {
		_, scope, _, err := splitPDProviderID(tc.pid)
		if err != nil {
			t.Fatalf("%s: %v", tc.pid, err)
		}
		if scope != tc.scope {
			t.Errorf("%s: scope = %q", tc.pid, scope)
		}
		if pdScopeIsRegional(scope) != tc.regional {
			t.Errorf("%s: regional = %v, want %v", tc.pid, !tc.regional, tc.regional)
		}
	}
	for _, bad := range []string{
		"gce:acme-prod:europe-west1-b:orders", // another service's id
		"pd:acme-prod:not a scope:orders",
		"pd:acme-prod:europe-west1-b:../../etc/passwd", // a path, not a name
		"pd:acme-prod:europe-west1-b",                  // truncated
		"pd::europe-west1-b:orders",                    // no project
	} {
		if _, _, _, err := splitPDProviderID(bad); err == nil {
			t.Errorf("%q was accepted as a persistent-disk providerId", bad)
		}
	}
}
