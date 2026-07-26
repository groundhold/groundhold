package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// gceServer answers the four calls this driver makes, routed by method+path so a
// test states what the API does rather than how the driver phrases the question.
type gceServer struct {
	insertStatus int
	insertBody   string
	getStatus    int
	getBody      string
	opBody       string
	deleteStatus int
	deleteBody   string
	calls        []string
}

func (s *gceServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case strings.Contains(p, "/operations/"):
			s.calls = append(s.calls, "operation")
			_, _ = w.Write([]byte(s.opBody))
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/instances"):
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

func gceDriver(t *testing.T, s *gceServer) (*Driver, func()) {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	srv := httptest.NewServer(s.handler())
	d := NewDriver("acme-prod")
	d.ComputeBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 50 * time.Millisecond
	return d, srv.Close
}

const gceOpDone = `{"name":"op-1","status":"DONE"}`

// ownedInstance is a machine carrying OUR labels.
const ownedInstance = `{"name":"web-production-abc12345","status":"RUNNING",
"labels":{"groundhold-capability":"web","groundhold-environment":"production"},
"networkInterfaces":[{}],
"disks":[{"boot":true}]}`

func TestCreateGCEInstanceHappyPath(t *testing.T) {
	s := &gceServer{insertStatus: 200, insertBody: `{"name":"op-1"}`, opBody: gceOpDone}
	d, done := gceDriver(t, s)
	defer done()

	res := d.createGCEInstance("web", "production", gceAttrs(), gceImpl(), 0)
	if res.Status != "succeeded" {
		t.Fatalf("status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if !strings.HasPrefix(res.ProviderID, "gce:acme-prod:europe-west1-b:") {
		t.Errorf("providerId = %q", res.ProviderID)
	}
}

// The deterministic name is GCP's idempotency mechanism, so a 409 is a
// CONTINUATION — but only when the labels say the machine is ours.
func TestCreateGCEInstanceNameConflict(t *testing.T) {
	t.Run("our own machine continues idempotently", func(t *testing.T) {
		s := &gceServer{insertStatus: 409, insertBody: `{}`, getStatus: 200, getBody: ownedInstance}
		d, done := gceDriver(t, s)
		defer done()
		res := d.createGCEInstance("web", "production", gceAttrs(), gceImpl(), 0)
		if res.Status != "succeeded" {
			t.Errorf("status = %q (%s), want succeeded — the name is ours", res.Status, res.Reason)
		}
	})

	t.Run("a stranger's machine is refused, never bound", func(t *testing.T) {
		foreign := strings.Replace(ownedInstance, `"groundhold-capability":"web"`, `"groundhold-capability":"someone-else"`, 1)
		s := &gceServer{insertStatus: 409, insertBody: `{}`, getStatus: 200, getBody: foreign}
		d, done := gceDriver(t, s)
		defer done()
		res := d.createGCEInstance("web", "production", gceAttrs(), gceImpl(), 0)
		if res.Status != "failed" || !strings.Contains(res.Reason, "refusing to bind") {
			t.Errorf("status = %q (%s), want a refusal — binding it would put a stranger's server under our contract",
				res.Status, res.Reason)
		}
	})

	t.Run("an unreadable conflict is unknown, never a bind", func(t *testing.T) {
		s := &gceServer{insertStatus: 409, insertBody: `{}`, getStatus: 500, getBody: `{}`}
		d, done := gceDriver(t, s)
		defer done()
		res := d.createGCEInstance("web", "production", gceAttrs(), gceImpl(), 0)
		if res.Status != "unknown" {
			t.Errorf("status = %q, want unknown — we do not bind what we could not read", res.Status)
		}
	})
}

func TestCreateGCEInstanceMutationHonesty(t *testing.T) {
	t.Run("5xx is unknown", func(t *testing.T) {
		s := &gceServer{insertStatus: 503, insertBody: `{}`}
		d, done := gceDriver(t, s)
		defer done()
		res := d.createGCEInstance("web", "production", gceAttrs(), gceImpl(), 0)
		if res.Status != "unknown" {
			t.Errorf("status = %q, want unknown — a 503 can front a machine that started", res.Status)
		}
	})

	t.Run("2xx with no operation is unknown", func(t *testing.T) {
		s := &gceServer{insertStatus: 200, insertBody: `{}`}
		d, done := gceDriver(t, s)
		defer done()
		res := d.createGCEInstance("web", "production", gceAttrs(), gceImpl(), 0)
		if res.Status != "unknown" {
			t.Errorf("status = %q, want unknown — an insert with no operation is not a success", res.Status)
		}
	})

	t.Run("an operation DONE with an error is failed", func(t *testing.T) {
		s := &gceServer{insertStatus: 200, insertBody: `{"name":"op-1"}`,
			opBody: `{"name":"op-1","status":"DONE","error":{"errors":[{"code":"QUOTA_EXCEEDED"}]}}`}
		d, done := gceDriver(t, s)
		defer done()
		res := d.createGCEInstance("web", "production", gceAttrs(), gceImpl(), 0)
		if res.Status != "failed" || !strings.Contains(res.Reason, "QUOTA_EXCEEDED") {
			t.Errorf("status = %q (%s), want failed naming the cause", res.Status, res.Reason)
		}
	})
}

func TestObserveGCEInstance(t *testing.T) {
	t.Run("a private instance with a customer key", func(t *testing.T) {
		doc := `{"name":"n","status":"RUNNING","labels":{},"networkInterfaces":[{}],
"disks":[{"boot":true,"diskEncryptionKey":{"kmsKeyName":"projects/p/locations/l/keyRings/r/cryptoKeys/k"}}]}`
		s := &gceServer{getStatus: 200, getBody: doc}
		d, done := gceDriver(t, s)
		defer done()

		obs, _, err := d.observeGCEInstance("web", "gce:acme-prod:europe-west1-b:web-abc12345")
		if err != nil {
			t.Fatalf("observe: %v", err)
		}
		got := map[string]any{}
		for _, o := range obs {
			got[o.Path] = o.Value
		}
		for path, want := range map[string]any{
			"location.region":                "europe-west1",
			"availability.class":             "zonal",
			"network.publicExposure":         false,
			"encryption.atRest":              true,
			"encryption.customerManagedKeys": true,
			"service.managed":                true,
		} {
			if got[path] != want {
				t.Errorf("%s = %v, want %v", path, got[path], want)
			}
		}
	})

	// Public exposure is the PRESENCE of an accessConfig, so the reverse mapping
	// must read presence rather than a field that does not exist.
	t.Run("an accessConfig makes it public", func(t *testing.T) {
		doc := `{"name":"n","status":"RUNNING","labels":{},
"networkInterfaces":[{"accessConfigs":[{"natIP":"34.1.2.3"}]}],"disks":[{"boot":true}]}`
		s := &gceServer{getStatus: 200, getBody: doc}
		d, done := gceDriver(t, s)
		defer done()
		obs, _, err := d.observeGCEInstance("web", "gce:acme-prod:europe-west1-b:web-abc12345")
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range obs {
			if o.Path == "network.publicExposure" && o.Value != true {
				t.Error("an instance with an external address was reported as private")
			}
			// Google-managed encryption is NOT a customer-managed key.
			if o.Path == "encryption.customerManagedKeys" && o.Value != false {
				t.Error("platform-managed disk encryption was reported as a customer key — " +
					"that certifies a revocable-key control the customer does not have")
			}
		}
	})
}

func TestDeleteGCEInstance(t *testing.T) {
	pid := "gce:acme-prod:europe-west1-b:web-abc12345"

	t.Run("deletes our own machine", func(t *testing.T) {
		s := &gceServer{getStatus: 200, getBody: ownedInstance, deleteStatus: 200,
			deleteBody: `{"name":"op-1"}`, opBody: gceOpDone}
		d, done := gceDriver(t, s)
		defer done()
		res := d.deleteGCEInstance("web", "production", pid)
		if res.Status != "succeeded" {
			t.Errorf("status = %q (%s), want succeeded", res.Status, res.Reason)
		}
	})

	t.Run("refuses a machine that is not ours", func(t *testing.T) {
		foreign := strings.Replace(ownedInstance, `"groundhold-capability":"web"`, `"groundhold-capability":"someone-else"`, 1)
		s := &gceServer{getStatus: 200, getBody: foreign}
		d, done := gceDriver(t, s)
		defer done()
		res := d.deleteGCEInstance("web", "production", pid)
		if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
			t.Errorf("status = %q (%s), want a refusal", res.Status, res.Reason)
		}
		for _, c := range s.calls {
			if c == "delete" {
				t.Fatal("a foreign machine was deleted — the label check is the only thing between us and someone else's production")
			}
		}
	})

	t.Run("an already-gone machine is idempotently succeeded", func(t *testing.T) {
		s := &gceServer{getStatus: 404, getBody: `{}`}
		d, done := gceDriver(t, s)
		defer done()
		res := d.deleteGCEInstance("web", "production", pid)
		if res.Status != "succeeded" {
			t.Errorf("status = %q, want succeeded (delete is idempotent)", res.Status)
		}
	})

	t.Run("an unreadable pre-delete state is unknown, never a delete", func(t *testing.T) {
		s := &gceServer{getStatus: 500, getBody: `{}`}
		d, done := gceDriver(t, s)
		defer done()
		res := d.deleteGCEInstance("web", "production", pid)
		if res.Status != "unknown" {
			t.Errorf("status = %q, want unknown", res.Status)
		}
		for _, c := range s.calls {
			if c == "delete" {
				t.Fatal("deleted a machine whose ownership was never established")
			}
		}
	})
}

func TestSplitGCEProviderID(t *testing.T) {
	for _, bad := range []string{
		"gce:acme-prod:europe-west1:web",   // a region, not a zone
		"gce:acme-prod:europe-west1-b",     // too few parts
		"gar:acme-prod:europe-west1-b:web", // wrong prefix
		"gce:X:europe-west1-b:web",         // invalid project
	} {
		if _, _, _, err := splitGCEProviderID(bad); err == nil {
			t.Errorf("%q was accepted as a provider id", bad)
		}
	}
	project, zone, name, err := splitGCEProviderID("gce:acme-prod:europe-west1-b:web-abc12345")
	if err != nil || project != "acme-prod" || zone != "europe-west1-b" || name != "web-abc12345" {
		t.Errorf("round trip failed: %q %q %q %v", project, zone, name, err)
	}
}

// Layer 5 (D87): the adversarial honesty harness injects transport faults, 5xx,
// truncated bodies and mid-flight failures into every mutating call, and asserts
// the driver never reports a verdict stronger than the evidence.
//
// The deterministic name means the pid is knowable even when the insert's outcome
// is not — so an unknown create still carries something reconcilable, which is
// exactly what stops a lost machine from becoming an unbilled mystery.
func TestHonestyHarnessGCEInstance(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := gceProviderID("acme-prod", "europe-west1-b", resourceName("acme-prod", "production", "web", 0, 63))
	happy := func() *httptest.Server {
		s := &gceServer{
			insertStatus: 200, insertBody: `{"name":"op-1"}`, opBody: gceOpDone,
			getStatus: 200, getBody: ownedInstance,
			deleteStatus: 200, deleteBody: `{"name":"op-1"}`,
		}
		return httptest.NewServer(s.handler())
	}
	p := &certifynet.Probe{
		AssertTransient: true,      // D237: create/delete route through mutationResult
		Name:            "gcp/gce", // LRO create/delete parse the operation name
		Classify:        gcpOpRole,
		OwnerTagValue:   "web",
		DeterministicID: true, // the instance name is a chosen slug+hash (D43)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: happy,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("gce", "web", "production", gceAttrs(), gceImpl(), "k", 0)
				},
			},
			{
				Name:  "delete",
				Happy: happy,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("gce", "web", "production", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}
