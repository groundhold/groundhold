package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// captureServer records the last PATCH (apply) body sent to it.
func captureServer(t *testing.T, path string, last *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, path) {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		if r.Method == "GET" {
			// A create's estate: the object is ABSENT. The fixture used to answer
			// 200-with-an-empty-metadata to every method, which modelled a server on
			// which nothing distinguishes "creating" from "applying onto whatever is
			// already there" — and the create path never looked, so nothing noticed
			// (D462).
			http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
			return
		}
		if r.Method == "PATCH" {
			b, _ := io.ReadAll(r.Body)
			*last = b
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"metadata":{}}`))
	}))
}

// quota's create body, now the sole (generic) path — pinned against the exact
// expected apply object (was a differential vs the deleted hand-coded twin).
func TestGenericCreateQuotaBody(t *testing.T) {
	attrs := map[string]any{"cpu.limit": "10", "memory.limit": "20Gi", "pods.max": 50, "service.managed": true}
	impl := map[string]any{"namespace": "team"}
	path := corePathNS("resourcequotas", "team", "budget-prod")

	var body []byte
	gs := captureServer(t, path, &body)
	defer gs.Close()
	gd := NewDriver(gs.URL, "tok")
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	if res := gd.createMapped(m, "budget", "prod", attrs, impl); res.Status != "succeeded" {
		t.Fatalf("generic create: %+v", res)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("apply body not JSON: %v (%s)", err, body)
	}
	want := map[string]any{
		"apiVersion": "v1", "kind": "ResourceQuota",
		"metadata": map[string]any{"name": "budget-prod", "namespace": "team",
			"labels": map[string]any{capLabel: "budget", envLabel: "prod"}},
		"spec": map[string]any{"hard": map[string]any{"limits.cpu": "10", "limits.memory": "20Gi", "pods": "50"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("apply body =\n %#v\n want\n %#v", got, want)
	}
}

func TestBuildMappedObjectConstContradictionRefuses(t *testing.T) {
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	// service.managed is a const=true; declaring false must refuse
	if err := m.validateMapped(map[string]any{"cpu.limit": "10", "service.managed": false}, nil); err == nil {
		t.Fatal("a const contradiction must refuse")
	}
	if err := m.validateMapped(map[string]any{"cpu.limit": "10", "service.managed": true}, nil); err != nil {
		t.Fatalf("a consistent candidate must validate, got %v", err)
	}
}

func TestGenericUpdateGuardsOwnership(t *testing.T) {
	body := map[string]any{"metadata": map[string]any{"name": "budget", "namespace": "team"}, "spec": map[string]any{"hard": map[string]any{}}}
	lbls := map[string]string{"app.kubernetes.io/managed-by": "terraform"} // not ours
	srv := coreServer(t, corePathNS("resourcequotas", "team", "budget"), body, &lbls)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	pid := m.providerID("team", "budget")
	res := d.updateMapped(m, "budget", "prod", pid, map[string]any{"cpu.limit": "20", "service.managed": true}, nil)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("update of an unclaimed object must refuse, got %+v", res)
	}
}

func TestGenericCreateRefusesOnDrift(t *testing.T) {
	path := corePathNS("resourcequotas", "team", "budget-prod")
	var body []byte
	srv := captureServer(t, path, &body)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	bad := loadQuotaSchemas(t)
	bad["io.k8s.apimachinery.pkg.api.resource.Quantity"].(map[string]any)["type"] = "integer"
	d.SchemaFetch = func(g, v string) (map[string]any, error) { return bad, nil }
	m := loadRealMapping(t, "k8s.resourcequota.yaml")
	res := d.createMapped(m, "budget", "prod", map[string]any{"cpu.limit": "10", "service.managed": true}, map[string]any{"namespace": "team"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "mapping-schema-drift") {
		t.Fatalf("create under drift must refuse, got %+v", res)
	}
	if len(body) != 0 {
		t.Fatal("create under drift must NOT have sent an apply body")
	}
}

// A server-side-apply conflict is the ONE refusal an operator cannot act on
// without the detail: "another manager owns fields" does not say which manager
// or which fields, and "release it first" does not say what to release. The API
// server hands both over in the Status message — this body is recorded verbatim
// from a real cluster, where `kubectl label` had taken the enforce label and the
// next converge could no longer correct the drift (D509). Every other branch of
// this helper already passes the body through mutDetail; this one dropped it,
// and no test covered it. It is the shared helper for all ten mapped services.
func TestApplyConflictKeepsTheServersDiagnosis(t *testing.T) {
	body := []byte(`{"kind":"Status","apiVersion":"v1","status":"Failure",` +
		`"message":"Apply failed with 1 conflict: conflict with \"kubectl-label\" using v1: ` +
		`.metadata.labels.pod-security.kubernetes.io/enforce","reason":"Conflict","code":409}`)
	res := netpolApplyResult("k8s://namespaces/ns-production", http.StatusConflict, body, nil)

	if res.Status != "failed" {
		t.Fatalf("a conflict must fail closed, got %q", res.Status)
	}
	for _, want := range []string{"kubectl-label", "pod-security.kubernetes.io/enforce"} {
		if !strings.Contains(res.Reason, want) {
			t.Errorf("the refusal drops %q — the operator is told to release a field "+
				"without being told which manager holds it or which field it is.\n  reason: %s",
				want, res.Reason)
		}
	}
}

// D699: a field-ownership conflict, with and without sealed consent.
//
// Both halves matter. Without consent the write must still FAIL — forcing by default
// would let groundhold stomp a live controller, which is the reason server-side apply
// refuses in the first place. With consent it must take the fields AND say whose they
// were: the 409 body is the only record of what was reclaimed, and a reclaim nobody
// can audit is worse than the block it replaces.
func TestFieldConflictIsReclaimedOnlyWithSealedConsent(t *testing.T) {
	const conflict = `{"kind":"Status","status":"Failure","message":"Apply failed with 1 ` +
		`conflict: conflict with \"kubectl-label\" using v1: .metadata.labels.pod-security"}`

	for _, tc := range []struct {
		name       string
		consent    bool
		wantStatus string
		wantForced bool
	}{
		{"no consent: the conflict stands", false, "failed", false},
		{"sealed consent: the fields are taken", true, "succeeded", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var forced []bool
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "PATCH" {
					isForce := r.URL.Query().Get("force") == "true"
					forced = append(forced, isForce)
					if !isForce {
						w.WriteHeader(http.StatusConflict)
						_, _ = w.Write([]byte(conflict))
						return
					}
					_, _ = w.Write([]byte(`{"kind":"Namespace","metadata":{"name":"app"}}`))
					return
				}
				// ownership pre-read: ours
				_, _ = w.Write([]byte(`{"kind":"Namespace","metadata":{"name":"app",` +
					`"labels":{"` + capLabel + `":"ns"}}}`))
			}))
			defer srv.Close()

			d := &Driver{Server: srv.URL, HTTP: srv.Client(), Mappings: embeddedMappings}
			d.SetFieldReclaim(tc.consent)
			m := d.Mappings["namespace"]
			if m == nil {
				t.Skip("no namespace mapping in this tree")
			}
			res := d.updateMapped(m, "ns", "test", m.providerID("", "app"),
				map[string]any{}, map[string]any{"name": "app"})

			if res.Status != tc.wantStatus {
				t.Fatalf("status = %q (%s), want %q", res.Status, res.Reason, tc.wantStatus)
			}
			// The first draft of this fixture carried the wrong ownership label, so the
			// no-consent half refused at the ownership pre-read and never reached the
			// conflict at all — and passed. A refusal for the wrong reason is not the
			// refusal under test.
			if len(forced) == 0 {
				t.Fatal("no apply patch was sent — the run refused before the conflict, " +
					"so this case measured something else entirely")
			}
			if !tc.consent && !strings.Contains(res.Reason, "conflict") {
				t.Errorf("without consent the refusal must be the CONFLICT; reason = %q", res.Reason)
			}
			sawForce := false
			for _, f := range forced {
				sawForce = sawForce || f
			}
			if sawForce != tc.wantForced {
				t.Errorf("force=true sent: %v, want %v (patches: %v)", sawForce, tc.wantForced, forced)
			}
			if tc.consent && !strings.Contains(res.Reason, "kubectl-label") {
				t.Errorf("a reclaim must name the manager it took from; reason = %q", res.Reason)
			}
		})
	}
}

// TestK8sDeletePollsToAbsence pins D986: a k8s DELETE is ACCEPTED (200/202) while the
// object enters Terminating (deletionTimestamp set, finalizers running). deleteMapped
// must poll the object to a confirmed 404 before concluding succeeded — a namespace
// (or a flux/argo CRD) held Terminating by a stuck finalizer is still live, with
// everything inside it running, and tombstoning it as gone is the dangerous direction.
func TestK8sDeletePollsToAbsence(t *testing.T) {
	present := func(w http.ResponseWriter, terminating bool) {
		dts := ""
		if terminating {
			dts = `"deletionTimestamp":"2026-01-01T00:00:00Z",`
		}
		_, _ = fmt.Fprintf(w, `{"metadata":{"name":"payments",%s"labels":{%q:"tenancy"}}}`, dts, capLabel)
	}

	t.Run("confirmed gone is succeeded", func(t *testing.T) {
		deleted := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodDelete:
				deleted = true
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"metadata":{}}`))
			case http.MethodGet:
				if deleted { // the object has finished terminating — gone
					http.Error(w, `{"kind":"Status","code":404}`, http.StatusNotFound)
					return
				}
				present(w, false)
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer srv.Close()
		d := NewDriver(srv.URL, "tok")
		d.PollInterval = time.Millisecond
		d.PollTimeout = 5 * time.Millisecond // if the poll never reads gone, fail fast, don't hang
		if res := d.Delete("namespace", "tenancy", "prod", nsProviderID("payments"), "k"); res.Status != "succeeded" {
			t.Fatalf("a delete confirmed gone must succeed, got %+v", res)
		}
	})

	t.Run("still terminating is unknown", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodDelete:
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"metadata":{}}`))
			case http.MethodGet: // never gone — Terminating with a stuck finalizer
				present(w, true)
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer srv.Close()
		d := NewDriver(srv.URL, "tok")
		d.PollInterval = time.Millisecond
		d.PollTimeout = 5 * time.Millisecond
		res := d.Delete("namespace", "tenancy", "prod", nsProviderID("payments"), "k")
		if res.Status != "unknown" || !strings.Contains(res.Reason, "Terminating") {
			t.Fatalf("an accepted-but-still-Terminating object must be unknown (keep the handle), got %+v", res)
		}
	})
}
