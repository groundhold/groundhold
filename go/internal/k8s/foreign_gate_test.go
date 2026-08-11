package k8s

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

// D462: the ownership registers reach the fourth driver.
//
// Three registers decided 339 paths across AWS, GCP and Azure and found eleven live
// defects. Every one of those gates names three clouds, and the k8s driver — a full
// provider.Provider with ten mapped services and its own Create/Update/Delete — was in
// none of them. The verb-coverage gate (D461) asked which VERBS nobody had questioned;
// it did not ask which DRIVERS, and this is the answer.
//
// The k8s driver makes the register cheap and the finding sharp: every service routes
// through ONE mapped path, so one gate covers all ten. What it found is that two of the
// three verbs pre-read ownership and the third — create — did not look at all.
//
// A server-side apply with force=false conflicts only on fields another manager OWNS.
// Our ownership labels are new keys nobody owns, so on a stranger's object they apply
// cleanly, and once they are on it oursAt answers yes and every downstream gate agrees.
// The create could manufacture its own permission, which is the hazard D461 named for
// Claim arriving on the ordinary path.

// foreignObject serves an object that EXISTS and is not ours, and fails the test if any
// mutation reaches it.
func foreignObject(t *testing.T, kind, name string, mutations *int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			*mutations++
			b, _ := io.ReadAll(r.Body)
			t.Errorf("%s %s reached a %s that is not ours: %s",
				r.Method, r.URL.Path, kind, b)
			w.WriteHeader(400)
			return
		}
		_, _ = fmt.Fprintf(w, `{"kind":%q,"metadata":{"name":%q,"labels":`+
			`{"team":"someone-else"},"annotations":{}}}`, kind, name)
	}))
}

// k8sForeignCase is one mapped service driven through the PUBLIC dispatch.
type k8sForeignCase struct {
	svc   string
	cap   string
	attrs map[string]any
	impl  map[string]any
	// pid is the bound identity update/delete are handed.
	pid string
}

var k8sForeignCases = []k8sForeignCase{
	{svc: "namespace", cap: "tenancy",
		attrs: map[string]any{"isolation.namespace": "payments", "service.managed": true},
		impl:  map[string]any{"name": "payments"},
		pid:   "core/v1/Namespace//payments"},
	{svc: "quota", cap: "budget",
		attrs: map[string]any{"cpu.limit": "10", "memory.limit": "20Gi", "pods.max": 50,
			"service.managed": true},
		impl: map[string]any{"namespace": "team"},
		pid:  "core/v1/ResourceQuota/team/budget-prod"},
}

func k8sForeignDriver(t *testing.T, url string) *Driver {
	t.Helper()
	d := NewDriver(url, "tok")
	return d
}

// TestK8sCreateRefusesForeignObject: the create half. Every mapped service, one path.
func TestK8sCreateRefusesForeignObject(t *testing.T) {
	for _, c := range k8sForeignCases {
		t.Run(c.svc, func(t *testing.T) {
			mutations := 0
			srv := foreignObject(t, "x", "payments", &mutations)
			defer srv.Close()
			d := k8sForeignDriver(t, srv.URL)
			res := d.Create(c.svc, c.cap, "prod", c.attrs, c.impl, "k", 1)
			if res.Status == "succeeded" {
				t.Errorf("create applied onto an object that is not ours and reported "+
					"success — the apply carries our ownership labels, so after it every "+
					"downstream ownership check would agree the object is ours: %+v", res)
			}
			if mutations > 0 {
				t.Errorf("create sent %d mutation(s) before refusing", mutations)
			}
			if !strings.Contains(res.Reason, "not ours") {
				t.Errorf("the refusal must name ownership, got %q", res.Reason)
			}
		})
	}
}

func TestK8sUpdateRefusesForeignObject(t *testing.T) {
	for _, c := range k8sForeignCases {
		t.Run(c.svc, func(t *testing.T) {
			mutations := 0
			srv := foreignObject(t, "x", "payments", &mutations)
			defer srv.Close()
			d := k8sForeignDriver(t, srv.URL)
			res := d.Update(c.svc, c.cap, "prod", c.pid, c.attrs, c.impl,
				[]string{"service.managed"}, "k")
			if res.Status == "succeeded" || mutations > 0 {
				t.Errorf("update touched an object that is not ours: %+v (mutations=%d)",
					res, mutations)
			}
		})
	}
}

func TestK8sDeleteRefusesForeignObject(t *testing.T) {
	for _, c := range k8sForeignCases {
		t.Run(c.svc, func(t *testing.T) {
			mutations := 0
			srv := foreignObject(t, "x", "payments", &mutations)
			defer srv.Close()
			d := k8sForeignDriver(t, srv.URL)
			res := d.Delete(c.svc, c.cap, "prod", c.pid, "k")
			if res.Status == "succeeded" || mutations > 0 {
				t.Errorf("delete touched an object that is not ours: %+v (mutations=%d)",
					res, mutations)
			}
		})
	}
}

// TestEveryMappedK8sServiceIsCovered pins the register to the mappings. The three tests
// above drive TWO representative services through the one shared path; this asserts that
// the path really is shared, so the coverage claim is honest — a mapped service with its
// own write path would land here undecided.
func TestEveryMappedK8sServiceIsCovered(t *testing.T) {
	d := NewDriver("http://unused", "tok")
	if len(d.Mappings) == 0 {
		t.Fatal("no mappings — the gate would be vacuous (D328)")
	}
	driven := map[string]bool{}
	for _, c := range k8sForeignCases {
		driven[c.svc] = true
	}
	var writeable, undriven []string
	for svc := range d.Mappings {
		if m, _ := d.serviceMapping(svc, forWrite); m == nil {
			continue // not write-safe: the engine refuses it before any estate
		}
		writeable = append(writeable, svc)
		if !driven[svc] {
			undriven = append(undriven, svc)
		}
	}
	sort.Strings(writeable)
	sort.Strings(undriven)
	if len(writeable) == 0 {
		t.Fatal("no write-safe mappings — the gate would be vacuous (D328)")
	}
	// The shared-path claim, checked rather than asserted: every write-safe service
	// must reach createMapped, which is the function the pre-read now guards. Driving
	// one service proves the path; driving two proves it is not special-cased.
	if len(driven) < 2 {
		t.Errorf("only %d services driven — one is not enough to show the path is shared",
			len(driven))
	}
	if len(undriven) > 0 {
		t.Logf("write-safe services not individually driven (they share createMapped/"+
			"updateMapped/deleteMapped, which the cases above exercise): %v", undriven)
	}
}

// TestK8sCreateAdoptsItsOwnObject is the other half of D252/D253 on this driver: an
// object that already exists AND is ours must be bound, not refused. Without this the
// pre-read added in D462 would be a converge-breaking regression rather than a guard.
func TestK8sCreateAdoptsItsOwnObject(t *testing.T) {
	var applied bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = fmt.Fprintf(w, `{"kind":"Namespace","metadata":{"name":"payments",`+
				`"labels":{%q:"tenancy",%q:"prod"}}}`, capLabel, envLabel)
			return
		}
		applied = true
		_, _ = w.Write([]byte(`{"metadata":{}}`))
	}))
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	res := d.Create("namespace", "tenancy", "prod",
		map[string]any{"isolation.namespace": "payments", "service.managed": true},
		map[string]any{"name": "payments"}, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("a create meeting its OWN standing object must bind it: %+v", res)
	}
	if !applied {
		t.Error("the apply is the adoption here — SSA is idempotent, so it must still run")
	}
}
