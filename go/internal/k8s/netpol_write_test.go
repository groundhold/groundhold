package k8s

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// netpolStore: a stateful fake serving one NetworkPolicy (GET/apply-PATCH/merge-PATCH/DELETE).
type netpolStore struct {
	ns, name string
	present  bool
	labels   map[string]string
}

func (s *netpolStore) server(t *testing.T) *httptest.Server {
	t.Helper()
	base := netpolPath(s.ns, s.name)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, base) {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			if !s.present {
				http.Error(w, "nf", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"name": s.name, "namespace": s.ns, "labels": s.labels},
				"spec":     map[string]any{"policyTypes": []any{"Ingress"}, "ingress": []any{}},
			})
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			var doc map[string]any
			_ = json.Unmarshal(b, &doc)
			if m, ok := doc["metadata"].(map[string]any); ok {
				if l, ok := m["labels"].(map[string]any); ok {
					if s.labels == nil {
						s.labels = map[string]string{}
					}
					for k, v := range l {
						s.labels[k] = v.(string)
					}
				}
			}
			s.present = true
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}})
		case "DELETE":
			s.present = false
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "m", http.StatusMethodNotAllowed)
		}
	}))
}

func TestNetpolClaimThenUpdateThenForeignDelete(t *testing.T) {
	// a NetworkPolicy authored by terraform — no groundhold labels
	s := &netpolStore{ns: "payments", name: "default-deny", present: true,
		labels: map[string]string{"app.kubernetes.io/managed-by": "terraform"}}
	srv := s.server(t)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	pid := netpolProviderID("payments", "default-deny")

	// update before claim -> refuse not-ours
	up := d.Update("netpol", "np", "prod", pid, map[string]any{"ingress.public": false, "service.managed": true}, nil, nil, "k")
	if up.Status != "failed" || !strings.Contains(up.Reason, "not ours") {
		t.Fatalf("update before claim must refuse, got %+v", up)
	}
	// claim stamps ownership
	if cl := d.Claim("netpol", "np", "prod", pid); cl.Status != "succeeded" {
		t.Fatalf("claim: %+v", cl)
	}
	if s.labels[capLabel] != "np" {
		t.Fatalf("claim must stamp ownership label, got %v", s.labels)
	}
	// now update succeeds
	if up := d.Update("netpol", "np", "prod", pid, map[string]any{"ingress.public": false, "egress.restricted": true, "service.managed": true}, nil, nil, "k"); up.Status != "succeeded" {
		t.Fatalf("update after claim: %+v", up)
	}

	// a foreign policy must not be deletable
	f := &netpolStore{ns: "ns", name: "foreign", present: true, labels: map[string]string{"app.kubernetes.io/managed-by": "helm"}}
	fsrv := f.server(t)
	defer fsrv.Close()
	fd := NewDriver(fsrv.URL, "tok")
	if del := fd.Delete("netpol", "np", "prod", netpolProviderID("ns", "foreign"), "k"); del.Status != "failed" || !strings.Contains(del.Reason, "not ours") {
		t.Fatalf("delete of a foreign netpol must refuse, got %+v", del)
	}
	if !f.present {
		t.Fatal("foreign netpol must not have been deleted")
	}
}

func TestCreateNetpolStampsOwnership(t *testing.T) {
	s := &netpolStore{ns: "default", name: "deny-prod"}
	srv := s.server(t)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	res := d.Create("netpol", "deny", "prod", map[string]any{"ingress.public": false, "service.managed": true}, map[string]any{"namespace": "default"}, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if s.labels[capLabel] != "deny" {
		t.Fatalf("create must stamp ownership, got %v", s.labels)
	}
}
