package k8s

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// roleStore is a tiny stateful fake API server for the write path: it holds one
// Role and serves GET / apply-PATCH / merge-PATCH / DELETE so the driver's
// server-side apply, claim label stamp, ownership guard and delete are exercised
// end to end without a cluster.
type roleStore struct {
	ns, name string
	present  bool
	labels   map[string]string
	rules    []any
	lastMgr  string
}

func (s *roleStore) server(t *testing.T) *httptest.Server {
	t.Helper()
	base := "/apis/rbac.authorization.k8s.io/v1/namespaces/" + s.ns + "/roles/" + s.name
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, base) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		switch r.Method {
		case "GET":
			if !s.present {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"name": s.name, "namespace": s.ns, "labels": s.labels},
				"rules":    s.rules,
			})
		case "PATCH":
			body, _ := io.ReadAll(r.Body)
			var doc map[string]any
			_ = json.Unmarshal(body, &doc)
			ct := r.Header.Get("Content-Type")
			meta, _ := doc["metadata"].(map[string]any)
			if lbls, ok := meta["labels"].(map[string]any); ok {
				if s.labels == nil {
					s.labels = map[string]string{}
				}
				for k, v := range lbls {
					s.labels[k] = v.(string)
				}
			}
			if ct == "application/apply-patch+yaml" {
				s.lastMgr = r.URL.Query().Get("fieldManager")
				if rules, ok := doc["rules"].([]any); ok {
					s.rules = rules
				}
			}
			s.present = true
			_ = json.NewEncoder(w).Encode(map[string]any{"metadata": meta})
		case "DELETE":
			if !s.present {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			s.present = false
			w.WriteHeader(http.StatusOK)
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	}))
}

func TestBuildRoleRulesRoundTrip(t *testing.T) {
	perms := []string{"apps/deployments:create", "apps/deployments:get", "core/pods:get"}
	rules, err := buildRoleRules(perms)
	if err != nil {
		t.Fatal(err)
	}
	// flatten the built rules back and expect the same set
	rr := make([]rbacRule, len(rules))
	for i, r := range rules {
		b, _ := json.Marshal(r)
		_ = json.Unmarshal(b, &rr[i])
	}
	got, _ := flattenRules(rr)
	if !reflect.DeepEqual(got, perms) {
		t.Fatalf("round-trip: got %v, want %v", got, perms)
	}
}

func TestCreateRoleAppliesWithOwnershipAndManager(t *testing.T) {
	s := &roleStore{ns: "default", name: "deploy-role-prod"}
	srv := s.server(t)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	attrs := map[string]any{"role.permissions": []any{"apps/deployments:get"}, "service.managed": true}
	res := d.Create("rbac-role", "deploy-role", "prod", attrs, nil, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if s.lastMgr != "groundhold" {
		t.Fatalf("server-side apply must use fieldManager=groundhold, got %q", s.lastMgr)
	}
	if s.labels[capLabel] != "deploy-role" {
		t.Fatalf("ownership label not stamped: %v", s.labels)
	}
}

func TestClaimStampsOwnershipThenUpdateSucceeds(t *testing.T) {
	// a Role created by "terraform" — no groundhold labels
	s := &roleStore{ns: "payments", name: "billing", present: true,
		labels: map[string]string{"app.kubernetes.io/managed-by": "terraform"},
		rules:  []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"pods"}, "verbs": []any{"get"}}}}
	srv := s.server(t)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	pid := rbacProviderID("rbac.authorization.k8s.io", "v1", "Role", "payments", "billing")

	// before claim, update must refuse — not ours
	upd := d.Update("rbac-role", "billing", "prod", pid,
		map[string]any{"role.permissions": []any{"core/pods:get"}, "service.managed": true}, nil, nil, "k")
	if upd.Status != "failed" || !strings.Contains(upd.Reason, "not ours") {
		t.Fatalf("update before claim must refuse not-ours, got %+v", upd)
	}

	// claim stamps ownership
	cl := d.Claim("rbac-role", "billing", "prod", pid)
	if cl.Status != "succeeded" {
		t.Fatalf("claim: %+v", cl)
	}
	if s.labels[capLabel] != "billing" {
		t.Fatalf("claim must add ownership label, got %v", s.labels)
	}

	// now update succeeds
	upd = d.Update("rbac-role", "billing", "prod", pid,
		map[string]any{"role.permissions": []any{"core/pods:get", "core/pods:list"}, "service.managed": true}, nil, nil, "k")
	if upd.Status != "succeeded" {
		t.Fatalf("update after claim: %+v", upd)
	}
}

func TestDeleteRefusesNotOurs(t *testing.T) {
	s := &roleStore{ns: "ns", name: "foreign", present: true,
		labels: map[string]string{"app.kubernetes.io/managed-by": "helm"}}
	srv := s.server(t)
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	pid := rbacProviderID("rbac.authorization.k8s.io", "v1", "Role", "ns", "foreign")
	res := d.Delete("rbac-role", "foreign", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("delete of a foreign role must refuse, got %+v", res)
	}
	if !s.present {
		t.Fatal("the foreign role must NOT have been deleted")
	}
}

func TestValidateRefusesUnmappableAttribute(t *testing.T) {
	d := NewDriver("http://unused", "tok")
	err := d.Validate("rbac-role", "r", "prod",
		map[string]any{"role.permissions": []any{"core/pods:get"}, "bogus.attr": 1}, nil, 1)
	if err == nil || !strings.Contains(err.Error(), "no k8s RBAC Role mapping") {
		t.Fatalf("validate must refuse an unmappable attribute, got %v", err)
	}
}
