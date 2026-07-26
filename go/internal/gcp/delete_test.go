package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const delPID = "acme-prod:europe-west1:orders-db"

// deleteServer routes the pre-delete GET (returning instanceJSON), the DELETE
// (returning an operation), and the operation poll (DONE).
func deleteServer(t *testing.T, instanceStatus int, instanceJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"status":"DONE"}`))
			case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/instances/orders-db"):
				w.WriteHeader(instanceStatus)
				_, _ = w.Write([]byte(instanceJSON))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"op-del-1"}`))
			default:
				w.WriteHeader(http.StatusInternalServerError)
			}
		}))
}

const ownedUnprotected = `{"name":"orders-db","settings":{` +
	`"userLabels":{"groundhold-capability":"db","groundhold-environment":"prod"},` +
	`"deletionProtectionEnabled":false}}`

func TestDeleteSucceeds(t *testing.T) {
	srv := deleteServer(t, http.StatusOK, ownedUnprotected)
	defer srv.Close()
	d := testDriver(t, srv)
	res := d.Delete("cloudsql", "db", "prod", delPID, "idem-1")
	if res.Status != "succeeded" || res.ProviderID != delPID {
		t.Fatalf("got %+v, want succeeded/%s", res, delPID)
	}
}

func TestDeleteRefusesProtected(t *testing.T) {
	inst := `{"name":"orders-db","settings":{` +
		`"userLabels":{"groundhold-capability":"db","groundhold-environment":"prod"},` +
		`"deletionProtectionEnabled":true}}`
	srv := deleteServer(t, http.StatusOK, inst)
	defer srv.Close()
	d := testDriver(t, srv)
	res := d.Delete("cloudsql", "db", "prod", delPID, "idem-1")
	if res.Status != "failed" || !strings.Contains(res.Reason, "deletion protection") {
		t.Fatalf("got %+v, want failed on deletion protection", res)
	}
}

func TestDeleteRefusesNotOurs(t *testing.T) {
	inst := `{"name":"orders-db","settings":{` +
		`"userLabels":{"groundhold-capability":"other","groundhold-environment":"prod"}}}`
	srv := deleteServer(t, http.StatusOK, inst)
	defer srv.Close()
	d := testDriver(t, srv)
	res := d.Delete("cloudsql", "db", "prod", delPID, "idem-1")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("got %+v, want failed on ownership", res)
	}
}

func TestDeleteIsIdempotentOn404(t *testing.T) {
	srv := deleteServer(t, http.StatusNotFound, `{}`)
	defer srv.Close()
	d := testDriver(t, srv)
	res := d.Delete("cloudsql", "db", "prod", delPID, "idem-1")
	if res.Status != "succeeded" {
		t.Fatalf("got %+v, want succeeded (deleting is idempotent on absence)", res)
	}
}

func TestDeleteRejectsMalformedProviderID(t *testing.T) {
	srv := deleteServer(t, http.StatusOK, ownedUnprotected)
	defer srv.Close()
	d := testDriver(t, srv)
	// a component with a path separator must never reach a REST path
	res := d.Delete("cloudsql", "db", "prod", "acme-prod:europe-west1:../evil", "idem-1")
	if res.Status != "failed" {
		t.Fatalf("got %+v, want failed on invalid providerId component", res)
	}
}
