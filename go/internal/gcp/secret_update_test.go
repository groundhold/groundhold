package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ourSecretJSON(capLabel string) string {
	return `{"name":"projects/acme-prod/secrets/pv-dbcreds-abcd1234",` +
		`"labels":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
		`"replication":{"automatic":{}}}`
}

// secretIamServer serves GET secret + IAM get/set, toggling public on setIamPolicy so a
// revoke confirm reads back private. startPublic seeds the initial policy.
func secretIamServer(t *testing.T, capLabel string, startPublic bool, setCalls *int) *httptest.Server {
	t.Helper()
	public := startPublic
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
				if public {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[{"role":"roles/secretmanager.secretAccessor","members":["allUsers"]}]}`))
				} else {
					_, _ = w.Write([]byte(`{"etag":"e1","bindings":[]}`))
				}
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":setIamPolicy"):
				*setCalls++
				// reflect the write: a grant makes it public, a revoke makes it private.
				b := make([]byte, r.ContentLength)
				_, _ = r.Body.Read(b)
				public = strings.Contains(string(b), "allUsers")
				_, _ = w.Write([]byte(`{"etag":"e2"}`))
			case r.Method == "GET":
				_, _ = w.Write([]byte(ourSecretJSON(capLabel)))
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestUpdateSecretGrantExposure(t *testing.T) {
	var setCalls int
	srv := secretIamServer(t, "dbcreds", false, &setCalls)
	defer srv.Close()
	d := secretDriver(t, srv)
	res := d.Update("secretmanager", "dbcreds", "prod", "gsecret:acme-prod:pv-dbcreds-abcd1234",
		map[string]any{"network.publicExposure": true}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "succeeded" {
		t.Fatalf("grant update: %+v", res)
	}
	if setCalls != 1 {
		t.Fatalf("expected one setIamPolicy, got %d", setCalls)
	}
}

func TestUpdateSecretRevokeExposure(t *testing.T) {
	var setCalls int
	srv := secretIamServer(t, "dbcreds", true, &setCalls)
	defer srv.Close()
	d := secretDriver(t, srv)
	res := d.Update("secretmanager", "dbcreds", "prod", "gsecret:acme-prod:pv-dbcreds-abcd1234",
		map[string]any{"network.publicExposure": false}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "succeeded" {
		t.Fatalf("revoke update: %+v", res)
	}
}

func TestUpdateSecretForeignRefused(t *testing.T) {
	var setCalls int
	srv := secretIamServer(t, "someone-else", false, &setCalls)
	defer srv.Close()
	d := secretDriver(t, srv)
	res := d.Update("secretmanager", "dbcreds", "prod", "gsecret:acme-prod:pv-dbcreds-abcd1234",
		map[string]any{"network.publicExposure": true}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign secret must refuse patch, got %+v", res)
	}
	if setCalls != 0 {
		t.Fatalf("no setIamPolicy must be sent for a foreign secret, got %d", setCalls)
	}
}

func TestClassifySecretChange(t *testing.T) {
	d := NewDriver("acme-prod")
	if cls, _ := d.ClassifyChange("secretmanager", "network.publicExposure", true, false, nil); cls != "mutable" {
		t.Fatalf("publicExposure must be mutable, got %q", cls)
	}
	// the honest per-cloud divergence: CMEK is mutable on ASM, immutable on a GCP secret.
	if cls, _ := d.ClassifyChange("secretmanager", "encryption.customerManagedKeys", nil, true, nil); cls != "immutable" {
		t.Fatalf("GCP secret CMEK must be immutable (create-time replication), got %q", cls)
	}
}
