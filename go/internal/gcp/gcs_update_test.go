package gcp

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gcsUpdateServer serves buckets.get (ours, with a metageneration) and buckets.patch,
// recording the patch body so the test can assert versioning was set.
func gcsUpdateServer(t *testing.T, capLabel string, patched *string) *httptest.Server {
	t.Helper()
	doc := `{"name":"pv-assets-abcd1234","metageneration":"7","projectNumber":"111",` +
		`"labels":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"},` +
		`"versioning":{"enabled":false}}`
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PATCH":
				b, _ := io.ReadAll(r.Body)
				*patched = string(b)
				if !strings.Contains(r.URL.RawQuery, "ifMetagenerationMatch=7") {
					w.WriteHeader(428) // a CAS-less patch must never happen
					return
				}
				_, _ = w.Write([]byte(doc))
			case "GET":
				_, _ = w.Write([]byte(doc))
			default:
				w.WriteHeader(500)
			}
		}))
}

func TestUpdateGCSVersioning(t *testing.T) {
	var patched string
	srv := gcsUpdateServer(t, "assets", &patched)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.Update("gcs", "assets", "prod", "gcs:acme-prod:pv-assets-abcd1234",
		map[string]any{"versioning.enabled": true}, nil, []string{"versioning.enabled"}, "k")
	if res.Status != "succeeded" {
		t.Fatalf("update: %+v", res)
	}
	if !strings.Contains(patched, `"versioning"`) || !strings.Contains(patched, `"enabled":true`) {
		t.Fatalf("patch body did not set versioning enabled: %s", patched)
	}
}

func TestUpdateGCSForeignRefused(t *testing.T) {
	var patched string
	srv := gcsUpdateServer(t, "someone-else", &patched)
	defer srv.Close()
	d := gcsDriver(t, srv)
	res := d.Update("gcs", "assets", "prod", "gcs:acme-prod:pv-assets-abcd1234",
		map[string]any{"versioning.enabled": true}, nil, []string{"versioning.enabled"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign bucket must refuse patch, got %+v", res)
	}
	if patched != "" {
		t.Fatalf("no patch must be sent for a foreign bucket, got %s", patched)
	}
}

func TestClassifyGCSChange(t *testing.T) {
	d := NewDriver("acme-prod")
	if cls, _ := d.ClassifyChange("gcs", "versioning.enabled", false, true, nil); cls != "mutable" {
		t.Fatalf("versioning must be mutable, got %q", cls)
	}
	if cls, _ := d.ClassifyChange("gcs", "location.region", "us", "eu", nil); cls != "immutable" {
		t.Fatalf("region must be immutable, got %q", cls)
	}
}
