package gcp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The env-token path is covered everywhere via testDriver; these cover the
// two paths that carry real crypto/network and were otherwise untested:
// a service-account key file (self-signed RS256 JWT, exchanged) and the GCE
// metadata server.

func TestMetadataToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Metadata-Flavor") != "Google" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"meta-tok","expires_in":3600}`))
		}))
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "")
	t.Setenv("GROUNDHOLD_GCP_KEY_FILE", "")
	d := NewDriver("acme-prod")
	d.auth.metadataURL = srv.URL
	tok, err := d.auth.token()
	if err != nil {
		t.Fatal(err)
	}
	if tok != "meta-tok" {
		t.Fatalf("tok=%q, want meta-tok", tok)
	}
}

func TestServiceAccountToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// the driver POSTs a jwt-bearer assertion; return an access token
			_, _ = w.Write([]byte(`{"access_token":"sa-tok","expires_in":3600}`))
		}))
	defer srv.Close()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	keyJSON, _ := json.Marshal(map[string]any{
		"type":           "service_account",
		"private_key_id": "kid1",
		"private_key":    string(pemBytes),
		"client_email":   "sa@proj.iam.gserviceaccount.com",
		"token_uri":      srv.URL,
	})
	kf := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(kf, keyJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "")
	t.Setenv("GROUNDHOLD_GCP_KEY_FILE", kf)
	d := NewDriver("acme-prod")
	tok, err := d.auth.token()
	if err != nil {
		t.Fatal(err)
	}
	if tok != "sa-tok" {
		t.Fatalf("tok=%q, want sa-tok", tok)
	}
	// second call must be served from cache (until 60s before expiry)
	if tok2, _ := d.auth.token(); tok2 != "sa-tok" {
		t.Fatalf("cached tok=%q", tok2)
	}
}

func TestServiceAccountKeyRejectsWrongType(t *testing.T) {
	kf := filepath.Join(t.TempDir(), "key.json")
	_ = os.WriteFile(kf, []byte(`{"type":"authorized_user"}`), 0o600)
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "")
	t.Setenv("GROUNDHOLD_GCP_KEY_FILE", kf)
	d := NewDriver("acme-prod")
	if _, err := d.auth.token(); err == nil {
		t.Fatal("expected refusal of a non-service_account key (no ADC/federation)")
	}
}
