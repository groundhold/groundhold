package fixture

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/provider"
)

// TestRecorderCapturesRealExchange proves the capture half offline: a fake
// upstream serves a body, a Recorder-wrapped client records the exact exchange,
// and BuildFixture assembles a `live` fixture that Load accepts — provenance,
// shapeHash and scrub all coherent. No live creds; the upstream is httptest.
func TestRecorderCapturesRealExchange(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// a body carrying an account-specific projectNumber to be scrubbed
		_, _ = w.Write([]byte(`{"name":"b","location":"EU","projectNumber":"999888777"}`))
	}))
	defer upstream.Close()

	rec := NewRecorder(nil)
	client := rec.Client()
	resp, err := client.Get(upstream.URL + "/storage/v1/b/b?alt=json")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(rec.Exchanges) != 1 {
		t.Fatalf("recorder captured %d exchanges, want 1", len(rec.Exchanges))
	}

	obs := []provider.Observation{{Path: "location.region", Value: "eu", Derivation: "measured"}}
	fx, err := BuildFixture(Meta{
		Provider: "gcp", Service: "gcs", Operation: "buckets.get", Variant: "ok",
		CapturedBy: "canary-gcp@run-42", CapturedAt: "2026-07-23T09:00:00Z",
		Redact: map[string]string{"999888777": "PROJECT_NUMBER"},
	}, rec.Exchanges[0], obs)
	if err != nil {
		t.Fatal(err)
	}
	if fx.Provenance != ProvenanceLive || fx.CapturedBy != "canary-gcp@run-42" {
		t.Fatalf("live provenance not stamped: %+v", fx.Provenance)
	}
	// scrub applied + recorded
	if len(fx.Scrubbed) != 1 || fx.Scrubbed[0] != "PROJECT_NUMBER" {
		t.Fatalf("scrub not recorded: %v", fx.Scrubbed)
	}
	if string(fx.Response.Raw) == "" || contains(string(fx.Response.Raw), "999888777") {
		t.Fatalf("account-specific value not scrubbed from body: %s", fx.Response.Raw)
	}
	// query recorded
	if fx.Request.Query["alt"] != "json" {
		t.Fatalf("query not captured: %v", fx.Request.Query)
	}

	// round-trip: write it, and Load must accept it (shapeHash coherent, live ok)
	dir := t.TempDir()
	p := filepath.Join(dir, "captured.json")
	writeFixtureJSON(t, p, fx)
	loaded, lerr := Load(p)
	if lerr != nil {
		t.Fatalf("a captured live fixture must Load cleanly: %v", lerr)
	}
	if loaded.ShapeHash != fx.ShapeHash {
		t.Fatal("shapeHash must survive the write/Load round-trip")
	}
}

func writeFixtureJSON(t *testing.T, path string, f *Fixture) {
	t.Helper()
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
