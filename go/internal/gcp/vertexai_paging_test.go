package gcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestVertexCreateAdoptionReadsEveryEndpointPage is the third read in D870, and the only
// one of the three that MUTATES when it is wrong.
//
// The scan is the read-before-write guard (D700/D804). Its caller says what a miss costs,
// in its own words: "a blind create on a lost ledger mints a SECOND model-serving endpoint
// — billed, live, and absent from the ledger". Vertex's discovery document gives
// `endpoints.list` a pageToken and a nextPageToken, so past the first page the guard was
// not weak — it was absent, and the create went ahead.
func TestVertexCreateAdoptionReadsEveryEndpointPage(t *testing.T) {
	var creates int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "GET" && strings.HasSuffix(p, "/endpoints"):
			if strings.Contains(r.URL.RawQuery, "pageToken") {
				// the standing endpoint — ours, at our displayName, on page two.
				_ = json.NewEncoder(w).Encode(map[string]any{
					"endpoints": []map[string]any{{
						"name":        vtxEndpointName("europe-west4", vtxID),
						"displayName": "claude-eu",
						"labels": map[string]string{
							"groundhold-capability":  "inference",
							"groundhold-environment": "prod",
						},
					}},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"endpoints": []map[string]any{{
					"name":        vtxEndpointName("europe-west4", "9999999999999999999"),
					"displayName": "someone-elses",
				}},
				"nextPageToken": "p2",
			})
		case r.Method == "POST" && strings.HasSuffix(p, "/endpoints"):
			creates++
			_, _ = w.Write([]byte(`{"name":"projects/` + vtxProj +
				`/locations/europe-west4/operations/opc"}`))
		case strings.Contains(p, "/operations/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"done": true,
				"response": map[string]any{"name": vtxEndpointName("europe-west4", vtxID)}})
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()

	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	vertexAIBaseURLOverride = srv.URL
	t.Cleanup(func() { vertexAIBaseURLOverride = "" })
	d := NewDriver(vtxProj)
	d.PollInterval = 0

	id, loc, found, err := d.findVertexEndpointByDisplayName("europe-west4", "claude-eu",
		"inference", "prod")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if !found {
		t.Fatalf("the standing endpoint sat on page two and the adoption scan reported "+
			"none. The create that follows mints a SECOND model-serving endpoint — billed, "+
			"live, and absent from the ledger (D870). creates so far: %d", creates)
	}
	if id != vtxID || loc != "europe-west4" {
		t.Fatalf("adopted %q in %q, want %q in europe-west4", id, loc, vtxID)
	}
}

// TestVertexAdoptionScanRefusesAnUnfinishedSweep: an endless chain is an error, and the
// caller treats an error as "could not tell" and proceeds to create — which is the right
// answer for a genuine first deploy and the reason the error must not be a false "none"
// dressed as a finished read.
func TestVertexAdoptionScanRefusesAnUnfinishedSweep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"endpoints": []map[string]any{}, "nextPageToken": "always-more"})
	}))
	defer srv.Close()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	vertexAIBaseURLOverride = srv.URL
	t.Cleanup(func() { vertexAIBaseURLOverride = "" })
	d := NewDriver(vtxProj)
	d.PollInterval = 0

	if _, _, found, err := d.findVertexEndpointByDisplayName("europe-west4", "claude-eu",
		"inference", "prod"); err == nil {
		t.Fatalf("an endless page chain returned found=%v with no error", found)
	}
}
