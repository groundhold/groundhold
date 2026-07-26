package gcp

import (
	"path/filepath"
	"testing"

	"groundhold/internal/fixture"
)

// TestGCSObserveReplay drives the REAL observeGCS parser against a recorded
// provider response (D234). Unlike the inline httptest fakes — which are written
// to the driver's own assumption — this replays a fixture whose shape is pinned
// independently (shapeHash) and asserts the exact semantic observations. A parser
// change that misreads the response fails here with no cloud access (drift
// direction 1); a provider shape change is caught when the canary re-records the
// fixture (direction 2, the shapeHash diff).
func TestGCSObserveReplay(t *testing.T) {
	fx, err := fixture.Load(filepath.Join("..", "fixture", "data", "gcp", "gcs", "buckets-get.ok.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := fixture.Serve(t, fx)

	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token") // replay never authenticates for real
	d := NewDriver("gh-fixture")                          // project must match the providerId below
	d.GcsBaseURL = srv.URL
	obs, _, oerr := d.observeGCS("assets", gcsProviderID("gh-fixture", "gh-fixture-bucket"))
	fixture.AssertExpected(t, fx, obs, oerr)
}
