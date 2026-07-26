//go:build capture

// This entrypoint runs ONLY under `-tags capture`, i.e. in the canary where real
// WIF credentials exist (D234) — never in the normal `make check` gate, and never
// on a dev host. It records the REAL GCS buckets.get response and writes a
// `provenance: live` fixture, flipping the handwritten-pending-canary one. The
// canary uploads the result for a review PR; it is never pushed directly.
package gcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/fixture"
)

func TestCaptureGCSFixture(t *testing.T) {
	token := os.Getenv("GROUNDHOLD_GCP_ACCESS_TOKEN")
	project := os.Getenv("PROJECT")
	bucket := os.Getenv("FIXTURE_BUCKET")
	runID := os.Getenv("RUN_ID")
	if token == "" || project == "" || bucket == "" {
		t.Skip("capture needs GROUNDHOLD_GCP_ACCESS_TOKEN + PROJECT + FIXTURE_BUCKET (canary only)")
	}

	d := NewDriver(project)
	rec := fixture.NewRecorder(d.HTTP.Transport) // wrap the driver's own transport
	d.HTTP = rec.Client()

	obs, _, err := d.observeGCS("assets", gcsProviderID(project, bucket))
	if err != nil {
		t.Fatalf("live observe failed: %v", err)
	}
	if len(rec.Exchanges) == 0 {
		t.Fatal("recorder captured no exchange")
	}

	fx, err := fixture.BuildFixture(fixture.Meta{
		Provider: "gcp", Service: "gcs", Operation: "buckets.get", Variant: "ok",
		CapturedBy: "canary-gcp@" + runID,
		APIVersion: "storage/v1",
		// scrub account-specifics: the fixture must not carry the project id/number
		Redact: map[string]string{project: "PROJECT", bucket: "gh-fixture-bucket"},
	}, rec.Exchanges[len(rec.Exchanges)-1], obs)
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join("..", "fixture", "data", "gcp", "gcs", "buckets-get.ok.json")
	b, _ := json.MarshalIndent(fx, "", "  ")
	if err := os.WriteFile(out, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("captured live GCS fixture -> %s (shape %s)", out, fx.ShapeHash)
}
