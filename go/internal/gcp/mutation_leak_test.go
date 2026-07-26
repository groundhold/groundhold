// D309: the GCP half of the receipt-redaction pin.
//
// Honest scope note: unlike AWS (MasterUserPassword) and Azure
// (administratorLoginPassword), no GCP driver puts a credential in a mutation
// body today — Cloud Scheduler explicitly REFUSES a payload/auth header as a
// secret (D53), and Cloud SQL creates no root password. So this is not a live
// leak being closed; it pins the WIRING, so that the day a GCP driver does take
// a credential, the boundary already scrubs it. A test that pretended otherwise
// would be the kind of claim this repo does not make.
package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

func TestGCPMutationBoundaryScrubsCredentialsFromTheReason(t *testing.T) {
	const credential = "gcp-credential-never-persisted"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":404,"status":"NOT_FOUND"}}`))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":400,"status":"INVALID_ARGUMENT",` +
			`"message":"bad value ` + credential + ` supplied"}}`))
	}))
	defer srv.Close()

	d := testDriver(t, srv)
	impl := map[string]any{"password": credential, "tier": "db-f1-micro"}
	res := d.Create("cloudsql", "db", "prod", map[string]any{
		"engine.protocol":        "postgresql/16",
		"location.region":        "europe-west1",
		"network.publicExposure": true,
	}, impl, "k", 1)

	if res.Status == "succeeded" {
		t.Fatalf("a 400 must not be succeeded; got %+v", res)
	}
	if strings.Contains(res.Reason, credential) {
		t.Errorf("the receipt reason carries a credential the driver was handed — the "+
			"Reason is persisted in the ledger and signed into capsules.\nreason: %s", res.Reason)
	}
	if !strings.Contains(res.Reason, provider.RedactionMark) {
		t.Errorf("the redaction must be visible in the reason; got: %s", res.Reason)
	}
}
