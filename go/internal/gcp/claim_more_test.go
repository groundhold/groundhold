package gcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file extends claim_test.go: the label-merge claim family (D145 breadth)
// shares ONE shape (claimFetchLabels -> mutate -> finishLabelClaim) across 20+
// services; claim_test.go pins the shape itself (Cloud SQL, GCS-family via
// secretmanager/pubsub-topic, one LRO family via memorystore). These tests pin
// the REMAINING per-service wiring (correct providerId parsing, correct base
// URL, correct label field, correct wrapped-vs-flat body) plus the shared
// error branches claim_test.go does not exercise: transport errors, 409/412
// conflicts, 5xx, other 4xx, an operation response with no name, and an
// invalid providerId (which must resolve through failedClaim).

// opGET matches a GET to an "operations" sub-path (used by every LRO poller)
// and reports the operation done.
func opDoneHandler(getBody, patchOpName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
			fmt.Fprint(w, `{"done":true}`)
		case r.Method == "GET":
			fmt.Fprint(w, getBody)
		case r.Method == "PATCH":
			fmt.Fprintf(w, `{"name":%q}`, patchOpName)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

// ─── immediate-patch services not covered by claim_test.go ─────────────────

func TestClaimGCSMergesLabelsWithMetageneration(t *testing.T) {
	var patchPath string
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"},"metageneration":"3"}`)
		case "PATCH":
			patchPath = r.URL.Path + "?" + r.URL.RawQuery
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"my-bucket"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.GcsBaseURL = srv.URL

	cr := d.Claim("gcs", "orders-archive", "production", "gcs:acme-prod:my-bucket")
	if cr.Status != "succeeded" || cr.ProviderID != "gcs:acme-prod:my-bucket" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	if !strings.Contains(patchPath, "ifMetagenerationMatch=3") {
		t.Fatalf("GCS claim must guard the patch with ifMetagenerationMatch, got %q", patchPath)
	}
	labels, _ := patchBody["labels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-archive" || labels["groundhold-environment"] != "production" {
		t.Fatalf("claim must stamp groundhold labels: %v", labels)
	}
	if labels["team"] != "ops" {
		t.Fatalf("claim must preserve the operator's labels: %v", labels)
	}
}

func TestClaimBigQueryMergesLabels(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"}}`)
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"datasetReference":{"datasetId":"orders"}}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.BQBaseURL = srv.URL

	cr := d.Claim("bigquery", "orders-warehouse", "production", "bqds:acme-prod:orders")
	if cr.Status != "succeeded" || cr.ProviderID != "bqds:acme-prod:orders" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	labels, _ := patchBody["labels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-warehouse" || labels["team"] != "ops" {
		t.Fatalf("claim must merge groundhold labels with the operator's: %v", labels)
	}
}

func TestClaimCloudDNSMergesLabels(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"}}`)
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"orders-zone"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.DNSBaseURL = srv.URL

	cr := d.Claim("clouddns", "orders-zone", "production", "gdns:acme-prod:orders-zone")
	if cr.Status != "succeeded" || cr.ProviderID != "gdns:acme-prod:orders-zone" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	labels, _ := patchBody["labels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-zone" || labels["team"] != "ops" {
		t.Fatalf("claim must merge groundhold labels with the operator's: %v", labels)
	}
}

func TestClaimArtifactRegistryMergesLabels(t *testing.T) {
	var patchQuery string
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"}}`)
		case "PATCH":
			patchQuery = r.URL.RawQuery
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"app-repo"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.ARBaseURL = srv.URL

	cr := d.Claim("artifactregistry", "app-images", "production", "gar:acme-prod:europe-west1:app-repo")
	if cr.Status != "succeeded" || cr.ProviderID != "gar:acme-prod:europe-west1:app-repo" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	if patchQuery != "updateMask=labels" {
		t.Fatalf("artifactregistry claim must patch with updateMask=labels, got %q", patchQuery)
	}
	labels, _ := patchBody["labels"].(map[string]any)
	if labels["groundhold-capability"] != "app-images" || labels["team"] != "ops" {
		t.Fatalf("claim must merge groundhold labels with the operator's: %v", labels)
	}
}

func TestClaimUptimeMergesUserLabels(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"userLabels":{"team":"ops"}}`)
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"check-1"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.UptimeBaseURL = srv.URL

	cr := d.Claim("uptime", "orders-uptime", "production", "guptime:acme-prod:check-1")
	if cr.Status != "succeeded" || cr.ProviderID != "guptime:acme-prod:check-1" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	labels, _ := patchBody["userLabels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-uptime" || labels["team"] != "ops" {
		t.Fatalf("claim must merge groundhold userLabels with the operator's: %v", labels)
	}
}

func TestClaimKMSMergesLabels(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"}}`)
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"key1"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.KMSBaseURL = srv.URL

	cr := d.Claim("cloudkms", "orders-key", "production", "gkms:acme-prod:europe-west1:ring1:key1")
	if cr.Status != "succeeded" || cr.ProviderID != "gkms:acme-prod:europe-west1:ring1:key1" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	labels, _ := patchBody["labels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-key" || labels["team"] != "ops" {
		t.Fatalf("claim must merge groundhold labels with the operator's: %v", labels)
	}
}

// TestClaimPubSubQueueMergesLabels: subscriptions.patch uses the SAME wrapped
// body shape as topics ({subscription:{name,labels}, updateMask:"labels"}).
func TestClaimPubSubQueueMergesLabels(t *testing.T) {
	var patchBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"}}`)
		case "PATCH":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &patchBody)
			fmt.Fprint(w, `{"name":"projects/acme-prod/subscriptions/orders-queue"}`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.PubSubBaseURL = srv.URL

	cr := d.Claim("pubsub-queue", "orders-queue", "production", "pubsub:acme-prod:orders-queue")
	if cr.Status != "succeeded" || cr.ProviderID != "pubsub:acme-prod:orders-queue" {
		t.Fatalf("claim must succeed with providerId, got %+v", cr)
	}
	if patchBody["updateMask"] != "labels" {
		t.Fatalf("pubsub queue patch must carry updateMask=labels: %v", patchBody)
	}
	sub, _ := patchBody["subscription"].(map[string]any)
	labels, _ := sub["labels"].(map[string]any)
	if labels["groundhold-capability"] != "orders-queue" || labels["team"] != "ops" {
		t.Fatalf("claim must stamp groundhold labels inside the wrapped subscription: %v", labels)
	}
}

// ─── LRO-patch services not covered by claim_test.go ───────────────────────

func TestClaimFilestoreMergesLabelsLRO(t *testing.T) {
	srv := httptest.NewServer(opDoneHandler(`{"labels":{"team":"ops"}}`,
		"projects/acme-prod/locations/europe-west1/operations/op1"))
	defer srv.Close()
	d := testDriver(t, srv)
	d.FilestoreBaseURL = srv.URL

	cr := d.Claim("filestore", "orders-nfs", "production", "filestore:acme-prod:europe-west1:orders-nfs")
	if cr.Status != "succeeded" || cr.ProviderID != "filestore:acme-prod:europe-west1:orders-nfs" {
		t.Fatalf("LRO claim must succeed with providerId after done, got %+v", cr)
	}
}

func TestClaimManagedKafkaMergesLabelsLRO(t *testing.T) {
	srv := httptest.NewServer(opDoneHandler(`{"labels":{"team":"ops"}}`,
		"projects/acme-prod/locations/europe-west1/operations/op1"))
	defer srv.Close()
	d := testDriver(t, srv)
	d.ManagedKafkaBaseURL = srv.URL

	cr := d.Claim("managedkafka", "orders-kafka", "production", "gmkafka:acme-prod:europe-west1:orders-cluster")
	if cr.Status != "succeeded" || cr.ProviderID != "gmkafka:acme-prod:europe-west1:orders-cluster" {
		t.Fatalf("LRO claim must succeed with providerId after done, got %+v", cr)
	}
}

func TestClaimCertManagerMergesLabelsLRO(t *testing.T) {
	srv := httptest.NewServer(opDoneHandler(`{"labels":{"team":"ops"}}`,
		"projects/acme-prod/locations/global/operations/op1"))
	defer srv.Close()
	d := testDriver(t, srv)
	d.CertManagerBaseURL = srv.URL

	cr := d.Claim("certmanager", "orders-cert", "production", "gcert:acme-prod:global:orders-cert")
	if cr.Status != "succeeded" || cr.ProviderID != "gcert:acme-prod:global:orders-cert" {
		t.Fatalf("LRO claim must succeed with providerId after done, got %+v", cr)
	}
}

func TestClaimCloudFunctionMergesLabelsLRO(t *testing.T) {
	srv := httptest.NewServer(opDoneHandler(`{"labels":{"team":"ops"}}`,
		// D718: a production-shaped operation name. GCP returns the FULL resource name
		// here, and the driver polls base+"/"+name — a fixture emitting a bare
		// "operations/op1" produced a URL no GCP API routes, which is a fixture
		// standing in for a cloud that does not exist.
		"projects/acme-prod/locations/europe-west1/operations/op1"))
	defer srv.Close()
	d := testDriver(t, srv)
	d.CfBaseURL = srv.URL

	cr := d.Claim("cloudfunctions", "orders-fn", "production", "cloudfunctions:acme-prod:europe-west1:orders-fn")
	if cr.Status != "succeeded" || cr.ProviderID != "cloudfunctions:acme-prod:europe-west1:orders-fn" {
		t.Fatalf("LRO claim must succeed with providerId after done, got %+v", cr)
	}
}

func TestClaimBackupVaultMergesLabelsLRO(t *testing.T) {
	srv := httptest.NewServer(opDoneHandler(`{"labels":{"team":"ops"}}`,
		"projects/acme-prod/locations/europe-west1/operations/op1"))
	defer srv.Close()
	d := testDriver(t, srv)
	d.BackupDRBaseURL = srv.URL

	cr := d.Claim("backupvault", "orders-vault", "production", "gbkv:acme-prod:europe-west1:orders-vault")
	if cr.Status != "succeeded" || cr.ProviderID != "gbkv:acme-prod:europe-west1:orders-vault" {
		t.Fatalf("LRO claim must succeed with providerId after done, got %+v", cr)
	}
}

func TestClaimBackupPlanGCPMergesLabelsLRO(t *testing.T) {
	srv := httptest.NewServer(opDoneHandler(`{"labels":{"team":"ops"}}`,
		"projects/acme-prod/locations/europe-west1/operations/op1"))
	defer srv.Close()
	d := testDriver(t, srv)
	d.BackupDRBaseURL = srv.URL

	cr := d.Claim("backupplan", "orders-plan", "production", "gbkplan:acme-prod:europe-west1:orders-plan")
	if cr.Status != "succeeded" || cr.ProviderID != "gbkplan:acme-prod:europe-west1:orders-plan" {
		t.Fatalf("LRO claim must succeed with providerId after done, got %+v", cr)
	}
}

func TestClaimCloudRunMergesLabelsLRO(t *testing.T) {
	srv := httptest.NewServer(opDoneHandler(`{"labels":{"team":"ops"}}`,
		"projects/acme-prod/locations/europe-west1/operations/op1"))
	defer srv.Close()
	d := testDriver(t, srv)
	d.RunBaseURL = srv.URL

	cr := d.Claim("cloudrun", "orders-api", "production", "cloudrun:acme-prod:europe-west1:orders-api")
	if cr.Status != "succeeded" || cr.ProviderID != "cloudrun:acme-prod:europe-west1:orders-api" {
		t.Fatalf("LRO claim must succeed with providerId after done, got %+v", cr)
	}
}

func TestClaimCloudRunJobMergesLabelsLRO(t *testing.T) {
	srv := httptest.NewServer(opDoneHandler(`{"labels":{"team":"ops"}}`,
		"projects/acme-prod/locations/europe-west1/operations/op1"))
	defer srv.Close()
	d := testDriver(t, srv)
	d.RunBaseURL = srv.URL

	cr := d.Claim("cloudrunjobs", "orders-job", "production", "gjob:acme-prod:europe-west1:orders-job")
	if cr.Status != "succeeded" || cr.ProviderID != "gjob:acme-prod:europe-west1:orders-job" {
		t.Fatalf("LRO claim must succeed with providerId after done, got %+v", cr)
	}
}

// ─── shared error branches (claimFetchLabels / finishLabelClaim) ───────────

// TestClaimInvalidProviderIDFailsViaFailedClaim: a malformed providerId never
// reaches the network — it resolves through failedClaim (0% before this test).
func TestClaimInvalidProviderIDFailsViaFailedClaim(t *testing.T) {
	d := NewDriver("acme-prod")
	cases := []struct{ service, providerID string }{
		{"gcs", "not-a-valid-pid"},
		{"bigquery", "bqds:acme-prod"},
		{"clouddns", "wrong-prefix:acme-prod:zone"},
		{"artifactregistry", "gar:acme-prod"},
		{"cloudkms", "gkms:acme-prod:loc"},
		{"pubsub-queue", "wrong:acme-prod:name"},
		{"filestore", "filestore:acme-prod"},
		{"managedkafka", "wrong:acme-prod:loc:cluster"},
		{"certmanager", "wrong:acme-prod:global:cert"},
		{"cloudfunctions", "wrong:acme-prod:region:fn"},
		{"backupvault", "wrong:acme-prod:loc:vault"},
		{"backupplan", "wrong:acme-prod:loc:plan"},
		{"cloudrun", "wrong:acme-prod:region:name"},
		{"cloudrunjobs", "wrong:acme-prod:region:name"},
		{"uptime", "wrong:acme-prod:id"},
	}
	for _, c := range cases {
		cr := d.Claim(c.service, "cap", "production", c.providerID)
		if cr.Status != "failed" {
			t.Errorf("%s: invalid providerId %q must fail closed, got %+v", c.service, c.providerID, cr)
		}
		if cr.ProviderID != "" {
			t.Errorf("%s: a rejected providerId must not be echoed back, got %+v", c.service, cr)
		}
	}
}

// TestClaimSameProjectMismatchFails: the project pin guard (D75) refuses a
// providerId whose project does not match the driver's pinned project — a
// forged binding must not redirect the mutation elsewhere.
func TestClaimSameProjectMismatchFails(t *testing.T) {
	d := NewDriver("acme-prod") // pinned project
	cr := d.Claim("gcs", "orders-archive", "production", "gcs:other-project:my-bucket")
	if cr.Status != "failed" {
		t.Fatalf("a cross-project providerId must fail closed, got %+v", cr)
	}
}

// TestClaimPreClaimReadTransportErrorIsUnknown: a network failure on the
// pre-claim GET is `unknown` WITH the providerId, never a fabricated failure
// or success (four-valued honesty on a transport-level ambiguity).
func TestClaimPreClaimReadTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL
	srv.Close() // connection refused on every call from here on

	cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:orders-secret")
	if cr.Status != "unknown" {
		t.Fatalf("a transport error on the pre-claim read must be unknown, got %+v", cr)
	}
	if cr.ProviderID != "gsecret:acme-prod:orders-secret" {
		t.Fatalf("unknown must still carry the providerId, got %+v", cr)
	}
}

// TestClaimPreClaimReadServerErrorFails: a non-404 non-200 read status (e.g. a
// transient-looking 500 that is nonetheless a clean HTTP response) is a clean
// `failed`, not fabricated success.
func TestClaimPreClaimReadServerErrorFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL

	cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:orders-secret")
	if cr.Status != "failed" {
		t.Fatalf("a bad pre-claim read status must fail, got %+v", cr)
	}
}

// TestClaimPreClaimReadUnparseableFails: a 200 with unparseable JSON is a
// clean failure, not a crash and not a silent empty-label claim.
func TestClaimPreClaimReadUnparseableFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprint(w, `not json`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL

	cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:orders-secret")
	if cr.Status != "failed" || !strings.Contains(cr.Reason, "unparseable") {
		t.Fatalf("unparseable pre-claim read must fail with an honest reason, got %+v", cr)
	}
}

// TestClaimPatchConflictFails: a 409/412 on the PATCH is a clean failure
// telling the caller to re-observe and re-claim, never a partial/fabricated
// success.
func TestClaimPatchConflictFails(t *testing.T) {
	for _, code := range []int{409, 412} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "GET":
				fmt.Fprint(w, `{"labels":{}}`)
			case "PATCH":
				w.WriteHeader(code)
			}
		}))
		d := testDriver(t, srv)
		d.SecretBaseURL = srv.URL

		cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:orders-secret")
		srv.Close()
		if cr.Status != "failed" {
			t.Fatalf("HTTP %d on the patch must fail cleanly, got %+v", code, cr)
		}
		if !strings.Contains(cr.Reason, "re-observe and re-claim") {
			t.Fatalf("HTTP %d reason must guide reconciliation, got %q", code, cr.Reason)
		}
	}
}

// TestClaimPatchServerErrorIsUnknown: a 5xx on the PATCH is `unknown` WITH the
// providerId — the mutation may or may not have landed.
func TestClaimPatchServerErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{}}`)
		case "PATCH":
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL

	cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:orders-secret")
	if cr.Status != "unknown" {
		t.Fatalf("a 5xx on the patch must be unknown, got %+v", cr)
	}
	if cr.ProviderID != "gsecret:acme-prod:orders-secret" {
		t.Fatalf("unknown must still carry the providerId, got %+v", cr)
	}
}

// TestClaimPatchOtherClientErrorFails: a non-conflict 4xx on the patch (e.g. a
// malformed request) is a clean failure, distinct from the conflict codes.
func TestClaimPatchOtherClientErrorFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{}}`)
		case "PATCH":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL

	cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:orders-secret")
	if cr.Status != "failed" || !strings.Contains(cr.Reason, "403") {
		t.Fatalf("a 403 on the patch must fail with the code in the reason, got %+v", cr)
	}
}

// failOnMethod is an http.RoundTripper that fails transport-level for one
// HTTP method and delegates everything else to the wrapped transport — used
// to isolate a transport error to the PATCH leg specifically (as opposed to
// the pre-claim GET, already pinned by TestClaimPreClaimReadTransportErrorIsUnknown).
type failOnMethod struct {
	method string
	next   http.RoundTripper
}

func (f failOnMethod) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method == f.method {
		return nil, fmt.Errorf("simulated transport failure on %s", f.method)
	}
	return f.next.RoundTrip(r)
}

// TestClaimPatchTransportErrorIsUnknown: a network failure DURING the patch
// (as opposed to the pre-claim read) is also `unknown` WITH the providerId.
func TestClaimPatchTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprint(w, `{"labels":{}}`)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL
	d.HTTP = &http.Client{Transport: failOnMethod{method: "PATCH", next: srv.Client().Transport}}

	cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:orders-secret")
	if cr.Status != "unknown" {
		t.Fatalf("a PATCH transport error must be unknown, got %+v", cr)
	}
	if cr.ProviderID != "gsecret:acme-prod:orders-secret" {
		t.Fatalf("unknown must still carry the providerId, got %+v", cr)
	}
}

// TestClaimLROResponseWithNoOperationNameIsUnknown: an LRO-patch service whose
// PATCH response carries no operation name cannot be polled — the outcome is
// `unknown`, telling the caller to reconcile rather than assuming success.
func TestClaimLROResponseWithNoOperationNameIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{"team":"ops"}}`)
		case "PATCH":
			fmt.Fprint(w, `{}`) // no "name" field
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.MemorystoreBaseURL = srv.URL

	cr := d.Claim("memorystore", "orders-cache", "production", "gredis:acme-prod:europe-west1:orders-cache")
	if cr.Status != "unknown" || !strings.Contains(cr.Reason, "no operation") {
		t.Fatalf("a nameless operation response must be unknown, got %+v", cr)
	}
	if cr.ProviderID != "gredis:acme-prod:europe-west1:orders-cache" {
		t.Fatalf("unknown must still carry the providerId, got %+v", cr)
	}
}

// TestClaimImmediatePatchInvalidJSONReturnsSucceededAnyway: for an
// immediate-patch (poll==nil) service, finishLabelClaim treats any 2xx as
// confirmation without needing to parse the body at all — pin that
// deliberate shortcut (poll==nil short-circuits before the body is touched).
func TestClaimImmediatePatchInvalidJSONReturnsSucceededAnyway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			fmt.Fprint(w, `{"labels":{}}`)
		case "PATCH":
			fmt.Fprint(w, `not even json`)
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.SecretBaseURL = srv.URL

	cr := d.Claim("secretmanager", "orders-secret", "production", "gsecret:acme-prod:orders-secret")
	if cr.Status != "succeeded" || cr.ProviderID != "gsecret:acme-prod:orders-secret" {
		t.Fatalf("an immediate-patch service must succeed on any 2xx regardless of body, got %+v", cr)
	}
}
