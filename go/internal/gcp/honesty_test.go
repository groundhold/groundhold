package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// newGcpHonestyDriver builds a Driver pointed at the happy server with the
// scripted transport injected, ALL per-service BaseURLs overridden so any
// service routes through it. Auth is stubbed by GROUNDHOLD_GCP_ACCESS_TOKEN in
// each test, so the trace the harness records is API calls only (never a token
// fetch). ProjNumber is pre-resolved (D82) so GCS's cross-project ownership
// check needs no CRM mock.
func newGcpHonestyDriver(happyURL string, rt http.RoundTripper) *Driver {
	d := NewDriver("acme-prod")
	d.HTTP = &http.Client{Transport: rt}
	d.BaseURL = happyURL
	d.CRMBaseURL = happyURL
	d.RunBaseURL = happyURL
	d.GcsBaseURL = happyURL
	d.ComputeBaseURL = happyURL
	d.CfBaseURL = happyURL
	d.PubSubBaseURL = happyURL
	d.SecretBaseURL = happyURL
	d.DNSBaseURL = happyURL
	d.MemorystoreBaseURL = happyURL
	d.IAMBaseURL = happyURL
	d.MonitoringBaseURL = happyURL
	d.DashboardBaseURL = happyURL
	d.UptimeBaseURL = happyURL
	d.LoggingBaseURL = happyURL
	d.ARBaseURL = happyURL
	d.FilestoreBaseURL = happyURL
	d.FirestoreBaseURL = happyURL
	d.ManagedKafkaBaseURL = happyURL
	d.CertManagerBaseURL = happyURL
	d.BQBaseURL = happyURL
	d.SchedulerBaseURL = happyURL
	d.KMSBaseURL = happyURL
	d.BackupDRBaseURL = happyURL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	d.ProjNumber = "111"
	return d
}

// gcpOpRole classifies the operation-based GCP protocols (Cloud SQL, Cloud Run,
// Cloud Functions, VPC/Compute). A GET is a read. A setIamPolicy POST is an
// OPAQUE mutation (its 200 body is not consumed — the driver re-reads to
// confirm). Every other mutation (create POST, delete DELETE) PARSES the
// long-running operation name from its body, so a garbled/empty body is
// ambiguous — RoleMutateParsed.
func gcpOpRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	if strings.HasSuffix(req.URL.Path, ":setIamPolicy") {
		return certifynet.RoleMutateOpaque
	}
	return certifynet.RoleMutateParsed
}

// gcsRole classifies the GCS JSON API. buckets.insert (POST) parses the bucket
// name it returns — RoleMutateParsed. The bucket DELETE is SYNCHRONOUS (204, no
// body consumed) and the IAM PUT is confirmed by a fresh read — both opaque.
func gcsRole(req *http.Request, _ []byte) certifynet.Role {
	switch req.Method {
	case http.MethodGet:
		return certifynet.RoleRead
	case http.MethodPost:
		return certifynet.RoleMutateParsed // buckets.insert — name consumed
	default:
		return certifynet.RoleMutateOpaque // PUT iam / DELETE — status-only
	}
}

func gcsPublicAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-central2",
		"network.publicExposure": true,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

func runPublicAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-central2",
		"network.publicExposure": true,
		"service.managed":        true,
	}
}

// ---- Cloud SQL --------------------------------------------------------------

func sqlHonestyCreateServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/instances"):
				_, _ = w.Write([]byte(`{"name":"op-create"}`))
			case strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"status":"DONE"}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

// secretRole: Secret Manager create is OPAQUE (name deterministic, response body
// not consumed); GET is a read; DELETE opaque.
func secretRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

func TestHonestyHarnessMemorystore(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "gredis:acme-prod:europe-west1:x"
	p := &certifynet.Probe{
		Name:            "gcp/memorystore",
		AssertTransient: true,      // D237 sweep
		Classify:        gcpOpRole, // LRO create/delete parse the operation name
		OwnerTagValue:   "sessions",
		DeterministicID: true, // the instance id is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return redisServer(t, "sessions", "STANDARD_HA", "SERVER_AUTHENTICATION", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("memorystore", "sessions", "prod", redisAttrs(), redisImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return redisServer(t, "sessions", "STANDARD_HA", "SERVER_AUTHENTICATION", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("memorystore", "sessions", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessCloudArmor certifies the Cloud Armor driver (D116): insert and
// delete are compute global-operation LROs (gcpOpRole parses the operation name),
// so an ambiguous fault is unknown WITH the deterministic providerId. Ownership is a
// DESCRIPTION MARKER, so the foreign-tag test poisons the marker on the delete read.
func TestHonestyHarnessCloudArmor(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := armorProviderID("acme-prod", ArmorPolicyName("acme-prod", "prod", "edge", 1))
	p := &certifynet.Probe{
		Name:            "gcp/cloudarmor",
		AssertTransient: true, // D237 sweep
		Classify:        gcpOpRole,
		OwnerTagValue:   "edge", // appears in the description marker
		DeterministicID: true,   // the policy name is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return armorServer(t, "edge", true, true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudarmor", "edge", "prod", armorAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return armorServer(t, "edge", true, true, true) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudarmor", "edge", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessGCPSecret(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "gsecret:acme-prod:x"
	p := &certifynet.Probe{
		Name:            "gcp/secretmanager",
		AssertTransient: true, // D237 sweep
		Classify:        secretRole,
		OwnerTagValue:   "dbcreds",
		DeterministicID: true,
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return secretServer(t, "dbcreds", umReplica) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("secretmanager", "dbcreds", "prod", secretAttrs(), secretImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return secretServer(t, "dbcreds", umReplica) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("secretmanager", "dbcreds", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessGCPCloudSQL(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.Probe{
		Name:            "gcp/cloudsql",
		AssertTransient: true, // D237 sweep
		Classify:        gcpOpRole,
		OwnerTagValue:   "db",
		DeterministicID: true, // instance name is a deterministic slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return sqlHonestyCreateServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudsql", "orders-db", "production", attrs, impl, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return deleteServer(t, http.StatusOK, ownedUnprotected) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudsql", "db", "prod", delPID, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// ---- GCS --------------------------------------------------------------------

func gcsHonestyDeleteServer(t *testing.T) *httptest.Server {
	t.Helper()
	bucket := `{"metageneration":"1","projectNumber":"111","labels":{` +
		`"groundhold-capability":"assets","groundhold-environment":"prod"}}`
	return gcsServer(t, bucket, 200, "", 204)
}

func TestHonestyHarnessGCS(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "gcs:acme-prod:the-bucket"
	p := &certifynet.Probe{
		Name:            "gcp/gcs",
		AssertTransient: true, // D237
		Classify:        gcsRole,
		OwnerTagValue:   "assets",
		DeterministicID: true, // bucket name is a deterministic slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return gcsServer(t, "", 200, "", 0) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("gcs", "assets", "prod", gcsPublicAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return gcsHonestyDeleteServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("gcs", "assets", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// ---- Cloud Run --------------------------------------------------------------

func TestHonestyHarnessCloudRun(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "cloudrun:acme-prod:europe-central2:app-be-x"
	ours := map[string]string{"groundhold-capability": "app-be", "groundhold-environment": "prod"}
	p := &certifynet.Probe{
		Name:            "gcp/cloudrun",
		AssertTransient: true, // D237
		Classify:        gcpOpRole,
		OwnerTagValue:   "app-be",
		DeterministicID: true, // service name is a deterministic slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return runServer(t, ours, "INGRESS_TRAFFIC_ALL", 200, "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudrun", "app-be", "prod", runPublicAttrs(),
						map[string]any{"image": "img"}, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return runServer(t, ours, "INGRESS_TRAFFIC_ALL", 200, "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudrun", "app-be", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// ---- Cloud Functions --------------------------------------------------------

func TestHonestyHarnessFunctions(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "cloudfunctions:acme-prod:europe-central2:api-x"
	p := &certifynet.Probe{
		Name:            "gcp/cloudfunctions",
		AssertTransient: true, // D237
		Classify:        gcpOpRole,
		OwnerTagValue:   "api",
		DeterministicID: true, // function name is a deterministic slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return cfServer(t, "", "ALLOW_ALL") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudfunctions", "api", "prod", cfAttrs(), cfImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return cfServer(t, "", "ALLOW_ALL") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudfunctions", "api", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// ---- Pub/Sub ----------------------------------------------------------------

// pubsubRole classifies the Pub/Sub JSON API. topics.create (PUT) parses the
// topic name it returns — RoleMutateParsed. The topic DELETE is SYNCHRONOUS
// (200 with an empty {} body, not consumed) and setIamPolicy (POST) is confirmed
// by a fresh read — both opaque.
func pubsubRole(req *http.Request, _ []byte) certifynet.Role {
	switch req.Method {
	case http.MethodGet:
		return certifynet.RoleRead
	case http.MethodDelete:
		return certifynet.RoleMutateOpaque
	default:
		if strings.HasSuffix(req.URL.Path, ":setIamPolicy") {
			return certifynet.RoleMutateOpaque
		}
		return certifynet.RoleMutateParsed // topics.create PUT — name consumed
	}
}

func TestHonestyHarnessPubSub(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "pubsub:acme-prod:the-topic"
	pubAttrs := map[string]any{
		"location.region":        "europe-west1",
		"network.publicExposure": true,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
	p := &certifynet.Probe{
		Name:            "gcp/pubsub",
		AssertTransient: true, // D237
		Classify:        pubsubRole,
		OwnerTagValue:   "events",
		DeterministicID: true, // topic name is a deterministic slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return pubsubServer(t, ownedTopic(`"europe-west1"`), 0, 0) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("pubsub-topic", "events", "prod", pubAttrs, nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return pubsubServer(t, ownedTopic(`"europe-west1"`), 0, 0) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("pubsub-topic", "events", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessPubSubQueue certifies the CONSTITUTIVE COMPOSITE (D95): the
// create trace is backing-topic PUT then subscription PUT (both parsed), so an
// ambiguous fault at either mutation must be unknown WITH the deterministic pid
// (a partial never loses the handle). Delete is reverse (subscription then
// topic), each an opaque mutation.
func TestHonestyHarnessPubSubQueue(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "pubsub:acme-prod:the-q"
	queueLabel := sanitizeLabel("orders") // ownership label is the capability ID, not the type
	pubAttrs := map[string]any{
		"location.region":        "europe-west1",
		"network.publicExposure": true,
		"encryption.atRest":      true,
		"delivery.guarantee":     "exactly-once",
		"retention.minimum":      "1h",
		"service.managed":        true,
	}
	p := &certifynet.Probe{
		Name:            "gcp/pubsub-queue",
		AssertTransient: true, // D237
		Classify:        pubsubRole,
		OwnerTagValue:   queueLabel,
		DeterministicID: true, // subscription id is a deterministic slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return pubsubQueueServer(t, queueLabel, "prod") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("pubsub-queue", "orders", "prod", pubAttrs, nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return pubsubQueueServer(t, queueLabel, "prod") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("pubsub-queue", "orders", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// ---- VPC (Compute) ----------------------------------------------------------

func TestHonestyHarnessGCPVPC(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "vpc:acme-prod:europe-central2:app-net-1"
	p := &certifynet.Probe{
		Name:            "gcp/vpc",
		AssertTransient: true, // D237
		Classify:        gcpOpRole,
		OwnerTagValue:   "app-net",
		DeterministicID: true, // network name is a deterministic slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return computeServer(t, "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("vpc", "app-net", "prod", vpcAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return computeServer(t, "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("vpc", "app-net", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessCloudDNS(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "gdns:acme-prod:x"
	p := &certifynet.Probe{
		Name:            "gcp/clouddns",
		AssertTransient: true,       // D237 sweep
		Classify:        secretRole, // GET read; POST create / DELETE opaque (name deterministic)
		OwnerTagValue:   "apex",
		DeterministicID: true, // the managed-zone name is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return dnsServer(t, "apex", "public", "on") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("clouddns", "apex", "prod", dnsAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return dnsServer(t, "apex", "public", "on") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("clouddns", "apex", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// iamBindingRole classifies the RMW IAM-binding protocol: both getIamPolicy and
// setIamPolicy are POSTs, so method alone can't tell them apart — the PATH does.
// getIamPolicy is a read; setIamPolicy is an opaque status-only mutation (its 200
// body is not consumed — success is the status).
func iamBindingRole(req *http.Request, _ []byte) certifynet.Role {
	if strings.HasSuffix(req.URL.Path, ":getIamPolicy") {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

func TestHonestyHarnessIAMBinding(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "gauth:acme-prod:roles/storage.objectViewer:serviceAccount:runner@acme-prod.iam.gserviceaccount.com"
	seed := `{"bindings":[{"role":"roles/storage.objectViewer","members":[` +
		`"serviceAccount:runner@acme-prod.iam.gserviceaccount.com"]}],"etag":"BwXseed"}`
	p := &certifynet.Probe{
		Name:            "gcp/iambinding",
		AssertTransient: true, // D237 sweep
		Classify:        iamBindingRole,
		OwnerTagValue:   "reader", // content-addressed: no tag to poison (foreign-tag n/a)
		DeterministicID: true,     // the pid is (project, role, member)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return crmPolicyServer(t, "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("iambinding", "reader", "prod", authzAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return crmPolicyServer(t, seed) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("iambinding", "reader", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessCustomRole(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := gcRoleProviderID("acme-prod", gcRoleID("prod", "viewer", 1))
	p := &certifynet.Probe{
		Name:            "gcp/customrole",
		AssertTransient: true,       // D237 sweep
		Classify:        secretRole, // GET read; POST create / DELETE opaque (roleId deterministic)
		OwnerTagValue:   "viewer",   // content-addressed by deterministic roleId (foreign-tag n/a)
		DeterministicID: true,
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return customRoleServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("customrole", "viewer", "prod", roleAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return customRoleServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("customrole", "viewer", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessAlertPolicy(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "galert:acme-prod:98765"
	p := &certifynet.Probe{
		Name:            "gcp/monitoring",
		AssertTransient: true,    // D237 sweep
		Classify:        gcsRole, // POST parses the server-assigned id; GET read; DELETE opaque
		OwnerTagValue:   "cpu",
		DeterministicID: false, // the alertPolicy id is server-assigned
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return alertOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("monitoring", "cpu", "prod", alertAttrs(), alertImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return alertOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("monitoring", "cpu", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessDashboard(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "gdash:acme-prod:abc123"
	p := &certifynet.Probe{
		Name:            "gcp/dashboard",
		AssertTransient: true,    // D237 sweep
		Classify:        gcsRole, // POST parses the server-assigned id; GET read; DELETE opaque
		OwnerTagValue:   "golden",
		DeterministicID: false, // the dashboard id is server-assigned
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return dashOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("dashboard", "golden", "prod", dashAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return dashOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("dashboard", "golden", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessUptimeCheck(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "guptime:acme-prod:xyz789"
	p := &certifynet.Probe{
		Name:            "gcp/uptime",
		AssertTransient: true,    // D237 sweep
		Classify:        gcsRole, // POST parses the server-assigned id; GET read; DELETE opaque
		OwnerTagValue:   "api",
		DeterministicID: false, // the config id is server-assigned
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return uptimeOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("uptime", "api", "prod", uptimeAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return uptimeOwnedServer(t) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("uptime", "api", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessLogMetric(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "glogmetric:acme-prod:app_error_count"
	p := &certifynet.Probe{
		Name:            "gcp/logmetric",
		AssertTransient: true,       // D237 sweep
		Classify:        secretRole, // GET read; POST create / DELETE opaque (name is the id)
		OwnerTagValue:   "errors",
		DeterministicID: true, // the metric name is the id
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return logMetricServer(t, "groundhold-managed errors (prod)") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("logmetric", "errors", "prod", logMetricAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return logMetricServer(t, "groundhold-managed errors (prod)") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("logmetric", "errors", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessARRepo(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "gar:acme-prod:europe-west1:pv-images-prod-abcd1234"
	p := &certifynet.Probe{
		Name:            "gcp/artifactregistry",
		AssertTransient: true,      // D237 sweep
		Classify:        gcpOpRole, // LRO create/delete parse the operation name
		OwnerTagValue:   "images",
		DeterministicID: true, // the repo id is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := newGcpHonestyDriver(happyURL, rt)
			d.PollInterval = 0
			return d
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return arServer(t, "images", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("artifactregistry", "images", "prod", arAttrs(), arImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return arServer(t, "images", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("artifactregistry", "images", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessFilestore(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "filestore:acme-prod:europe-west1:x"
	p := &certifynet.Probe{
		Name:            "gcp/filestore",
		AssertTransient: true, // D237 sweep
		Classify:        gcpOpRole,
		OwnerTagValue:   "shared",
		DeterministicID: true, // the instance id is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return filestoreServer(t, "shared", "ENTERPRISE", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("filestore", "shared", "prod", fsAttrs(), fsImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return filestoreServer(t, "shared", "ENTERPRISE", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("filestore", "shared", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// create/delete parse the operation name (gcpOpRole -> RoleMutateParsed), so an
// ambiguous fault at either mutation must be unknown WITH the deterministic,
// content-addressed providerId. Firestore has no labels, so the foreign-tag
// ownership test is n/a (ownership is the databaseId itself).
func TestHonestyHarnessFirestore(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := firestoreProviderID("acme-prod", FirestoreDatabaseID("acme-prod", "prod", "sessions", 1))
	p := &certifynet.Probe{
		Name:            "gcp/firestore",
		AssertTransient: true, // D237 sweep
		Classify:        gcpOpRole,
		OwnerTagValue:   "sessions", // tagless: never appears in a response, so foreign-tag is n/a
		DeterministicID: true,       // the databaseId is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return firestoreServer(t, "europe-west1", true, false, "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("firestore", "sessions", "prod", firestoreAttrs(), firestoreImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return firestoreServer(t, "europe-west1", true, false, "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("firestore", "sessions", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessManagedKafka certifies the Managed Kafka driver (D115): LRO
// create/delete parse the operation name (gcpOpRole -> RoleMutateParsed), so an
// ambiguous fault at either mutation is unknown WITH the deterministic providerId.
func TestHonestyHarnessManagedKafka(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := managedKafkaProviderID("acme-prod", "europe-west1", ManagedKafkaClusterID("acme-prod", "prod", "bus", 1))
	p := &certifynet.Probe{
		Name:            "gcp/managedkafka",
		AssertTransient: true, // D237 sweep
		Classify:        gcpOpRole,
		OwnerTagValue:   "bus",
		DeterministicID: true, // the clusterId is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return mkafkaServer(t, "bus", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("managedkafka", "bus", "prod", mkafkaAttrs(), mkafkaImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return mkafkaServer(t, "bus", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("managedkafka", "bus", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessCertManager certifies the Certificate Manager driver (D117):
// LRO create/delete parse the operation name (gcpOpRole -> RoleMutateParsed), so an
// ambiguous fault is unknown WITH the deterministic providerId. Ownership is labels.
func TestHonestyHarnessCertManager(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := certManagerProviderID("acme-prod", "global", CertManagerCertID("acme-prod", "prod", "web", 1))
	p := &certifynet.Probe{
		Name:            "gcp/certmanager",
		AssertTransient: true, // D237 sweep
		Classify:        gcpOpRole,
		OwnerTagValue:   "web",
		DeterministicID: true, // the certificateId is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return cmServer(t, "web", "app.example.com") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("certmanager", "web", "prod", cmAttrs(), cmImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return cmServer(t, "web", "app.example.com") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("certmanager", "web", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessCloudRunJob certifies the Cloud Run Jobs driver (D120): LRO
// create/delete parse the operation name (gcpOpRole -> RoleMutateParsed), so an
// ambiguous fault is unknown WITH the deterministic providerId. Ownership is labels.
func TestHonestyHarnessCloudRunJob(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := cloudRunJobProviderID("acme-prod", "europe-west1", resourceName("acme-prod", "prod", "worker", 1, 63))
	p := &certifynet.Probe{
		Name:            "gcp/cloudrunjobs",
		AssertTransient: true, // D237 sweep
		Classify:        gcpOpRole,
		OwnerTagValue:   "worker",
		DeterministicID: true, // the jobId is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return crjServer(t, "worker", "gcr.io/proj/worker:1.2", "600s") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudrunjobs", "worker", "prod", crjAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return crjServer(t, "worker", "gcr.io/proj/worker:1.2", "600s") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudrunjobs", "worker", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestHonestyHarnessGServiceAccount certifies the service-account driver (D121):
// synchronous create (secretRole — GET read, POST/DELETE opaque, accountId
// deterministic). Ownership is a DESCRIPTION MARKER, so the foreign-tag test poisons
// the marker on the reads.
func TestHonestyHarnessGServiceAccount(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := gsaProviderID("acme-prod", GServiceAccountID("acme-prod", "prod", "runner", 1))
	p := &certifynet.Probe{
		Name:            "gcp/serviceaccount",
		AssertTransient: true, // D237 sweep
		Classify:        secretRole,
		OwnerTagValue:   "runner", // appears in the description marker
		DeterministicID: true,     // the accountId is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return gsaServer(t, "runner", "batch-runner") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("serviceaccount", "runner", "prod", gsaAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return gsaServer(t, "runner", "batch-runner") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("serviceaccount", "runner", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessBigQuery(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := bqProviderID("acme-prod", BQDatasetID("acme-prod", "prod", "lake", 1))
	p := &certifynet.Probe{
		Name:            "gcp/bigquery",
		AssertTransient: true,       // D237 sweep
		Classify:        secretRole, // sync REST: GET read, POST/DELETE opaque (id deterministic)
		OwnerTagValue:   "lake",
		DeterministicID: true, // the dataset id is a chosen slug+hash
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return bqServer(t, "lake", "US", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("bigquery", "lake", "prod", bqAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return bqServer(t, "lake", "US", "") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("bigquery", "lake", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

func TestHonestyHarnessCloudKMS(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	pid := "gkms:acme-prod:europe-west1:groundhold-prod:x"
	p := &certifynet.Probe{
		Name:            "gcp/cloudkms",
		AssertTransient: true,       // D237 sweep
		Classify:        secretRole, // GET read; keyRing/cryptoKey POST + destroy opaque
		OwnerTagValue:   "datakey",
		DeterministicID: true, // ring + key names are chosen
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newGcpHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return kmsServer(t, "datakey", "HSM", "2592000s") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("cloudkms", "datakey", "prod", kmsAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return kmsServer(t, "datakey", "HSM", "2592000s") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("cloudkms", "datakey", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// --- D266 cross-driver honesty gates for the GKE cluster driver ---

// gkeRole classifies GKE REST-JSON (container v1) requests structurally for the
// read-storm / bounded-poll gates: a GET is a read, everything else a mutation.
// Mirrors aws.eksRole.
func gkeRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestReadStormGKE enrolls GKE in the cross-driver read-retry gate (D266): a
// greenfield create whose first reads throttle must still succeed, because the
// ownership pre-read rides the transient class out via gcpGetRetry. A regression
// dropping the retry fails here (the Acme D260 class). GKE points its container
// endpoint at the happy server via the gkeBaseURLOverride package var (see
// gke_net.go), not a Driver field, so New sets it and a Cleanup resets it.
func TestReadStormGKE(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "tok")
	name := gkePlanName(t)
	attrs, impl := gkeCandidate()
	t.Cleanup(func() { gkeBaseURLOverride = "" })
	p := &certifynet.Probe{
		Name:     "gcp/gke",
		Classify: gkeRole,
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("test-proj")
			d.HTTP = &http.Client{Transport: rt}
			gkeBaseURLOverride = happyURL
			d.PollInterval = 0
			d.PollTimeout = 2 * time.Second
			d.GKELROTimeout = 2 * time.Second
			return d
		},
		Ops: []certifynet.Op{{
			Name: "create",
			Happy: func() *httptest.Server {
				return httptest.NewServer(newFakeGKE(name, "europe-west1").handler())
			},
			Run: func(pr provider.Provider) provider.CreateResult {
				return pr.Create("gke", gkeCap, "prod", attrs, impl, "k", 1)
			},
		}},
	}
	certifynet.CertifyReadRetry(t, p)
}

// TestBoundedPollGKE enrolls GKE in the bounded-poll gate (D266): a cluster whose
// control plane never leaves PROVISIONING must conclude unknown-with-pid within
// the LRO budget, never hang and never fabricate success (the D258/D259 phantom-
// poll class). newFakeGKE's readiness field is `status`; the driver waits for
// "RUNNING" (gkeHealthy), so "PROVISIONING" is neither ready nor a terminal
// failure.
func TestBoundedPollGKE(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "tok")
	name := gkePlanName(t)
	attrs, impl := gkeCandidate()
	t.Cleanup(func() { gkeBaseURLOverride = "" })
	p := &certifynet.LifecycleProbe{
		Name: "gcp/gke",
		StuckServer: func() *httptest.Server {
			f := newFakeGKE(name, "europe-west1")
			f.status = "PROVISIONING" // control plane never reaches RUNNING
			return httptest.NewServer(f.handler())
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("test-proj")
			d.HTTP = &http.Client{Transport: rt}
			gkeBaseURLOverride = happyURL
			d.PollInterval = 0
			d.PollTimeout = time.Second
			d.GKELROTimeout = time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("gke", gkeCap, "prod", attrs, impl, "k", 1)
		},
		PID: gkeProviderID("test-proj", "europe-west1", name),
	}
	certifynet.CertifyBoundedPoll(t, p)
}

// TestNoDuplicateGKE enrolls GKE in the no-duplicate gate (D267): a candidate that
// names a cluster to adopt (implementation.clusterName) which does NOT exist must
// refuse, sending zero mutations — never a duplicate (the Acme D261 root cause,
// mirrored from AWS EKS). AbsentServer serves a fake where the named cluster 404s.
func TestNoDuplicateGKE(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "tok")
	attrs, impl := gkeAdoptByNameCandidate("acme")
	t.Cleanup(func() { gkeBaseURLOverride = "" })
	p := &certifynet.DuplicateProbe{
		Name:     "gcp/gke",
		Classify: gkeRole,
		AbsentServer: func() *httptest.Server {
			return httptest.NewServer(newFakeGKENamed("acme", "europe-west1", false, false).handler())
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("test-proj")
			d.HTTP = &http.Client{Transport: rt}
			gkeBaseURLOverride = happyURL
			d.PollInterval = 0
			d.PollTimeout = time.Second
			d.GKELROTimeout = time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("gke", gkeCap, "prod", attrs, impl, "k", 1)
		},
	}
	certifynet.CertifyNoDuplicate(t, p)
}
