package gcp

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"time"

	"strings"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// D415: the GCP fixtures are uniform — a happy server that answers the create and then
// describes the resource with our labels on every GET. The estate an adoption meets is
// that same server with ONE difference: the create is refused as already-existing.
//
// Writing that difference out by hand per driver meant re-copying forty lines of fake and
// getting the wire shape subtly wrong (the AWS sweep did exactly that, three times). So
// the difference is expressed once: wrap the driver's own happy fixture and answer 409 to
// the request that creates. Everything else — the reads the adoption path performs, the
// exact document shape, the label spellings — stays the fixture the driver's own tests
// already trust, which is the point: the estate is real, only the create outcome changed.
func conflictOnCreate(t *testing.T, inner *httptest.Server, isCreate func(*http.Request) bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		if isCreate(r) {
			// Let the inner fixture SEE the create before refusing it. A stateful fake
			// (customrole echoes back the permission set it was given) only describes a
			// standing resource once something created it — and in the estate being
			// modelled, something did: a previous run. Discarding the response and
			// answering 409 is what the driver would meet on its re-run.
			inner.Config.Handler.ServeHTTP(httptest.NewRecorder(), r)
			r.Body = io.NopCloser(bytes.NewReader(body))
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":{"code":409,"status":"ALREADY_EXISTS",` +
				`"message":"resource already exists"}}`))
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(func() { srv.Close(); inner.Close() })
	return srv
}

// gcpReadRole: GET is the ownership read on every GCP surface in this package; the
// :getIamPolicy and :testIamPermissions POSTs are reads wearing a POST.
func gcpReadRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	switch {
	case hasSuffix(req.URL.Path, ":getIamPolicy"), hasSuffix(req.URL.Path, ":testIamPermissions"):
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

func hasSuffix(s, suf string) bool { return len(s) >= len(suf) && s[len(s)-len(suf):] == suf }

// postCreate is the common "this request creates" predicate: a POST to a collection.
// GCP's `:verb` suffixes are method calls on an EXISTING resource — getIamPolicy reads
// it, setIamPolicy writes its policy — so none of them is the create, and refusing one
// models a conflict on a follow-up write rather than a resource that already exists.
// Cloud Run taught this: with :setIamPolicy refused, the driver reported "public
// exposure: setIamPolicy HTTP 409", which is a true statement about a false estate.
func postCreate(r *http.Request) bool {
	return r.Method == http.MethodPost && !strings.Contains(r.URL.Path, ":")
}

// ---- D415 enrolments: five GCP services, each against its OWN happy fixture with the
// create refused. The estate is the one the driver's existing tests already trust.

func TestAdoptsExistingMemorystore(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/memorystore",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			return conflictOnCreate(t, redisServer(t, "sessions", "STANDARD_HA", "SERVER_AUTHENTICATION", ""), postCreate)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.MemorystoreBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("memorystore", "sessions", "prod", redisAttrs(), redisImpl(), "k", 1)
		},
		AllowedMutations: 1,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func TestAdoptsExistingFilestore(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/filestore",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			// D1048: the existing instance must serve the SAME customer key fsImpl declares,
			// or the 409-adopt correctly refuses (a key mismatch is not a match to adopt).
			return conflictOnCreate(t, filestoreServer(t, "shared", "ENTERPRISE",
				"projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k"), postCreate)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.FilestoreBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("filestore", "shared", "prod", fsAttrs(), fsImpl(), "k", 1)
		},
		AllowedMutations: 1,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func TestAdoptsExistingCloudDNS(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/clouddns",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			return conflictOnCreate(t, dnsServer(t, "apex", "public", "on"), postCreate)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.DNSBaseURL = happyURL
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("clouddns", "apex", "prod", dnsAttrs(), nil, "k", 1)
		},
		AllowedMutations: 1,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func TestAdoptsExistingCloudKMS(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/cloudkms",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			return conflictOnCreate(t, kmsServer(t, "datakey", "HSM", "7776000s"), postCreate)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.KMSBaseURL = happyURL
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("cloudkms", "datakey", "prod", kmsAttrs(), nil, "k", 1)
		},
		AllowedMutations: 2, // key ring + key: two creates, both refused as existing
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func TestAdoptsExistingCloudScheduler(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/cloudscheduler",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			return conflictOnCreate(t, schedServer(t, "nightly", "ENABLED"), postCreate)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.SchedulerBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("cloudscheduler", "nightly", "prod", schedAttrs(), schedImpl(), "k", 1)
		},
		AllowedMutations: 1,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D416: eight more on the same wrapper. Capability names and fixture arguments are
// copied from each driver's own happy test, so the estate is theirs, not a second guess.

type adoptCase struct {
	svc, cap  string
	server    func(t *testing.T) *httptest.Server
	base      func(d *Driver, url string)
	attrs     func() map[string]any
	impl      func() map[string]any
	mutations int
	// isCreate overrides postCreate for a service whose create is not a POST.
	// D546: Pub/Sub creates its topic with PUT, so the shared POST-only predicate
	// never fired, the conflict wrapper let the create through, and the probe
	// exercised a clean CREATE while claiming to test adoption.
	isCreate func(*http.Request) bool
}

func runAdoptCase(t *testing.T, c adoptCase) {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	var im map[string]any
	if c.impl != nil {
		im = c.impl()
	}
	p := &certifynet.ExistingProbe{
		Name:     "gcp/" + c.svc,
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			mk := c.isCreate
			if mk == nil {
				mk = postCreate
			}
			return conflictOnCreate(t, c.server(t), mk)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			c.base(d, happyURL)
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create(c.svc, c.cap, "prod", c.attrs(), im, "k", 1)
		},
		AllowedMutations: c.mutations,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func TestAdoptsExistingCertManager(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "certmanager", cap: "web",
		server: func(t *testing.T) *httptest.Server { return cmServer(t, "web", "example.com") },
		base:   func(d *Driver, u string) { d.CertManagerBaseURL = u },
		attrs:  cmAttrs, impl: cmImpl, mutations: 2})
}

func TestAdoptsExistingFirestore(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "firestore", cap: "sessions",
		server: func(t *testing.T) *httptest.Server { return firestoreServer(t, "eur3", true, true, "") },
		base:   func(d *Driver, u string) { d.FirestoreBaseURL = u },
		attrs:  firestoreAttrs, impl: firestoreImpl, mutations: 2})
}

func TestAdoptsExistingCustomRole(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "customrole", cap: "viewer",
		server: func(t *testing.T) *httptest.Server { return customRoleServer(t) },
		base:   func(d *Driver, u string) { d.IAMBaseURL = u },
		attrs:  roleAttrs, mutations: 1})
}

func TestAdoptsExistingLogMetric(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "logmetric", cap: "errors",
		server: func(t *testing.T) *httptest.Server { return logMetricServer(t, logMetricDescription("errors", "prod")) },
		base:   func(d *Driver, u string) { d.LoggingBaseURL = u },
		attrs:  logMetricAttrs, mutations: 1})
}

func TestAdoptsExistingServiceAccount(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "serviceaccount", cap: "runner",
		server: func(t *testing.T) *httptest.Server { return gsaServer(t, "runner", "runner sa") },
		base:   func(d *Driver, u string) { d.IAMBaseURL = u },
		attrs:  gsaAttrs, mutations: 1})
}

func TestAdoptsExistingCloudArmor(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "cloudarmor", cap: "edge",
		server: func(t *testing.T) *httptest.Server { return armorServer(t, "edge", true, true, false) },
		base:   func(d *Driver, u string) { d.ComputeBaseURL = u },
		attrs:  armorAttrs, mutations: 2})
}

func TestAdoptsExistingManagedKafka(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "managedkafka", cap: "bus",
		server: func(t *testing.T) *httptest.Server { return mkafkaServer(t, "bus", "") },
		base:   func(d *Driver, u string) { d.ManagedKafkaBaseURL = u },
		attrs:  mkafkaAttrs, impl: mkafkaImpl, mutations: 1})
}

func TestAdoptsExistingCloudRunJob(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "cloudrunjobs", cap: "worker",
		server: func(t *testing.T) *httptest.Server { return crjServer(t, "worker", "img", "600s") },
		base:   func(d *Driver, u string) { d.RunBaseURL = u },
		attrs:  crjAttrs, mutations: 2})
}

// ---- D417: six more. Each fixture argument is copied from that driver's own happy
// test, including the ownership marker — the D416 lesson: a fixture's ownership evidence
// must be the one the driver writes, not a plausible-looking substitute.

func TestAdoptsExistingLogBucket(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "logbucket", cap: "flowlogs",
		server: func(t *testing.T) *httptest.Server {
			return logBucketServer(t, fakeLogBucket{
				description: "groundhold-managed flowlogs (prod)", retentionDays: 90}, nil)
		},
		base:  func(d *Driver, u string) { d.LoggingBaseURL = u },
		attrs: logBucketAttrs, mutations: 2})
}

// TestAdoptsExistingUptimeCheck and TestAdoptsExistingDashboard: both ids are
// SERVER-assigned, so D255 gave them a pre-scan by displayName rather than a 409 branch —
// the create is never even attempted when the check is already there. Their own happy
// fixtures create fresh, so the LIST they serve is empty and the adoption path had no
// test at all. These fixtures serve the list envelope findByDisplayName reads.
func TestAdoptsExistingUptimeCheck(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	name := resourceName("acme-prod", "prod", "api", 1, 63)
	runAdoptCase(t, adoptCase{svc: "uptime", cap: "api",
		server: func(t *testing.T) *httptest.Server {
			return listingServer(t, "uptimeCheckConfigs",
				"projects/acme-prod/uptimeCheckConfigs/xyz789", name)
		},
		base:  func(d *Driver, u string) { d.UptimeBaseURL = u },
		attrs: uptimeAttrs, mutations: 0}) // never attempts a create at all
}

func TestAdoptsExistingDashboard(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	runAdoptCase(t, adoptCase{svc: "dashboard", cap: "golden",
		server: func(t *testing.T) *httptest.Server {
			return listingServer(t, "dashboards",
				"projects/acme-prod/dashboards/dash-1", dashDisplayName("golden", "prod"))
		},
		base:  func(d *Driver, u string) { d.DashboardBaseURL = u },
		attrs: dashAttrs, mutations: 0})
}

func TestAdoptsExistingVPC(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "vpc", cap: "app-net",
		server: func(t *testing.T) *httptest.Server { return computeServer(t, "") },
		base:   func(d *Driver, u string) { d.ComputeBaseURL = u },
		attrs:  vpcAttrs, mutations: 4})
}

func TestAdoptsExistingAssetFeed(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "assetfeed", cap: "changefeed",
		server: func(t *testing.T) *httptest.Server {
			srv, _ := assetFeedServer(t, "projects/acme-prod/topics/infra-changes")
			return srv
		},
		base:  func(d *Driver, u string) { d.AssetFeedBaseURL = u; d.ProjNumber = "12345" },
		attrs: assetFeedAttrs, mutations: 1})
}

// listingServer serves the LIST envelope findByDisplayName reads (D255 adoption), with
// one item already carrying our deterministic displayName. A create reaching it is a
// failure: the scan should have bound first.
func listingServer(t *testing.T, arrayKey, name, displayName string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"` + arrayKey + `":[{"name":"` + name +
				`","displayName":"` + displayName + `"}]}`))
			return
		}
		t.Errorf("create-adoption must not %s %s — the displayName scan should have bound "+
			"the standing resource", r.Method, r.URL.Path)
		w.WriteHeader(400)
	}))
}

// ---- D418: pubsub-topic and gcs. Both already had a conflict fixture written for
// another purpose; the adoption case is the one those fixtures never asserted.

// TestAdoptsExistingPubSubTopic: a topic PUT is answered 409 and the driver reads the
// standing topic's labels. pubsubConflictServer already existed for the UNREADABLE and
// FOREIGN cases (both refusals); the ours case is the one every re-converge takes.
func TestAdoptsExistingPubSubTopic(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/pubsub-topic",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			return pubsubConflictServer(t, 200,
				`{"name":"projects/acme-prod/topics/the-topic",`+
					`"messageStoragePolicy":{"allowedPersistenceRegions":["europe-west1"]},`+
					`"labels":{"groundhold-capability":"events","groundhold-environment":"prod"}}`)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.PubSubBaseURL = happyURL
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("pubsub-topic", "events", "prod", pubsubAttrs(), nil, "k", 1)
		},
		AllowedMutations: 1, // the refused PUT
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// TestAdoptsExistingGCS: the bucket exists in OUR project. GCS is the one GCP service
// whose ownership proof is NOT labels — bucket names are a global namespace and labels
// are forgeable cross-project, so the authoritative check is the live projectNumber
// (D82). The fixture pins the project number the driver was given.
func TestAdoptsExistingGCS(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/gcs",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPost && !hasSuffix(r.URL.Path, "/iam"):
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write([]byte(`{"error":{"code":409,"message":"already own it"}}`))
				case hasSuffix(r.URL.Path, "/iam") && r.Method == http.MethodGet:
					_, _ = w.Write([]byte(`{"etag":"e1","version":3,"bindings":[]}`))
				case r.Method == http.MethodGet:
					_, _ = w.Write([]byte(`{"name":"pv-assets-prod-x","projectNumber":"111",` +
						`"location":"EUROPE-WEST1","versioning":{"enabled":true},` +
						`"iamConfiguration":{"publicAccessPrevention":"enforced",` +
						`"uniformBucketLevelAccess":{"enabled":true}},` +
						`"labels":{"groundhold-capability":"assets","groundhold-environment":"prod"}}`))
				default:
					w.WriteHeader(404)
				}
			}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.GcsBaseURL = happyURL
			d.ProjNumber = "111" // pre-resolved (D82): the authoritative ownership proof
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("gcs", "assets", "prod", gcsAdoptAttrs(), nil, "k", 1)
		},
		AllowedMutations: 1, // the refused create
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func gcsAdoptAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-west1",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"versioning.enabled":     true,
		"service.managed":        true,
	}
}

// ---- D419: billingbudget and backupplan, both stateful fixtures the wrapper can seed.

// TestAdoptsExistingBillingBudget: the driver's guard is a pre-scan by displayName,
// with the same recovery repeated on a lost response and on a 5xx — its own comment
// explains why ("GCP does not dedupe on display name — this is the only guard against a
// duplicate on a retried create"). So the estate it actually meets is one where the LIST
// already carries our budget, not one where a create is refused; the fixture models that.
//
// Checked while here: 409 is the ONE create outcome with no re-list. Given the comment
// above, that branch may be unreachable for budgets — GCP will not 409 a display-name
// collision it does not dedupe on. Recorded rather than "fixed", because a defence
// against an outcome the API does not produce is a guess dressed as caution.
func TestAdoptsExistingBillingBudget(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "billingbudget", cap: "cost",
		server: func(t *testing.T) *httptest.Server { return budgetListingServer(t) },
		base: func(d *Driver, u string) {
			billingBudgetsBaseURLOverride = u
			t.Cleanup(func() { billingBudgetsBaseURLOverride = "" })
		},
		attrs: budgetAttrs, impl: budgetImpl, mutations: 0}) // never attempts a create
}

func TestAdoptsExistingBackupPlanGCP(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "backupplan", cap: "nightly",
		server: func(t *testing.T) *httptest.Server { return gbpServer(t, "nightly") },
		base:   func(d *Driver, u string) { d.BackupDRBaseURL = u },
		attrs:  gbpAttrs, impl: gbpImpl, mutations: 1})
}

// budgetListingServer: the billing account already carries OUR budget, so the
// displayName scan binds it and no create is attempted.
func budgetListingServer(t *testing.T) *httptest.Server {
	t.Helper()
	name := "billingAccounts/" + testBillingAccount + "/budgets/budget-abc123"
	display := BillingBudgetDisplayName("prod", "cost", 1)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case hasSuffix(r.URL.Path, "/billingInfo") && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"billingAccountName":"billingAccounts/` + testBillingAccount +
				`","billingEnabled":true}`))
		case r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"budgets":[{"name":"` + name + `","displayName":"` + display + `"}]}`))
		default:
			t.Errorf("create-adoption must not %s %s — the displayName scan should have bound "+
				"the standing budget", r.Method, r.URL.Path)
			w.WriteHeader(400)
		}
	}))
}

// ---- D420: one enrolled of four attempted. cloudfunctions and loadbalancer were left on the
// ratchet: the first routes its IAM read to a base this probe does not redirect (a 401
// escaping the fake, which the D391 account-pin rule exists to forbid), the second is a
// composite whose address create the wrapper refuses without the fixture then describing
// it. Both need a fixture built for the estate rather than borrowed, and an enrolment
// that cannot honestly model the estate is worth less than the debt line it removes.
//
// gke-workloadidentity joins iambinding for the reason D417 gave: its "create" IS a
// setIamPolicy write, so a refusal models an etag conflict — a concurrent edit — and not
// a binding that already exists. Two services now wait on the same missing fixture shape,
// which is a better description of that debt than two separate unexplained lines.

func TestAdoptsExistingDNSRecord(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "clouddnsrecord", cap: dnsRecordCap,
		server: func(t *testing.T) *httptest.Server {
			return dnsRecordServer(t, sanitizeLabel(dnsRecordCap))
		},
		base:  func(d *Driver, u string) { d.DNSBaseURL = u },
		attrs: dnsRecordAttrs, impl: dnsRecordImpl, mutations: 1})
}

// ---- D421: the two policy-write services, with the estate they actually meet.
//
// D417 and D420 left iambinding and gke-workloadidentity on the ratchet because the
// conflictOnCreate wrapper modelled the wrong thing: their "create" IS a setIamPolicy
// write, so refusing it produces an etag conflict — a concurrent edit — rather than a
// binding that already exists. The estate they meet is a POLICY THAT ALREADY CONTAINS
// the binding, and both drivers have an explicit branch for it that returns succeeded
// having written nothing. So the property holds at ZERO mutations, which is its
// strongest form, and no wrapper is involved at all.

func TestAdoptsExistingIAMBinding(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	seed := `{"etag":"BwXseed","bindings":[{"role":"roles/storage.objectViewer",` +
		`"members":["serviceAccount:runner@acme-prod.iam.gserviceaccount.com"]}]}`
	p := &certifynet.ExistingProbe{
		Name:           "gcp/iambinding",
		Classify:       gcpReadRole,
		ExistingServer: func() *httptest.Server { return crmPolicyServer(t, seed) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.CRMBaseURL = happyURL
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("iambinding", "reader", "prod", authzAttrs(), nil, "k", 1)
		},
		// zero: the member is already in the role, so nothing is written at all
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func TestAdoptsExistingWorkloadIdentity(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/gke-workloadidentity",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			return saPolicyServer(t, &iamPolicy{Etag: "BwXseed", Bindings: []iamPolicyBinding{
				{Role: wiRole, Members: []string{wiMember("acme-prod", "default", "app-sa")}},
			}}, false)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.IAMBaseURL = happyURL
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("gke-workloadidentity", "runner", "prod", wiAttrs(), wiImpl(), "k", 1)
		},
		PID: wiPID(),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D422: cloudrun and auditlogs.

func TestAdoptsExistingCloudRun(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "cloudrun", cap: "be",
		server: func(t *testing.T) *httptest.Server {
			return runServer(t, map[string]string{
				"groundhold-capability": "be", "groundhold-environment": "prod"},
				"INGRESS_TRAFFIC_ALL", 200, "")
		},
		base:      func(d *Driver, u string) { d.RunBaseURL = u },
		attrs:     publicAttrs,
		impl:      func() map[string]any { return map[string]any{"image": "img"} },
		mutations: 2}) // the refused create + the public-invoker grant it re-asserts
}

// TestAdoptsExistingAuditLogs: a log sink is name-addressed and carries its ownership in
// the DESCRIPTION, like logmetric (D416) — sinks take no labels. The fixture's own
// description helper is used rather than a plausible substitute, which is the whole
// lesson of that entry.
func TestAdoptsExistingAuditLogs(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "auditlogs", cap: "capability.audit.trail",
		server: func(t *testing.T) *httptest.Server {
			srv, _, _ := auditSinkServer(t, false)
			return srv
		},
		base: func(d *Driver, u string) {
			auditLogsBaseURLOverride = u
			t.Cleanup(func() { auditLogsBaseURLOverride = "" })
		},
		attrs: auditAttrs, impl: auditImpl, mutations: 2})
}

// ---- D423: scc, whose "create" is a settings PATCH.
//
// Security Command Center has no create at all: the modules exist for the project by
// definition and a converge PATCHes their intended state. So the estate a re-converge
// meets is one where the modules ALREADY carry the state the contract asks for, and the
// property is that the driver recognises it — the same shape as the AWS upsert family
// (D408), reached from a different direction.
func TestAdoptsExistingSCC(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/scc",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			// the estate a re-converge meets: the modules already carry the state
			// the contract asks for (enabled + kubernetes, malware off)
			return newFakeSCC("ENABLED", "ENABLED", "DISABLED").handler(t)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			sccBaseURLOverride = happyURL
			t.Cleanup(func() { sccBaseURLOverride = "" })
			d := NewDriver(sccProject)
			d.HTTP = &http.Client{Transport: rt}
			d.PollInterval = time.Millisecond
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("scc", sccCap, "prod", sccAttrs(true, true, false), sccImpl(), "k", 1)
		},
		AllowedMutations: 2, // the module PATCHes that assert the intended state
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D424: vertexai. Its endpoint id is server-assigned, so like uptime and dashboard
// (D417) the guard has to be a pre-scan; the fake's LIST route already serves the
// standing endpoint and its labels decide.
func TestAdoptsExistingVertexAI(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/vertexai",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			f := &fakeVertex{loc: vtxRegion, labels: groundholdLabels()}
			srv := httptest.NewServer(f.handler(t))
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			vertexAIBaseURLOverride = happyURL
			t.Cleanup(func() { vertexAIBaseURLOverride = "" })
			d := NewDriver(vtxProj)
			d.HTTP = &http.Client{Transport: rt}
			d.PollInterval = 0
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("vertexai", vtxCap, "prod",
				map[string]any{"location.region": vtxRegion, "service.managed": true},
				map[string]any{"displayName": "claude-eu",
					"publisherModel": "publishers/anthropic/models/claude"}, "k", 1)
		},
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D425: gke-addon, the fourth create-shape: an addon is a FIELD on a cluster that
// already exists, so "create" is an update and "already there" is the addon already
// enabled. The driver's own branch says so — "idempotent — already enabled".
func TestAdoptsExistingGKEAddon(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/gke-addon",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			return gkeAddonServer(t, true, true) // already enabled on a cluster that exists
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			gkeAddonBaseOverride = happyURL
			t.Cleanup(func() { gkeAddonBaseOverride = "" })
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			d.GKELROTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("gke-addon", "csi", "prod", gkeAddonAttrs(), gkeAddonImpl(), "k", 1)
		},
		// zero: an addon already enabled needs no update at all
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D425 (cont): pd. The disk name is deterministic and a 409 is answered by reading
// the standing disk's labels — and the driver says exactly why that check has to be
// there: "otherwise we would bind a stranger's DATA to this contract, and put our delete
// gate over it". Adopting the wrong disk is worse than duplicating one.
func TestAdoptsExistingPersistentDisk(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/pd",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			s := &pdServer{insertStatus: http.StatusConflict, getStatus: http.StatusOK,
				getBody: ownedRegionalDisk}
			srv := httptest.NewServer(s.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.ComputeBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("pd", "orders-data", "production", pdAttrs(), pdImpl(), "k", 1)
		},
		AllowedMutations: 1, // the refused insert
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D426: mig. Same shape as pd, same reasoning in the driver's own words — "we would
// bind a stranger's FLEET to this contract, and put our delete over it" — except the
// ownership marker is the DESCRIPTION rather than labels, because an instance group
// manager takes none. Fourth GCP service to put its ownership somewhere other than labels.
func TestAdoptsExistingMIG(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/mig",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			s := &migServer{
				insertStatus: http.StatusConflict, getStatus: http.StatusOK,
				getBody:      migOwnedDoc(),
				autoStatus:   http.StatusOK,
				autoListBody: migAutoscalerList(),
				templateBody: migPrivateTemplate,
				opBody:       `{"status":"DONE"}`,
			}
			srv := httptest.NewServer(s.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.ComputeBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 50 * time.Millisecond
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("mig", "web-fleet", "production", migAttrs(), migImpl(), "k", 1)
		},
		AllowedMutations: 2, // the refused insert + the autoscaler assert
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D426 (cont): gce. Same 409-then-labels shape as pd, and the same reason in the
// driver's words: "otherwise we would bind a stranger's machine to this contract".
func TestAdoptsExistingGCEInstance(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ExistingProbe{
		Name:     "gcp/gce",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			s := &gceServer{
				insertStatus: http.StatusConflict, insertBody: `{"error":{"code":409}}`,
				getStatus: http.StatusOK, getBody: ownedInstance, opBody: gceOpDone,
			}
			srv := httptest.NewServer(s.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.ComputeBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 50 * time.Millisecond
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("gce", "web", "production", gceAttrs(), gceImpl(), "k", 0)
		},
		AllowedMutations: 1, // the refused insert
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D427: monitoring and vpngateway.

// TestAdoptsExistingAlertPolicy: the third D255 pre-scan service after uptime and
// dashboard — a server-assigned id guarded by a displayName scan, so the create is never
// attempted against a standing policy.
func TestAdoptsExistingAlertPolicy(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	runAdoptCase(t, adoptCase{svc: "monitoring", cap: "cpu",
		server: func(t *testing.T) *httptest.Server {
			return listingServer(t, "alertPolicies", "projects/acme-prod/alertPolicies/98765",
				resourceName("acme-prod", "prod", "cpu", 1, 63))
		},
		base:  func(d *Driver, u string) { d.MonitoringBaseURL = u },
		attrs: alertAttrs, impl: alertImpl, mutations: 0})
}

// TestAdoptsExistingCloudVPN: the GCP twin of the AWS vpngateway defect (D409). Worth
// checking rather than assuming symmetry — and unlike its AWS counterpart this one is
// name-addressed, so the 409 arrives and the labels decide.
func TestAdoptsExistingCloudVPN(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "vpngateway", cap: "site",
		server: func(t *testing.T) *httptest.Server { return vpnServer(t, "site", "IPV4_ONLY") },
		base:   func(d *Driver, u string) { d.ComputeBaseURL = u },
		attrs:  vpnAttrs, impl: vpnImpl, mutations: 2})
}

// ---- D427 (cont): pubsub-queue. A queue is a topic plus a subscription, both
// name-addressed, so the wrapper's 409 lands on each in turn and the labels decide.
func TestAdoptsExistingPubSubQueue(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "pubsub-queue", cap: "orders",
		// D546: the topic create is a PUT, not a POST.
		isCreate: func(r *http.Request) bool {
			return r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/topics/")
		},
		server: func(t *testing.T) *httptest.Server { return pubsubQueueServer(t, "orders", "prod") },
		base:   func(d *Driver, u string) { d.PubSubBaseURL = u },
		attrs:  queueAttrs, mutations: 3})
}

// ---- D428: cloudfunctions, the D420 leftover.
//
// It failed then with a 401 from the REAL Google IAM endpoint, and D420 left it on the
// ratchet rather than guessing a second base URL from the error. The reason is worth the
// wait: a Cloud Functions gen2 function's public exposure lives on its BACKING CLOUD RUN
// SERVICE, so the driver reads run.googleapis.com through RunBaseURL while the function
// itself goes through CfBaseURL. A probe that redirects one and not the other leaves its
// fixture mid-create — which is the failure mode the D391 account-pin rule exists to
// forbid, met here through a different door.
func TestAdoptsExistingCloudFunction(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "cloudfunctions", cap: "api",
		server: func(t *testing.T) *httptest.Server { return cfServer(t, "", "ALLOW_ALL") },
		base: func(d *Driver, u string) {
			d.CfBaseURL = u
			d.RunBaseURL = u // the backing service's IAM surface — see above
		},
		attrs: cfAttrs, impl: cfImpl, mutations: 2})
}

// ---- D428 (cont): cloudfunctions-fn, the function-only twin. Its own driver helper sets
// BOTH bases, which is the confirmation that D420's 401 was a probe gap rather than a
// driver one.
func TestAdoptsExistingCloudFunctionFn(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "cloudfunctions-fn", cap: "api",
		server: func(t *testing.T) *httptest.Server { return fnServer(t, true, "ALLOW_ALL") },
		base: func(d *Driver, u string) {
			d.CfBaseURL = u
			d.RunBaseURL = u
		},
		attrs: fnAttrs, impl: fnImpl, mutations: 2})
}

// ---- D429: loadbalancer, the composite the wrapper could not model.
//
// D420 left it here because refusing the address create left the fake unable to describe
// the address — an estate that cannot exist. The reason it could not describe it is that
// lbFake answered every POST by overwriting, so "the name is taken" was not expressible.
// It answers 409 now, as GCP does, and the estate is built the way a real one is: by a
// PREVIOUS CONVERGE. The probe runs the create twice against one fake — the first stands
// the composite up, the second is the re-converge under test.
func TestAdoptsExistingLoadBalancer(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	attrs := map[string]any{"network.publicExposure": true, "service.managed": true}
	fake := newLBFake(t)
	srv := fake.server()
	t.Cleanup(srv.Close)

	// the previous converge
	seed := NewDriver("acme-prod")
	seed.ComputeBaseURL = srv.URL
	if res := seed.Create("loadbalancer", "capability.network.loadbalancer", "prod",
		attrs, nil, "k", 1); res.Status != "succeeded" {
		t.Fatalf("seeding the standing composite failed: %+v", res)
	}

	p := &certifynet.ExistingProbe{
		Name:           "gcp/loadbalancer",
		Classify:       gcpReadRole,
		ExistingServer: func() *httptest.Server { return srv },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.ComputeBaseURL = happyURL
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("loadbalancer", "capability.network.loadbalancer", "prod",
				attrs, nil, "k", 1)
		},
		PID: lbProviderID("acme-prod", "global",
			lbComposeNames("acme-prod", "prod", "capability.network.loadbalancer", 1).ForwardingRule),
		AllowedMutations: 6, // each piece is re-POSTed and answered "already exists"
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D430: backupvault. The GCP twin of the AWS backup vault (D400), and the same
// damage model: a duplicate vault splits the backup estate — the new one is empty and
// looks healthy while the real one goes unmanaged, and the discovery happens at restore.
func TestAdoptsExistingBackupVaultGCP(t *testing.T) {
	runAdoptCase(t, adoptCase{svc: "backupvault", cap: "archive",
		server: func(t *testing.T) *httptest.Server { return bkdrServer(t, "archive", "7776000s") },
		base:   func(d *Driver, u string) { d.BackupDRBaseURL = u },
		attrs:  bkdrAttrs, mutations: 1})
}

// ---- D430 (cont): gke, the last one, and the second driver in the sweep to DECLARE
// that it defers.
//
// I predicted this one would defer like cloudtrail (D398), because its 409 branch returns
// unknown-with-pid and says "reconcile ownership". It does not: the driver BINDS, because
// a cluster of ours already standing is found before the create is ever attempted. The
// 409 branch is the narrower case where the pre-read missed and the API caught it.
//
// Recorded because the prediction was wrong in the safe direction, and because it is the
// only place in this sweep where reading a driver's conflict branch gave a worse answer
// than driving it. GKE also carries the explicit adopt-by-name path (D267, mirroring EKS
// D261) for the brownfield cluster with a custom name.
func TestAdoptsExistingGKE(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "tok")
	name := gkePlanName(t)
	attrs, impl := gkeCandidate()
	p := &certifynet.ExistingProbe{
		Name:     "gcp/gke",
		Classify: gcpReadRole,
		ExistingServer: func() *httptest.Server {
			f := newFakeGKE(name, "europe-west1")
			f.exists = true
			srv := httptest.NewServer(f.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			gkeBaseURLOverride = happyURL
			t.Cleanup(func() { gkeBaseURLOverride = "" })
			d := NewDriver("test-proj")
			d.HTTP = &http.Client{Transport: rt}
			d.PollInterval = 0
			d.PollTimeout = 2 * time.Second
			d.GKELROTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("gke", gkeCap, "prod", attrs, impl, "k", 1)
		},
		AllowedMutations: 1,
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// ---- D451: the GCP delete-ownership register opens with the two services whose only
// evidence is a name, both found by the D443 diagnostic.

func runForeignDeleteGCP(t *testing.T, svc, cap, pid string,
	server func(t *testing.T) *httptest.Server, base func(d *Driver, url string)) {
	t.Helper()
	runForeignDeleteGCPIn(t, "acme-prod", svc, cap, pid, server, base)
}

// runForeignDeleteGCPIn is the same probe against a fake pinned to a different project.
// A fake that serves 404 for the project under test would make the delete report success
// on "already gone" — which is correct behaviour and a vacuous test, so the project must
// line up with the fixture. The probe caught exactly that on gke (D455).
func runForeignDeleteGCPIn(t *testing.T, project, svc, cap, pid string,
	server func(t *testing.T) *httptest.Server, base func(d *Driver, url string)) {
	t.Helper()
	runForeignDeleteGCPCore(t, project, svc, cap, pid, server, base, false)
}

// runForeignDeleteGCPFromID is for the drivers whose ownership evidence is the
// CONTENT-ADDRESSED id itself, with no estate read possible: IAM custom roles and asset
// feeds carry no labels (D451), and a Firestore database id is derived from
// project+environment+capability. Declared per driver rather than tolerated globally,
// because "derived from the id" and "never looked" are indistinguishable from outside.
func runForeignDeleteGCPFromID(t *testing.T, svc, cap, pid string,
	server func(t *testing.T) *httptest.Server, base func(d *Driver, url string)) {
	t.Helper()
	runForeignDeleteGCPCore(t, "acme-prod", svc, cap, pid, server, base, true)
}

func runForeignDeleteGCPCore(t *testing.T, project, svc, cap, pid string,
	server func(t *testing.T) *httptest.Server, base func(d *Driver, url string),
	fromID bool) {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.ForeignProbe{
		Name:          "gcp/" + svc,
		Classify:      gcpReadRole,
		ForeignServer: func() *httptest.Server { return server(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(project)
			d.HTTP = &http.Client{Transport: rt}
			base(d, happyURL)
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Delete: func(pr provider.Provider) provider.CreateResult {
			return pr.Delete(svc, cap, "prod", pid, "k")
		},
		OwnershipFromIDAlone: fromID,
	}
	certifynet.CertifyDeleteRefusesForeign(t, p)
}

// TestRefusesForeignDeleteCustomRoleGCP: a GCP custom role carries NO LABELS — IAM offers
// none — so its deterministic id is the only ownership evidence. Deleting a stranger's
// role revokes every permission it grants, from every principal bound to it, at once.
func TestRefusesForeignDeleteCustomRoleGCP(t *testing.T) {
	runForeignDeleteGCPFromID(t, "customrole", "viewer",
		gcRoleProviderID("acme-prod", "finance_team_readonly"),
		func(t *testing.T) *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("delete must not reach the API for a role outside our naming scheme")
				w.WriteHeader(400)
			}))
			t.Cleanup(srv.Close)
			return srv
		},
		func(d *Driver, u string) { d.IAMBaseURL = u })
}

// TestRefusesForeignDeleteAssetFeed: the driver's own comment reasoned that the feed id
// "lives in groundhold's deterministic namespace (feeds carry no labels)" — and never
// checked that the id is one we would produce.
func TestRefusesForeignDeleteAssetFeed(t *testing.T) {
	runForeignDeleteGCPFromID(t, "assetfeed", "changefeed",
		assetFeedProviderID("acme-prod", "security-team-audit-feed"),
		func(t *testing.T) *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("delete must not reach the API for a feed outside our naming scheme")
				w.WriteHeader(400)
			}))
			t.Cleanup(srv.Close)
			return srv
		},
		func(d *Driver, u string) { d.AssetFeedBaseURL = u })
}

// ---- D452: eight GCP deletes off their own foreign fixtures.

func TestRefusesForeignDeleteARRepo(t *testing.T) {
	runForeignDeleteGCP(t, "artifactregistry", "images",
		"gar:acme-prod:europe-west1:pv-images-prod-abcd1234",
		func(t *testing.T) *httptest.Server { return arServer(t, "someone-else", false) },
		func(d *Driver, u string) { d.ARBaseURL = u; suBaseOverride = u })
}

func TestRefusesForeignDeleteCloudDNS(t *testing.T) {
	runForeignDeleteGCP(t, "clouddns", "apex", "gdns:acme-prod:x",
		func(t *testing.T) *httptest.Server { return dnsServer(t, "someone-else", "public", "off") },
		func(d *Driver, u string) { d.DNSBaseURL = u })
}

func TestRefusesForeignDeleteCloudKMS(t *testing.T) {
	runForeignDeleteGCP(t, "cloudkms", "datakey",
		"gkms:acme-prod:europe-west1:groundhold-prod:x",
		func(t *testing.T) *httptest.Server { return kmsServer(t, "someone-else", "SOFTWARE", "") },
		func(d *Driver, u string) { d.KMSBaseURL = u })
}

func TestRefusesForeignDeleteMemorystore(t *testing.T) {
	runForeignDeleteGCP(t, "memorystore", "sessions", "gredis:acme-prod:europe-west1:x",
		func(t *testing.T) *httptest.Server {
			return redisServer(t, "someone-else", "BASIC", "DISABLED", "")
		},
		func(d *Driver, u string) { d.MemorystoreBaseURL = u })
}

func TestRefusesForeignDeleteSecretGCP(t *testing.T) {
	runForeignDeleteGCP(t, "secretmanager", "dbcreds", "gsecret:acme-prod:x",
		func(t *testing.T) *httptest.Server { return secretServer(t, "someone-else", umReplica) },
		func(d *Driver, u string) { d.SecretBaseURL = u })
}

func TestRefusesForeignDeleteCertManager(t *testing.T) {
	runForeignDeleteGCP(t, "certmanager", "web",
		certManagerProviderID("acme-prod", "global", CertManagerCertID("acme-prod", "prod", "web", 1)),
		func(t *testing.T) *httptest.Server { return cmServer(t, "someone-else", "app.example.com") },
		func(d *Driver, u string) { d.CertManagerBaseURL = u })
}

func TestRefusesForeignDeleteCloudArmor(t *testing.T) {
	runForeignDeleteGCP(t, "cloudarmor", "edge",
		armorProviderID("acme-prod", ArmorPolicyName("acme-prod", "prod", "edge", 1)),
		func(t *testing.T) *httptest.Server {
			return armorServer(t, "someone-else", true, false, false)
		},
		func(d *Driver, u string) { d.ComputeBaseURL = u })
}

func TestRefusesForeignDeleteManagedKafka(t *testing.T) {
	runForeignDeleteGCP(t, "managedkafka", "bus",
		managedKafkaProviderID("acme-prod", "europe-west1",
			ManagedKafkaClusterID("acme-prod", "prod", "bus", 1)),
		func(t *testing.T) *httptest.Server { return mkafkaServer(t, "someone-else", "") },
		func(d *Driver, u string) { d.ManagedKafkaBaseURL = u })
}

// ---- D453: eight more GCP deletes.

func TestRefusesForeignDeleteBigQuery(t *testing.T) {
	runForeignDeleteGCP(t, "bigquery", "lake",
		bqProviderID("acme-prod", BQDatasetID("acme-prod", "prod", "lake", 1)),
		func(t *testing.T) *httptest.Server { return bqServer(t, "someone-else", "US", "") },
		func(d *Driver, u string) { d.BQBaseURL = u })
}

func TestRefusesForeignDeleteBackupVaultGCP(t *testing.T) {
	runForeignDeleteGCP(t, "backupvault", "archive",
		backupDRProviderID("acme-prod", "europe-west1",
			resourceName("acme-prod", "prod", "archive", 1, 63)),
		func(t *testing.T) *httptest.Server { return bkdrServer(t, "someone-else", "7776000s") },
		func(d *Driver, u string) { d.BackupDRBaseURL = u })
}

func TestRefusesForeignDeleteCloudRunJob(t *testing.T) {
	runForeignDeleteGCP(t, "cloudrunjobs", "worker",
		cloudRunJobProviderID("acme-prod", "europe-west1",
			resourceName("acme-prod", "prod", "worker", 1, 63)),
		func(t *testing.T) *httptest.Server { return crjServer(t, "someone-else", "img", "600s") },
		func(d *Driver, u string) { d.RunBaseURL = u })
}

func TestRefusesForeignDeleteCloudScheduler(t *testing.T) {
	runForeignDeleteGCP(t, "cloudscheduler", "nightly",
		schedProviderID("acme-prod", "europe-west1", SchedulerJobID("prod", "nightly", 1)),
		func(t *testing.T) *httptest.Server { return schedServer(t, "someone-else", "ENABLED") },
		func(d *Driver, u string) { d.SchedulerBaseURL = u })
}

func TestRefusesForeignDeleteCloudVPN(t *testing.T) {
	runForeignDeleteGCP(t, "vpngateway", "site",
		cloudVPNProviderID("acme-prod", "europe-west1", "pv-site-x"),
		func(t *testing.T) *httptest.Server { return vpnServer(t, "someone-else", "IPV4_ONLY") },
		func(d *Driver, u string) { d.ComputeBaseURL = u })
}

func TestRefusesForeignDeleteBackupPlanGCP(t *testing.T) {
	runForeignDeleteGCP(t, "backupplan", "nightly",
		gbpProviderID("acme-prod", "europe-west1",
			resourceName("acme-prod", "prod", "nightly", 1, 62)),
		func(t *testing.T) *httptest.Server { return gbpServer(t, "someone-else") },
		func(d *Driver, u string) { d.BackupDRBaseURL = u })
}

func TestRefusesForeignDeleteServiceAccount(t *testing.T) {
	runForeignDeleteGCP(t, "serviceaccount", "runner",
		gsaProviderID("acme-prod", GServiceAccountID("acme-prod", "prod", "runner", 1)),
		func(t *testing.T) *httptest.Server { return gsaServer(t, "someone-else", "batch-runner") },
		func(d *Driver, u string) { d.IAMBaseURL = u })
}

// TestRefusesForeignDeleteLogMetric: a log metric carries no labels, so ownership rides
// in the DESCRIPTION (D416) — and unlike the five AWS services with that shape, this
// driver was already checking it.
func TestRefusesForeignDeleteLogMetric(t *testing.T) {
	runForeignDeleteGCP(t, "logmetric", "errors",
		glogmetricProviderID("acme-prod", "app_error_count"),
		func(t *testing.T) *httptest.Server {
			return logMetricServer(t, "some other team's metric")
		},
		func(d *Driver, u string) { d.LoggingBaseURL = u })
}

// ---- D454: three more.

func TestRefusesForeignDeleteCloudRunGCP(t *testing.T) {
	runForeignDeleteGCP(t, "cloudrun", "be", "cloudrun:acme-prod:europe-central2:be-x",
		func(t *testing.T) *httptest.Server {
			return runServer(t, map[string]string{
				"groundhold-capability": "other", "groundhold-environment": "prod"},
				"INGRESS_TRAFFIC_ALL", 200, "")
		},
		func(d *Driver, u string) { d.RunBaseURL = u })
}

func TestRefusesForeignDeleteFilestore(t *testing.T) {
	runForeignDeleteGCP(t, "filestore", "shared",
		filestoreProviderID("acme-prod", "europe-west1",
			resourceName("acme-prod", "prod", "shared", 1, 63)),
		func(t *testing.T) *httptest.Server {
			return filestoreServer(t, "someone-else", "BASIC_HDD", "")
		},
		func(d *Driver, u string) { d.FilestoreBaseURL = u })
}

// TestRefusesForeignDeleteDNSRecordGCP: the ownership evidence is the parent ZONE's
// labels, one level up — a record has nowhere to carry a marker, the same answer both
// clouds reached independently (D408/D420/D449).
func TestRefusesForeignDeleteDNSRecordGCP(t *testing.T) {
	runForeignDeleteGCP(t, "clouddnsrecord", dnsRecordCap,
		gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com."),
		func(t *testing.T) *httptest.Server { return dnsRecordServer(t, "someone-else") },
		func(d *Driver, u string) { d.DNSBaseURL = u })
}

// ---- D454 batch two: the label-carrying majority.

func labeledForeignGET(body string) func(t *testing.T) *httptest.Server {
	return func(t *testing.T) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					_, _ = w.Write([]byte(body))
					return
				}
				w.WriteHeader(200)
			}))
	}
}

func TestRefusesForeignDeleteAlertPolicy(t *testing.T) {
	runForeignDeleteGCP(t, "monitoring", "cpu", "galert:acme-prod:policy-abc",
		labeledForeignGET(`{"userLabels":{"groundhold-capability":"someone-else",`+
			`"groundhold-environment":"prod"},"conditions":[{"conditionThreshold":`+
			`{"filter":"metric.type=\"x\"","comparison":"COMPARISON_GT","thresholdValue":1}}]}`),
		func(d *Driver, u string) { d.MonitoringBaseURL = u })
}

// TestRefusesForeignDeleteDashboard: a Monitoring dashboard carries NO labels. The
// displayName is the whole of the evidence — the GCP twin of the AWS shape that produced
// five defects (D444-D449).
func TestRefusesForeignDeleteDashboard(t *testing.T) {
	runForeignDeleteGCP(t, "dashboard", "golden", "gdash:acme-prod:abc123",
		labeledForeignGET(`{"displayName":"someone else's board","mosaicLayout":{"tiles":[]}}`),
		func(d *Driver, u string) { d.DashboardBaseURL = u })
}

func TestRefusesForeignDeleteUptimeCheck(t *testing.T) {
	runForeignDeleteGCP(t, "uptime", "api", "guptime:acme-prod:xyz789",
		labeledForeignGET(`{"userLabels":{"groundhold-capability":"someone-else",`+
			`"groundhold-environment":"prod"},"monitoredResource":{"labels":{"host":"x"}},`+
			`"httpCheck":{"path":"/","useSsl":true},"period":"60s"}`),
		func(d *Driver, u string) { d.UptimeBaseURL = u })
}

func TestRefusesForeignDeletePubSubTopic(t *testing.T) {
	runForeignDeleteGCP(t, "pubsub-topic", "events", "pubsub:acme-prod:the-topic",
		labeledForeignGET(`{"name":"projects/acme-prod/topics/the-topic",`+
			`"labels":{"groundhold-capability":"other"}}`),
		func(d *Driver, u string) { d.PubSubBaseURL = u })
}

func TestRefusesForeignDeletePubSubQueue(t *testing.T) {
	runForeignDeleteGCP(t, "pubsub-queue", "orders", "pubsub:acme-prod:the-q",
		labeledForeignGET(`{"name":"projects/acme-prod/subscriptions/the-q",`+
			`"labels":{"groundhold-capability":"other"}}`),
		func(d *Driver, u string) { d.PubSubBaseURL = u })
}

func TestRefusesForeignDeleteCloudFunction(t *testing.T) {
	runForeignDeleteGCP(t, "cloudfunctions", "api",
		"cloudfunctions:acme-prod:europe-central2:api-1",
		labeledForeignGET(`{"labels":{"groundhold-capability":"other",`+
			`"groundhold-environment":"prod"}}`),
		func(d *Driver, u string) { d.CfBaseURL, d.RunBaseURL = u, u })
}

func TestRefusesForeignDeleteCloudFunctionFn(t *testing.T) {
	runForeignDeleteGCP(t, "cloudfunctions-fn", "api",
		"cffn:acme-prod:europe-west1:api-abcdefgh",
		labeledForeignGET(`{"labels":{"groundhold-capability":"other",`+
			`"groundhold-environment":"prod"}}`),
		func(d *Driver, u string) { d.CfBaseURL, d.RunBaseURL = u, u })
}

// TestRefusesForeignDeleteVPC: a network has no labels either — ownership rides in the
// description marker, and deleting a stranger's VPC takes every attached workload with it.
func TestRefusesForeignDeleteVPC(t *testing.T) {
	runForeignDeleteGCP(t, "vpc", "app-net", "vpc:acme-prod:europe-central2:app-net-1",
		labeledForeignGET(`{"description":"groundhold:capability=other;environment=prod",`+
			`"autoCreateSubnetworks":false}`),
		func(d *Driver, u string) { d.ComputeBaseURL = u })
}

func TestRefusesForeignDeleteBillingBudget(t *testing.T) {
	t.Cleanup(func() { billingBudgetsBaseURLOverride, cloudBillingBaseURLOverride = "", "" })
	runForeignDeleteGCP(t, "billingbudget", "cost",
		billingBudgetProviderID(testBillingAccount, "budget-abc123"),
		labeledForeignGET(`{"name":"billingAccounts/`+testBillingAccount+
			`/budgets/budget-abc123","displayName":"someones-hand-made-budget"}`),
		func(d *Driver, u string) {
			billingBudgetsBaseURLOverride, cloudBillingBaseURLOverride = u, u
		})
}

// ---- D455: the remainder that has a check to prove.

func TestRefusesForeignDeleteGCE(t *testing.T) {
	foreign := strings.Replace(ownedInstance, `"groundhold-capability":"web"`,
		`"groundhold-capability":"someone-else"`, 1)
	runForeignDeleteGCP(t, "gce", "web",
		"gce:acme-prod:europe-west1-b:web-production-abc12345",
		labeledForeignGET(foreign),
		func(d *Driver, u string) { d.ComputeBaseURL = u })
}

func TestRefusesForeignDeletePD(t *testing.T) {
	foreign := strings.Replace(ownedDisk, `"groundhold-capability":"orders-data"`,
		`"groundhold-capability":"someone-elses-database"`, 1)
	runForeignDeleteGCP(t, "pd", "orders-data",
		"pd:acme-prod:europe-west1-b:orders-data-production-abc12345",
		labeledForeignGET(foreign),
		func(d *Driver, u string) { d.ComputeBaseURL = u })
}

func TestRefusesForeignDeleteMIG(t *testing.T) {
	foreign := strings.Replace(migOwnedDoc(),
		vpcOwnerMarker("web-fleet", "production"), "someone-elses-fleet", 1)
	runForeignDeleteGCP(t, "mig", "web-fleet",
		"mig:acme-prod:europe-west1:web-fleet-production-abc12345",
		labeledForeignGET(foreign),
		func(d *Driver, u string) { d.ComputeBaseURL = u })
}

func TestRefusesForeignDeleteLogBucket(t *testing.T) {
	runForeignDeleteGCP(t, "logbucket", "flowlogs",
		"gcp-logbucket:acme-prod:us-central1:flowlogs-prod-abc",
		func(t *testing.T) *httptest.Server {
			return logBucketServer(t, fakeLogBucket{
				description: "someone else's bucket", retentionDays: 30}, nil)
		},
		func(d *Driver, u string) { d.LoggingBaseURL = u })
}

// TestRefusesForeignDeleteGCSBucket: GCS's ownership evidence is the LIVE projectNumber
// (D82), not a label — a bucket name is global, so a stranger's bucket can sit at a name
// our scheme would have chosen.
func TestRefusesForeignDeleteGCSBucket(t *testing.T) {
	runForeignDeleteGCP(t, "gcs", "assets", "gcs:acme-prod:the-bucket",
		func(t *testing.T) *httptest.Server {
			return gcsServer(t, `{"metageneration":"1","projectNumber":"999","labels":{`+
				`"groundhold-capability":"assets","groundhold-environment":"prod"}}`,
				200, "", 204)
		},
		func(d *Driver, u string) { d.GcsBaseURL, d.ProjNumber = u, "111" })
}

func TestRefusesForeignDeleteVertexAI(t *testing.T) {
	runForeignDeleteGCP(t, "vertexai", vtxCap,
		vertexProviderID(vtxProj, vtxRegion, vtxID),
		func(t *testing.T) *httptest.Server {
			f := &fakeVertex{loc: vtxRegion,
				labels: map[string]string{"groundhold-capability": "other"}, etag: "e1"}
			srv := httptest.NewServer(f.handler(t))
			vertexAIBaseURLOverride = srv.URL
			t.Cleanup(func() { vertexAIBaseURLOverride = "" })
			return srv
		},
		func(d *Driver, u string) {})
}

func TestRefusesForeignDeleteGKECluster(t *testing.T) {
	name := gkePlanName(t)
	runForeignDeleteGCPIn(t, "test-proj", "gke", gkeCap,
		gkeProviderID("test-proj", "europe-west1", name),
		func(t *testing.T) *httptest.Server {
			f := newFakeGKE(name, "europe-west1")
			f.exists = true
			f.labels = map[string]string{"team": "someone-else"}
			srv := httptest.NewServer(f.handler())
			gkeBaseURLOverride = srv.URL
			t.Cleanup(func() { gkeBaseURLOverride = "" })
			return srv
		},
		func(d *Driver, u string) {})
}

func TestRefusesForeignDeleteAuditSink(t *testing.T) {
	runForeignDeleteGCP(t, "auditlogs", "capability.audit.trail",
		"auditlogs:acme-prod:groundhold-audit-prod",
		labeledForeignGET(`{"name":"groundhold-audit-prod",`+
			`"destination":"storage.googleapis.com/x","description":"someone elses sink"}`),
		func(d *Driver, u string) {
			auditLogsBaseURLOverride = u
			t.Cleanup(func() { auditLogsBaseURLOverride = "" })
		})
}

// TestRefusesForeignDeleteFirestore: the database id is CONTENT-ADDRESSED, so ownership is
// derivable from the id alone — no read of any marker is needed or possible (a Firestore
// database carries no labels). Deleting a stranger's database destroys the data in it.
func TestRefusesForeignDeleteFirestore(t *testing.T) {
	runForeignDeleteGCPFromID(t, "firestore", "sessions",
		firestoreProviderID("acme-prod", "someone-elses-database"),
		func(t *testing.T) *httptest.Server {
			return firestoreServer(t, "europe-west1", false, false, "")
		},
		func(d *Driver, u string) { d.FirestoreBaseURL = u })
}

func TestRefusesForeignDeleteLoadBalancer(t *testing.T) {
	names := lbComposeNames("acme-prod", "prod", "capability.network.loadbalancer", 1)
	runForeignDeleteGCP(t, "loadbalancer", "capability.network.loadbalancer",
		lbProviderID("acme-prod", "global", names.ForwardingRule),
		func(t *testing.T) *httptest.Server {
			fake := newLBFake(t)
			fake.store["/projects/acme-prod/global/forwardingRules/"+names.ForwardingRule] =
				[]byte(`{"name":"` + names.ForwardingRule +
					`","description":"terraform-owned; not groundhold"}`)
			return fake.server()
		},
		func(d *Driver, u string) { d.ComputeBaseURL = u })
}
