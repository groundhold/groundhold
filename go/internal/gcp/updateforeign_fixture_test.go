package gcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// D460: the update register on GCP. The argument is D459's — an update that lands on a
// resource which is not ours is a takeover rather than a destruction, and it is quieter
// for it. On GCP the mutation is usually a PATCH, so the stranger's resource keeps every
// field we did not name and silently acquires the ones we did.

type gcpUpdateCase struct {
	svc, cap string
	server   func(t *testing.T) *httptest.Server
	base     func(d *Driver, url string)
	pid      string
	attrs    map[string]any
	impl     map[string]any
	changes  []string
	project  string
	fromID   bool
}

func runForeignUpdateGCP(t *testing.T, c gcpUpdateCase) {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	project := c.project
	if project == "" {
		project = "acme-prod"
	}
	p := &certifynet.ForeignProbe{
		Name:                 "gcp/" + c.svc,
		Classify:             gcpReadRole,
		OwnershipFromIDAlone: c.fromID,
		ForeignServer:        func() *httptest.Server { return c.server(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(project)
			d.HTTP = &http.Client{Transport: rt}
			c.base(d, happyURL)
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Update: func(pr provider.Provider) provider.CreateResult {
			return pr.Update(c.svc, c.cap, "prod", c.pid, c.attrs, c.impl, c.changes, "k")
		},
	}
	certifynet.CertifyUpdateRefusesForeign(t, p)
}

func TestRefusesForeignUpdateGCS(t *testing.T) {
	var patched string
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "gcs", cap: "assets",
		server:  func(t *testing.T) *httptest.Server { return gcsUpdateServer(t, "someone-else", &patched) },
		base:    func(d *Driver, u string) { d.GcsBaseURL, d.ProjNumber = u, "111" },
		pid:     "gcs:acme-prod:pv-assets-abcd1234",
		attrs:   map[string]any{"versioning.enabled": true},
		changes: []string{"versioning.enabled"}})
}

// TestRefusesForeignUpdateFirestore (D1215): Firestore carries no tags, so ownership is the
// deterministic database id — a name this capability/environment would never mint is refused
// from the id ALONE, before any read (fromID).
func TestRefusesForeignUpdateFirestore(t *testing.T) {
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "firestore", cap: "sessions", fromID: true,
		server:  func(t *testing.T) *httptest.Server { return firestoreServer(t, "us-central1", false, false, "") },
		base:    func(d *Driver, u string) { d.FirestoreBaseURL = u },
		pid:     firestoreProviderID("acme-prod", "someone-elses-db"),
		attrs:   map[string]any{"backup.pointInTimeRecovery": true},
		changes: []string{"backup.pointInTimeRecovery"}})
}

func TestRefusesForeignUpdatePubSubTopic(t *testing.T) {
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "pubsub-topic", cap: "events",
		server:  func(t *testing.T) *httptest.Server { return pubsubServer(t, ourTopicJSON("someone-else"), 0, 0) },
		base:    func(d *Driver, u string) { d.PubSubBaseURL = u },
		pid:     "pubsub:acme-prod:pv-events-abcd1234",
		attrs:   map[string]any{"network.publicExposure": true},
		changes: []string{"network.publicExposure"}})
}

func TestRefusesForeignUpdatePubSubQueue(t *testing.T) {
	var patched, query string
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "pubsub-queue", cap: "orders",
		server:  func(t *testing.T) *httptest.Server { return pqUpdateServer(t, "someone-else", &patched, &query) },
		base:    func(d *Driver, u string) { d.PubSubBaseURL = u },
		pid:     "pubsub:acme-prod:pv-orders-abcd1234",
		attrs:   map[string]any{"retention.minimum": "86400s"},
		changes: []string{"retention.minimum"}})
}

func TestRefusesForeignUpdateSecret(t *testing.T) {
	var setCalls int
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "secretmanager", cap: "dbcreds",
		server:  func(t *testing.T) *httptest.Server { return secretIamServer(t, "someone-else", false, &setCalls) },
		base:    func(d *Driver, u string) { d.SecretBaseURL = u },
		pid:     "gsecret:acme-prod:pv-dbcreds-abcd1234",
		attrs:   map[string]any{"network.publicExposure": true},
		changes: []string{"network.publicExposure"}})
}

func TestRefusesForeignUpdateLogBucketGCP(t *testing.T) {
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "logbucket", cap: "flowlogs",
		server: func(t *testing.T) *httptest.Server {
			return logBucketServer(t, fakeLogBucket{
				description: "someone else's bucket", retentionDays: 30}, nil)
		},
		base:    func(d *Driver, u string) { d.LoggingBaseURL = u },
		pid:     "gcp-logbucket:acme-prod:us-central1:flowlogs-prod-abc",
		attrs:   map[string]any{"retention.days": "365d"},
		changes: []string{"retention.days"}})
}

// TestRefusesForeignUpdateDNSRecordGCP: the update at stake is a REPOINT — sending a
// stranger's traffic to our target. The evidence is the parent zone's labels.
func TestRefusesForeignUpdateDNSRecordGCP(t *testing.T) {
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "clouddnsrecord", cap: dnsRecordCap,
		server:  func(t *testing.T) *httptest.Server { return dnsRecordServer(t, "someone-else") },
		base:    func(d *Driver, u string) { d.DNSBaseURL = u },
		pid:     gdnsrecProviderID("acme-prod", "example-com", "CNAME", "connect.example.com."),
		attrs:   map[string]any{"dns.target": "origin2.example.net"},
		changes: []string{"dns.target"}})
}

func TestRefusesForeignUpdateGKE(t *testing.T) {
	name := gkePlanName(t)
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "gke", cap: gkeCap, project: "test-proj",
		server: func(t *testing.T) *httptest.Server {
			f := newFakeGKE(name, "europe-west1")
			f.exists = true
			f.labels = map[string]string{"team": "someone-else"}
			srv := httptest.NewServer(f.handler())
			gkeBaseURLOverride = srv.URL
			t.Cleanup(func() { gkeBaseURLOverride = "" })
			return srv
		},
		base:    func(d *Driver, u string) {},
		pid:     gkeProviderID("test-proj", "europe-west1", name),
		attrs:   map[string]any{"cluster.version": "1.30"},
		changes: []string{"cluster.version"}})
}

func TestRefusesForeignUpdateBackupPlanGCP(t *testing.T) {
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "backupplan", cap: "nightly",
		server:  func(t *testing.T) *httptest.Server { return gbpServer(t, "someone-else") },
		base:    func(d *Driver, u string) { d.BackupDRBaseURL = u },
		pid:     gbpProviderID("acme-prod", "europe-west1", resourceName("acme-prod", "prod", "nightly", 1, 62)),
		attrs:   gbpAttrs(),
		impl:    gbpImpl(),
		changes: []string{"retention.duration"}})
}

func TestRefusesForeignUpdateBillingBudget(t *testing.T) {
	t.Cleanup(func() { billingBudgetsBaseURLOverride, cloudBillingBaseURLOverride = "", "" })
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "billingbudget", cap: "cost",
		server: labeledForeignGET(`{"name":"billingAccounts/` + testBillingAccount +
			`/budgets/budget-abc123","displayName":"someones-hand-made-budget"}`),
		base: func(d *Driver, u string) {
			billingBudgetsBaseURLOverride, cloudBillingBaseURLOverride = u, u
		},
		pid:     billingBudgetProviderID(testBillingAccount, "budget-abc123"),
		attrs:   budgetAttrs(),
		impl:    budgetImpl(),
		changes: []string{"budget.limit"}})
}

func TestRefusesForeignUpdateAuditSink(t *testing.T) {
	runForeignUpdateGCP(t, gcpUpdateCase{svc: "auditlogs", cap: "capability.audit.trail",
		server: labeledForeignGET(`{"name":"groundhold-audit-prod",` +
			`"destination":"storage.googleapis.com/x","description":"someone elses sink"}`),
		base: func(d *Driver, u string) {
			auditLogsBaseURLOverride = u
			t.Cleanup(func() { auditLogsBaseURLOverride = "" })
		},
		pid:     "auditlogs:acme-prod:" + AuditSinkName("acme-prod", "prod", "capability.audit.trail", 1),
		attrs:   auditAttrs(),
		impl:    auditImpl(),
		changes: []string{"delivery.assured"}})
}
