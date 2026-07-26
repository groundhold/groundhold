// The network shell of the Cloud SQL driver (D43): token, POST, 409
// classification, operation polling. Everything semantic lives in the
// pure builder (cloudsql.go); everything here is thin and
// httptest-covered.
package gcp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"groundhold/internal/provider"
	"groundhold/internal/scalars"
)

type Driver struct {
	Project string
	// secrets (D309) holds the credential values of the mutation in flight so the
	// driver can scrub them out of a Reason before it is persisted.
	secrets             provider.Redactor
	BaseURL             string // override for tests; default sqladmin
	CRMBaseURL          string // override for tests; default cloudresourcemanager (D75)
	RunBaseURL          string // override for tests; default run.googleapis.com (D76)
	GcsBaseURL          string // override for tests; default storage.googleapis.com (D77)
	ComputeBaseURL      string // override for tests; default compute.googleapis.com (D83)
	CfBaseURL           string // override for tests; default cloudfunctions.googleapis.com (D84)
	SecretBaseURL       string // override for tests; default secretmanager.googleapis.com (D97)
	PubSubBaseURL       string // override for tests; default pubsub.googleapis.com (D94)
	MemorystoreBaseURL  string // override for tests; default redis.googleapis.com (D100)
	DNSBaseURL          string // override for tests; default dns.googleapis.com (D101)
	IAMBaseURL          string // override for tests; default iam.googleapis.com (D105; shared w/ D103)
	MonitoringBaseURL   string // override for tests; default monitoring.googleapis.com (D106)
	DashboardBaseURL    string // override for tests; default monitoring.googleapis.com/v1 (D107)
	UptimeBaseURL       string // override for tests; default monitoring.googleapis.com/v3 (D108)
	LoggingBaseURL      string // override for tests; default logging.googleapis.com/v2 (D109)
	ARBaseURL           string // override for tests; default artifactregistry.googleapis.com/v1 (D110)
	FilestoreBaseURL    string // override for tests; default file.googleapis.com (D111)
	FirestoreBaseURL    string // override for tests; default firestore.googleapis.com (D112)
	ManagedKafkaBaseURL string // override for tests; default managedkafka.googleapis.com (D115)
	CertManagerBaseURL  string // override for tests; default certificatemanager.googleapis.com (D117)
	BQBaseURL           string // override for tests; default bigquery.googleapis.com (D122)
	SchedulerBaseURL    string // override for tests; default cloudscheduler.googleapis.com (D123)
	KMSBaseURL          string // override for tests; default cloudkms.googleapis.com (D124)
	BackupDRBaseURL     string // override for tests; default backupdr.googleapis.com (D127)
	AssetFeedBaseURL    string // override for tests; default cloudasset.googleapis.com/v1 (D141)
	OrgPolicyBaseURL    string // override for tests; default orgpolicy.googleapis.com/v2 (D238)
	HTTP                *http.Client
	Now                 func() time.Time
	PollInterval        time.Duration
	PollTimeout         time.Duration
	// GKELROTimeout is the poll deadline for GKE long-running operations (cluster
	// create/upgrade, node-pool + addon ops), which routinely outrun the generic
	// 20-minute PollTimeout — a real control-plane upgrade can exceed it (D264
	// class). Defaults to 60m in NewDriver; 0 falls back to PollTimeout (see
	// gkeLROTimeout). Mirrors the AWS EKSLROTimeout.
	GKELROTimeout time.Duration
	// Dial is the exposure probe's handshake (D65); nil = net.DialTimeout
	Dial func(network, addr string, timeout time.Duration) (net.Conn, error)
	// ProjNumber is our pinned project's NUMBER (D82): the cross-project
	// ownership check for GCS's global namespace compares it against a bucket's
	// projectNumber. Resolved once via CRM and cached; tests may set it directly.
	ProjNumber string

	auth *authenticator
}

// newResilientHTTPClient (D269) hardens the GCP HTTP client against the dead-idle-
// connection HANG a long GKE control-plane upgrade would expose (the AWS/EKS twin was
// Acme F29: a wedged HTTP/2 transport ignored Client.Timeout and hung 19+ min). It
// forces HTTP/1.1 (TLSNextProto disabled), where the per-request Timeout and
// ResponseHeaderTimeout are honored reliably and a broken connection is discarded on
// error — no dependency on the HTTP/2 ping config that failed in the field (D268).
func newResilientHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = false // D269: force HTTP/1.1 — the F29 hang lived in the wedged HTTP/2 transport
	// Restrict ALPN to http/1.1 so an h2-capable server does NOT negotiate HTTP/2
	// (TLSNextProto alone leaves ALPN advertising "h2" -> the server speaks h2 while the
	// transport parses http1 -> "malformed HTTP response", which broke EVERY request in
	// D269's first cut). Clone the shared TLS config before mutating it.
	tc := tr.TLSClientConfig
	if tc == nil {
		tc = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tc = tc.Clone()
	}
	tc.NextProtos = []string{"http/1.1"}
	tc.MinVersion = tls.VersionTLS12 // all three cloud control planes require >=1.2
	tr.TLSClientConfig = tc
	tr.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
	tr.IdleConnTimeout = 90 * time.Second
	tr.ResponseHeaderTimeout = 30 * time.Second // reliably honored on HTTP/1.1, bounds a stuck read
	return &http.Client{Timeout: 60 * time.Second, Transport: tr}
}

func NewDriver(project string) *Driver {
	httpClient := newResilientHTTPClient()
	return &Driver{
		Project:        project,
		BaseURL:        baseURL,
		CRMBaseURL:     crmBaseURL,
		RunBaseURL:     runBaseURL,
		GcsBaseURL:     gcsBaseURL,
		ComputeBaseURL: computeBaseURL,
		CfBaseURL:      cloudfunctionsBaseURL,
		PubSubBaseURL:  pubsubBaseURL,
		HTTP:           httpClient,
		Now:            time.Now,
		PollInterval:   5 * time.Second,
		PollTimeout:    20 * time.Minute,
		GKELROTimeout:  60 * time.Minute,
		auth: &authenticator{http: httpClient, now: time.Now,
			metadataURL: "http://metadata.google.internal"},
	}
}

func (d *Driver) Name() string { return "gcp" }

// serviceFromTarget parses the service token from a "provider.service/cap"
// target or binding type — "gcp.cloudsql/db" -> "cloudsql". "" for a
// malformed value, which the dispatch then refuses.
func serviceFromTarget(target string) string {
	dot := strings.IndexByte(target, '.')
	slash := strings.IndexByte(target, '/')
	if dot < 0 || slash < 0 || slash < dot {
		return ""
	}
	return target[dot+1 : slash]
}

// requireService is the multi-service dispatch gate (D76): Cloud SQL is
// wired; Cloud Run and GCS are pending their network shells (slice 3 / D77);
// anything else fails CLOSED. The driver NEVER defaults to a service — an
// empty or unknown token is a refusal, never a silent route into Cloud SQL.
// projectOK bounds the pinned project before it is interpolated into REST
// paths: a GCP project ID (lowercase, 6-30 chars) or a numeric project number.
// A malformed --project must not build an off-target URL (confused deputy).
var projectOK = regexp.MustCompile(`^([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{1,20})$`)

func (d *Driver) requireService(service string) error {
	switch service {
	case "cloudsql", "cloudrun", "gcs", "vpc", "cloudfunctions", "cloudfunctions-fn", "pubsub-topic", "pubsub-queue", "secretmanager", "memorystore", "clouddns", "clouddnsrecord", "iambinding", "customrole", "monitoring", "dashboard", "uptime", "logmetric", "artifactregistry", "filestore", "firestore", "managedkafka", "cloudarmor", "certmanager", "cloudrunjobs", "serviceaccount", "bigquery", "cloudscheduler", "cloudkms", "vpngateway", "backupvault", "assetfeed", "loadbalancer", "billingbudget", "logbucket", "auditlogs", "scc", "vertexai", "gke", "gke-addon", "gke-workloadidentity", "backupplan", "gce", "pd", "computeimage", "mig":
		// project is empty on read-only paths (observe/discover — it rides in
		// the providerId); when pinned it MUST be a valid identifier.
		if d.Project != "" && !projectOK.MatchString(d.Project) {
			return fmt.Errorf("gcp driver: pinned project %q is not a valid "+
				"project id/number — refusing to interpolate it into an API path", d.Project)
		}
		return nil
	default:
		return fmt.Errorf("gcp driver: unknown service %q — refusing "+
			"(no default service)", service)
	}
}

func (d *Driver) Validate(service, capability, environment string,
	attrs, impl map[string]any, generation int) error {
	if err := d.requireService(service); err != nil {
		return err
	}
	if service == "backupplan" {
		_, err := BuildBackupPlanGCP(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "gke" {
		_, err := BuildGKE(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "gke-addon" {
		_, err := BuildGKEAddon(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "gke-workloadidentity" {
		_, err := BuildGKEWorkloadIdentity(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "billingbudget" {
		_, err := BuildBillingBudget(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "logbucket" {
		_, err := BuildLogBucket(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "auditlogs" {
		_, err := BuildAuditSink(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "scc" {
		_, err := BuildSCC(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "vertexai" {
		_, err := BuildVertexAI(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "cloudrun" {
		_, err := BuildCloudRunCreateRequest(d.Project, environment,
			capability, attrs, impl, generation)
		return err
	}
	if service == "gcs" {
		_, err := BuildGCSCreateRequest(d.Project, environment, capability,
			attrs, impl, generation)
		return err
	}
	if service == "secretmanager" {
		_, err := BuildSecretCreate(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "cloudkms" {
		_, err := BuildKMSKey(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "clouddns" {
		_, err := BuildCloudDNSZone(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "clouddnsrecord" {
		_, err := BuildCloudDNSRecord(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "iambinding" {
		_, err := BuildIAMBinding(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "customrole" {
		_, err := BuildCustomRole(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "monitoring" {
		_, err := BuildAlertPolicy(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "dashboard" {
		_, err := BuildDashboard(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "uptime" {
		_, err := BuildUptimeCheck(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "logmetric" {
		_, err := BuildLogMetric(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "gce" {
		_, err := BuildGCEInstanceCreate(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "pd" {
		_, err := BuildPDCreate(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "mig" {
		_, err := BuildMIGCreate(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	// A WITNESS service (D177/D370) is refused before any operand check: the reason
	// has nothing to do with the operands, and the first thing said should be true.
	if !provider.CanAuthor("gcp", service) {
		return errWitnessOnlyGCP(service)
	}
	if service == "artifactregistry" {
		_, err := BuildARRepo(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "firestore" {
		_, err := BuildFirestoreCreate(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "managedkafka" {
		_, err := BuildManagedKafka(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "cloudarmor" {
		_, err := BuildArmor(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "certmanager" {
		_, err := BuildCertManager(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "cloudrunjobs" {
		_, err := BuildCloudRunJob(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "serviceaccount" {
		_, err := BuildGServiceAccount(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "bigquery" {
		_, err := BuildBigQueryDataset(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "cloudscheduler" {
		_, err := BuildCloudSchedulerJob(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "vpngateway" {
		_, err := BuildCloudVPNGateway(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "backupvault" {
		_, err := BuildBackupDRVault(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "assetfeed" {
		_, err := BuildAssetFeed(d.Project, environment, capability, attrs, impl, generation)
		return err
	}
	if service == "vpc" {
		_, err := BuildVPCRequests(d.Project, environment, capability,
			attrs, impl, generation)
		return err
	}
	if service == "loadbalancer" {
		_, err := BuildLoadBalancerPlan(d.Project, environment, capability,
			attrs, impl, generation)
		return err
	}
	if service == "cloudfunctions" {
		_, err := BuildCloudFunctionCreateRequest(d.Project, environment,
			capability, attrs, impl, generation)
		return err
	}
	if service == "cloudfunctions-fn" {
		_, err := BuildCloudFunctionFnRequest(d.Project, environment,
			capability, attrs, impl, generation)
		return err
	}
	if service == "pubsub-queue" {
		_, err := BuildPubSubQueuePlan(d.Project, environment, capability,
			attrs, impl, generation)
		return err
	}
	if service == "pubsub-topic" {
		_, err := BuildPubSubCreateRequest(d.Project, environment, capability,
			attrs, impl, generation)
		return err
	}
	if service == "memorystore" {
		_, err := BuildMemorystoreCreate(d.Project, environment, capability,
			attrs, impl, generation)
		return err
	}
	if service == "filestore" {
		_, err := BuildFilestoreCreate(d.Project, environment, capability,
			attrs, impl, generation)
		return err
	}
	_, err := BuildCreateRequest(d.Project, environment, capability,
		attrs, impl, generation)
	return err
}

// Create dispatches the per-service create and, for services declaring typed
// outputs (D284), attaches them to a succeeded result — derived from the
// provider id (plus one network read for vpc subnetworks), so every succeeded
// path receipts the same truthful set.
func (d *Driver) Create(service, capability, environment string,
	attrs, impl map[string]any, key string,
	generation int) provider.CreateResult {
	// D309: the credentials this action carries are remembered for the duration of
	// the mutation and scrubbed out of its Reason on the way back — the Reason is
	// persisted in the ledger and signed into capsules.
	defer d.forgetSecrets()
	d.rememberSecrets(impl)
	cr := d.createService(service, capability, environment, attrs, impl, key, generation)
	d.attachOutputs(service, &cr)
	cr.Reason = d.scrub(cr.Reason)
	return cr
}

// ---- credential redaction (D309) -------------------------------------------
// See internal/provider/redact.go for why this is exact rather than pattern-matching.

func (d *Driver) rememberSecrets(impl map[string]any) { d.secrets.Remember(impl) }

func (d *Driver) forgetSecrets() { d.secrets.Forget() }

func (d *Driver) scrub(s string) string { return d.secrets.Scrub(s) }

func (d *Driver) createService(service, capability, environment string,
	attrs, impl map[string]any, key string,
	generation int) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if service == "backupplan" {
		return d.createBackupPlanGCP(capability, environment, attrs, impl, generation)
	}
	if service == "gke" {
		return d.createGKE(environment, capability, attrs, impl, generation)
	}
	if service == "gke-addon" {
		return d.createGKEAddon(environment, capability, attrs, impl, generation)
	}
	if service == "gke-workloadidentity" {
		return d.createGKEWorkloadIdentity(capability, environment, attrs, impl, generation)
	}
	if service == "billingbudget" {
		return d.createBillingBudget(capability, environment, attrs, impl, generation)
	}
	if service == "logbucket" {
		return d.createLogBucket(capability, environment, attrs, impl, generation)
	}
	if service == "auditlogs" {
		return d.createAuditLogs(capability, environment, attrs, impl, generation)
	}
	if service == "scc" {
		return d.createSCC(capability, environment, attrs, impl, generation)
	}
	if service == "vertexai" {
		return d.createVertexAI(capability, environment, attrs, impl, generation)
	}
	if service == "cloudrun" {
		return d.createCloudRun(capability, environment, attrs, impl, generation)
	}
	if service == "gcs" {
		return d.createGCS(capability, environment, attrs, impl, generation)
	}
	if service == "secretmanager" {
		return d.createSecret(capability, environment, attrs, impl, generation)
	}
	if service == "cloudkms" {
		return d.createKMS(environment, capability, attrs, impl, generation)
	}
	if service == "clouddns" {
		return d.createCloudDNS(environment, capability, attrs, impl, generation)
	}
	if service == "clouddnsrecord" {
		return d.createCloudDNSRecord(environment, capability, attrs, impl, generation)
	}
	if service == "iambinding" {
		return d.createIAMBinding(capability, environment, attrs, impl, generation)
	}
	if service == "customrole" {
		return d.createCustomRole(capability, environment, attrs, impl, generation)
	}
	if service == "monitoring" {
		return d.createAlertPolicy(capability, environment, attrs, impl, generation)
	}
	if service == "dashboard" {
		return d.createDashboard(capability, environment, attrs, impl, generation)
	}
	if service == "uptime" {
		return d.createUptimeCheck(capability, environment, attrs, impl, generation)
	}
	if service == "logmetric" {
		return d.createLogMetric(capability, environment, attrs, impl, generation)
	}
	if service == "gce" {
		return d.createGCEInstance(capability, environment, attrs, impl, generation)
	}
	if service == "pd" {
		return d.createPD(capability, environment, attrs, impl, generation)
	}
	if service == "mig" {
		return d.createMIG(capability, environment, attrs, impl, generation)
	}
	if !provider.CanAuthor("gcp", service) {
		return provider.CreateResult{Status: "failed", Reason: errWitnessOnlyGCP(service).Error()}
	}
	if service == "artifactregistry" {
		return d.createARRepo(capability, environment, attrs, impl, generation)
	}
	if service == "firestore" {
		return d.createFirestore(environment, capability, attrs, impl, generation)
	}
	if service == "managedkafka" {
		return d.createManagedKafka(environment, capability, attrs, impl, generation)
	}
	if service == "cloudarmor" {
		return d.createArmor(environment, capability, attrs, impl, generation)
	}
	if service == "certmanager" {
		return d.createCertManager(environment, capability, attrs, impl, generation)
	}
	if service == "cloudrunjobs" {
		return d.createCloudRunJob(environment, capability, attrs, impl, generation)
	}
	if service == "serviceaccount" {
		return d.createGServiceAccount(environment, capability, attrs, impl, generation)
	}
	if service == "bigquery" {
		return d.createBigQuery(capability, environment, attrs, impl, generation)
	}
	if service == "cloudscheduler" {
		return d.createCloudScheduler(capability, environment, attrs, impl, generation)
	}
	if service == "vpngateway" {
		return d.createCloudVPN(capability, environment, attrs, impl, generation)
	}
	if service == "backupvault" {
		return d.createBackupDR(capability, environment, attrs, impl, generation)
	}
	if service == "assetfeed" {
		return d.createAssetFeed(capability, environment, attrs, impl, generation)
	}
	if service == "loadbalancer" {
		return d.createLoadBalancer(capability, environment, attrs, impl, generation)
	}
	if service == "vpc" {
		return d.createVPC(capability, environment, attrs, impl, generation)
	}
	if service == "cloudfunctions" {
		return d.createCloudFunction(capability, environment, attrs, impl, generation)
	}
	if service == "cloudfunctions-fn" {
		return d.createCloudFunctionFn(capability, environment, attrs, impl, generation)
	}
	if service == "pubsub-queue" {
		return d.createPubSubQueue(capability, environment, attrs, impl, generation)
	}
	if service == "pubsub-topic" {
		return d.createPubSub(capability, environment, attrs, impl, generation)
	}
	if service == "memorystore" {
		return d.createMemorystore(environment, capability, attrs, impl, generation)
	}
	if service == "filestore" {
		return d.createFilestore(environment, capability, attrs, impl, generation)
	}
	req, err := BuildCreateRequest(d.Project, environment, capability,
		attrs, impl, generation)
	if err != nil {
		// Validate ran in preflight; reaching this is a bug, but refuse
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// tests override BaseURL; rebuild the URL against it
	req.URL = fmt.Sprintf("%s/projects/%s/instances", d.BaseURL, d.Project)
	name, _ := req.Body["name"].(string)
	region, _ := req.Body["region"].(string)
	// the instance name is deterministic, so the providerId is knowable BEFORE
	// the insert response — a lost/garbled outcome (D29) must carry it so the
	// instance that may have landed is never orphaned (handle never lost).
	pid := d.providerID(region, name)

	status, respBody, err := d.call(req.Method, req.URL, req.Body)
	if err != nil {
		// a lost response after a mutating request is NOT a failure —
		// the instance may exist (D29)
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("insert outcome unknown: %v", err)}
	}
	switch {
	case status == http.StatusConflict:
		return d.classify409(name, region, environment, capability)
	case status >= 400:
		res := mutationResult("insert", status, respBody)
		if res.Status == "unknown" {
			res.ProviderID = pid // 5xx may have landed — keep the handle
		}
		return res
	}

	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(respBody, &op) != nil || op.Name == "" {
		// a 2xx insert MUST return an operation; an empty name is a truncated
		// body (the instance may exist, D29) — never poll the list endpoint.
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "insert response carried no operation — reconcile"}
	}
	return d.pollOperation(op.Name, name, region)
}

// providerID canonical format: project:region:name (matches the binding
// examples in spec/state-model.md — pinned one way, everywhere).
func (d *Driver) providerID(region, name string) string {
	return d.Project + ":" + region + ":" + name
}

// Observe: the read side. providerID parses back to (project, region,
// name); the reverse mapping itself is the pure MapInstance.
func (d *Driver) Observe(service, capability,
	providerID string) ([]provider.Observation, []string, error) {
	if err := d.requireService(service); err != nil {
		return nil, nil, err
	}
	if service == "backupplan" {
		return d.observeBackupPlanGCP(capability, providerID)
	}
	if service == "gke" {
		return d.observeGKE(capability, providerID)
	}
	if service == "gke-addon" {
		return d.observeGKEAddon(capability, providerID)
	}
	if service == "gke-workloadidentity" {
		return d.observeGKEWorkloadIdentity(capability, providerID)
	}
	if service == "billingbudget" {
		return d.observeBillingBudget(capability, providerID)
	}
	if service == "logbucket" {
		return d.observeLogBucket(capability, providerID)
	}
	if service == "auditlogs" {
		return d.observeAuditLogs(capability, providerID)
	}
	if service == "scc" {
		return d.observeSCC(capability, providerID)
	}
	if service == "vertexai" {
		return d.observeVertexAI(capability, providerID)
	}
	if service == "cloudrun" {
		return d.observeCloudRun(capability, providerID)
	}
	if service == "gcs" {
		return d.observeGCS(capability, providerID)
	}
	if service == "secretmanager" {
		return d.observeSecret(capability, providerID)
	}
	if service == "cloudkms" {
		return d.observeKMS(capability, providerID)
	}
	if service == "clouddns" {
		return d.observeCloudDNS(capability, providerID)
	}
	if service == "clouddnsrecord" {
		return d.observeCloudDNSRecord(capability, providerID)
	}
	if service == "iambinding" {
		return d.observeIAMBinding(capability, providerID)
	}
	if service == "customrole" {
		return d.observeCustomRole(capability, providerID)
	}
	if service == "monitoring" {
		return d.observeAlertPolicy(capability, providerID)
	}
	if service == "dashboard" {
		return d.observeDashboard(capability, providerID)
	}
	if service == "uptime" {
		return d.observeUptimeCheck(capability, providerID)
	}
	if service == "logmetric" {
		return d.observeLogMetric(capability, providerID)
	}
	if service == "gce" {
		return d.observeGCEInstance(capability, providerID)
	}
	if service == "pd" {
		return d.observePD(capability, providerID)
	}
	if service == "computeimage" {
		return d.observeGCPImage(capability, providerID)
	}
	if service == "mig" {
		return d.observeMIG(capability, providerID)
	}
	if service == "artifactregistry" {
		return d.observeARRepo(capability, providerID)
	}
	if service == "firestore" {
		return d.observeFirestore(capability, providerID)
	}
	if service == "managedkafka" {
		return d.observeManagedKafka(capability, providerID)
	}
	if service == "cloudarmor" {
		return d.observeArmor(capability, providerID)
	}
	if service == "certmanager" {
		return d.observeCertManager(capability, providerID)
	}
	if service == "cloudrunjobs" {
		return d.observeCloudRunJob(capability, providerID)
	}
	if service == "serviceaccount" {
		return d.observeGServiceAccount(capability, providerID)
	}
	if service == "bigquery" {
		return d.observeBigQuery(capability, providerID)
	}
	if service == "cloudscheduler" {
		return d.observeCloudScheduler(capability, providerID)
	}
	if service == "vpngateway" {
		return d.observeCloudVPN(capability, providerID)
	}
	if service == "backupvault" {
		return d.observeBackupDR(capability, providerID)
	}
	if service == "assetfeed" {
		return d.observeAssetFeed(capability, providerID)
	}
	if service == "loadbalancer" {
		return d.observeLoadBalancer(capability, providerID)
	}
	if service == "vpc" {
		return d.observeVPC(capability, providerID)
	}
	if service == "cloudfunctions" {
		return d.observeCloudFunction(capability, providerID)
	}
	if service == "cloudfunctions-fn" {
		return d.observeCloudFunctionFn(capability, providerID)
	}
	if service == "pubsub-queue" {
		return d.observePubSubQueue(capability, providerID)
	}
	if service == "pubsub-topic" {
		return d.observePubSub(capability, providerID)
	}
	if service == "memorystore" {
		return d.observeMemorystore(capability, providerID)
	}
	if service == "filestore" {
		return d.observeFilestore(capability, providerID)
	}
	project, _, name, err := splitProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/instances/%s", d.BaseURL, project, name), nil)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("instances.get: HTTP %d", status)
	}
	var inst map[string]any
	if err := json.Unmarshal(body, &inst); err != nil {
		return nil, nil, err
	}
	observed, diags := MapInstance(inst)
	out := make([]provider.Observation, 0, len(observed))
	for _, o := range observed {
		out = append(out, provider.Observation{
			Path: o.Path, Value: o.Value, Derivation: o.Derivation})
	}
	return out, diags, nil
}

// classify409: idempotent continuation ONLY when the existing instance
// carries our ownership labels — binding someone else's database is a
// decision (a future explicit adopt action), not a conflict handler.
func (d *Driver) classify409(name, region, environment,
	capability string) provider.CreateResult {
	const op = "instances.get"
	status, body, cerr := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/instances/%s", d.BaseURL, d.Project, name), nil)
	if cerr != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "name conflict, existing instance gave no answer: " + readTransport(op, cerr).Error()}
	}
	if status != http.StatusOK {
		return provider.CreateResult{Status: "unknown",
			Reason: "name conflict, existing instance gave no answer: " +
				readHTTP(op, status, gcpErrCode(body)).Error()}
	}
	var inst struct {
		Region   string `json:"region"`
		Settings struct {
			UserLabels map[string]string `json:"userLabels"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(body, &inst); err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "name conflict, existing instance unparseable"}
	}
	if inst.Settings.UserLabels["groundhold-capability"] != sanitizeLabel(capability) ||
		inst.Settings.UserLabels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("instance %s exists and is not ours "+
				"(labels do not match) — adopt is an explicit action, "+
				"not a conflict handler", name)}
	}
	// region is create-time immutable: an ours-labeled instance in a DIFFERENT
	// region is not the instance our contract wants and cannot be repaired in
	// place — reporting succeeded would bind the wrong resource (adversarial review).
	if inst.Region != "" && region != "" && !strings.EqualFold(inst.Region, region) {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
			"existing instance %s is in region %q, not the desired %q; region is "+
				"immutable — this is a replacement, not a conflict", name, inst.Region, region)}
	}
	// bind using the LIVE region, never the request's fabricated one.
	liveRegion := inst.Region
	if liveRegion == "" {
		liveRegion = region
	}
	return provider.CreateResult{
		ProviderID: d.providerID(liveRegion, name), Status: "succeeded"}
}

// pollOperation: PENDING|RUNNING|DONE — and DONE is not success unless
// the error field is absent. Timeout is an UNKNOWN outcome carrying the
// real operation name for reconciliation.
func (d *Driver) pollOperation(opName, instance,
	region string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		status, body, err := d.call("GET", fmt.Sprintf(
			"%s/projects/%s/operations/%s", d.BaseURL, d.Project, opName), nil)
		if err == nil && status == http.StatusOK {
			var op struct {
				Status string `json:"status"`
				Error  *struct {
					Errors []struct {
						Code string `json:"code"`
					} `json:"errors"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Status == "DONE" {
				// ANY non-nil error object is a failure — an error present with
				// an empty/differently-shaped errors array must NOT fall through
				// to success (fail-open, adversarial review).
				if op.Error != nil {
					code := "unspecified"
					if len(op.Error.Errors) > 0 {
						code = op.Error.Errors[0].Code
					}
					return provider.CreateResult{OperationID: opName,
						Status: "failed", Reason: "operation failed: " + code}
				}
				return provider.CreateResult{
					ProviderID:  d.providerID(region, instance),
					OperationID: opName, Status: "succeeded"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{OperationID: opName,
				Status: "unknown", Reason: "operation still running at " +
					"poll timeout — reconcile via operations.get"}
		}
		time.Sleep(d.PollInterval)
	}
}

// mutationResult maps a non-2xx status on a MUTATING call. A 5xx does NOT prove
// the mutation did not execute (a 502/504 from a frontend can sit in front of a
// create/patch/delete that landed) — that is `unknown` (D29), which routes into
// the reconcile machinery. A 4xx is a definitive rejection — `failed`.
func mutationResult(op string, status int, body []byte) provider.CreateResult {
	// D237: route through the shared classifier. A throttle (429), server error
	// (5xx), or live permission denial (403) is unknown — the caller adds the
	// providerId when known (see the gcs/cloudrun/... callers). Only a clean 4xx
	// refusal fails. pid is left empty here; callers patch it on unknown.
	if r := provider.MutationResult(status, gcpErrCode(body), nil, "", op); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed",
		Reason: fmt.Sprintf("%s: HTTP %d: %s", op, status, mutDetail(body))}
}

// gcpErrCode extracts the normalized error code from a GCP JSON error body:
// {"error":{"status":"RESOURCE_EXHAUSTED","errors":[{"reason":"rateLimitExceeded"}]}}.
// The REST `reason` is most specific (a 403 carrying rateLimitExceeded is a quota
// throttle, not a permission denial), so it wins; the gRPC-style `status` is the
// fallback. Empty when the body is not a recognizable GCP error.
func gcpErrCode(body []byte) string {
	var e struct {
		Error struct {
			Status string `json:"status"`
			Errors []struct {
				Reason string `json:"reason"`
			} `json:"errors"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	if len(e.Error.Errors) > 0 && e.Error.Errors[0].Reason != "" {
		return e.Error.Errors[0].Reason
	}
	return e.Error.Status
}

func (d *Driver) call(method, url string,
	body map[string]any) (int, []byte, error) {
	tok, err := d.auth.token()
	if err != nil {
		return 0, nil, err
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, respBody, nil
}

// List enumerates existing Cloud SQL instances in the project (D52
// discovery). Read-only; each item runs through the same pure
// MapInstance as Observe. An empty region matches everything.
func (d *Driver) discoverCloudSQL(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/instances", d.BaseURL, d.Project), nil)
	if err != nil {
		return nil, nil, err
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("instances.list: HTTP %d", status)
	}
	var resp struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, err
	}
	var out []provider.Discovered
	var diags []string
	for _, inst := range resp.Items {
		name, _ := inst["name"].(string)
		instRegion, _ := inst["region"].(string)
		if name == "" || (region != "" && instRegion != region) {
			continue
		}
		observed, ds := MapInstance(inst)
		for _, dg := range ds {
			diags = append(diags, name+": "+dg)
		}
		obs := make([]provider.Observation, 0, len(observed))
		for _, o := range observed {
			obs = append(obs, provider.Observation{
				Path: o.Path, Value: o.Value, Derivation: o.Derivation})
		}
		out = append(out, provider.Discovered{
			ProviderID:   d.providerID(instRegion, name),
			ResourceType: "capability.database.relational",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// Reconcile (D57): READ-ONLY conclusion of a pending receipt. The
// authority ladder: operations.get when the real operation name
// survived; otherwise the deterministic instance name answers — with
// the review's not-found discipline: for a create, 404 may mean
// failed OR not-yet-visible, so without an operation name it stays
// unknown; for a delete, 404 is success ONLY because it is tied to the
// receipt's pinned target.
//
// reconcileCloudSQL is the Cloud SQL-specific path (the reconcile dispatch on the
// receipt's target service lives in reconcile_gcp.go). It is kept bespoke — and
// pinned by tests — because its authority ladder (operations.get, then the
// deterministic InstanceName read by name with region resolved live) predates the
// generic reconciler and must stay byte-identical.
func (d *Driver) reconcileCloudSQL(capability, environment string,
	receipt map[string]any) provider.ReconcileResult {
	op, _ := receipt["operation"].(string)

	if pop, _ := receipt["providerOperation"].(string); pop != "" {
		status, body, err := d.call("GET", fmt.Sprintf(
			"%s/projects/%s/operations/%s", d.BaseURL, d.Project, pop), nil)
		switch {
		case err == nil && status == http.StatusOK:
			var opDoc struct {
				Status string `json:"status"`
				Error  *struct {
					Errors []struct {
						Code string `json:"code"`
					} `json:"errors"`
				} `json:"error"`
				TargetID string `json:"targetId"`
			}
			if json.Unmarshal(body, &opDoc) == nil &&
				opDoc.Status == "DONE" {
				// ANY non-nil error object is a failure (not just a non-empty
				// errors array) — the same fail-open pollOperation closed.
				if opDoc.Error != nil {
					code := "unspecified"
					if len(opDoc.Error.Errors) > 0 {
						code = opDoc.Error.Errors[0].Code
					}
					return provider.ReconcileResult{Status: "failed",
						Reason: fmt.Sprintf("operation %s concluded with %s", pop, code)}
				}
				return d.reconcileByName(capability, environment, op, receipt)
			}
			return provider.ReconcileResult{Status: "unknown",
				Reason: fmt.Sprintf("operation %s still running", pop)}
		case err == nil && status == http.StatusNotFound:
			// operation expired past its retention window — the instance NAME
			// outlives it, so fall through to name-based reconciliation.
		default:
			// a TRANSIENT op read (429/403/5xx, transport) is not evidence of
			// anything — do NOT guess a verdict via the name (adversarial review);
			// stay unknown and let the caller retry the reconcile.
			return provider.ReconcileResult{Status: "unknown",
				Reason: fmt.Sprintf("operation %s read failed (HTTP %d) — retry reconcile", pop, status)}
		}
	}
	return d.reconcileByName(capability, environment, op, receipt)
}

func (d *Driver) reconcileByName(capability, environment, op string,
	receipt map[string]any) provider.ReconcileResult {
	var name string
	if op == "delete" || op == "update" {
		pinned, _ := receipt["targetProviderId"].(string)
		_, _, n, err := splitProviderID(pinned)
		if err != nil {
			return provider.ReconcileResult{Status: "unknown",
				Reason: op + " receipt target is unparseable: " + err.Error()}
		}
		name = n
	} else {
		gen, _ := receipt["generation"].(int)
		if gen < 1 {
			gen = 1
		}
		name = InstanceName(d.Project, environment, capability, gen)
	}
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/instances/%s", d.BaseURL, d.Project, name), nil)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: err.Error()}
	}
	switch {
	case status == http.StatusNotFound && op == "delete":
		pinned, _ := receipt["targetProviderId"].(string)
		return provider.ReconcileResult{Status: "succeeded",
			ProviderID: pinned}
	case status == http.StatusNotFound && op == "update":
		return provider.ReconcileResult{Status: "unknown",
			Reason: fmt.Sprintf("instance %s not found — the update's "+
				"target vanished; re-observe before concluding anything",
				name)}
	case status == http.StatusNotFound:
		// create + 404: failed OR not yet visible — never guessed
		return provider.ReconcileResult{Status: "unknown",
			Reason: fmt.Sprintf("instance %s not found — the create "+
				"may have failed or not yet be visible; retry resume "+
				"or check the operation log", name)}
	case status == http.StatusOK:
		var inst struct {
			Region   string `json:"region"`
			Settings struct {
				UserLabels map[string]string `json:"userLabels"`
			} `json:"settings"`
		}
		if err := json.Unmarshal(body, &inst); err != nil {
			return provider.ReconcileResult{Status: "unknown",
				Reason: err.Error()}
		}
		if op == "delete" {
			return provider.ReconcileResult{Status: "failed",
				Reason: fmt.Sprintf("instance %s still exists — the "+
					"delete never completed", name)}
		}
		if inst.Settings.UserLabels["groundhold-capability"] != sanitizeLabel(capability) ||
			inst.Settings.UserLabels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.ReconcileResult{Status: "failed",
				Reason: fmt.Sprintf("instance %s exists and is not ours "+
					"(labels do not match)", name)}
		}
		if op == "update" {
			// D72: conclude by MEASURING — the receipt's desired values
			// against the live reverse mapping; a mismatch stays
			// unknown (the patch may still be in flight), never failed.
			// Measure against the instance OWNERSHIP just validated
			// (d.Project + name), never the receipt's project component:
			// a forged receipt "other-project:region:name" must not
			// redirect the measurement to a different project (security).
			pinned, _ := receipt["targetProviderId"].(string)
			region := ""
			if parts := strings.Split(pinned, ":"); len(parts) == 3 {
				region = parts[1]
			}
			safe := d.providerID(region, name) // name = ownership-checked
			return d.reconcileUpdateByValues(capability, safe, receipt)
		}
		return provider.ReconcileResult{Status: "succeeded",
			ProviderID: d.providerID(inst.Region, name)}
	}
	return provider.ReconcileResult{Status: "unknown",
		Reason: fmt.Sprintf("instances.get: HTTP %d", status)}
}

// reconcileUpdateByValues (D72): every desired value the receipt
// pinned must be measurable in the live reverse mapping and equal.
// Equal everywhere -> the update landed (idempotent conclusion).
// Anything else stays unknown: a missing path, an unparseable value or
// a mismatch may be a patch still in flight — never guessed as failed.
func (d *Driver) reconcileUpdateByValues(capability, pinned string,
	receipt map[string]any) provider.ReconcileResult {
	changes, _ := receipt["changes"].([]any)
	if len(changes) == 0 {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "update receipt pins no desired values — " +
				"reconcile manually"}
	}
	// D76: the reconciler dispatches Observe on the receipt's own target
	// service — no interface param needed, the receipt carries it.
	tgt, _ := receipt["target"].(string)
	obs, _, err := d.Observe(serviceFromTarget(tgt), capability, pinned)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: err.Error()}
	}
	live := map[string]any{}
	for _, o := range obs {
		live[o.Path] = o.Value
	}
	for _, chAny := range changes {
		ch, _ := chAny.(map[string]any)
		path, _ := ch["path"].(string)
		got, has := live[path]
		if !has {
			return provider.ReconcileResult{Status: "unknown",
				Reason: fmt.Sprintf("%s is not derivable from config "+
					"(e.g. a probe-only attribute like an RPO under PITR) "+
					"— resume cannot conclude it by measurement; verify "+
					"with `probe` or adopt the resource, then retry", path)}
		}
		want, err1 := scalars.Parse(ch["to"])
		gotS, err2 := scalars.Parse(got)
		if err1 != nil || err2 != nil {
			return provider.ReconcileResult{Status: "unknown",
				Reason: fmt.Sprintf("%s: desired/observed value "+
					"unparseable — cannot conclude", path)}
		}
		equal, err := scalars.Operators["equals"](gotS, want)
		if err != nil || !equal {
			return provider.ReconcileResult{Status: "unknown",
				Reason: fmt.Sprintf("%s is not at the desired value yet "+
					"— the patch may still be in flight; retry resume",
					path)}
		}
	}
	return provider.ReconcileResult{Status: "succeeded",
		ProviderID: pinned}
}
