// The AWS driver (D86): a second provider.Provider implementation alongside
// internal/gcp, proving the provider-agnostic thesis — the SAME capability
// vocabularies (storage.object, database.relational, workload.container)
// fulfilled by RDS/S3/ECS. Dispatch is on the SERVICE token (D76), fail-closed
// on unknown. Auth is SigV4 (sign.go), not a bearer token. Everything semantic
// lives in per-service pure builders; the shells are thin and httptest-covered.
package aws

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"groundhold/internal/provider"
)

type Driver struct {
	Region       string
	Account      string // acting identity's account id; resolved via STS, cached
	HTTP         *http.Client
	Now          func() time.Time
	PollInterval time.Duration
	PollTimeout  time.Duration
	// EKSLROTimeout is the ceiling for EKS long-running operations (D264): a
	// control-plane minor-version upgrade routinely takes 20-40 min in real AWS —
	// longer than the 20-min PollTimeout other services use. Without a larger ceiling
	// a HEALTHY, still-progressing 1.33->1.34 upgrade would trip the poll timeout and
	// report unknown (exit 4, converge DIED) — a false failure on a slow-but-fine op.
	// Zero falls back to PollTimeout (tests set a small value for fast timeout paths).
	EKSLROTimeout time.Duration
	// progress (D257) is an optional intra-action heartbeat sink the executor wires
	// in so a long poll loop (a cluster upgrade, a node-group roll) reports what it
	// is waiting on instead of going silent for minutes. nil = no sink (the driver's
	// semantics are identical either way). Set via SetProgress; emit via progress().
	progressSink func(phase string)
	// secrets (D309) holds the credential values of the mutation in flight so the
	// driver can scrub them out of a Reason before it is persisted.
	secrets provider.Redactor
	// Dial is the exposure probe's TCP handshake (D65 parity); nil = net.DialTimeout.
	// Tests override it to simulate a reachable / filtered endpoint.
	Dial  func(network, addr string, timeout time.Duration) (net.Conn, error)
	creds Credentials
	// endpoint overrides for tests (per-service base URL); empty = real AWS.
	S3BaseURL                    string
	S3ControlBaseURL             string // D240 account-level Block Public Access (s3-control)
	RDSBaseURL                   string
	ECSBaseURL                   string
	EC2BaseURL                   string
	STSBaseURL                   string
	SNSBaseURL                   string
	SQSBaseURL                   string
	SecretsManagerBaseURL        string
	ElastiCacheBaseURL           string
	ElastiCacheServerlessBaseURL string // cache.keyvalue second backend (ElastiCache Serverless, pay-per-use)
	Route53BaseURL               string
	IAMBaseURL                   string // shared IAM Query plumbing (D103/D104/D105)
	CloudWatchBaseURL            string // D106 metric alert
	CloudWatchDashBaseURL        string // D107 metric dashboard
	LogsBaseURL                  string // D109 log-metric (CloudWatch Logs metric filter)
	ECRBaseURL                   string // D110 container registry (ECR)
	EFSBaseURL                   string // D111 filesystem (EFS)
	DynamoDBBaseURL              string // D112 nosql (DynamoDB)
	OpenSearchBaseURL            string // D113 search (OpenSearch)
	OpenSearchServerlessBaseURL  string // search.index second backend (OpenSearch Serverless, pay-per-use)
	KinesisBaseURL               string // D114 streaming (Kinesis)
	MSKBaseURL                   string // D115 managed-kafka (MSK)
	WAFBaseURL                   string // D116 waf (WAFv2 CLOUDFRONT-scope)
	ACMBaseURL                   string // D117 tls-certificate (ACM)
	CloudFrontBaseURL            string // D118 cdn (CloudFront)
	APIGatewayBaseURL            string // D119 apigateway (API Gateway v2)
	RedshiftServerlessBaseURL    string // D122 data-warehouse (Redshift Serverless)
	SchedulerBaseURL             string // D123 cron (EventBridge Scheduler)
	KMSBaseURL                   string // D124 key.encryption (KMS)
	BackupBaseURL                string // D127 backup (AWS Backup)
	EventBridgeBaseURL           string // D143 changefeed (EventBridge rule on CloudTrail)
	ELBv2BaseURL                 string // network.loadbalancer (ELBv2 ALB/NLB, read-only)
	RGTBaseURL                   string // D145 Resource Groups Tagging API (generic claim by ARN)
	EKSBaseURL                   string // D147 EKS cluster substrate (observe)
	SESBaseURL                   string // D148 email.sending (SESv2 outbound-email composite)
	BedrockBaseURL               string // D150 ai.inference (Bedrock inference profiles, observe-first)
	AppRunnerBaseURL             string // workload.container second backend (App Runner, Cloud Run twin)
	LambdaBaseURL                string // capability.function.serverless (Lambda, container-image)
}

// SetProgress wires the executor's intra-action heartbeat sink (D257 —
// provider.ProgressReporter). Passing nil detaches it.
func (d *Driver) SetProgress(report func(phase string)) { d.progressSink = report }

// progress emits an intra-action heartbeat (a no-op when no sink is wired). A long
// poll loop calls it each iteration so the phase (e.g. "cluster upgrading") reaches
// the user instead of a multi-minute silence.
func (d *Driver) progress(phase string) {
	if d.progressSink != nil {
		d.progressSink(phase)
	}
}

// eksLROTimeout is the deadline for an EKS long-running poll (D264). Falls back to
// PollTimeout when unset (0) so tests keep their fast timeout paths.
func (d *Driver) eksLROTimeout() time.Duration {
	if d.EKSLROTimeout > 0 {
		return d.EKSLROTimeout
	}
	return d.PollTimeout
}

// LROTimeout implements provider.LROBudgeter (D265): the driver's long-running-operation
// ceiling. EKS is the AWS driver's slowest LRO (a control-plane upgrade), so its budget
// is the driver's budget. The cross-driver floor gate asserts this is generous enough.
func (d *Driver) LROTimeout() time.Duration { return d.eksLROTimeout() }

// NewDriver reads credentials from the standard AWS environment variables
// (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN), the same
// contract the GCP driver has with GROUNDHOLD_GCP_ACCESS_TOKEN.
// newResilientHTTPClient (D268/D269) is the shared HTTP client for the AWS driver,
// hardened against the dead-idle-connection HANG a long EKS control-plane upgrade
// exposed (Acme F29). A ~40-min upgrade leaves the connection to the EKS API idle for
// long stretches; an LB/NAT can drop it SILENTLY (no FIN/RST). The FIRST attempt (D268 —
// HTTP/2 health-check pings via http.HTTP2Config) did NOT break the hang in the field:
// the wedged HTTP/2 transport ignored both the ping config and http.Client.Timeout, and
// a poll read blocked for 19+ min until SIGQUIT. D269 removes the whole failure class by
// forcing HTTP/1.1 (every AWS control-plane API supports it): on HTTP/1.1 the per-request
// Timeout and ResponseHeaderTimeout are honored RELIABLY and a broken connection is
// discarded on error, so a poll on a dead connection fails fast (<=ResponseHeaderTimeout)
// and the driver's bounded retry (eksGet, D260) gets a fresh one — no dependency on a
// subtle transport field. ResponseHeaderTimeout bounds a stuck read; IdleConnTimeout
// keeps stale connections from lingering.
func newResilientHTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = false
	// A non-nil empty TLSNextProto disables the HTTP/2 ALPN upgrade — the canonical,
	// reliable way to pin HTTP/1.1 (the F29 hang lived entirely in the HTTP/2 transport).
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
	tr.ResponseHeaderTimeout = 30 * time.Second
	return &http.Client{Timeout: 60 * time.Second, Transport: tr}
}

func NewDriver(region string) *Driver {
	if region == "" {
		// AWS_REGION is the standard SDK/CLI variable and the one users actually set;
		// fall back to AWS_DEFAULT_REGION too (Acme: resume only saw AWS_DEFAULT_REGION).
		if region = os.Getenv("AWS_REGION"); region == "" {
			region = os.Getenv("AWS_DEFAULT_REGION")
		}
	}
	return &Driver{
		Region:        region,
		HTTP:          newResilientHTTPClient(),
		Now:           time.Now,
		PollInterval:  15 * time.Second,
		PollTimeout:   20 * time.Minute,
		EKSLROTimeout: 60 * time.Minute, // control-plane upgrades run 20-40 min (D264)
		creds: Credentials{
			AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
			SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			SessionToken:    os.Getenv("AWS_SESSION_TOKEN"),
		},
	}
}

func (d *Driver) Name() string { return "aws" }

// isAWSManagedKMSKey reports whether a KMS key identifier is the AWS-MANAGED
// default for a service — the alias aws/<service> in any of the forms an AWS API
// returns it (bare, alias/-prefixed, or an ARN with an :alias/ suffix). An
// AWS-managed key is NOT customer-managed, so it must never yield
// encryption.customerManagedKeys=true — that would falsely certify a BYOK /
// independently-revocable-key compliance control on a resource the customer does
// not independently control (the false-satisfied direction, D53-adjacent honesty).
// Use only where the API reliably reports the managed default AS this alias; where
// it returns an opaque key ARN indistinguishable from a customer key (RDS,
// DynamoDB, MSK), refuse to observe CMEK instead.
func isAWSManagedKMSKey(key, service string) bool {
	alias := "aws/" + service
	return key == alias || key == "alias/"+alias || strings.HasSuffix(key, ":alias/"+alias)
}

func (d *Driver) amzDate() string {
	return d.Now().UTC().Format("20060102T150405Z")
}

// hasCreds reports whether signing credentials are present. A missing credential
// is a config error, not an ambiguous mutation outcome — the mutating entry points
// refuse (failed) before sending anything (refuse-before-mutate), rather than
// letting the send fail and mislabel it "unknown — may have landed".
func (d *Driver) hasCreds() bool {
	return d.creds.AccessKeyID != "" && d.creds.SecretAccessKey != ""
}

// doSigned signs a request with SigV4 (for the given region) and executes it.
func (d *Driver) doSigned(method, rawURL, service, region string,
	headers map[string]string, body []byte) (int, []byte, error) {
	status, respBody, _, err := d.doSignedH(method, rawURL, service, region, headers, body)
	return status, respBody, err
}

// doSignedH is doSigned that also returns the response headers — needed by services
// whose concurrency token is an HTTP header (CloudFront's ETag), not the XML body.
func (d *Driver) doSignedH(method, rawURL, service, region string,
	headers map[string]string, body []byte) (int, []byte, http.Header, error) {
	if !d.hasCreds() {
		return 0, nil, nil, fmt.Errorf("no AWS credentials in the environment")
	}
	// D209 refuse-before-mutate at the wire: a mutating request that omits a field
	// AWS requires refuses HERE, before signing — never mid-flight after a sibling
	// resource landed. A no-op for reads and unmodeled operations.
	if err := enforceAWSWireContract(headers, body); err != nil {
		return 0, nil, nil, err
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return 0, nil, nil, err
	}
	payloadHash := sha256hex(body) // hex(SHA256("")) for a nil body is the empty hash
	if headers == nil {
		headers = map[string]string{}
	}
	// S3 REQUIRES x-amz-content-sha256 as a signed header (the generic services
	// do not sign it); add it so it is both signed and sent.
	if service == "s3" {
		headers["x-amz-content-sha256"] = payloadHash
	}
	signedHeaders := Sign(method, u, headers, payloadHash, region, service,
		d.amzDate(), d.creds)

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, rdr)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range signedHeaders {
		req.Header.Set(k, v)
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		// a mid-body connection drop must not surface as a well-formed short
		// body (which a decision-gating parse would misread) — it is an error.
		return resp.StatusCode, nil, resp.Header, fmt.Errorf("response body read failed: %v", rerr)
	}
	return resp.StatusCode, respBody, resp.Header, nil
}

// stsBase / regional endpoints; tests override the *BaseURL fields.
func (d *Driver) stsBase() string {
	if d.STSBaseURL != "" {
		return d.STSBaseURL
	}
	region := d.Region
	if region == "" {
		region = "us-east-1" // STS is global; any valid region works for the call
	}
	return "https://sts." + region + ".amazonaws.com"
}

// CallerIdentity returns the acting identity's account/arn (STS
// GetCallerIdentity) — used for recon and, later, the create-scope pin.
func (d *Driver) CallerIdentity() (account, arn string, err error) {
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	stsRegion := d.Region
	if stsRegion == "" {
		stsRegion = "us-east-1"
	}
	status, resp, err := d.doSigned("POST", d.stsBase()+"/", "sts", stsRegion,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, body)
	if err != nil {
		return "", "", err
	}
	if status != http.StatusOK {
		return "", "", fmt.Errorf("STS GetCallerIdentity: HTTP %d: %s", status, mutDetail(resp))
	}
	s := string(resp)
	account = between(s, "<Account>", "</Account>")
	// a garbled/truncated 200 must not cache an empty account (which would strip
	// the account component from every deterministic name).
	if !account12.MatchString(account) {
		return "", "", fmt.Errorf("STS GetCallerIdentity: no valid account in response")
	}
	return account, between(s, "<Arn>", "</Arn>"), nil
}

var account12 = regexp.MustCompile(`^[0-9]{12}$`)

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	i += len(a)
	j := strings.Index(s[i:], b)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}
