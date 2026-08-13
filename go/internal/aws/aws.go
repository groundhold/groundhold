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
	"runtime"
	"strings"
	"time"

	"groundhold/internal/provider"
)

type Driver struct {
	// D803: pages the provider said existed and this driver did not follow. A POINTER,
	// so a scoped copy of the driver shares the record rather than losing it — the
	// truncation belongs to the sweep, not to the struct that happened to see it.
	trunc *truncRecord

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
	// emissionAdopt (D1036) is the executor's per-action emission-adopt grant (D1034):
	// when set, createCWLogs may take over a log group the PROVIDER created — the
	// /aws/lambda/<fn> group a bound monitoring.logs governs — instead of refusing it
	// as un-owned. Set from the SEALED plan before the create and cleared after, so it
	// never leaks onto the next action. Narrow by construction: it only lets the create
	// set retention on the group its own Target already names; the compiler minted the
	// grant only for a $ref to a certified emission (D1032), so the driver never decides
	// adoption from the group name.
	emissionAdopt bool
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
	AutoScalingBaseURL           string // D371 compute.autoscaling (Auto Scaling groups)
}

// SetProgress wires the executor's intra-action heartbeat sink (D257 —
// provider.ProgressReporter). Passing nil detaches it.
func (d *Driver) SetProgress(report func(phase string)) { d.progressSink = report }

// SetEmissionAdopt implements provider.EmissionAdopter (D1036). The executor sets it
// per action from the plan's sealed grant (D1034) and clears it after the call.
func (d *Driver) SetEmissionAdopt(allowed bool) { d.emissionAdopt = allowed }

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
		trunc:         &truncRecord{}, // D803
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

// noCredentialsError says what is missing AND what to do about it (D731).
//
// This driver reads the three standard variables and nothing else — a narrow adapter,
// documented as such since D346. But "no AWS credentials in the environment" is a true
// sentence that teaches nothing, and it is FALSE about the operator's situation in the
// one case they are most likely to be in: `AWS_PROFILE` set, the CLI working, and this
// tool claiming there are no credentials. A pilot on MFA and Identity Center hit exactly
// that and had to create a separate MFA-less role to get past it.
//
// Naming the bridge is the whole job of a refusal here (D730). `aws configure
// export-credentials --format env` is the vendor's own command for turning any profile —
// static, assume-role, MFA, SSO — into the three variables this driver reads.
func noCredentialsError() error {
	if p := os.Getenv("AWS_PROFILE"); p != "" {
		return fmt.Errorf("AWS_PROFILE=%s is set, but this driver reads credentials ONLY "+
			"from AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN — it does "+
			"not read ~/.aws/config or ~/.aws/credentials, so profiles, MFA and Identity "+
			"Center are invisible to it. Bridge the profile with: eval \"$(aws configure "+
			"export-credentials --profile %s --format env)\"", p, p)
	}
	return fmt.Errorf("no AWS credentials in the environment — this driver reads " +
		"AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN only, and does not " +
		"read ~/.aws/config or ~/.aws/credentials. From a configured profile: " +
		"eval \"$(aws configure export-credentials --format env)\"")
}

// doSigned signs a request with SigV4 (for the given region) and executes it.
func (d *Driver) doSigned(method, rawURL, service, region string,
	headers map[string]string, body []byte) (int, []byte, error) {
	status, respBody, _, err := d.doSignedH(method, rawURL, service, region, headers, body)
	return status, respBody, err
}

// routeSink is nil in production and stays nil: it is the seam through which a test
// can record every (method, path, service) the drivers ACTUALLY construct, instead of
// reading the paths back out of the source. D317 is the reason for the distinction —
// a static scrape of these drivers gave four different wrong answers, so the question
// "what routes do we call?" is asked of the drivers, at the one funnel they all pass
// through. See routecapture_test.go.
var routeSink func(method, rawURL, service, op, chain string)

// awsCallChain names the functions INSIDE this driver that led to a request, outermost
// first — "wafListByName>wafListPage>wafCall".
//
// D871: the paging ratchet needs to know which CODE issued an operation, and a join by
// operation NAME cannot tell it. `ListTagsForResource` paginates for wafv2 and the literal
// appears at twenty-three call sites across thirteen other services; `ListServices` belongs
// to both App Runner and ECS; `ListClusters` to both ECS and EKS. Asking the recorder is
// the same move D853 made for the operation itself, and D317's rule for the same reason:
// ask the drivers, do not scrape them.
//
// The chain rather than one frame, because "the call site" is ambiguous by design — a read
// that follows its pages may do so in the reader, in a per-page helper, or in the shared
// loop. Paging is followed if ANY function in the chain handles the continuation.
func awsCallChain() string {
	var pcs [24]uintptr
	n := runtime.Callers(3, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])
	var names []string
	for {
		f, more := frames.Next()
		if strings.Contains(f.Function, "groundhold/internal/aws.") &&
			!strings.HasSuffix(f.File, "_test.go") {
			// Test frames are dropped: they would make the chain per-TEST rather than
			// per call site, and the same read reached from three fixtures is one read.
			names = append(names, f.Function[strings.LastIndex(f.Function, ".")+1:])
		}
		if !more {
			break
		}
	}
	for i, j := 0, len(names)-1; i < j; i, j = i+1, j-1 {
		names[i], names[j] = names[j], names[i]
	}
	return strings.Join(names, ">")
}

// doSignedH is doSigned that also returns the response headers — needed by services
// whose concurrency token is an HTTP header (CloudFront's ETag), not the XML body.

// truncRecord holds the pages a driver was told about and did not follow (D803). The
// bookkeeping itself is shared (D818): a truncation is evidence of an incomplete answer
// only if the continuation it handed back was never used, and that rule belongs to how
// paging works rather than to any one provider.
type truncRecord = provider.ListingRecord

// noteTruncation records that a response said more results exist, along with the
// continuation values that would prove a sweep went and read them. A driver built without
// a record (a bare literal in a test) simply keeps none.
func (d *Driver) noteTruncation(call string, values []string) {
	d.trunc.Note(call, values)
}

// noteFollowed clears the note belonging to any continuation an OUTGOING request carries.
func (d *Driver) noteFollowed(rawURL string, body []byte) {
	d.trunc.Followed(provider.RequestValues(rawURL, body))
}

// TruncatedListings implements provider.ListingCompleteness. It RESETS the record, so one
// sweep cannot report the next one's pages.
func (d *Driver) TruncatedListings() []provider.TruncationNote {
	return d.trunc.Take()
}

func (d *Driver) doSignedH(method, rawURL, service, region string,
	headers map[string]string, body []byte) (int, []byte, http.Header, error) {
	if routeSink != nil {
		// FIRST, ahead of every refusal below: a route is constructed whether or not
		// this process holds credentials, and a route we refuse to send is still a
		// route the driver believes in.
		//
		// D853: for 27 of the 40 signed services the PATH names no operation — the
		// Query protocol selects it with an `Action` field in the form body, the JSON
		// protocol with an `X-Amz-Target` header. Recorded without it, every call to
		// such a service collapsed to one line, `service POST /`, and the permission
		// gate could say nothing about any of them. The hint travels here because this
		// is the one place that holds the body AND the headers.
		routeSink(method, rawURL, service, awsOperationHint(rawURL, headers, body), awsCallChain())
	}
	if !d.hasCreds() {
		return 0, nil, nil, noCredentialsError()
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
	// D818: a request that carries a continuation handed back earlier is the sweep
	// saying it went and read the rest — that clears the note the response left.
	d.noteFollowed(rawURL, body)
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
	// D803: the provider just said whether more results exist. Read it HERE, where every
	// response arrives, rather than in the 139 sweeps that would each have to remember.
	if resp.StatusCode == http.StatusOK {
		if more, values := provider.ListingContinuation(respBody); more {
			call := method + " " + u.Path
			if a := awsActionOf(u, body); a != "" {
				call = a // the query-protocol services name the operation this way
			} else if t := headers["X-Amz-Target"]; t != "" {
				call = t
			}
			d.noteTruncation(service+" "+call, values)
		}
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

// awsActionOf returns the operation a Query-protocol request names, from wherever that
// service puts it (D818).
//
// EC2 puts Action in the query string; SNS, SQS, IAM, Auto Scaling, ElastiCache and RDS
// put it in the form-encoded BODY, and every one of their operations is a POST to "/". So
// reading only the query named every one of those truncations "POST /", which is exactly
// the "sends nobody anywhere" that D803 set out to avoid.
func awsActionOf(u *url.URL, body []byte) string {
	if a := u.Query().Get("Action"); a != "" {
		return a
	}
	if len(body) == 0 || bytes.HasPrefix(bytes.TrimSpace(body), []byte("{")) {
		return ""
	}
	q, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}
	return q.Get("Action")
}

// awsOperationHint names the operation a request carries when the path does not.
// Empty for the REST services, whose path already says which operation it is (D853).
func awsOperationHint(rawURL string, headers map[string]string, body []byte) string {
	if t := headers["X-Amz-Target"]; t != "" {
		// AWS JSON: `<targetPrefix>.<Operation>` — the suffix is the operation.
		if i := strings.LastIndex(t, "."); i >= 0 && i+1 < len(t) {
			return t[i+1:]
		}
		return t
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return awsActionOf(u, body)
}
