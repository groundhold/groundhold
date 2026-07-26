// The Azure driver (D99): a THIRD provider.Provider implementation alongside
// internal/gcp and internal/aws, proving the provider-agnostic thesis on a third
// cloud — the SAME capability vocabularies, honored-or-refused per Azure's shape.
// Auth is an AAD bearer token (like GCP's, not SigV4). ARM is a JSON REST control
// plane; dispatch is on the SERVICE token (D76), fail-closed on unknown. Azure has
// NO credentials in this environment, so drivers are code + honesty-harness
// certified but NOT live-validated — flagged honestly, never claimed proven.
//
// The account/subscription trap (D99): Blob's storage account, SQL's logical
// server, the resource group and subscription are IMPL-PROVIDED substrate groundhold
// does NOT create (the Azure analogue of a GCP project). An attribute that is a
// property of that substrate is verified-or-refused, never silently mutated on
// someone else's account. The capability binds to the leaf resource (container /
// database / container-group / vnet), one ledger identity.
package azure

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	"groundhold/internal/provider"
)

const armBaseURL = "https://management.azure.com"

// azResourceName is a deterministic, azNameOK-bounded resource name (the
// idempotency handle): prefix-slug-hash8, lowercase, <=63. Generation >= 2 salts
// the hash so a replacement (D48) coexists with its predecessor.
func azResourceName(prefix, environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = nonAZ.ReplaceAllString(toLowerASCII(slug), "-")
	hashInput := prefix + "|" + environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	maxSlug := 63 - len(prefix) - 1 - len(tail)
	if len(slug) > maxSlug {
		slug = slug[:maxSlug]
	}
	slug = trimDash(slug)
	name := prefix + "-" + slug + tail
	return name
}

var nonAZ = regexp.MustCompile(`[^a-z0-9-]+`)

// azStorageName is a storage-account name: 3-24 chars, lowercase alphanumeric ONLY
// (no hyphens), globally unique — a pure hash (the account is the constitutive
// substrate; its name is never author-visible). generation salts a replacement.
func azStorageName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv" + hex.EncodeToString(sum[:])[:20] // "pv" + 20 hex = 22 chars
}

var storageNameOK = regexp.MustCompile(`^[a-z0-9]{3,24}$`)

func toLowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func trimDash(s string) string {
	for len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	for len(s) > 0 && s[len(s)-1] == '-' {
		s = s[:len(s)-1]
	}
	return s
}

// Driver is the Azure provider. Subscription is driver-level (like GCP's Project);
// resource group + the substrate account/server ride in the candidate impl block.
type Driver struct {
	Subscription string
	// secrets (D309) holds the credential values of the mutation in flight so the
	// driver can scrub them out of a Reason before it is persisted.
	secrets      provider.Redactor
	HTTP         *http.Client
	Now          func() time.Time
	PollInterval time.Duration
	PollTimeout  time.Duration
	// AKSLROTimeout is the ceiling for AKS long-running operations (D264 class): a
	// managed-cluster create or control-plane minor-version upgrade routinely takes
	// 20-40 min in real Azure — longer than the 20-min PollTimeout other services use.
	// Without a larger ceiling a HEALTHY, still-progressing upgrade would trip the poll
	// timeout and report unknown (converge DIED) — a false failure on a slow-but-fine op.
	// Zero falls back to PollTimeout (tests set a small value for fast timeout paths).
	AKSLROTimeout time.Duration
	BaseURL       string // ARM base; override for tests, default management.azure.com
	token         string // AAD bearer, from GROUNDHOLD_AZURE_ACCESS_TOKEN
	// Dial is the exposure probe's TCP handshake (parity with the GCP prober);
	// nil = net.DialTimeout. Tests override it.
	Dial func(network, addr string, timeout time.Duration) (net.Conn, error)
}

// NewDriver reads the bearer token from GROUNDHOLD_AZURE_ACCESS_TOKEN — the same
// env-token contract the GCP driver has (GROUNDHOLD_GCP_ACCESS_TOKEN). A full AAD
// client-credentials/JWT exchange is a later addition; the env token is enough for
// CI, tests, and a supplied short-lived token.
// newResilientHTTPClient (D269) hardens the Azure HTTP client against the dead-idle-
// connection HANG a long AKS control-plane upgrade would expose (the AWS/EKS twin was
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

func NewDriver(subscription string) *Driver {
	return &Driver{
		Subscription:  subscription,
		HTTP:          newResilientHTTPClient(),
		Now:           time.Now,
		PollInterval:  10 * time.Second,
		PollTimeout:   20 * time.Minute,
		AKSLROTimeout: 60 * time.Minute, // AKS create/upgrade run 20-40 min (D264 class)
		BaseURL:       armBaseURL,
		token:         os.Getenv("GROUNDHOLD_AZURE_ACCESS_TOKEN"),
	}
}

func (d *Driver) Name() string { return "azure" }

// aksLROTimeout is the deadline for an AKS long-running poll (D264 class). Falls back
// to PollTimeout when unset (0) so tests keep their fast timeout paths.
func (d *Driver) aksLROTimeout() time.Duration {
	if d.AKSLROTimeout > 0 {
		return d.AKSLROTimeout
	}
	return d.PollTimeout
}

// LROTimeout satisfies provider.LROBudgeter: the ceiling this driver applies to a
// long-running provider operation. For Azure that budget is the AKS one (the family
// with control-plane upgrades that outrun the generic PollTimeout).
func (d *Driver) LROTimeout() time.Duration { return d.aksLROTimeout() }

// sanitizeAzTag bounds an ownership tag value (parity with the AWS/GCP discipline).
func sanitizeAzTag(s string) string {
	return nonAZ.ReplaceAllString(toLowerASCII(s), "-")
}

// hasToken reports whether a bearer token is present — a missing token is a config
// error (refuse-before-mutate), never an ambiguous "unknown" mutation outcome.
func (d *Driver) hasToken() bool { return d.token != "" }

// subOK / rgOK bound the subscription and resource-group before they are
// interpolated into an ARM URL (the D73 injection boundary).
var (
	subOK = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)
	rgOK  = regexp.MustCompile(`^[A-Za-z0-9._()-]{1,90}$`)
	// azNameOK bounds a leaf resource name (conservative shared subset).
	azNameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
)

// doARM signs an ARM request with the bearer token and executes it.
func (d *Driver) doARM(method, url string, body []byte) (int, []byte, error) {
	return d.doARMHeader(method, url, body, nil)
}

// doARMHeader is doARM with extra headers (e.g. If-Match for a CAS lock).
func (d *Driver) doARMHeader(method, url string, body []byte, extra map[string]string) (int, []byte, error) {
	if !d.hasToken() {
		return 0, nil, fmt.Errorf("no Azure access token in the environment")
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		// a mid-body drop must not surface as a well-formed short body a
		// decision-gating parse would misread — it is an error (D87).
		return resp.StatusCode, nil, fmt.Errorf("response body read failed: %v", rerr)
	}
	return resp.StatusCode, respBody, nil
}

// azReadAttempts bounds the transient-retry budget for a single-shot ARM read.
const azReadAttempts = 4

// armGet issues a signed ARM GET and RETRIES a bounded number of times on a TRANSIENT
// failure (transport error, 429 throttle, or 5xx) — the read layer's answer to the
// D260 class. Ownership pre-reads (cluster/addon/workload-identity) are single-shot:
// WITHOUT retry a momentary throttle/503/transport blip turns into a fatal readable=false
// "unknown" that aborts the whole converge. A DEFINITIVE status returns at once: 2xx,
// 404 (a real absence), 403 or any other 4xx (a real permission/validation gap is NOT
// something to spin on). Only the transient class is retried, d.PollInterval apart (tiny
// in tests). This never turns a genuine failure into a success — it only rides out the
// noise a live read is guaranteed to hit. Mirrors aws.eksGet.
func (d *Driver) armGet(url string) (int, []byte, error) {
	var st int
	var body []byte
	var err error
	for attempt := 0; attempt < azReadAttempts; attempt++ {
		st, body, err = d.doARM("GET", url, nil)
		if err == nil && st != http.StatusTooManyRequests && st < 500 {
			return st, body, err // definitive (2xx / 4xx incl. 403 / 404)
		}
		if attempt < azReadAttempts-1 {
			time.Sleep(d.PollInterval) // transient: transport error / 429 / 5xx
		}
	}
	return st, body, err
}

// armURL builds a management-plane resource URL, bounding the subscription and
// resource group before interpolation (the D73 injection boundary). provider is
// the ARM provider+type path (e.g. "Microsoft.Network/virtualNetworks/<name>").
func (d *Driver) armURL(resourceGroup, providerPath, apiVersion string) (string, error) {
	if !subOK.MatchString(d.Subscription) {
		return "", fmt.Errorf("azure subscription %q is not a valid GUID", d.Subscription)
	}
	if !rgOK.MatchString(resourceGroup) {
		return "", fmt.Errorf("resource_group %q is not a valid Azure resource group name", resourceGroup)
	}
	return fmt.Sprintf("%s/subscriptions/%s/resourceGroups/%s/providers/%s?api-version=%s",
		d.BaseURL, d.Subscription, resourceGroup, providerPath, apiVersion), nil
}
