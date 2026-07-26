// The Upstash driver: a read-only crawl adapter for the Upstash serverless
// data platform (Redis/Kafka/QStash). It PAIRS via a credential REFERENCE
// (env:UPSTASH_API_KEY, with the companion UPSTASH_EMAIL) and gently CRAWLS
// the Developer/Management API (https://api.upstash.com/v2) to discover
// resources for context — strictly read-only, never provisioning.
//
// Auth is HTTP Basic (email as username, API key as password) — the Upstash
// Developer API contract — not SigV4 like AWS. Everything semantic lives in a
// pure reverse-map (mapRedisDB); the shell is thin and httptest-covered, with
// an injectable BaseURL for golden tests. Secrets are never read: the driver
// hits only the LIST endpoint, which returns no password/rest_token.
//
// This slice implements Name() + the optional Discoverer (List). The mutating
// provider.Provider methods are honest "not implemented" stubs — the crawl
// path only needs Name()+Discoverer, but crawlProvider returns provider.Provider,
// so the type must satisfy the whole interface. It never provisions.
package upstash

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"groundhold/internal/provider"
)

type Driver struct {
	HTTP *http.Client
	Now  func() time.Time

	email  string
	apiKey string

	// BaseURL overrides the real API for httptest golden tests; empty = real Upstash.
	BaseURL string
}

// NewDriver reads credentials from the Upstash environment variables
// (UPSTASH_EMAIL + UPSTASH_API_KEY), the same env-sourced contract the AWS
// driver has with AWS_ACCESS_KEY_ID etc. The pairing references the API key
// (the secret half); the email is the non-secret Basic-auth username.
func NewDriver() *Driver {
	return &Driver{
		HTTP:   &http.Client{Timeout: 60 * time.Second},
		Now:    time.Now,
		email:  os.Getenv("UPSTASH_EMAIL"),
		apiKey: os.Getenv("UPSTASH_API_KEY"),
	}
}

func (d *Driver) Name() string { return "upstash" }

// base is the API root; tests override BaseURL.
func (d *Driver) base() string {
	if d.BaseURL != "" {
		return d.BaseURL
	}
	return "https://api.upstash.com/v2"
}

// hasCreds reports whether both halves of the Basic credential are present.
// A missing credential is a config error, refused before any request is sent,
// never an ambiguous network outcome.
func (d *Driver) hasCreds() bool {
	return d.email != "" && d.apiKey != ""
}

// doGET issues a read-only GET against the Developer API with HTTP Basic auth
// (email:apiKey). The analogue of AWS's doSigned, but Upstash is a plain
// basic-auth REST API — no request signer.
func (d *Driver) doGET(path string) (int, []byte, error) {
	if !d.hasCreds() {
		return 0, nil, fmt.Errorf("no Upstash credentials in the environment (UPSTASH_EMAIL / UPSTASH_API_KEY)")
	}
	req, err := http.NewRequest("GET", d.base()+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.SetBasicAuth(d.email, d.apiKey)
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		// a mid-body drop must not surface as a well-formed short body a
		// decision-gating parse would misread — it is an error.
		return resp.StatusCode, nil, fmt.Errorf("response body read failed: %v", rerr)
	}
	return resp.StatusCode, body, nil
}

// --- provider.Provider stubs: this driver is discovery-only. -----------------
// The crawl needs only Name()+Discoverer, but crawlProvider hands back a
// provider.Provider, so the type satisfies the whole interface. Every mutating
// entry point refuses honestly rather than pretending — Upstash provisioning is
// a deferred slice (D141: read-only, never provisioning yet).

const notImplemented = "upstash driver is discovery-only — provisioning is not implemented"

func (d *Driver) Validate(service, capability, environment string,
	attributes, implementation map[string]any, generation int) error {
	return fmt.Errorf("%s", notImplemented)
}

func (d *Driver) Create(service, capability, environment string,
	attributes, implementation map[string]any,
	idempotencyKey string, generation int) provider.CreateResult {
	return provider.CreateResult{Status: "failed", Reason: notImplemented}
}

func (d *Driver) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	return nil, nil, fmt.Errorf("%s", notImplemented)
}

func (d *Driver) ClassifyChange(service, path string, current, desired any,
	implementation map[string]any) (string, string) {
	return "unsupported", notImplemented
}

func (d *Driver) Update(service, capability, environment, providerID string,
	attributes, implementation map[string]any,
	changes []string, idempotencyKey string) provider.CreateResult {
	return provider.CreateResult{Status: "failed", Reason: notImplemented}
}

func (d *Driver) Delete(service, capability, environment, providerID string,
	idempotencyKey string) provider.CreateResult {
	return provider.CreateResult{Status: "failed", Reason: notImplemented}
}
