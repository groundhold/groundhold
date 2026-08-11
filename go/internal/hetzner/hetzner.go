// The Hetzner Cloud driver: a read-only pairing/crawl adapter (D141). Auth is a
// per-project Bearer token (Authorization: Bearer <HCLOUD_TOKEN>), not SigV4, so
// the shell is far thinner than internal/aws. v0 is a Discoverer ONLY — the
// mutating provider.Provider methods refuse-closed (read-only pairing never
// provisions). Everything semantic lives in a pure reverse-map
// (discover_hetzner.go); the shell is thin and httptest-covered.
//
// The token is sourced from the environment at construction time and never
// persisted (the D53/D141 discipline: a pairing holds a REFERENCE, env:HCLOUD_TOKEN,
// never the secret). The struct has nowhere to write it back out.
package hetzner

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"groundhold/internal/provider"
)

// compile-time proof the driver satisfies both the full provider.Provider
// interface (so it can be passed to discover.Run / crawlProvider) and the
// OPTIONAL Discoverer (so discovery routing finds it).
var (
	_ provider.Provider   = (*Driver)(nil)
	_ provider.Discoverer = (*Driver)(nil)
)

const defaultBaseURL = "https://api.hetzner.cloud/v1"

type Driver struct {
	Token   string // per-project API token; read from env, never persisted
	Scope   string // pairing's project label — providerId discriminator, optional
	BaseURL string // "" => defaultBaseURL; httptest overrides for golden tests
	HTTP    *http.Client
	Now     func() time.Time
}

// NewDriver reads the token from HCLOUD_TOKEN — the same env-var reference the
// pairing recorded (`groundhold pair hetzner --cred-ref env:HCLOUD_TOKEN`) and
// validated with Resolves(), resolved here on the crawling host at crawl time,
// exactly as the aws driver sources AWS_ACCESS_KEY_ID.
func NewDriver(scope string) *Driver {
	return &Driver{
		Token: os.Getenv("HCLOUD_TOKEN"),
		Scope: scope,
		HTTP:  &http.Client{Timeout: 60 * time.Second},
		Now:   time.Now,
	}
}

func (d *Driver) Name() string { return "hetzner" }

// D732: this driver OBSERVES and never authors — every write verb below returns
// notImplemented. Without saying so, `provider.CanAuthor` returned its permissive
// default, the compiler planned a create, the plan SEALED, and only apply discovered
// there was nothing to write. D177 built the witness concept for exactly this and said
// why: emitting a create for a service the driver refuses at apply is a lie in the plan.
func init() {
	provider.RegisterWitnessPredicate("hetzner", func(service string) bool { return true })
}

func (d *Driver) base() string {
	if d.BaseURL != "" {
		return d.BaseURL
	}
	return defaultBaseURL
}

// hasToken reports whether a token is present. A missing token is a config
// error, not an ambiguous outcome — discovery refuses cleanly rather than
// letting an unauthenticated request 401.
func (d *Driver) hasToken() bool { return d.Token != "" }

// get performs one authenticated GET and returns status + body. The body is
// capped (a mid-body drop must not surface as a well-formed short read, which a
// decision-gating parse would misread — it is an error), mirroring aws.doSignedH.
func (d *Driver) get(path string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, d.base()+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+d.Token)
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, rerr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if rerr != nil {
		return resp.StatusCode, nil, fmt.Errorf("response body read failed: %v", rerr)
	}
	return resp.StatusCode, body, nil
}

// --- provider.Provider: v0 is read-only. The mutating methods refuse-closed so
// the type satisfies the interface (discover.Run takes a provider.Provider) yet
// can never provision — pairing/crawl is discovery only (the task's boundary). ---

func (d *Driver) Validate(service, capability, environment string,
	attributes, implementation map[string]any, generation int) error {
	return fmt.Errorf("hetzner driver is read-only (pairing/crawl); provisioning is not implemented")
}

func (d *Driver) Create(service, capability, environment string,
	attributes, implementation map[string]any,
	idempotencyKey string, generation int) provider.CreateResult {
	return provider.CreateResult{Status: "failed",
		Reason: "hetzner driver is read-only (pairing/crawl); Create is not implemented"}
}

func (d *Driver) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	return nil, nil, fmt.Errorf("hetzner driver is read-only; single-resource Observe is not implemented (discovery reverse-maps from the list payload)")
}

func (d *Driver) ClassifyChange(service, path string, current, desired any,
	implementation map[string]any) (string, string) {
	return "unsupported", "hetzner driver is read-only; change classification is not implemented"
}

func (d *Driver) Update(service, capability, environment, providerID string,
	attributes, implementation map[string]any,
	changes []string, idempotencyKey string) provider.CreateResult {
	return provider.CreateResult{Status: "failed",
		Reason: "hetzner driver is read-only (pairing/crawl); Update is not implemented"}
}

func (d *Driver) Delete(service, capability, environment, providerID string,
	idempotencyKey string) provider.CreateResult {
	return provider.CreateResult{Status: "failed",
		Reason: "hetzner driver is read-only (pairing/crawl); Delete is not implemented"}
}
