// The Cloudflare driver: a read-only pairing/crawl adapter (D141) for the edge/DNS
// layer. Auth is a STATIC API token (Authorization: Bearer <CLOUDFLARE_API_TOKEN>),
// the delegated-credential shape Hetzner/Upstash share — so the shell is thin, no
// request signer. v0 covers DNS records only: pair + discover + observe. The
// mutating provider.Provider methods refuse-closed (read-only pairing never
// provisions; create/update/delete DNS records is a later slice).
//
// The token is sourced from the environment at construction time and never
// persisted (the D53/D141 discipline: a pairing holds a REFERENCE,
// env:CLOUDFLARE_API_TOKEN, never the secret). The struct has nowhere to write it
// back out, and the driver hits only LIST/GET endpoints, which return no secret.
//
// Everything semantic lives in a pure reverse-map (discover_cloudflare.go,
// mapRecord); the shell is thin and httptest-covered, with an injectable BaseURL
// for golden tests.
package cloudflare

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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

const defaultBaseURL = "https://api.cloudflare.com/client/v4"

type Driver struct {
	Token   string // static API token; read from env, never persisted
	Scope   string // pairing's account/zone label — providerId discriminator, optional
	BaseURL string // "" => defaultBaseURL; httptest overrides for golden tests
	HTTP    *http.Client
	Now     func() time.Time
}

// NewDriver reads the token from CLOUDFLARE_API_TOKEN — the same env-var reference
// the pairing recorded (`groundhold pair cloudflare --cred-ref env:CLOUDFLARE_API_TOKEN`)
// and validated with Resolves(), resolved here on the crawling host at crawl time,
// exactly as the aws driver sources AWS_ACCESS_KEY_ID.
func NewDriver(scope string) *Driver {
	return &Driver{
		Token: os.Getenv("CLOUDFLARE_API_TOKEN"),
		Scope: scope,
		HTTP:  &http.Client{Timeout: 60 * time.Second},
		Now:   time.Now,
	}
}

func (d *Driver) Name() string { return "cloudflare" }

// D732: this driver OBSERVES and never authors — every write verb below returns
// notImplemented. Without saying so, `provider.CanAuthor` returned its permissive
// default, the compiler planned a create, the plan SEALED, and only apply discovered
// there was nothing to write. D177 built the witness concept for exactly this and said
// why: emitting a create for a service the driver refuses at apply is a lie in the plan.
func init() {
	provider.RegisterWitnessPredicate("cloudflare", func(service string) bool { return true })
}

func (d *Driver) base() string {
	if d.BaseURL != "" {
		return d.BaseURL
	}
	return defaultBaseURL
}

// hasToken reports whether a token is present. A missing token is a config error,
// not an ambiguous outcome — discovery refuses cleanly rather than letting an
// unauthenticated request 401.
func (d *Driver) hasToken() bool { return d.Token != "" }

// get performs one authenticated GET and returns status + body. The body is capped
// (a mid-body drop must not surface as a well-formed short read a decision-gating
// parse would misread — it is an error), mirroring hetzner/upstash.
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

// --- provider.Provider: v0 is read-only except Observe. -----------------------
// Observe reverse-maps a single bound DNS record; the mutating methods
// refuse-closed so the type satisfies the interface (discover.Run takes a
// provider.Provider) yet can never provision — pairing/crawl is discovery only.

// Observe reads one bound DNS record (providerId dns:<zoneId>:<recordId>) via
// GET /zones/{zone_id}/dns_records/{dns_record_id} and reverse-maps it with the
// SAME pure mapRecord that discovery uses — every observation `measured`. A missing
// token or an unreadable providerId refuses; a list/read failure is a hard error
// (never a fabricated absence — D44 four-valued honesty).
func (d *Driver) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	if !d.hasToken() {
		return nil, nil, fmt.Errorf("cloudflare Observe requires CLOUDFLARE_API_TOKEN in the environment")
	}
	// D874: WAF posture is bound as cfwaf:<zoneId>; DNS as dns:<zoneId>:<recordId>.
	if zoneID, ok := parseWAFProviderID(providerID); ok {
		obs, diags := d.mapZoneWAF(zoneID)
		return obs, diags, nil
	}
	zoneID, recordID, ok := parseRecordProviderID(providerID)
	if !ok {
		return nil, nil, fmt.Errorf("cloudflare Observe: providerId %q is not dns:<zoneId>:<recordId> or cfwaf:<zoneId>", providerID)
	}
	st, body, err := d.get("/zones/" + zoneID + "/dns_records/" + recordID)
	if err != nil {
		return nil, nil, err
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("cloudflare get dns_record: HTTP %d", st)
	}
	var doc struct {
		Success bool      `json:"success"`
		Result  dnsRecord `json:"result"`
	}
	if json.Unmarshal(body, &doc) != nil || !doc.Success {
		return nil, nil, fmt.Errorf("cloudflare get dns_record: unreadable or unsuccessful response")
	}
	return mapRecord(doc.Result), nil, nil
}

// parseRecordProviderID splits dns:<zoneId>:<recordId>. Ids are Cloudflare's
// 32-hex identifiers (no embedded colon), so a strict three-field split is safe.
func parseRecordProviderID(id string) (zoneID, recordID string, ok bool) {
	parts := strings.Split(id, ":")
	if len(parts) != 3 || parts[0] != "dns" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

const notImplemented = "cloudflare driver is read-only (pairing/crawl); provisioning DNS records is not implemented"

func (d *Driver) Validate(service, capability, environment string,
	attributes, implementation map[string]any, generation int) error {
	return fmt.Errorf("%s", notImplemented)
}

func (d *Driver) Create(service, capability, environment string,
	attributes, implementation map[string]any,
	idempotencyKey string, generation int) provider.CreateResult {
	return provider.CreateResult{Status: "failed", Reason: notImplemented}
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
