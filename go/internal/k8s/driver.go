// Kubernetes control-plane driver: groundhold as the Terraform/Pulumi replacement
// for cluster GOVERNANCE (RBAC first — Role/RoleBinding). It speaks the k8s REST
// API the same way the cloud drivers speak their control planes, from wherever
// the CLI runs. It provisions the governance object, never the application
// workloads that run on top (those stay with ArgoCD/Helm/CI). RBAC is the first
// capability deliberately: unlike a NetworkPolicy (stored by every API server but
// only ENFORCED if the CNI implements it — which would let adoption confirm a
// restriction that isn't real), RBAC is enforced by the API server itself, so the
// observed config IS the enforced reality and adoption cannot lie.
package k8s

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"groundhold/internal/provider"
)

// Driver is bound to one cluster. Server/BearerToken/HTTP come from a kubeconfig
// context in production (static token or client cert only — exec auth plugins are
// refused, they are non-hermetic); tests set Server to an httptest URL. ClusterID
// pins the cluster for the same-cluster guard, mirroring gcp's Project.
type Driver struct {
	Server      string // API server base URL (no trailing slash)
	BearerToken string // static bearer token; empty when client-cert auth (on HTTP.Transport)
	ClusterID   string // stable cluster identity (server URL / CA fingerprint) for sameCluster
	HTTP        *http.Client
	Now         func() time.Time
	// PollTimeout/PollInterval bound the delete's poll-to-absence (D986): a k8s DELETE
	// is accepted (200/202) while the object enters Terminating, and a finalizer can
	// hold it there indefinitely. Zero means the default (2m / 2s); tests set them small.
	PollTimeout  time.Duration
	PollInterval time.Duration
	// trunc records incomplete listings so the crawl can mark a scope a lower bound
	// (D803/D873). k8s reads full lists (no `limit`), so it has no page-truncation to
	// note — but a discovery sweep that FAILS is incompleteness all the same, and until
	// D873 k8s had no channel to say so at all.
	trunc *provider.ListingRecord
	// Dial is the NetworkPolicy reachability probe's handshake (D59); nil =
	// net.DialTimeout. Injectable so golden tests measure without a network.
	Dial func(network, addr string, timeout time.Duration) (net.Conn, error)
	// SchemaFetch returns the OpenAPI components.schemas map for an API group
	// (the schema-driven engine's drift guard). nil = drift-checking off (the
	// generic engine still reads, unfingerprinted). Injectable for tests.
	SchemaFetch func(group, version string) (map[string]any, error)
	schemaCache map[string]map[string]any
	// Mappings: the schema-driven registry the dispatch routes through for a
	// mapped service (defaults to the embedded set). A writeSafe mapping fully
	// replaces its hand-coded twin.
	Mappings map[string]*Mapping
	// fieldReclaim (D699): the executor sets this per action from the SEALED plan's
	// consent, and clears it after. Unexported so the only way to arm it is
	// SetFieldReclaim — there is no field a caller can set by construction and forget.
	fieldReclaim bool
}

// SetFieldReclaim implements provider.FieldReclaimer (D699).
func (d *Driver) SetFieldReclaim(allowed bool) { d.fieldReclaim = allowed }

// NewDriver builds a driver for an already-resolved API server + token. The
// kubeconfig resolution (context selection, client-cert/CA wiring, exec-plugin
// refusal) lands with the CLI wiring; this constructor keeps the driver testable
// and lets that wiring hand in a ready client.
func NewDriver(server, token string) *Driver {
	return &Driver{
		Server:      strings.TrimRight(server, "/"),
		BearerToken: token,
		ClusterID:   server,
		HTTP:        &http.Client{Timeout: 60 * time.Second},
		Now:         time.Now,
		Mappings:    embeddedMappings,
		trunc:       &provider.ListingRecord{}, // D873
	}
}

// TruncatedListings implements provider.ListingCompleteness (D803/D873): the calls whose
// listings did not finish since the last reset — for k8s, discovery sweeps that failed.
func (d *Driver) TruncatedListings() []provider.TruncationNote { return d.trunc.Take() }

// The k8s driver is a full provider.Provider; every governance service routes
// through the schema-driven engine (a mapping + its lenses), no hand-coded twins.
var _ provider.Provider = (*Driver)(nil)

func (d *Driver) Name() string { return "k8s" }

// requireService is the closed dispatch gate (D76 discipline): only wired
// governance services route; anything else fails CLOSED, never a silent default.
// intent says what a verb is about to do with a service. It exists so the read/write
// question is ASKED rather than remembered: D550 gated a read on a write predicate at
// three call sites, D574 found a fourth, and both were possible because each verb
// picked its own helper and `genericMapping` does not say "write" in its name (D584).
type intent int

const (
	forRead  intent = iota // observe, classify, ownership checks, probes
	forWrite               // create, update, delete
)

// serviceMapping resolves the mapping a verb may use for its INTENT.
//
//	(m, nil)    — use the generic mapped path
//	(nil, nil)  — not mapped; fall through to the hand-coded services
//	(nil, err)  — refuse, worded for the intent that was asked for
//
// Reading admits every mapped service. Writing additionally requires a write lens,
// and its refusal says so, because "unknown service" for one the driver demonstrably
// serves sends the reader hunting a bug that is not there.
func (d *Driver) serviceMapping(service string, in intent) (*Mapping, error) {
	m := d.mappingFor(service)
	if m == nil {
		return nil, nil
	}
	if in == forWrite && !m.writeSafe() {
		return nil, fmt.Errorf("k8s driver: service %q is observed but not written — its "+
			"mapping has no write lens, so groundhold can read and adopt it but "+
			"cannot create, update or delete it", service)
	}
	return m, nil
}

func (d *Driver) requireService(service string) error {
	// D584: the mapped half is serviceMapping's business — including the refusal
	// worded for a read-only service, which D550 added here and which now lives in
	// the one place that knows read from write. What remains is the hand-coded
	// dispatch this gate was originally written for (D76).
	if m, err := d.serviceMapping(service, forWrite); err != nil {
		return err
	} else if m != nil {
		return nil
	}
	switch service {
	case "rbac-role", "rbac-grant", "rbac-clusterrole", "rbac-clustergrant", "netpol", "quota", "namespace":
		return nil
	}
	return fmt.Errorf("k8s driver: unknown service %q (wired: rbac-role, rbac-grant, rbac-clusterrole, rbac-clustergrant, netpol, quota, namespace)", service)
}

// call issues a bearer-signed (or client-cert, via HTTP.Transport) request to the
// API server and returns (status, body, transport-error). A transport error is
// never a verdict — the caller maps it to unknown/unverifiable, never false.
func (d *Driver) call(method, path string, body []byte) (int, []byte, error) {
	return d.callCT(method, path, body, "application/json")
}

// callCT is call with an explicit Content-Type, for the k8s patch media types
// (application/apply-patch+yaml for server-side apply, application/merge-patch+json
// for the claim label stamp).
func (d *Driver) callCT(method, path string, body []byte, contentType string) (int, []byte, error) {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, d.Server+path, r)
	if err != nil {
		return 0, nil, err
	}
	if d.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+d.BearerToken)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := d.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, nil
}

// --- providerId: <group>/<version>/<Kind>/<namespace>/<name> -----------------
// A k8s object's identity is its GVK + namespace + name; the providerId encodes
// exactly that, parsed only by this driver (adopt/ledger treat it opaquely). The
// charset admits the dots of a group name and the slashes between fields.

var k8sNameOK = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)
var k8sGroupOK = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// rbacProviderID builds the id — 5 fields for a namespaced kind, 4 for a
// cluster-scoped one (empty namespace).
func rbacProviderID(group, version, kind, namespace, name string) string {
	if namespace == "" {
		return strings.Join([]string{group, version, kind, name}, "/")
	}
	return strings.Join([]string{group, version, kind, namespace, name}, "/")
}

// splitRBACProviderID validates and splits a providerId. A namespaced kind carries
// <group>/<version>/<Kind>/<namespace>/<name> (5 fields); a cluster-scoped kind
// carries <group>/<version>/<Kind>/<name> (4). Every field is bounded before it is
// interpolated into a REST path (confused-deputy boundary, D73): a malformed id
// must not build an off-target URL. namespace is "" for cluster-scoped kinds.
func splitRBACProviderID(providerID, wantKind string) (group, version, namespace, name string, err error) {
	parts := strings.Split(providerID, "/")
	ns := isNamespacedKind(wantKind)
	want := 4
	shape := "<group>/<version>/<Kind>/<name>"
	if ns {
		want, shape = 5, "<group>/<version>/<Kind>/<namespace>/<name>"
	}
	if len(parts) != want {
		return "", "", "", "", fmt.Errorf("providerId %q is not %s", providerID, shape)
	}
	group, version, kind := parts[0], parts[1], parts[2]
	if ns {
		namespace, name = parts[3], parts[4]
	} else {
		name = parts[3]
	}
	if kind != wantKind {
		return "", "", "", "", fmt.Errorf("providerId kind %q is not %s", kind, wantKind)
	}
	if !k8sGroupOK.MatchString(group) {
		return "", "", "", "", fmt.Errorf("providerId group %q is invalid", group)
	}
	if version == "" || !k8sNameOK.MatchString(version) {
		return "", "", "", "", fmt.Errorf("providerId version %q is invalid", version)
	}
	if ns && !k8sNameOK.MatchString(namespace) {
		return "", "", "", "", fmt.Errorf("providerId namespace %q is invalid", namespace)
	}
	if !k8sNameOK.MatchString(name) {
		return "", "", "", "", fmt.Errorf("providerId name %q is invalid", name)
	}
	return group, version, namespace, name, nil
}

// --- provider.Provider interface ---------------------------------------------

// Every governance service now routes through the schema-driven engine (a mapping +
// its lenses); the hand-coded twins are gone. A service with no writeSafe mapping
// falls to requireService, which fails closed with the wired-services list.
func (d *Driver) Observe(service, capability, providerID string) ([]provider.Observation, []string, error) {
	// D550: reading asks the mapping registry, NOT genericMapping (registry AND
	// write-safe). Gating a read on a write predicate made the driver contradict
	// itself: `discover` enumerated an ArgoCD Application with measured values while
	// `observe` on that same service refused it as unknown.
	if m, err := d.serviceMapping(service, forRead); err != nil {
		return nil, nil, err
	} else if m != nil {
		return d.observeMapped(m, providerID)
	}
	if err := d.requireService(service); err != nil {
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("k8s driver: observe not wired for service %q", service)
}

func (d *Driver) Validate(service, capability, environment string,
	attributes, implementation map[string]any, generation int) error {
	if m, err := d.serviceMapping(service, forWrite); err != nil {
		return err
	} else if m != nil {
		return m.validateMapped(attributes, implementation)
	}
	if err := d.requireService(service); err != nil {
		return err
	}
	return fmt.Errorf("k8s driver: validate not wired for service %q", service)
}

func (d *Driver) Create(service, capability, environment string,
	attributes, implementation map[string]any, idempotencyKey string, generation int) provider.CreateResult {
	if m, err := d.serviceMapping(service, forWrite); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	} else if m != nil {
		return d.createMapped(m, capability, environment, attributes, implementation)
	}
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("k8s driver: create not wired for service %q", service)}
}

// ClassifyChange is pure provider knowledge: a mapped attribute's class comes from
// its op-attribute (default mutable), a lens-emitted path's from the mapping's
// classify table (e.g. a RoleBinding's grant.role/access.scope are immutable — a
// roleRef change is a replacement, not an in-place patch).
func (d *Driver) ClassifyChange(service, path string, current, desired any,
	implementation map[string]any) (string, string) {
	if m, _ := d.serviceMapping(service, forRead); m != nil { // classification is a read
		if a, ok := m.Attributes[path]; ok {
			if a.Change != "" {
				return a.Change, ""
			}
			return "mutable", ""
		}
		if c, ok := m.Classify[path]; ok {
			return c.Change, c.Reason
		}
		return "unsupported", "no mapping for " + path
	}
	return "unsupported", "no k8s mapping for service " + service
}

func (d *Driver) Update(service, capability, environment, providerID string,
	attributes, implementation map[string]any, changes []string, idempotencyKey string) provider.CreateResult {
	if m, err := d.serviceMapping(service, forWrite); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	} else if m != nil {
		return d.updateMapped(m, capability, environment, providerID, attributes, implementation)
	}
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("k8s driver: update not wired for service %q", service)}
}

func (d *Driver) Delete(service, capability, environment, providerID string,
	idempotencyKey string) provider.CreateResult {
	if m, err := d.serviceMapping(service, forWrite); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	} else if m != nil {
		return d.deleteMapped(m, capability, providerID)
	}
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("k8s driver: delete not wired for service %q", service)}
}
