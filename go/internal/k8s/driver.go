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
}

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
	}
}

// The k8s driver is a full provider.Provider; every governance service routes
// through the schema-driven engine (a mapping + its lenses), no hand-coded twins.
var _ provider.Provider = (*Driver)(nil)

func (d *Driver) Name() string { return "k8s" }

// requireService is the closed dispatch gate (D76 discipline): only wired
// governance services route; anything else fails CLOSED, never a silent default.
func (d *Driver) requireService(service string) error {
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
	if m := d.genericMapping(service); m != nil {
		return d.observeMapped(m, providerID)
	}
	if err := d.requireService(service); err != nil {
		return nil, nil, err
	}
	return nil, nil, fmt.Errorf("k8s driver: observe not wired for service %q", service)
}

func (d *Driver) Validate(service, capability, environment string,
	attributes, implementation map[string]any, generation int) error {
	if m := d.genericMapping(service); m != nil {
		return m.validateMapped(attributes, implementation)
	}
	if err := d.requireService(service); err != nil {
		return err
	}
	return fmt.Errorf("k8s driver: validate not wired for service %q", service)
}

func (d *Driver) Create(service, capability, environment string,
	attributes, implementation map[string]any, idempotencyKey string, generation int) provider.CreateResult {
	if m := d.genericMapping(service); m != nil {
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
	if m := d.genericMapping(service); m != nil {
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
	if m := d.genericMapping(service); m != nil {
		return d.updateMapped(m, capability, environment, providerID, attributes, implementation)
	}
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("k8s driver: update not wired for service %q", service)}
}

func (d *Driver) Delete(service, capability, environment, providerID string,
	idempotencyKey string) provider.CreateResult {
	if m := d.genericMapping(service); m != nil {
		return d.deleteMapped(m, capability, providerID)
	}
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("k8s driver: delete not wired for service %q", service)}
}
