// Reverse mapping for capability.network.loadbalancer (READ-ONLY slice): a GCP
// Cloud Load Balancing FRONTEND — a forwarding rule (compute/v1) — reverse-mapped
// to the exposure posture an org governs. A PURE function pinned by golden tests,
// same honesty rules as MapInstance (absent fields emit nothing, unknown enums
// skip with a diagnostic, never a fabricated default).
//
// The two governed facts come from two places on the forwarding rule:
//   - network.publicExposure ← loadBalancingScheme: EXTERNAL / EXTERNAL_MANAGED
//     are internet-facing; INTERNAL / INTERNAL_MANAGED / INTERNAL_SELF_MANAGED
//     are network-private.
//   - encryption.inTransit ← the TARGET PROXY TYPE the rule points at: an HTTPS
//     or SSL target proxy terminates TLS; an HTTP / TCP / gRPC proxy (or a bare
//     backendService L4 passthrough) does not. The proxy type is encoded in the
//     `target` URL's collection segment (".../targetHttpsProxies/<name>"), so it
//     is derivable WITHOUT a second GET — cleaner and one fewer failure mode.
package gcp

import (
	"fmt"
	"sort"
	"strings"
)

// lbForwardingRule is the subset of a compute forwardingRules item (get /
// aggregatedList) the reverse map reads. Everything else — IP, ports, the
// backend internals, health checks — is operational noise the vocab excludes.
type lbForwardingRule struct {
	Name                string `json:"name"`
	LoadBalancingScheme string `json:"loadBalancingScheme"`
	Target              string `json:"target"`
	BackendService      string `json:"backendService"`
}

// MapLoadBalancer reverse-maps a forwarding rule to
// capability.network.loadbalancer attributes. Diagnostics name what was
// deliberately not observed and why. Pure + golden-tested.
func MapLoadBalancer(fr lbForwardingRule) ([]Observed, []string) {
	var out []Observed
	var diags []string

	// network.publicExposure: EXTERNAL* schemes are internet-facing; INTERNAL*
	// are network-private. A legacy/classic forwarding rule omits the scheme
	// entirely — those are external — so an empty value maps to public with a
	// diagnostic recording the interpretation.
	switch scheme := fr.LoadBalancingScheme; {
	case strings.HasPrefix(scheme, "EXTERNAL"):
		out = append(out, Observed{"network.publicExposure", true, "measured"})
	case strings.HasPrefix(scheme, "INTERNAL"):
		out = append(out, Observed{"network.publicExposure", false, "measured"})
	case scheme == "":
		out = append(out, Observed{"network.publicExposure", true, "measured"})
		diags = append(diags, "loadBalancingScheme empty (legacy classic LB) — treated as external/public")
	default:
		diags = append(diags, fmt.Sprintf(
			"loadBalancingScheme %q: unknown enum, publicExposure skipped", scheme))
	}

	// encryption.inTransit: the target proxy TYPE (encoded in the target URL).
	switch kind := targetProxyKind(fr.Target); kind {
	case "targetHttpsProxies", "targetSslProxies":
		out = append(out, Observed{"encryption.inTransit", true, "measured"})
	case "targetHttpProxies", "targetTcpProxies", "targetGrpcProxies":
		out = append(out, Observed{"encryption.inTransit", false, "measured"})
	case "":
		// No target proxy. A bare backendService is an L4 passthrough rule — it
		// terminates no TLS, so inTransit is false (measured). With neither a
		// target nor a backend service there is nothing to conclude — skip.
		if fr.BackendService != "" {
			out = append(out, Observed{"encryption.inTransit", false, "measured"})
		} else {
			diags = append(diags, "forwarding rule has neither a target proxy nor "+
				"a backend service — encryption.inTransit unknown, skipped")
		}
	default:
		diags = append(diags, fmt.Sprintf(
			"target proxy kind %q: not a recognized TLS-terminating type, inTransit skipped", kind))
	}

	// service.managed: a GCP forwarding rule is always a managed cloud LB.
	out = append(out, Observed{"service.managed", true, "measured"})
	return out, diags
}

// -----------------------------------------------------------------------------
// FULL PROVISIONING (D26): the GCP GLOBAL EXTERNAL HTTP(S) load-balancer
// composite. capability.network.loadbalancer maps to a chain of compute/v1
// resources — a global external IP, a health check, a backend service, a URL
// map, a target proxy (HTTP or, when encryption.inTransit, HTTPS with an SSL
// certificate operand), and a global forwarding rule — the minimal working unit
// groundhold can take over from Terraform.
//
// ATTRIBUTE vs OPERAND (D26):
//   - CAPABILITY attributes drive SHAPE: network.publicExposure=true selects
//     loadBalancingScheme EXTERNAL_MANAGED; encryption.inTransit=true selects a
//     targetHttpsProxies (which REQUIRES an sslCertificate operand); false selects
//     a targetHttpProxies.
//   - OPERANDS ride in the candidate implementation: block: `sslCertificate` (an
//     existing compute sslCertificates name/URL, required iff inTransit), `port`
//     (default 443/80), `healthCheckPath` (default "/"), and an optional
//     `backendService` (backends config, else a plumbing-only backend service).
//
// Ownership rides in each resource's DESCRIPTION marker (target proxies and URL
// maps carry no labels), the same discipline VPC uses. Sub-resource names are
// derived by SUFFIX from the forwarding-rule name, so delete recomputes every
// sibling from the providerId alone — no generation, no chain traversal.

// lbNames are the deterministic composite names, all derived from the
// forwarding-rule (primary) name by suffix so retirement can reconstruct the
// whole composite from the providerId.
type lbNames struct {
	ForwardingRule string
	HealthCheck    string
	BackendService string
	URLMap         string
	HTTPProxy      string
	HTTPSProxy     string
	Address        string
}

// lbComposeNames derives every sub-resource name from the forwarding-rule name.
// The forwarding rule is <=55 chars (resourceName), leaving room for a 3-char
// suffix under the 63-char compute limit.
func lbComposeNames(project, environment, capability string, generation int) lbNames {
	fr := resourceName(project, environment, capability, generation, 55)
	return lbNames{
		ForwardingRule: fr,
		HealthCheck:    fr + "-hc",
		BackendService: fr + "-bs",
		URLMap:         fr + "-um",
		HTTPProxy:      fr + "-hp",
		HTTPSProxy:     fr + "-sp",
		Address:        fr + "-ip",
	}
}

// lbSubResource is one insert in the composite: its collection segment (also the
// REST path segment and the ownership-marker key), its name, and its body.
type lbSubResource struct {
	Kind string
	Name string
	Body map[string]any
}

// LoadBalancerPlan is the ORDERED set of inserts a create issues (dependency
// order); delete walks the reverse. HTTPS records whether the target proxy is a
// targetHttpsProxies (an SSL cert operand was consumed).
type LoadBalancerPlan struct {
	Names  lbNames
	HTTPS  bool
	Create []lbSubResource
}

func lbSelf(project, collection, name string) string {
	return fmt.Sprintf("%s/projects/%s/global/%s/%s", computeBaseURL, project, collection, name)
}

// BuildLoadBalancerPlan maps capability.network.loadbalancer to the compute
// requests for a GLOBAL EXTERNAL HTTP(S) load balancer. Every error is a REFUSAL
// apply surfaces in preflight, before any mutation — never a half-built stack.
func BuildLoadBalancerPlan(project, environment, capability string,
	attrs, impl map[string]any, generation int) (LoadBalancerPlan, error) {
	if generation < 1 {
		generation = 1
	}

	public := false
	inTransit := false

	paths := make([]string, 0, len(attrs))
	for p := range attrs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "network.publicExposure":
			public, _ = raw.(bool)
		case "encryption.inTransit":
			inTransit, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return LoadBalancerPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored by a GCP managed load balancer")
			}
		default:
			return LoadBalancerPlan{}, fmt.Errorf(
				"attribute %s has no GCP load-balancer mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}

	// SHAPE gate: this driver provisions the GLOBAL EXTERNAL HTTP(S) LB. An
	// internal (network-private) LB is a different, REGIONAL composite — refuse
	// rather than build the wrong shape.
	if !public {
		return LoadBalancerPlan{}, fmt.Errorf(
			"network.publicExposure=false selects an INTERNAL load balancer — this driver " +
				"provisions the global EXTERNAL HTTP(S) LB; a regional internal LB is a later slice")
	}

	// OPERANDS.
	port, err := lbPortOperand(impl, inTransit)
	if err != nil {
		return LoadBalancerPlan{}, err
	}
	hcPath := "/"
	if p, ok := impl["healthCheckPath"].(string); ok && p != "" {
		hcPath = p
	}

	// sslCertificate is REQUIRED iff inTransit; supplying it WITHOUT inTransit is
	// a contradiction (a cert on a plaintext proxy). Refuse both — never half-build.
	certRaw, certGiven := impl["sslCertificate"].(string)
	certGiven = certGiven && certRaw != ""
	if inTransit && !certGiven {
		return LoadBalancerPlan{}, fmt.Errorf(
			"encryption.inTransit=true requires an `sslCertificate` operand " +
				"(an existing compute sslCertificates resource) — refusing to build a " +
				"target HTTPS proxy with no certificate")
	}
	if !inTransit && certGiven {
		return LoadBalancerPlan{}, fmt.Errorf(
			"an `sslCertificate` operand was supplied but encryption.inTransit is false — " +
				"a certificate on a plaintext HTTP proxy is a contradiction; set inTransit=true or drop the cert")
	}

	names := lbComposeNames(project, environment, capability, generation)
	marker := vpcOwnerMarker(capability, environment)
	plan := LoadBalancerPlan{Names: names, HTTPS: inTransit}

	// 1. global external IP (no dependencies) — reserved so retirement can release it.
	plan.Create = append(plan.Create, lbSubResource{
		Kind: "addresses", Name: names.Address,
		Body: map[string]any{
			"name":        names.Address,
			"description": marker,
			"addressType": "EXTERNAL",
			"ipVersion":   "IPV4",
		}})

	// 2. health check.
	plan.Create = append(plan.Create, lbSubResource{
		Kind: "healthChecks", Name: names.HealthCheck,
		Body: map[string]any{
			"name":            names.HealthCheck,
			"description":     marker,
			"type":            "HTTP",
			"httpHealthCheck": map[string]any{"requestPath": hcPath, "port": port},
		}})

	// 3. backend service (references the health check).
	besBody := map[string]any{
		"name":                names.BackendService,
		"description":         marker,
		"protocol":            "HTTP",
		"loadBalancingScheme": "EXTERNAL_MANAGED",
		"portName":            "http",
		"healthChecks":        []any{lbSelf(project, "healthChecks", names.HealthCheck)},
	}
	if err := applyBackendServiceOperand(besBody, impl["backendService"]); err != nil {
		return LoadBalancerPlan{}, err
	}
	plan.Create = append(plan.Create, lbSubResource{
		Kind: "backendServices", Name: names.BackendService, Body: besBody})

	// 4. URL map (default routes all to the backend service).
	plan.Create = append(plan.Create, lbSubResource{
		Kind: "urlMaps", Name: names.URLMap,
		Body: map[string]any{
			"name":           names.URLMap,
			"description":    marker,
			"defaultService": lbSelf(project, "backendServices", names.BackendService),
		}})

	// 5. target proxy — HTTPS (needs the cert operand) or HTTP.
	var proxyName, proxyKind string
	if inTransit {
		proxyName, proxyKind = names.HTTPSProxy, "targetHttpsProxies"
		cert := certRaw
		if !strings.Contains(cert, "/") {
			if !gcpName.MatchString(cert) {
				return LoadBalancerPlan{}, fmt.Errorf(
					"sslCertificate %q is not a valid compute resource name", cert)
			}
			cert = lbSelf(project, "sslCertificates", cert)
		}
		plan.Create = append(plan.Create, lbSubResource{
			Kind: proxyKind, Name: proxyName,
			Body: map[string]any{
				"name":            proxyName,
				"description":     marker,
				"urlMap":          lbSelf(project, "urlMaps", names.URLMap),
				"sslCertificates": []any{cert},
			}})
	} else {
		proxyName, proxyKind = names.HTTPProxy, "targetHttpProxies"
		plan.Create = append(plan.Create, lbSubResource{
			Kind: proxyKind, Name: proxyName,
			Body: map[string]any{
				"name":        proxyName,
				"description": marker,
				"urlMap":      lbSelf(project, "urlMaps", names.URLMap),
			}})
	}

	// 6. global forwarding rule (references the proxy + the reserved IP).
	plan.Create = append(plan.Create, lbSubResource{
		Kind: "forwardingRules", Name: names.ForwardingRule,
		Body: map[string]any{
			"name":                names.ForwardingRule,
			"description":         marker,
			"loadBalancingScheme": "EXTERNAL_MANAGED",
			"target":              lbSelf(project, proxyKind, proxyName),
			"IPAddress":           lbSelf(project, "addresses", names.Address),
			"portRange":           fmt.Sprintf("%d", port),
		}})

	return plan, nil
}

// lbPortOperand reads the `port` operand (default 443 when inTransit else 80) and
// range-validates it. Accepts a JSON number or a numeric string.
func lbPortOperand(impl map[string]any, inTransit bool) (int, error) {
	def := 80
	if inTransit {
		def = 443
	}
	raw, ok := impl["port"]
	if !ok || raw == nil {
		return def, nil
	}
	var port int
	switch v := raw.(type) {
	case float64:
		port = int(v)
	case int:
		port = v
	case string:
		if _, err := fmt.Sscanf(v, "%d", &port); err != nil {
			return 0, fmt.Errorf("port operand %q is not a number", v)
		}
	default:
		return 0, fmt.Errorf("port operand has an unsupported type %T", raw)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port operand %d is out of range 1-65535", port)
	}
	return port, nil
}

// applyBackendServiceOperand merges the optional `backendService` operand into
// the backend-service body. A string is an existing backend group (NEG/instance
// group) self-link attached as a single backend; a map may carry `protocol` and
// a verbatim `backends` array. Absent -> a valid plumbing-only backend service
// (no backends): the composite is the deliverable, real capacity is app-owned.
func applyBackendServiceOperand(body map[string]any, raw any) error {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		if v == "" {
			return nil
		}
		body["backends"] = []any{map[string]any{"group": v}}
	case map[string]any:
		if p, ok := v["protocol"].(string); ok && p != "" {
			body["protocol"] = p
		}
		if b, ok := v["backends"].([]any); ok {
			body["backends"] = b
		}
		if neg, ok := v["neg"].(string); ok && neg != "" {
			body["backends"] = []any{map[string]any{"group": neg}}
		}
	default:
		return fmt.Errorf("backendService operand has an unsupported type %T", raw)
	}
	return nil
}

// classifyLoadBalancerChange: which transitions can be honored in place? The
// exposure SCHEME and the in-transit posture are baked into the resource SHAPE
// (EXTERNAL vs internal, an HTTP vs an HTTPS target proxy) — a change is a
// REPLACEMENT. The health-check path is a mutable property of the health check.
func classifyLoadBalancerChange(path string) (string, string) {
	switch path {
	case "network.publicExposure":
		return "immutable", "a load balancer's exposure scheme (EXTERNAL vs internal) is baked into the composite shape — a change is a replacement"
	case "encryption.inTransit":
		return "immutable", "the in-transit posture selects an HTTP vs an HTTPS target proxy (a different resource) — a change is a replacement"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		// healthCheckPath is an OPERAND (implementation block), not a capability
		// attribute, so it does not reach ClassifyChange as a semantic path; a
		// health-check patch is the next step. Any other path has no mapping.
		return "unsupported", "no load-balancer in-place mapping for " + path
	}
}

// targetProxyKind pulls the target-proxy collection segment out of a forwarding
// rule's target URL (".../global/targetHttpsProxies/my-proxy" -> "targetHttpsProxies").
// The proxy TYPE is encoded in the URL, so the in-transit posture is derivable
// without a second GET. Returns "" when the target is empty or names no
// target* segment (e.g. a targetPool/targetInstance/serviceAttachment target).
func targetProxyKind(target string) string {
	if target == "" {
		return ""
	}
	for _, seg := range strings.Split(target, "/") {
		if strings.HasPrefix(seg, "target") {
			return seg
		}
	}
	return ""
}
