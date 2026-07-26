// GCP Vertex AI inference driver (D76): the PURE half of the GCP
// capability.ai.inference vocab — the DIRECT twin of AWS Bedrock (bedrock.go),
// giving capability.ai.inference a second service so the residency rule (D1)
// is a cross-cloud PARITY property, not an AWS quirk. The crux is the same as
// Bedrock's eu-south-2 trap, in the GCP shape: a Vertex AI endpoint is served
// from a REGIONAL host (europe-west4-aiplatform.googleapis.com) and inference
// lands in THAT region — but Vertex also offers a "global" endpoint that routes
// to ANY available region for higher availability. For an EU-residency contract
// that global endpoint is exactly the Bedrock trap: it can route outside the EU.
// groundhold catches it DETERMINISTICALLY: the driver OBSERVES the endpoint's
// destination region(s) from the SERVER-RETURNED resource (network in observe,
// never in the verifier, #6), a "global" endpoint reduces to the ["global"]
// sentinel (not an EU region), and a contract asserts
//
//	inference.destinationRegions subset-of [<EU allowlist>]
//
// with the EXISTING subset-of operator — the trap becomes a `violated` verdict
// before any traffic. model.access is a MANUAL-GATE: Model Garden access to a
// gated family (e.g. Claude on Vertex) is granted by accepting terms in the
// console, never an API create — the driver OBSERVES it, CREATE refuses to fake
// it. This file is PURE (identity + forward map + change classification +
// resource-name parsing); the net shell (vertexai_net.go) drives the Vertex AI
// Endpoint REST API.
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

// vertexEndpointIDOK bounds a Vertex AI endpoint id. Vertex assigns NUMERIC
// endpoint ids (the endpointId create param permits only digits, 1-20), so the
// id is never a slug — a digit-only class keeps a forged/stale binding from
// smuggling a slash or dot into the REST path (D73 boundary).
var vertexEndpointIDOK = regexp.MustCompile(`^[0-9]{1,20}$`)

// vertexPublisherModelOK bounds the publisherModel operand: publishers/<provider>/
// models/<model>[@version]. It is a REFERENCE (names a model), never a secret
// (D53). The version tail may carry '@' and dots; the provider/model segments are
// the load-bearing part.
var vertexPublisherModelOK = regexp.MustCompile(`^publishers/[a-z0-9-]+/models/[A-Za-z0-9._@-]+$`)

// vertexDisplayNameOK bounds an endpoint display name (Vertex: <=128 chars, any
// printable). Kept conservative — alnum, space and a few separators.
var vertexDisplayNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:/=+@-]{0,127}$`)

// vertexProviderID pins the identity: vertexai:<project>:<location>:<endpointId>.
// Service-PREFIXED (D76), like cloudrun: — the token qualifies the identity so a
// forged/stale binding cannot route a Cloud Run id into aiplatform paths (or
// vice-versa). The bare service token (never "gcp-vertexai") matches the GCP
// convention every other service here uses (cloudrun:, cloudsql:...).
func vertexProviderID(project, location, endpointID string) string {
	return "vertexai:" + project + ":" + location + ":" + endpointID
}

// splitVertexProviderID validates every component BEFORE it is interpolated into
// a REST path (D73 confused-deputy boundary). The service token is matched by
// exact string, never interpolated. location may be a region OR "global".
func splitVertexProviderID(providerID string) (project, location, endpointID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "vertexai" {
		return "", "", "", fmt.Errorf(
			"providerId %q is not vertexai:project:location:endpointId", providerID)
	}
	project, location, endpointID = parts[1], parts[2], parts[3]
	if !projectOK.MatchString(project) {
		return "", "", "", fmt.Errorf(
			"providerId project %q is not a valid GCP project id/number — "+
				"refusing to interpolate it into an API path", project)
	}
	if !isVertexLocationValid(location) {
		return "", "", "", fmt.Errorf(
			"providerId location %q is not a valid Vertex location — "+
				"refusing to interpolate it into an API path", location)
	}
	if !vertexEndpointIDOK.MatchString(endpointID) {
		return "", "", "", fmt.Errorf(
			"providerId endpoint id %q is not a valid Vertex endpoint id", endpointID)
	}
	return project, location, endpointID, nil
}

// isVertexLocationValid accepts a GCP region charset OR the special "global"
// location (the trap surface — it must round-trip through the id so a global
// endpoint can be observed and refused, not silently dropped).
func isVertexLocationValid(loc string) bool {
	return loc == "global" || gcpName.MatchString(loc)
}

// locationFromEndpointName extracts the AUTHORITATIVE location from a
// server-returned endpoint resource name:
// projects/<p>/locations/<LOC>/endpoints/<id>. Returns "" when unparseable — the
// caller keeps this honest (measured from the server value, never fabricated).
func locationFromEndpointName(name string) string {
	i := strings.Index(name, "/locations/")
	if i < 0 {
		return ""
	}
	rest := name[i+len("/locations/"):]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		return rest[:slash]
	}
	return rest
}

// endpointIDFromName extracts the terminal endpoint id from a server-returned
// resource name projects/<p>/locations/<l>/endpoints/<ID>. "" when unparseable.
func endpointIDFromName(name string) string {
	i := strings.LastIndex(name, "/endpoints/")
	if i < 0 {
		return ""
	}
	id := name[i+len("/endpoints/"):]
	if slash := strings.IndexByte(id, '/'); slash >= 0 {
		id = id[:slash]
	}
	return id
}

// destinationRegionsFromLocation reduces an endpoint's SERVED location to the
// residency surface the subset-of contract asserts against — the D1 verifier-rule
// input. A regional endpoint routes to THAT region; the "global" endpoint routes
// to any available region, which is NOT a bounded EU set — it reduces to the
// ["global"] sentinel so subset-of an EU allowlist yields `violated`, catching
// the trap DETERMINISTICALLY (the direct twin of Bedrock's eu-south-2).
func destinationRegionsFromLocation(location string) []string {
	if location == "" {
		return nil
	}
	return []string{location}
}

// providerFromDeployedModels picks the model provider/family from an endpoint's
// deployed models — parsed from a publisher model path
// (publishers/anthropic/models/... -> "anthropic"). Returns "" when none is a
// publisher model (e.g. only custom-uploaded models), so observe omits rather
// than fabricates model.provider.
func providerFromDeployedModels(models []string) string {
	for _, m := range models {
		if p := providerFromPublisherModel(m); p != "" {
			return p
		}
	}
	return ""
}

// providerFromPublisherModel extracts <provider> from publishers/<provider>/
// models/<model>. "" for a non-publisher (custom) model resource.
func providerFromPublisherModel(model string) string {
	const pfx = "publishers/"
	i := strings.Index(model, pfx)
	if i < 0 {
		return ""
	}
	rest := model[i+len(pfx):]
	if slash := strings.IndexByte(rest, '/'); slash >= 0 {
		return rest[:slash]
	}
	return ""
}

// VertexPlan is the operand-derived shape a CREATE of a Vertex AI endpoint
// assembles. The routing (destination region) is DETERMINED by the endpoint's
// location — it is observed + verified after create (the subset-of contract),
// never a build input. The plan carries only what a create supplies: the region
// to place the endpoint in, the display name, the model family the endpoint will
// serve (informational at create; provider is OBSERVED live), and whether
// model.access was required (a MANUAL-GATE the create must not fake).
type VertexPlan struct {
	Region         string // the endpoint's home region (from attrs; scopes the create)
	DisplayName    string // endpoint display name (operand, required)
	PublisherModel string // publishers/<provider>/models/<model> (operand, required)
	NeedsAccess    bool   // model.access=true was required — a MANUAL-GATE the create must not fake
}

// BuildVertexAI maps capability.ai.inference attributes + implementation operands
// to a Vertex AI endpoint plan, or REFUSES. Every error is a preflight refusal
// (never a half-build): an unmapped attribute, or a missing/invalid required
// operand, is refused here, before the first Vertex mutation (invariant #4, D26).
// model.access is NOT a build input that can be honored — a true requirement is
// recorded as NeedsAccess so the create can honest-refuse the manual-gate. This
// is the exact shape of BuildBedrock (aws/bedrock.go), the parity twin.
func BuildVertexAI(project, environment, capability string,
	attrs, impl map[string]any, generation int) (VertexPlan, error) {
	p := VertexPlan{}

	// --- CAPABILITY attributes (refuse any unmapped attribute) ---
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "model.access":
			b, ok := raw.(bool)
			if !ok {
				return VertexPlan{}, fmt.Errorf("model.access must be a bool")
			}
			p.NeedsAccess = b
		case "service.managed":
			if raw != true {
				return VertexPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — groundhold manages the Vertex endpoint it stands up")
			}
		case "inference.destinationRegions":
			// the destination region is DETERMINED by the endpoint's location — an
			// endpoint cannot set a separate routing set. It is observed + verified
			// after create (the subset-of contract), never a build input; accept
			// without acting on it.
		case "model.provider":
			// determined by the model deployed on the endpoint; informational at
			// create time (observed live).
		default:
			return VertexPlan{}, fmt.Errorf(
				"attribute %s has no Vertex AI inference mapping — refusing rather than silently dropping it "+
					"(the ai.inference vocab governs location.region, inference.destinationRegions, model.provider, model.access)", path)
		}
	}

	if p.Region == "" {
		return VertexPlan{}, fmt.Errorf(
			"vertex ai requires location.region (the endpoint's region)")
	}
	// region is interpolated into the REST host + path — validate the charset
	// before use (D73 boundary). "global" is a valid Vertex location.
	if !isVertexLocationValid(p.Region) {
		return VertexPlan{}, fmt.Errorf(
			"location.region %q is not a valid Vertex location — refusing to interpolate it", p.Region)
	}

	// --- OPERATOR operands (implementation: block, D26) ---
	dn, _ := impl["displayName"].(string)
	p.DisplayName = strings.TrimSpace(dn)
	if p.DisplayName == "" {
		return VertexPlan{}, fmt.Errorf("implementation.displayName is required (the endpoint display name)")
	}
	if !vertexDisplayNameOK.MatchString(p.DisplayName) {
		return VertexPlan{}, fmt.Errorf("implementation.displayName %q is not a valid endpoint display name", p.DisplayName)
	}
	pm, _ := impl["publisherModel"].(string)
	p.PublisherModel = strings.TrimSpace(pm)
	if p.PublisherModel == "" {
		return VertexPlan{}, fmt.Errorf(
			"implementation.publisherModel is required (a publishers/<provider>/models/<model> reference — the model family the endpoint serves)")
	}
	if !vertexPublisherModelOK.MatchString(p.PublisherModel) {
		return VertexPlan{}, fmt.Errorf("implementation.publisherModel %q is not a valid Vertex publisher model reference", p.PublisherModel)
	}
	return p, nil
}

// classifyVertexChange (D46): PURE — can a capability.ai.inference transition be
// honored in place? An endpoint's ROUTING is fixed by its location, so
// inference.destinationRegions and location.region are IMMUTABLE (a change is a
// new endpoint, not a patch). model.provider is fixed by the deployed model
// family (a new endpoint). model.access is UNSUPPORTED (a Model Garden manual-gate
// groundhold observes, never provisions). service.managed is a projection. The exact
// twin of classifyBedrockChange (aws/bedrock.go).
func classifyVertexChange(path string) (string, string) {
	switch path {
	case "inference.destinationRegions":
		return "immutable", "a Vertex endpoint's destination region is fixed by its location — a change is a new endpoint, not an in-place patch"
	case "location.region":
		return "immutable", "a Vertex endpoint is region-bound — a region change is a new endpoint, not a patch"
	case "model.provider":
		return "immutable", "the model provider/family is fixed by the model deployed on the endpoint — a change is a new endpoint, not an in-place patch"
	case "model.access":
		return "unsupported", "model access is a manual-gate — granted by accepting terms in the Vertex Model Garden console, never an API patch; groundhold observes it, does not provision it"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Vertex AI inference in-place mapping for " + path
	}
}
