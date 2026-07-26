// Cloud Functions (Gen 2) request building (D84): the fifth GCP service, and
// the SECOND service under capability.workload.container (D76 — one capability
// type, many services). A function's source/runtime/no-image shape is
// implementation noise; what an org contracts (residency, exposure, capacity
// floor, TLS, cost) is the same stateless-workload surface Cloud Run fulfils,
// so this reuses the container vocab verbatim — zero new attributes. v0 handles
// HTTP-invoked functions; an event-driven trigger is candidate wiring the
// driver REFUSES (fail-closed) until an eventing capability is decided on its
// own merits. image.signedProvenance is likewise REFUSED — a function is not an
// image and the driver cannot honestly enforce equivalent provenance in v0.
package gcp

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/scalars"
)

const cloudfunctionsBaseURL = "https://cloudfunctions.googleapis.com/v2"

// FunctionName is the deterministic function id. Cloud Functions Gen2 ids are
// 4-63 chars, LETTERS AND HYPHENS ONLY (no digits, per the live API doc) — so
// unlike the other drivers' names the hash tail is encoded as lowercase
// LETTERS, valid under the strictest reading of the constraint.
func FunctionName(project, environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.ToLower(slug)
	// keep only [a-z-]; anything else (including digits) becomes a hyphen — the
	// letter hash below preserves determinism/uniqueness regardless.
	var b strings.Builder
	for _, r := range slug {
		if r >= 'a' && r <= 'z' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	slug = strings.Trim(b.String(), "-")

	hashInput := project + "|" + environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	tail := "-" + letterHash(hashInput, 8)
	const maxLen = 63
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
		slug = strings.TrimRight(slug, "-")
	}
	name := slug + tail
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		name = "p" + strings.TrimLeft(name, "-")
	}
	return name
}

// letterHash encodes a deterministic digest as n lowercase letters (a-z).
func letterHash(input string, n int) string {
	sum := sha256.Sum256([]byte(input))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = 'a' + (sum[i] % 26)
	}
	return string(out)
}

// BuildCloudFunctionCreateRequest maps capability.workload.container attributes
// + the implementation block to a Cloud Functions v2 create request. Every
// error is a refusal apply surfaces in preflight, before any mutation.
func BuildCloudFunctionCreateRequest(project, environment, capability string,
	attrs, impl map[string]any, generation int) (Request, error) {
	// implementation block (D26): a function cannot exist without source +
	// runtime + entry point — provider detail, refused if absent.
	runtime, _ := impl["runtime"].(string)
	if runtime == "" {
		return Request{}, fmt.Errorf("cloud functions requires implementation.runtime (e.g. nodejs20)")
	}
	entry, _ := impl["entry_point"].(string)
	if entry == "" {
		return Request{}, fmt.Errorf("cloud functions requires implementation.entry_point")
	}
	src, _ := impl["source"].(map[string]any)
	bucket, _ := src["bucket"].(string)
	object, _ := src["object"].(string)
	if bucket == "" || object == "" {
		return Request{}, fmt.Errorf(
			"cloud functions requires implementation.source.{bucket,object} (the code zip in GCS)")
	}
	if _, hasEvent := impl["event_trigger"]; hasEvent {
		return Request{}, fmt.Errorf(
			"event-driven triggers are not wired in v0 — this driver handles " +
				"HTTP functions; an eventing capability is a separate decision")
	}

	name := FunctionName(project, environment, capability, generation)
	serviceConfig := map[string]any{}
	buildConfig := map[string]any{
		"runtime":    runtime,
		"entryPoint": entry,
		"source": map[string]any{
			"storageSource": map[string]any{"bucket": bucket, "object": object},
		},
	}

	region := ""
	paths := make([]string, 0, len(attrs))
	for p := range attrs {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "availability.class":
			if raw != "regional" {
				return Request{}, fmt.Errorf(
					"availability.class %v cannot be honored by Cloud Functions "+
						"(regional by construction)", raw)
			}
		case "network.publicExposure":
			if exposed, _ := raw.(bool); exposed {
				serviceConfig["ingressSettings"] = "ALLOW_ALL"
			} else {
				serviceConfig["ingressSettings"] = "ALLOW_INTERNAL_ONLY"
			}
		case "replicas.minimum":
			n, err := scalars.Parse(raw)
			if err != nil || n.Kind != scalars.Number {
				return Request{}, fmt.Errorf("replicas.minimum is not a number")
			}
			nf := n.Value.(float64)
			if nf != float64(int64(nf)) {
				return Request{}, fmt.Errorf(
					"replicas.minimum must be a whole number, got %v", nf)
			}
			serviceConfig["minInstanceCount"] = int(nf)
		case "autoscaling.enabled":
			if raw != true {
				return Request{}, fmt.Errorf(
					"autoscaling.enabled=false cannot be honored (Cloud Functions " +
						"always autoscales; maxInstanceCount bounds it)")
			}
		case "tls.enforced":
			if raw != true {
				return Request{}, fmt.Errorf(
					"tls.enforced=false cannot be honored (Cloud Functions is HTTPS-only)")
			}
		case "image.signedProvenance":
			// a function is not an image; the driver cannot honestly enforce an
			// equivalent provenance gate in v0 — refuse rather than claim it.
			return Request{}, fmt.Errorf(
				"image.signedProvenance is not honored by the cloud functions driver " +
					"in v0 (no equivalent provenance gate is enforced) — refusing rather than lie")
		case "service.managed":
			if raw != true {
				return Request{}, fmt.Errorf("service.managed=false cannot be honored")
			}
		default:
			return Request{}, fmt.Errorf(
				"attribute %s has no Cloud Functions mapping — refusing rather "+
					"than silently dropping it", path)
		}
	}
	if region == "" {
		return Request{}, fmt.Errorf("cloud functions requires location.region")
	}

	body := map[string]any{
		"name":          name, // set for golden determinism; the URL rebuilds it
		"environment":   "GEN_2",
		"labels":        map[string]any{"groundhold-capability": sanitizeLabel(capability), "groundhold-environment": sanitizeLabel(environment)},
		"buildConfig":   buildConfig,
		"serviceConfig": serviceConfig,
	}
	url := fmt.Sprintf("%s/projects/%s/locations/%s/functions?functionId=%s",
		cloudfunctionsBaseURL, project, region, name)
	return Request{Method: "POST", URL: url, Body: body}, nil
}
