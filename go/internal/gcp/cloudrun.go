// Cloud Run request building (D76): the semantic core of the SECOND GCP
// driver, and the proof the D43 driver pattern generalizes. Same split as
// Cloud SQL — a PURE function of its inputs, pinned by golden tests; the
// network shell is thin and httptest-covered. Same rule: REFUSE what cannot
// be honored, never silently drop an attribute that satisfied a constraint.
//
// Maps capability.workload.container attributes to the Cloud Run Admin API
// v2 `services.create` body. Image digests, ports and other pod detail are
// the CANDIDATE's business (the free-form implementation block), not the
// contract's — the vocabulary carries capability semantics only.
package gcp

import (
	"fmt"
	"sort"

	"groundhold/internal/scalars"
)

const runBaseURL = "https://run.googleapis.com/v2"

// ServiceName is the deterministic Cloud Run service name — the idempotency
// mechanism, exactly as InstanceName is for Cloud SQL. Cloud Run v2 requires a
// serviceId of FEWER THAN 50 characters (verified against the live discovery
// doc); a 63-char name passes local validation then 400s after apply starts, so
// we cap at 49 — the safe direction (a shorter deterministic name never hurts).
func ServiceName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 49)
}

// BuildCloudRunCreateRequest maps semantic attributes + the implementation
// block to a Cloud Run v2 services.create request. Every error is a refusal
// apply surfaces in preflight, before any mutation.
func BuildCloudRunCreateRequest(project, environment, capability string,
	attrs, impl map[string]any, generation int) (Request, error) {

	if generation < 1 {
		generation = 1
	}
	name := ServiceName(project, environment, capability, generation)

	// The image is the candidate's business (implementation block), but a
	// service cannot exist without one — refuse rather than create an empty.
	image, _ := impl["image"].(string)
	if image == "" {
		return Request{}, fmt.Errorf(
			"cloud run requires implementation.image (the container to run)")
	}
	container := map[string]any{"image": image}
	if port, ok := impl["port"]; ok {
		p, err := scalars.Parse(port)
		if err != nil || p.Kind != scalars.Number {
			return Request{}, fmt.Errorf("implementation.port is not a number")
		}
		pf := p.Value.(float64)
		if pf != float64(int64(pf)) {
			return Request{}, fmt.Errorf("implementation.port must be a whole number, got %v", pf)
		}
		container["ports"] = []any{
			map[string]any{"containerPort": int(pf)}}
	}

	template := map[string]any{}
	svc := map[string]any{
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
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
			// Cloud Run is regional by construction; nothing to configure,
			// but a zonal/multi-regional REQUIREMENT cannot be honored.
			if raw != "regional" {
				return Request{}, fmt.Errorf(
					"availability.class %v cannot be honored by Cloud Run "+
						"(regional by construction)", raw)
			}
		case "network.publicExposure":
			exposed, _ := raw.(bool)
			if exposed {
				svc["ingress"] = "INGRESS_TRAFFIC_ALL"
			} else {
				svc["ingress"] = "INGRESS_TRAFFIC_INTERNAL_ONLY"
			}
		case "replicas.minimum":
			n, err := scalars.Parse(raw)
			if err != nil || n.Kind != scalars.Number {
				return Request{}, fmt.Errorf("replicas.minimum is not a number")
			}
			nf := n.Value.(float64)
			if nf != float64(int64(nf)) {
				// truncating 2.9 -> 2 would silently provision BELOW the
				// declared minimum — refuse rather than under-satisfy.
				return Request{}, fmt.Errorf(
					"replicas.minimum must be a whole number, got %v", nf)
			}
			scaling, _ := template["scaling"].(map[string]any)
			if scaling == nil {
				scaling = map[string]any{}
			}
			scaling["minInstanceCount"] = int(nf)
			template["scaling"] = scaling
		case "autoscaling.enabled":
			// Cloud Run always autoscales (maxInstances bounds it); an
			// explicit "no autoscaling" requirement cannot be honored.
			if raw != true {
				return Request{}, fmt.Errorf(
					"autoscaling.enabled=false cannot be honored by Cloud Run " +
						"(it always autoscales)")
			}
		case "image.signedProvenance":
			if raw == true {
				// Binary Authorization enforces build provenance at admission.
				svc["binaryAuthorization"] = map[string]any{"useDefault": true}
			}
		case "tls.enforced":
			// Cloud Run serves HTTPS only; tls.enforced=true is satisfied by
			// construction, =false ("plaintext allowed") cannot be honored.
			if raw != true {
				return Request{}, fmt.Errorf(
					"tls.enforced=false cannot be honored by Cloud Run " +
						"(HTTPS-only by construction)")
			}
		case "service.managed":
			if raw != true {
				return Request{}, fmt.Errorf(
					"service.managed=false cannot be honored by Cloud Run")
			}
		default:
			return Request{}, fmt.Errorf(
				"attribute %s has no Cloud Run mapping — refusing rather "+
					"than silently dropping it", path)
		}
	}

	if region == "" {
		return Request{}, fmt.Errorf(
			"cloud run requires location.region (the service's region)")
	}
	// region is interpolated into the REST path (unlike Cloud SQL, where it
	// rides in the body) — validate the charset before use (D73 boundary).
	if !gcpName.MatchString(region) {
		return Request{}, fmt.Errorf(
			"location.region %q is not a valid GCP region identifier — "+
				"refusing to interpolate it into an API path", region)
	}
	template["containers"] = []any{container}
	svc["template"] = template

	url := fmt.Sprintf("%s/projects/%s/locations/%s/services?serviceId=%s",
		runBaseURL, project, region, name)
	return Request{Method: "POST", URL: url, Body: svc}, nil
}
