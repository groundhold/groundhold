// GCP Cloud Functions (Gen 2) request building for capability.function.serverless
// — the request-driven, SCALE-TO-ZERO twin of AWS Lambda, and the NATURAL home for
// a Cloud Function (a function is a function). This is a SECOND service token on the
// Cloud Functions product: the bare `cloudfunctions` token already fulfils
// capability.workload.container (D84 — a function shoehorned onto the container
// vocab), and the cross-cloud parity matrix is one-capability-per-token, so this
// distinct token (Pub/Sub precedent: pubsub-topic / pubsub-queue, one product, two
// capability tokens) carries function.serverless. Its providerId prefix is `cffn:`
// so it never collides with the workload driver's `cloudfunctions:` ids.
//
// $0-idle by construction: replicas.minimum:0 (pure scale-to-zero) is honored — and
// so is a warm floor > 0 (serviceConfig.minInstanceCount), unlike the Lambda driver.
// timeout.maximum maps to serviceConfig.timeoutSeconds (hard max 3600s / 60 min); a
// longer contract is REFUSED (Lambda's ceiling is 900s — an honest per-cloud gap).
// The runtime / entry point / code zip are implementation config (D26); an
// event-driven trigger is refused (this driver handles HTTP-invoked functions).
package gcp

import (
	"fmt"
	"regexp"

	"groundhold/internal/scalars"
)

// gcfMaxTimeoutSec is Cloud Functions gen2's hard per-invocation ceiling: 60 minutes.
const gcfMaxTimeoutSec = 3600

// vpcConnectorNameOK bounds a Serverless VPC Access connector resource name before
// it is interpolated into the request body: projects/P/locations/L/connectors/NAME.
var vpcConnectorNameOK = regexp.MustCompile(
	`^projects/[a-z][-a-z0-9]{0,61}[a-z0-9]/locations/[a-z][-a-z0-9]*[a-z0-9]/connectors/[a-z][-a-z0-9]{0,61}[a-z0-9]$`)

// isRefShape reports whether v is an unresolved intra-plan $ref operand
// ({$ref:{...}}). At apply the compiler-sealed reference is resolved to a concrete
// value BEFORE the builder runs; a raw $ref is only ever seen at validate/preflight
// (where the map-value slot is not stood in), so the builder tolerates it there
// rather than misreading it as a literal.
func isRefShape(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	_, has := m["$ref"]
	return has
}

func gcfTimeoutSeconds(raw any) (int, error) {
	sc, err := scalars.Parse(raw)
	if err != nil || sc.Kind != scalars.Duration {
		return 0, fmt.Errorf("not a duration")
	}
	ms, _ := sc.Value.(float64)
	secs := int(ms) / 1000
	if secs < 1 {
		return 0, fmt.Errorf("below 1 second cannot be honored")
	}
	return secs, nil
}

// BuildCloudFunctionFnRequest maps capability.function.serverless attributes + the
// implementation block to a Cloud Functions v2 create request. Every error is a
// refusal apply surfaces in preflight, before any mutation.
func BuildCloudFunctionFnRequest(project, environment, capability string,
	attrs, impl map[string]any, generation int) (Request, error) {
	// implementation block (D26): a function cannot exist without source + runtime +
	// entry point — provider detail, refused if absent.
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
			"event-driven triggers are not wired in v0 — this driver handles HTTP " +
				"functions; an eventing capability is a separate decision")
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
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "network.publicExposure":
			if exposed, _ := raw.(bool); exposed {
				serviceConfig["ingressSettings"] = "ALLOW_ALL"
			} else {
				serviceConfig["ingressSettings"] = "ALLOW_INTERNAL_ONLY"
			}
		case "tls.enforced":
			if raw != true {
				return Request{}, fmt.Errorf(
					"tls.enforced=false cannot be honored (Cloud Functions is HTTPS-only)")
			}
		case "timeout.maximum":
			secs, err := gcfTimeoutSeconds(raw)
			if err != nil {
				return Request{}, fmt.Errorf("timeout.maximum: %v", err)
			}
			if secs > gcfMaxTimeoutSec {
				return Request{}, fmt.Errorf(
					"timeout.maximum %ds exceeds Cloud Functions gen2's hard maximum of %ds (60 minutes) — "+
						"refusing rather than silently clamping", secs, gcfMaxTimeoutSec)
			}
			serviceConfig["timeoutSeconds"] = secs
		case "replicas.minimum":
			n, err := scalars.Parse(raw)
			if err != nil || n.Kind != scalars.Number {
				return Request{}, fmt.Errorf("replicas.minimum is not a number")
			}
			nf := n.Value.(float64)
			if nf != float64(int64(nf)) || nf < 0 {
				return Request{}, fmt.Errorf("replicas.minimum must be a whole number >= 0, got %v", nf)
			}
			// 0 = pure scale-to-zero ($0 idle); > 0 = a warm floor (minInstanceCount).
			serviceConfig["minInstanceCount"] = int(nf)
		case "service.managed":
			if raw != true {
				return Request{}, fmt.Errorf("service.managed=false cannot be honored")
			}
		default:
			return Request{}, fmt.Errorf(
				"attribute %s has no Cloud Functions mapping — refusing rather than silently "+
					"dropping it (the handler, memory size, env vars, VPC connector are opaque "+
					"implementation config)", path)
		}
	}
	if region == "" {
		return Request{}, fmt.Errorf("cloud functions requires location.region")
	}

	// ---- VPC connector operand (D26): serverless egress into a VPC so the
	// function can reach a private Cloud SQL by its privateIpAddress. GCP's
	// Serverless VPC Access connector is a DISTINCT resource groundhold has no
	// capability for (the vocab calls VPC-connector wiring implementation noise),
	// so the connector is a LITERAL resource name
	// (projects/P/locations/L/connectors/NAME) — NOT $ref-able to a producer,
	// unlike AWS Lambda which attaches directly to a vpc's privateSubnetIds.
	if conn, has := impl["vpc_connector"]; has {
		s, ok := conn.(string)
		if !ok || !vpcConnectorNameOK.MatchString(s) {
			return Request{}, fmt.Errorf(
				"implementation.vpc_connector must be a connector resource name " +
					"projects/P/locations/L/connectors/NAME")
		}
		serviceConfig["vpcConnector"] = s
		// egress settings only mean something WITH a connector: PRIVATE_RANGES_ONLY
		// (only RFC1918 + configured private ranges route through the connector) or
		// ALL_TRAFFIC (all egress through it). Refuse an unknown value.
		if eg, has := impl["vpc_connector_egress_settings"]; has {
			es, _ := eg.(string)
			switch es {
			case "PRIVATE_RANGES_ONLY", "ALL_TRAFFIC":
				serviceConfig["vpcConnectorEgressSettings"] = es
			default:
				return Request{}, fmt.Errorf(
					"implementation.vpc_connector_egress_settings must be " +
						"PRIVATE_RANGES_ONLY or ALL_TRAFFIC")
			}
		}
	} else if _, has := impl["vpc_connector_egress_settings"]; has {
		return Request{}, fmt.Errorf(
			"implementation.vpc_connector_egress_settings requires implementation.vpc_connector")
	}

	// ---- Environment operand (D26): serviceConfig.environmentVariables, a map of
	// string->string whose values may be a literal OR a $ref to a NON-SECRET
	// producer output (e.g. a Cloud SQL privateIpAddress host). The compiler
	// resolves a $ref nested in a map operand's values generically (D308), so a
	// value arrives here as a concrete string at apply. SECRETS STAY OFF-LEDGER: a
	// DB password is NEVER a plaintext env literal — wire host/port via $ref and
	// inject the password through serviceConfig.secretEnvironmentVariables (a
	// Secret Manager reference the function reads at runtime), which this driver
	// does not build.
	if envRaw, has := impl["environment"]; has {
		envMap, ok := envRaw.(map[string]any)
		if !ok {
			return Request{}, fmt.Errorf(
				"implementation.environment must be a map of string to string")
		}
		env := map[string]any{}
		for _, k := range sortedKeysG(envMap) {
			v := envMap[k]
			switch val := v.(type) {
			case string:
				env[k] = val
			default:
				if isRefShape(v) {
					// an unresolved $ref (validate/preflight only) — apply resolves
					// it to a string before the builder runs.
					continue
				}
				return Request{}, fmt.Errorf(
					"implementation.environment[%s] must be a string (a literal or a "+
						"non-secret $ref, e.g. a Cloud SQL privateIpAddress); a plaintext "+
						"secret does not belong in env — wire it through a secret reference", k)
			}
		}
		if len(env) > 0 {
			serviceConfig["environmentVariables"] = env
		}
	}

	body := map[string]any{
		// D925: Cloud Functions v2 validates the body name against the FULL resource
		// pattern projects/{p}/locations/{l}/functions/{f}; the bare deterministic name is
		// rejected ("Invalid resource name ... for pattern projects/.../functions/{function}").
		"name":        fmt.Sprintf("projects/%s/locations/%s/functions/%s", project, region, name),
		"environment": "GEN_2",
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
		"buildConfig":   buildConfig,
		"serviceConfig": serviceConfig,
	}
	url := fmt.Sprintf("%s/projects/%s/locations/%s/functions?functionId=%s",
		cloudfunctionsBaseURL, project, region, name)
	return Request{Method: "POST", URL: url, Body: body}, nil
}

func fnServerlessProviderID(project, region, name string) string {
	return "cffn:" + project + ":" + region + ":" + name
}
