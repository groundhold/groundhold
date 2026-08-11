// App Runner request building: a SECOND AWS backend for
// capability.workload.container (D76 — one capability TYPE, many services),
// alongside ecs. App Runner is the Cloud Run twin: a container image ->
// a managed HTTPS endpoint with request autoscaling, dispatched by the service
// token `apprunner`. Same split as ecs/cloudrun — a PURE builder pinned by
// golden tests, a thin httptest-covered net shell. Same rule: REFUSE what
// cannot be honored, never silently drop or clamp an attribute that satisfied a
// constraint.
//
// App Runner speaks the AWS JSON-1.0 protocol (X-Amz-Target = AppRunner.<Op>) at
// apprunner.<region>.amazonaws.com; SigV4 service name "apprunner". The image,
// port, cpu/memory and (for private ECR) the access role are implementation
// detail — the vocabulary carries capability semantics only.
package aws

import (
	"fmt"
	"regexp"
	"strings"

	"groundhold/internal/scalars"
)

const apprunnerTarget = "AppRunner"

// apprunnerNameOK bounds an App Runner ServiceName (AWS: [A-Za-z0-9] then
// letters/digits/hyphen/underscore, 4..40 total) before it is interpolated
// anywhere (the JSON body / the deterministic providerId).
var apprunnerNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{3,39}$`)

// AppRunnerName is the deterministic ServiceName — the idempotency mechanism
// (a ServiceName is unique per account per region, exactly as ECS's cluster/
// service name is). Capped at 40 (App Runner's max); the stable hash suffix
// carries uniqueness, so a truncated slug never collides.
func AppRunnerName(account, environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	var b strings.Builder
	for _, r := range strings.ToLower(slug) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	slug = strings.Trim(b.String(), "-")
	tail := "-" + letterHash(account+"|"+environment+"|"+capability+genSuffix(generation), 8)
	const maxLen = 40
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
		slug = strings.TrimRight(slug, "-")
	}
	name := slug + tail
	if len(name) < 4 {
		name = "app" + tail
	}
	return name
}

// AppRunnerPlan is the create input: the deterministic ServiceName + the
// CreateService request body (JSON). Single-resource (unlike ECS's cluster+
// taskdef+service) — the managed endpoint IS the service.
type AppRunnerPlan struct {
	Name              string
	Region            string
	CreateServiceBody string // JSON
}

func appRunnerTags(capability, environment string) []any {
	return []any{
		map[string]any{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
		map[string]any{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
	}
}

// appRunnerAutoScalingArn resolves the AutoScalingConfigurationArn a create/update
// must reference to honor replicas.minimum. App Runner has NO scale-to-zero
// (AutoScalingConfiguration MinSize >= 1):
//   - minimum 0 is REFUSED at the call site (fail-closed, never a silent 0->1 clamp);
//   - minimum 1 (or unset) rides App Runner's DEFAULT autoscaling (MinSize 1) — no arn;
//   - minimum >1 requires implementation.autoScalingConfigurationArn (an operand — a
//     pre-created AutoScalingConfiguration whose MinSize matches, exactly as ECS brings
//     a pre-created target group / execution role, the one-binding rule D26). observe
//     traces the referenced config's real MinSize, so a wrong operand is caught.
//
// Returns ("", nil) when the default suffices (minSize <= 1).
func appRunnerAutoScalingArn(minSize int, impl map[string]any) (string, error) {
	if minSize <= 1 {
		return "", nil
	}
	arn, _ := impl["autoScalingConfigurationArn"].(string)
	if arn == "" {
		arn, _ = impl["auto_scaling_configuration_arn"].(string)
	}
	if arn == "" {
		return "", fmt.Errorf(
			"replicas.minimum=%d (>1) requires implementation.autoScalingConfigurationArn "+
				"(a pre-created App Runner AutoScalingConfiguration with MinSize=%d) — a separate "+
				"binding the driver references but does not create; App Runner's default "+
				"autoscaling only guarantees MinSize=1", minSize, minSize)
	}
	if !strings.HasPrefix(arn, "arn:aws:apprunner:") || !strings.Contains(arn, ":autoscalingconfiguration/") {
		return "", fmt.Errorf(
			"implementation.autoScalingConfigurationArn %q is not an App Runner "+
				"autoscalingconfiguration ARN", arn)
	}
	return arn, nil
}

// BuildAppRunnerRequests maps capability.workload.container attributes + the impl
// block to the App Runner CreateService request. Every error is a refusal apply
// surfaces in preflight, before any mutation.
func BuildAppRunnerRequests(account, environment, capability string,
	attrs, impl map[string]any, generation int) (AppRunnerPlan, error) {
	if generation < 1 {
		generation = 1
	}
	name := AppRunnerName(account, environment, capability, generation)

	image, _ := impl["image"].(string)
	if image == "" {
		return AppRunnerPlan{}, fmt.Errorf("apprunner requires implementation.image (the container to run)")
	}
	// ECR_PUBLIC images need no access role; a PRIVATE ECR image needs an
	// AuthenticationConfiguration.AccessRoleArn (App Runner pulls the image AS
	// that role) — a separate binding the operator brings (the one-binding rule),
	// exactly as ECS brings the execution role.
	repoType := "ECR"
	if strings.HasPrefix(image, "public.ecr.aws/") {
		repoType = "ECR_PUBLIC"
	}
	if rt, ok := impl["image_repository_type"].(string); ok && rt != "" {
		if rt != "ECR" && rt != "ECR_PUBLIC" {
			return AppRunnerPlan{}, fmt.Errorf(
				"implementation.image_repository_type must be ECR or ECR_PUBLIC, got %q", rt)
		}
		repoType = rt
	}
	accessRole, _ := impl["access_role_arn"].(string)
	if repoType == "ECR" && accessRole == "" {
		return AppRunnerPlan{}, fmt.Errorf(
			"apprunner with a private ECR image requires implementation.access_role_arn " +
				"(the role App Runner assumes to pull the image); a public.ecr.aws image needs none")
	}

	imageConfig := map[string]any{}
	if raw, ok := impl["port"]; ok {
		p, err := scalars.Parse(raw)
		if err != nil || p.Kind != scalars.Number {
			return AppRunnerPlan{}, fmt.Errorf("implementation.port is not a number")
		}
		pf := p.Value.(float64)
		if pf != float64(int64(pf)) || pf < 1 || pf > 65535 {
			return AppRunnerPlan{}, fmt.Errorf("implementation.port must be a whole number 1..65535, got %v", pf)
		}
		imageConfig["Port"] = fmt.Sprintf("%d", int64(pf)) // App Runner Port is a STRING
	}
	cpu, _ := impl["cpu"].(string)
	if cpu == "" {
		cpu = "1024"
	}
	mem, _ := impl["memory"].(string)
	if mem == "" {
		mem = "2048"
	}

	region := ""
	isPublic := true // App Runner's default ingress is public; the vocab attr overrides it
	minSize := 1     // App Runner default autoscaling MinSize is 1 (no scale-to-zero)

	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "availability.class":
			if raw != "regional" {
				return AppRunnerPlan{}, fmt.Errorf(
					"availability.class %v cannot be honored by App Runner (regional by construction)", raw)
			}
		case "network.publicExposure":
			b, _ := raw.(bool)
			isPublic = b
		case "replicas.minimum":
			n, err := scalars.Parse(raw)
			if err != nil || n.Kind != scalars.Number {
				return AppRunnerPlan{}, fmt.Errorf("replicas.minimum is not a number")
			}
			nf := n.Value.(float64)
			if nf != float64(int64(nf)) {
				// truncating 2.9 -> 2 would silently provision BELOW the declared
				// minimum — refuse rather than under-satisfy.
				return AppRunnerPlan{}, fmt.Errorf("replicas.minimum must be a whole number, got %v", nf)
			}
			if nf == 0 {
				// App Runner has NO scale-to-zero — refuse rather than silently clamp
				// 0 -> 1 (which would provision an always-on instance the contract said
				// must be zero at idle, and bill for it). Fail closed and name the twin.
				return AppRunnerPlan{}, fmt.Errorf(
					"App Runner has no scale-to-zero (minimum is 1 instance); use " +
						"capability.function.serverless for pay-per-request $0-idle")
			}
			if nf < 0 {
				return AppRunnerPlan{}, fmt.Errorf("replicas.minimum must be >= 1, got %v", nf)
			}
			minSize = int(nf)
		case "autoscaling.enabled":
			if raw != true {
				return AppRunnerPlan{}, fmt.Errorf(
					"autoscaling.enabled=false cannot be honored by App Runner (it always autoscales, MaxSize bounds it)")
			}
		case "image.signedProvenance":
			return AppRunnerPlan{}, fmt.Errorf(
				"image.signedProvenance is not honored by the apprunner driver in v0 " +
					"(no equivalent provenance gate is enforced) — refusing rather than lie")
		case "tls.enforced":
			// App Runner's managed endpoint is HTTPS-only by construction; =true is
			// satisfied by construction, =false ("plaintext allowed") cannot be honored.
			if raw != true {
				return AppRunnerPlan{}, fmt.Errorf(
					"tls.enforced=false cannot be honored by App Runner (HTTPS-only by construction)")
			}
		case "service.managed":
			if raw != true {
				return AppRunnerPlan{}, fmt.Errorf("service.managed=false cannot be honored by App Runner")
			}
		default:
			return AppRunnerPlan{}, fmt.Errorf(
				"attribute %s has no App Runner mapping — refusing rather than silently dropping it", path)
		}
	}
	if region == "" {
		return AppRunnerPlan{}, fmt.Errorf("apprunner requires location.region")
	}

	autoScalingArn, err := appRunnerAutoScalingArn(minSize, impl)
	if err != nil {
		return AppRunnerPlan{}, err
	}

	imageRepo := map[string]any{
		"ImageIdentifier":     image,
		"ImageRepositoryType": repoType,
	}
	if len(imageConfig) > 0 {
		imageRepo["ImageConfiguration"] = imageConfig
	}
	source := map[string]any{
		"ImageRepository":        imageRepo,
		"AutoDeploymentsEnabled": false,
	}
	if repoType == "ECR" {
		source["AuthenticationConfiguration"] = map[string]any{"AccessRoleArn": accessRole}
	}
	body := map[string]any{
		"ServiceName":         name,
		"SourceConfiguration": source,
		"InstanceConfiguration": map[string]any{
			"Cpu":    cpu,
			"Memory": mem,
		},
		"NetworkConfiguration": map[string]any{
			"IngressConfiguration": map[string]any{"IsPubliclyAccessible": isPublic},
		},
		"Tags": appRunnerTags(capability, environment),
	}
	if autoScalingArn != "" {
		body["AutoScalingConfigurationArn"] = autoScalingArn
	}

	return AppRunnerPlan{Name: name, Region: region, CreateServiceBody: jsonBody(body)}, nil
}

// classifyAppRunnerChange (D46): PURE — can a capability.workload.container
// transition be honored IN PLACE on App Runner? replicas.minimum swaps the
// referenced AutoScalingConfigurationArn via UpdateService (in place). Everything
// else is either satisfied by construction (tls/autoscaling), a platform/projection
// property, or an ingress/region property App Runner sets at create — reconciling a
// drift there is a REPLACEMENT (safe: workload.container is STATELESS, so a replace
// destroys no data and needs no allow_replace_stateful consent).
func classifyAppRunnerChange(path string) (string, string) {
	switch path {
	case "replicas.minimum":
		return "mutable", "in place via UpdateService (swap the AutoScalingConfigurationArn)"
	case "network.publicExposure":
		// D822: "set at create" is a claim about App Runner, and App Runner's own model
		// contradicts it — UpdateService accepts NetworkConfiguration (botocore
		// apprunner/2020-05-15). The service is stateless, so a replacement costs less here
		// than it does for a machine or a database, but it is still an outage nobody needs
		// and a false reason for it.
		return "unsupported", "in-place ingress change is not wired for App Runner in this " +
			"slice — AWS does support it (UpdateService takes NetworkConfiguration), so this " +
			"is a gap in groundhold rather than a reason to replace the service"
	case "location.region":
		return "immutable", "the region is the service's home — a change is a new service (replacement; stateless, no data loss)"
	case "tls.enforced":
		return "unsupported", "App Runner is HTTPS-only by construction — nothing to patch (=false cannot be honored)"
	case "autoscaling.enabled":
		return "unsupported", "App Runner always autoscales — nothing to patch"
	case "availability.class":
		return "unsupported", "App Runner is regional by construction — nothing to patch"
	case "image.signedProvenance":
		return "unsupported", "the apprunner driver enforces no provenance gate — refused at create, never patched"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no App Runner in-place mapping for " + path
	}
}
