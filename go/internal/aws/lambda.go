// AWS Lambda request building — the semantic core of the AWS
// capability.function.serverless driver (the request-driven, scale-to-zero
// twin of GCP Cloud Functions gen2). A Lambda function is $0-idle by
// construction, so replicas.minimum:0 is HONORED here (unlike a min-1 container
// workload). The container-IMAGE package type carries the code (PackageType=
// Image, Code.ImageUri) — the image, handler, memory size, env vars and VPC
// config are opaque implementation config, never vocabulary attributes
// (invariant #4). timeout.maximum is a REAL per-cloud limit: Lambda caps a
// single invocation at 900s (15 min), so a longer contract is REFUSED here
// (satisfiable on GCP gen2, whose cap is 3600s) — refused, never clamped.
package aws

import (
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/scalars"
)

// lambdaMaxTimeoutSec is AWS Lambda's hard per-invocation ceiling: 15 minutes.
const lambdaMaxTimeoutSec = 900

// LambdaPlan is the attribute-derived shape a create assembles.
type LambdaPlan struct {
	Name       string
	Region     string
	ImageUri   string
	RoleArn    string
	TimeoutSec int
	Public     bool

	// URLAuth REFINES how a public exposure is realised (D26 operand): it is the
	// Function URL AuthType, "none" (anonymous, AuthType=NONE + a principal:*
	// invoke grant — the world can call it) or "iam" (AuthType=AWS_IAM, NO
	// anonymous grant — a SigV4-signed caller only). "iam" is the edge pattern:
	// a CloudFront distribution with an Origin Access Control signs the origin
	// request, so the function is reachable at the edge WITHOUT anonymous invoke
	// (the org RCP that forbids Principal:* on a Function URL never triggers).
	// url_auth does NOT decide WHETHER a URL exists — network.publicExposure does;
	// url_auth only decides how that URL authenticates. Default "none" (the
	// pre-D26 behaviour). Meaningless without a URL, so it REFUSES when the
	// function is not public (fail closed).
	URLAuth string

	// VpcConfig operands (D26): the private subnets + security groups the
	// function's ENIs attach to, so a Lambda can reach a private Aurora. Named
	// exactly as the ecs driver reads them (subnets / security_groups) for
	// cross-driver consistency; both, or neither (a VpcConfig needs both).
	// subnets is $ref-able to a vpc's privateSubnetIds (a list output).
	Subnets        []string
	SecurityGroups []string

	// Environment operands (D26): plain function env vars. A value may be a
	// literal OR a $ref to a NON-SECRET producer output (e.g. an Aurora
	// endpoint host). SECRETS STAY OFF-LEDGER: a DB password is NEVER a
	// hand-pasted env literal — wire host/port via $ref to the Aurora endpoint
	// and inject the password through a secret reference the function reads at
	// runtime. This driver does not build secret injection.
	Environment map[string]string
}

// isRefShape reports whether v is an unresolved intra-plan $ref operand
// ({$ref:{capability,output}}). At apply the compiler-sealed reference is
// resolved to a concrete value BEFORE the builder runs; a raw $ref is only
// ever seen at validate/preflight (where the map-value slot is not stood in),
// so the builder tolerates it there rather than misreading it as a literal.
func isRefShape(v any) bool {
	m, ok := v.(map[string]any)
	if !ok || len(m) != 1 {
		return false
	}
	_, has := m["$ref"]
	return has
}

func lambdaTimeoutSeconds(raw any) (int, error) {
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

// BuildLambda maps capability.function.serverless attributes + the implementation
// block to a create plan. Every error is a preflight refusal apply surfaces before
// any mutation.
func BuildLambda(account, environment, capability string,
	attrs, impl map[string]any, generation int) (LambdaPlan, error) {
	// container-image package type: the image IS the code (D26 implementation block).
	imageUri, _ := impl["image_uri"].(string)
	imageUri = strings.TrimSpace(imageUri)
	if imageUri == "" {
		return LambdaPlan{}, fmt.Errorf(
			"lambda requires implementation.image_uri (the container image; PackageType=Image)")
	}
	roleArn, _ := impl["role_arn"].(string)
	roleArn = strings.TrimSpace(roleArn)
	if roleArn == "" {
		return LambdaPlan{}, fmt.Errorf(
			"lambda requires implementation.role_arn (the function's execution role)")
	}
	p := LambdaPlan{
		Name:     ECSName(account, environment, capability, generation),
		ImageUri: imageUri,
		RoleArn:  roleArn,
		URLAuth:  "none",
	}

	// ---- url_auth operand (D26): the Function URL AuthType. A $ref shape is
	// never valid here (this is a closed enum, not a producer output), so only a
	// literal string is read; an absent operand keeps the "none" default. ----
	if raw, has := impl["url_auth"]; has {
		s, ok := raw.(string)
		if !ok {
			return LambdaPlan{}, fmt.Errorf("implementation.url_auth must be a string (\"iam\" or \"none\")")
		}
		switch strings.TrimSpace(strings.ToLower(s)) {
		case "iam":
			p.URLAuth = "iam"
		case "none", "":
			p.URLAuth = "none"
		default:
			return LambdaPlan{}, fmt.Errorf(
				"implementation.url_auth %q is not a Function URL AuthType — use \"iam\" "+
					"(AWS_IAM, edge/SigV4 only) or \"none\" (anonymous)", s)
		}
	}

	// ---- VpcConfig operands (D26): reuse ecs's subnets/security_groups names ----
	// A Lambda VpcConfig needs BOTH a subnet set and a security-group set; one
	// without the other is a partial config AWS rejects, so refuse in preflight.
	subnets := toStrSlice(impl["subnets"])
	secGroups := toStrSlice(impl["security_groups"])
	switch {
	case len(subnets) > 0 && len(secGroups) == 0:
		return LambdaPlan{}, fmt.Errorf(
			"implementation.subnets requires implementation.security_groups (a Lambda VpcConfig needs both)")
	case len(secGroups) > 0 && len(subnets) == 0:
		return LambdaPlan{}, fmt.Errorf(
			"implementation.security_groups requires implementation.subnets (a Lambda VpcConfig needs both)")
	}
	p.Subnets = subnets
	p.SecurityGroups = secGroups

	// ---- Environment operands (D26): map of string->string, values may be $ref ----
	if envRaw, has := impl["environment"]; has {
		envMap, ok := envRaw.(map[string]any)
		if !ok {
			return LambdaPlan{}, fmt.Errorf(
				"implementation.environment must be a map of string to string")
		}
		env := make(map[string]string, len(envMap))
		for k, v := range envMap {
			switch val := v.(type) {
			case string:
				env[k] = val
			default:
				if isRefShape(v) {
					// an unresolved $ref (validate/preflight only) — apply resolves
					// it to a string before the builder runs.
					continue
				}
				return LambdaPlan{}, fmt.Errorf(
					"implementation.environment[%s] must be a string (a literal or a "+
						"non-secret $ref, e.g. an Aurora endpoint), got %T — a plaintext "+
						"secret does not belong in env; wire it through a secret reference", k, v)
			}
		}
		if len(env) > 0 {
			p.Environment = env
		}
	}

	paths := make([]string, 0, len(attrs))
	for path := range attrs {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "tls.enforced":
			if raw != true {
				return LambdaPlan{}, fmt.Errorf(
					"tls.enforced=false cannot be honored (a Lambda Function URL is HTTPS-only by construction)")
			}
		case "timeout.maximum":
			secs, err := lambdaTimeoutSeconds(raw)
			if err != nil {
				return LambdaPlan{}, fmt.Errorf("timeout.maximum: %v", err)
			}
			if secs > lambdaMaxTimeoutSec {
				return LambdaPlan{}, fmt.Errorf(
					"timeout.maximum %ds exceeds AWS Lambda's hard maximum of %ds (15 minutes) — "+
						"refusing rather than silently clamping (a longer maximum is satisfiable on "+
						"GCP Cloud Functions gen2, whose ceiling is 3600s)", secs, lambdaMaxTimeoutSec)
			}
			p.TimeoutSec = secs
		case "replicas.minimum":
			n, err := scalars.Parse(raw)
			if err != nil || n.Kind != scalars.Number {
				return LambdaPlan{}, fmt.Errorf("replicas.minimum is not a number")
			}
			nf := n.Value.(float64)
			if nf != float64(int64(nf)) || nf < 0 {
				return LambdaPlan{}, fmt.Errorf("replicas.minimum must be a whole number >= 0, got %v", nf)
			}
			if nf > 0 {
				return LambdaPlan{}, fmt.Errorf(
					"replicas.minimum=%d (a warm floor > 0) cannot be honored by the lambda driver in v0 — "+
						"that is provisioned concurrency, which needs a published version/alias (out of this "+
						"single resource's scope); replicas.minimum:0 (pure scale-to-zero, $0 idle) is the native mode",
					int64(nf))
			}
			// nf == 0 -> native scale-to-zero; nothing to configure.
		case "service.managed":
			if raw != true {
				return LambdaPlan{}, fmt.Errorf("service.managed=false cannot be honored")
			}
		default:
			return LambdaPlan{}, fmt.Errorf(
				"attribute %s has no Lambda mapping — refusing rather than silently dropping it "+
					"(handler, memory size, env vars, layers, VPC config are opaque implementation config)", path)
		}
	}
	// url_auth REFINES a public exposure; on a private function there is no URL
	// for it to refine — refuse rather than silently ignore it (fail closed).
	if p.URLAuth == "iam" && !p.Public {
		return LambdaPlan{}, fmt.Errorf(
			"implementation.url_auth=iam requires network.publicExposure: true — it refines HOW a " +
				"Function URL authenticates, and a private function has no URL to authenticate")
	}
	if p.Region == "" {
		return LambdaPlan{}, fmt.Errorf("lambda requires location.region")
	}
	if p.Name == "" {
		return LambdaPlan{}, fmt.Errorf("derived function name is empty")
	}
	return p, nil
}

// createBody is the CreateFunction request body (POST /2015-03-31/functions).
// Ownership is Tags, returned inline by GetFunction.
func (p LambdaPlan) createBody(capability, environment string) map[string]any {
	body := map[string]any{
		"FunctionName": p.Name,
		"PackageType":  "Image",
		"Code":         map[string]any{"ImageUri": p.ImageUri},
		"Role":         p.RoleArn,
		"Tags": map[string]any{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	if p.TimeoutSec > 0 {
		body["Timeout"] = p.TimeoutSec
	}
	if vc := p.vpcConfig(); vc != nil {
		body["VpcConfig"] = vc
	}
	if env := p.envConfig(); env != nil {
		body["Environment"] = env
	}
	return body
}

// vpcConfig renders the CreateFunction/UpdateFunctionConfiguration VpcConfig
// block, or nil when the function is not VPC-attached.
func (p LambdaPlan) vpcConfig() map[string]any {
	if len(p.Subnets) == 0 || len(p.SecurityGroups) == 0 {
		return nil
	}
	return map[string]any{
		"SubnetIds":        toAny(p.Subnets),
		"SecurityGroupIds": toAny(p.SecurityGroups),
	}
}

// envConfig renders the Environment.Variables block, or nil when no env is set.
func (p LambdaPlan) envConfig() map[string]any {
	if len(p.Environment) == 0 {
		return nil
	}
	vars := make(map[string]any, len(p.Environment))
	for k, v := range p.Environment {
		vars[k] = v
	}
	return map[string]any{"Variables": vars}
}

// updateCodeBody is the UpdateFunctionCode request body (PUT .../code): a new
// container image, patched IN PLACE (no replacement). The image is code, not
// configuration, so it rides its own call, distinct from updateConfigBody.
func (p LambdaPlan) updateCodeBody() map[string]any {
	return map[string]any{"ImageUri": p.ImageUri}
}

// canonSubnetsSGs renders a VpcConfig into a stable, order-independent string so
// observe (from the live config) and the drift comparison (from the plan)
// produce byte-identical values for an equal attachment. Empty = no VpcConfig.
func canonSubnetsSGs(subnets, secGroups []string) string {
	s := append([]string(nil), subnets...)
	g := append([]string(nil), secGroups...)
	sort.Strings(s)
	sort.Strings(g)
	if len(s) == 0 && len(g) == 0 {
		return ""
	}
	return "subnets=" + strings.Join(s, ",") + ";sgs=" + strings.Join(g, ",")
}

// canonEnv renders an environment map into a stable string (sorted keys), so an
// operand comparison is order-independent. Empty map = "".
func canonEnv(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+env[k])
	}
	return strings.Join(parts, ";")
}

// operandCanon projects a plan's operands to their canonical observation values,
// keyed by the reserved operand path (provider.OperandPrefix + name). observe
// and OperandTargets share it so DECLARED and OBSERVED operands compare exactly.
func (p LambdaPlan) operandCanon() (vpc, env, pkg string) {
	return canonSubnetsSGs(p.Subnets, p.SecurityGroups), canonEnv(p.Environment), p.ImageUri
}

// updateConfigBody is the UpdateFunctionConfiguration request body (PUT
// .../configuration). It carries the full DERIVABLE configuration — Role,
// Timeout, VpcConfig and Environment — so a patched function never drifts on
// the operands the candidate declares. The image (Code) is not a configuration
// field; a code change is UpdateFunctionCode (updateCodeBody), a separate call.
func (p LambdaPlan) updateConfigBody() map[string]any {
	body := map[string]any{"Role": p.RoleArn}
	if p.TimeoutSec > 0 {
		body["Timeout"] = p.TimeoutSec
	}
	// VpcConfig is sent unconditionally so DETACHING from a VPC (empty lists)
	// is expressible — an omitted VpcConfig would leave a stale attachment.
	if vc := p.vpcConfig(); vc != nil {
		body["VpcConfig"] = vc
	} else {
		body["VpcConfig"] = map[string]any{"SubnetIds": []any{}, "SecurityGroupIds": []any{}}
	}
	if env := p.envConfig(); env != nil {
		body["Environment"] = env
	} else {
		body["Environment"] = map[string]any{"Variables": map[string]any{}}
	}
	return body
}

// lambdaLogGroupName is the CloudWatch Logs group AWS creates for a function
// (D381). The shape is fixed by the service — `/aws/lambda/<functionName>` — so
// it is derivable with no read, and derivable BEFORE the group exists: AWS makes
// it on first invocation, and a retention guarantee that only applies after the
// first log line is not a guarantee.
func lambdaLogGroupName(functionName string) string {
	return "/aws/lambda/" + functionName
}
