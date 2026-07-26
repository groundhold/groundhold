// ECS/Fargate request building (D86): the semantic core of the AWS
// workload.container driver — the SAME vocabulary Cloud Run / Cloud Functions
// fulfil (thesis proof, D85). ECS uses the AWS JSON protocol (X-Amz-Target
// header). A container workload is MULTI-RESOURCE on ECS: a cluster + a task
// definition (the container spec) + a service (runs N tasks, with awsvpc
// networking). Image, cpu/memory, subnets, security groups and the execution
// role are implementation detail; the vocabulary carries capability semantics.
package aws

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"groundhold/internal/scalars"
)

const ecsTarget = "AmazonEC2ContainerServiceV20141113"

// ecsNameOK bounds a cluster/service/family name (ECS: letters, digits, hyphen,
// underscore, up to 255) before it is interpolated anywhere.
var ecsNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,254}$`)

// ECSName is the deterministic cluster/service/family base name.
func ECSName(account, environment, capability string, generation int) string {
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
	const maxLen = 64
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
		slug = strings.TrimRight(slug, "-")
	}
	name := slug + tail
	if name == "" {
		name = "app" + tail
	}
	return name
}

// ECSPlan is the ordered create sequence: cluster -> register task def ->
// create service. The shell sequences and polls the service to stable.
type ECSPlan struct {
	Name              string
	Cluster           string
	Family            string
	AssignPublicIP    string
	DesiredCount      int
	TargetGroupArn    string // tls.enforced: the pre-created ALB target group the service registers behind
	ContainerPort     int    // the container port the target group routes to (set with TargetGroupArn)
	RegisterTaskBody  string // JSON
	CreateServiceFn   func(taskDefArn string) string
	CreateClusterBody string
}

func ecsTags(capability, environment string) []any {
	return []any{
		map[string]any{"key": "groundhold-capability", "value": sanitizeTag(capability)},
		map[string]any{"key": "groundhold-environment", "value": sanitizeTag(environment)},
	}
}

// BuildECSRequests maps capability.workload.container attributes + the impl
// block to the ECS create sequence. Every error is a refusal apply surfaces in
// preflight, before any mutation.
func BuildECSRequests(account, environment, capability string,
	attrs, impl map[string]any, generation int) (ECSPlan, error) {
	name := ECSName(account, environment, capability, generation)

	image, _ := impl["image"].(string)
	if image == "" {
		return ECSPlan{}, fmt.Errorf("ecs requires implementation.image (the container to run)")
	}
	subnets := toStrSlice(impl["subnets"])
	if len(subnets) == 0 {
		return ECSPlan{}, fmt.Errorf("ecs (Fargate awsvpc) requires implementation.subnets")
	}
	secGroups := toStrSlice(impl["security_groups"])
	if len(secGroups) == 0 {
		return ECSPlan{}, fmt.Errorf("ecs (Fargate awsvpc) requires implementation.security_groups")
	}
	execRole, _ := impl["execution_role_arn"].(string)
	if execRole == "" {
		return ECSPlan{}, fmt.Errorf("ecs requires implementation.execution_role_arn (to pull the image + write logs)")
	}
	cpu, _ := impl["cpu"].(string)
	if cpu == "" {
		cpu = "256"
	}
	mem, _ := impl["memory"].(string)
	if mem == "" {
		mem = "512"
	}

	region := ""
	desired := 1
	assignPublic := "DISABLED"
	tgArn := ""
	containerPort := 0

	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "availability.class":
			if raw != "regional" {
				return ECSPlan{}, fmt.Errorf(
					"availability.class %v cannot be honored by Fargate (regional by construction)", raw)
			}
		case "network.publicExposure":
			if raw == true {
				assignPublic = "ENABLED"
			}
		case "replicas.minimum":
			n, err := scalars.Parse(raw)
			if err != nil || n.Kind != scalars.Number {
				return ECSPlan{}, fmt.Errorf("replicas.minimum is not a number")
			}
			nf := n.Value.(float64)
			if nf != float64(int64(nf)) {
				return ECSPlan{}, fmt.Errorf("replicas.minimum must be a whole number, got %v", nf)
			}
			desired = int(nf)
		case "autoscaling.enabled":
			if raw != true {
				return ECSPlan{}, fmt.Errorf(
					"autoscaling.enabled=false cannot be honored (a Fargate service scales via desiredCount / App Auto Scaling)")
			}
		case "image.signedProvenance":
			return ECSPlan{}, fmt.Errorf(
				"image.signedProvenance is not honored by the ecs driver in v0 " +
					"(no equivalent provenance gate is enforced) — refusing rather than lie")
		case "tls.enforced":
			// A bare Fargate service has no ingress, so TLS termination lives on an
			// ALB + ACM cert — a SEPARATE binding the driver must not create (the
			// one-binding rule). The operator BRINGS a pre-created target group
			// fronted by an HTTPS/TLS listener, exactly as they bring the subnets,
			// security groups and execution role (D26); the service REGISTERS behind
			// it (loadBalancers on CreateService). Observe traces the target group to
			// its listener protocol, so a plaintext front door is caught as violated.
			if raw == true {
				arn, _ := impl["targetGroupArn"].(string)
				if arn == "" {
					return ECSPlan{}, fmt.Errorf(
						"tls.enforced=true requires implementation.targetGroupArn (a target group " +
							"fronted by an HTTPS/TLS listener + ACM cert) — a separate binding the " +
							"driver references but does not create")
				}
				port, err := containerPortOperand(impl)
				if err != nil {
					return ECSPlan{}, err
				}
				tgArn = arn
				containerPort = port
			}
		case "service.managed":
			if raw != true {
				return ECSPlan{}, fmt.Errorf("service.managed=false cannot be honored by Fargate")
			}
		default:
			return ECSPlan{}, fmt.Errorf(
				"attribute %s has no ECS mapping — refusing rather than silently dropping it", path)
		}
	}
	if region == "" {
		return ECSPlan{}, fmt.Errorf("ecs requires location.region")
	}

	plan := ECSPlan{
		Name: name, Cluster: name, Family: name,
		AssignPublicIP: assignPublic, DesiredCount: desired,
	}
	plan.CreateClusterBody = jsonBody(map[string]any{
		"clusterName": name, "tags": ecsTags(capability, environment)})
	plan.RegisterTaskBody = jsonBody(map[string]any{
		"family":                  name,
		"requiresCompatibilities": []any{"FARGATE"},
		"networkMode":             "awsvpc",
		"cpu":                     cpu,
		"memory":                  mem,
		"executionRoleArn":        execRole,
		"containerDefinitions":    []any{containerDef(image, containerPort)},
		"tags":                    ecsTags(capability, environment),
	})
	plan.TargetGroupArn = tgArn
	plan.ContainerPort = containerPort
	plan.CreateServiceFn = func(taskDefArn string) string {
		body := map[string]any{
			"cluster":        name,
			"serviceName":    name,
			"taskDefinition": taskDefArn,
			"desiredCount":   desired,
			"launchType":     "FARGATE",
			"networkConfiguration": map[string]any{
				"awsvpcConfiguration": map[string]any{
					"subnets":        toAny(subnets),
					"securityGroups": toAny(secGroups),
					"assignPublicIp": assignPublic,
				}},
			"tags": ecsTags(capability, environment),
		}
		// tls.enforced: register the service behind the operator's TLS-terminating
		// target group. The container port must appear in the task def's portMappings
		// (above) or CreateService is rejected.
		if tgArn != "" {
			body["loadBalancers"] = []any{map[string]any{
				"targetGroupArn": tgArn,
				"containerName":  "app",
				"containerPort":  containerPort,
			}}
		}
		return jsonBody(body)
	}
	return plan, nil
}

// containerDef builds the single "app" container definition, adding a portMapping
// only when the service is fronted by a target group (tls.enforced).
func containerDef(image string, port int) map[string]any {
	c := map[string]any{"name": "app", "image": image, "essential": true}
	if port > 0 {
		c["portMappings"] = []any{map[string]any{"containerPort": port}}
	}
	return c
}

// containerPortOperand reads implementation.containerPort — the container port the
// TLS target group routes to. Required (no silent default) because a wrong port
// health-checks red; a target group has a specific backend port the operator knows.
func containerPortOperand(impl map[string]any) (int, error) {
	raw, ok := impl["containerPort"]
	if !ok {
		return 0, fmt.Errorf(
			"tls.enforced=true requires implementation.containerPort (the container port " +
				"the target group routes to)")
	}
	f, ok := raw.(float64)
	if !ok || f != float64(int64(f)) || f < 1 || f > 65535 {
		return 0, fmt.Errorf("implementation.containerPort must be a whole number 1..65535, got %v", raw)
	}
	return int(f), nil
}

func jsonBody(m map[string]any) string {
	b, _ := json.Marshal(m)
	return string(b)
}

func toStrSlice(v any) []string {
	switch x := v.(type) {
	case []string:
		return x
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func toAny(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
