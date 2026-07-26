// AWS VPC request building (D86): the semantic core of the AWS network.private
// driver — the SAME vocabulary the GCP VPC driver fulfils (thesis proof, D85),
// closing GCP/AWS parity on the current surface. EC2 uses the Query protocol
// (form params, XML). A private network is MULTI-RESOURCE: a VPC + a subnet +
// (optionally) VPC Flow Logs. A fresh VPC has NO Internet Gateway, so it is
// PRIVATE by construction (ingress.public=false) and has no internet egress
// route (egress.restricted) — the vocab semantics map to the AWS default
// posture; the driver refuses what would break it.
package aws

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const ec2Version = "2016-11-15"

// awsSubnet is one private (workload) subnet to create. AZ is the availability
// zone to pin it to; "" lets AWS choose (the zonal default). AWS subnets are
// AZ-bound, so spanning zones (availability.class=regional) means >=2 of these.
type awsSubnet struct {
	CIDR string
	AZ   string
}

// awsVPCPlan is the ordered create sequence.
type awsVPCPlan struct {
	CIDR              string
	SubnetCIDR        string      // the private (workload) subnet (zonal default / base)
	PrivateSubnets    []awsSubnet // resolved private subnets (1 zonal, >=2 regional)
	PublicSubnets     []awsSubnet // resolved public subnets (D280: 1 zonal, >=2 regional matching the private AZs; nat road only)
	AvailabilityClass string      // "" | "zonal" | "regional"
	PublicSubnetCIDR  string      // public base CIDR (first public subnet — the NAT gateway home)
	EgressInternet    string      // "none" | "nat" | "direct" — the egress ROAD (D26 operands hidden)
	FlowLogs          bool
	FlowLogDst        string // impl.flow_log_destination (a CloudWatch log group ARN or s3 arn)
	FlowLogRole       string
	ServiceAccess     bool     // serviceAccess.private: keep provider-API traffic on the private backbone
	EndpointServices  []string // short svc names to realize (canonical set, or impl["vpc_endpoints"] override)
	BaselineSG        bool     // author a baseline security group (ingress.public posture as an OBJECT)
	BaselineIngress   []sgRule // baseline SG ingress rules (D26 operand; safe default: intra-VPC only)
	Tags              map[string]string
}

// sgRule is a baseline security-group ingress rule — a REALIZATION OPERAND (D26),
// not vocabulary (the closed operator set #4 keeps port/CIDR arithmetic out of
// constraints; the WAF precedent: rules are opaque, the posture is a flag). The
// driver AUTHORS these; it never authors a 0.0.0.0/0 (or ::/0) rule (that would
// contradict ingress.public=false — refused at build).
type sgRule struct {
	Protocol string // "-1" (all), "tcp", "udp", "icmp"
	FromPort int    // ignored when Protocol == "-1"
	ToPort   int
	CIDR     string // IPv4 (CidrIp) or IPv6 (CidrIpv6, detected by ":")
}

// defaultBaselineIngress is the safe baseline: allow intra-VPC traffic only, no
// door from the world. It admits nothing from 0.0.0.0/0 — the whole point of the
// baseline SG is to make ingress.public=false a materialized, observable object.
func defaultBaselineIngress(vpcCIDR string) []sgRule {
	return []sgRule{{Protocol: "-1", CIDR: vpcCIDR}}
}

// isOpenCIDR: a rule opening the whole IPv4/IPv6 internet.
func isOpenCIDR(cidr string) bool { return cidr == "0.0.0.0/0" || cidr == "::/0" }

// parseBaselineIngress reads impl["baseline_sg_ingress"]: a list of
// {port, cidr, protocol} operands. protocol defaults to "-1" (all); port is
// optional (required for tcp/udp). Every parse error is a refusal.
func parseBaselineIngress(raw any) ([]sgRule, error) {
	list, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("implementation.baseline_sg_ingress must be a list of {port,cidr,protocol} rules")
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("implementation.baseline_sg_ingress, if set, must be non-empty")
	}
	var out []sgRule
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("each baseline_sg_ingress rule must be a mapping {port,cidr,protocol}")
		}
		cidr, _ := m["cidr"].(string)
		if cidr == "" {
			return nil, fmt.Errorf("baseline_sg_ingress rule missing a non-empty cidr")
		}
		proto, _ := m["protocol"].(string)
		if proto == "" {
			proto = "-1"
		}
		r := sgRule{Protocol: proto, CIDR: cidr}
		if pr, ok := m["port"]; ok {
			port, ok := intOperand(pr)
			if !ok {
				return nil, fmt.Errorf("baseline_sg_ingress port must be an integer, got %T", pr)
			}
			r.FromPort, r.ToPort = port, port
		} else if proto == "tcp" || proto == "udp" {
			return nil, fmt.Errorf("baseline_sg_ingress %s rule requires a port", proto)
		}
		out = append(out, r)
	}
	return out, nil
}

// defaultVPCEndpointServices is the canonical private-service-access set the
// Acme substrate requires: an S3 GATEWAY endpoint plus INTERFACE endpoints for
// the control-plane/data services private EKS workloads call. gateway-vs-
// interface is MECHANICS (a gateway endpoint for S3/DynamoDB, an interface
// endpoint for the rest), not vocabulary. Operators may override the set via
// implementation.vpc_endpoints; the driver's KNOWN-required set (the observe
// side) stays this canonical list.
var defaultVPCEndpointServices = []string{
	"bedrock-runtime", "ecr.api", "ecr.dkr", "kms", "logs",
	"s3", "secretsmanager", "sqs", "sts",
}

// isGatewayEndpointService: S3 and DynamoDB are gateway endpoints (route-table
// associated, free); every other AWS service is an interface endpoint (an ENI
// in a subnet + private DNS).
func isGatewayEndpointService(svc string) bool { return svc == "s3" || svc == "dynamodb" }

// endpointServiceName renders the AWS service name for a short svc token.
func endpointServiceName(region, svc string) string { return "com.amazonaws." + region + "." + svc }

// requiredEndpointServiceNames is the driver's KNOWN required set — the verifier
// side of serviceAccess.private (D26 operands, but the driver knows the answer):
// observe emits serviceAccess.private=true iff the observed set of AVAILABLE
// endpoint ServiceNames is a superset of this.
func requiredEndpointServiceNames(region string) []string {
	out := make([]string, 0, len(defaultVPCEndpointServices))
	for _, s := range defaultVPCEndpointServices {
		out = append(out, endpointServiceName(region, s))
	}
	sort.Strings(out)
	return out
}

// ec2Tags renders TagSpecification.N params for a resource type.
func ec2TagParams(resourceType string, tags map[string]string) map[string]string {
	p := map[string]string{
		"TagSpecification.1.ResourceType": resourceType,
	}
	i := 1
	for _, k := range sortedStrs(tags) {
		p[fmt.Sprintf("TagSpecification.1.Tag.%d.Key", i)] = k
		p[fmt.Sprintf("TagSpecification.1.Tag.%d.Value", i)] = tags[k]
		i++
	}
	return p
}

func sortedStrs(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// regionalSubnetCIDRs resolves the private-subnet CIDRs for a regional network.
// implementation.subnet_cidrs (a list of >=2) wins; otherwise a second /24 is
// derived from the base by advancing the third octet by 2 (skipping the NAT
// public subnet at +1). A base that is not a simple IPv4 /24 must supply
// subnet_cidrs explicitly rather than have the driver guess.
func regionalSubnetCIDRs(base string, impl map[string]any) ([]string, error) {
	if raw, ok := impl["subnet_cidrs"]; ok {
		list, ok := raw.([]any)
		if !ok || len(list) < 2 {
			return nil, fmt.Errorf("implementation.subnet_cidrs must be a list of >=2 CIDRs for a regional network")
		}
		out := make([]string, 0, len(list))
		for _, e := range list {
			s, ok := e.(string)
			if !ok || s == "" {
				return nil, fmt.Errorf("implementation.subnet_cidrs entries must be non-empty CIDR strings")
			}
			out = append(out, s)
		}
		return out, nil
	}
	second, ok := deriveSecondSubnet24(base)
	if !ok {
		return nil, fmt.Errorf(
			"a regional network needs >=2 subnet CIDRs; the base subnet %q is not a "+
				"simple IPv4 /24 to derive a second from — supply implementation.subnet_cidrs", base)
	}
	return []string{base, second}, nil
}

// publicSubnetCIDRs resolves the PUBLIC subnet CIDRs for a regional network
// (D280): an explicit implementation.public_subnet_cidrs list (>=n), or a chain
// derived from the public base by advancing the third octet by 2 (1 -> 3 -> 5,
// interleaving with the private chain 0 -> 2 -> 4).
func publicSubnetCIDRs(base string, impl map[string]any, n int) ([]string, error) {
	if raw, ok := impl["public_subnet_cidrs"]; ok {
		list, ok := raw.([]any)
		if !ok || len(list) < n {
			return nil, fmt.Errorf(
				"implementation.public_subnet_cidrs must be a list of >=%d CIDRs for this regional network", n)
		}
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			s, ok := list[i].(string)
			if !ok || s == "" {
				return nil, fmt.Errorf("implementation.public_subnet_cidrs entries must be non-empty CIDR strings")
			}
			out = append(out, s)
		}
		return out, nil
	}
	out := []string{base}
	cur := base
	for len(out) < n {
		next, ok := deriveSecondSubnet24(cur)
		if !ok {
			return nil, fmt.Errorf(
				"a regional network needs %d public subnet CIDRs; the public base %q is not a "+
					"simple IPv4 /24 to derive from — supply implementation.public_subnet_cidrs", n, base)
		}
		out = append(out, next)
		cur = next
	}
	return out, nil
}

// deriveSecondSubnet24 advances an "a.b.c.0/24" third octet by 2 (skip +1 = the
// NAT public subnet). Returns ("", false) for anything that is not a plain /24.
func deriveSecondSubnet24(cidr string) (string, bool) {
	host, ok := strings.CutSuffix(cidr, "/24")
	if !ok {
		return "", false
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 || parts[3] != "0" {
		return "", false
	}
	c, err := strconv.Atoi(parts[2])
	if err != nil || c+2 > 255 {
		return "", false
	}
	return fmt.Sprintf("%s.%s.%d.0/24", parts[0], parts[1], c+2), true
}

// regionalAZs resolves n availability zones. implementation.availability_zones
// (>=n) wins; otherwise the region's a/b/c... AZ letters (AWS naming).
func regionalAZs(region string, impl map[string]any, n int) ([]string, error) {
	if raw, ok := impl["availability_zones"]; ok {
		list, ok := raw.([]any)
		if !ok || len(list) < n {
			return nil, fmt.Errorf(
				"implementation.availability_zones must be a list of >=%d zones for this regional network", n)
		}
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			s, ok := list[i].(string)
			if !ok || s == "" {
				return nil, fmt.Errorf("implementation.availability_zones entries must be non-empty strings")
			}
			out = append(out, s)
		}
		return out, nil
	}
	const letters = "abcdef"
	if n > len(letters) {
		return nil, fmt.Errorf("more than %d default AZs requested; supply implementation.availability_zones", len(letters))
	}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, region+string(letters[i]))
	}
	return out, nil
}

// BuildAWSVPC maps capability.network.private attributes + the impl block to the
// create sequence. Every error is a refusal apply surfaces in preflight.
func BuildAWSVPC(account, environment, capability string,
	attrs, impl map[string]any, generation int) (awsVPCPlan, error) {
	plan := awsVPCPlan{
		CIDR:             "10.0.0.0/16",
		SubnetCIDR:       "10.0.0.0/24",
		PublicSubnetCIDR: "10.0.1.0/24",
		EgressInternet:   "none", // absent egress.internet == today's isolated posture (back-compat)
		Tags: map[string]string{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
			"Name":                   ECSName(account, environment, capability, generation),
		},
	}
	if c, _ := impl["cidr"].(string); c != "" {
		plan.CIDR = c
	}
	if c, _ := impl["subnet_cidr"].(string); c != "" {
		plan.SubnetCIDR = c
	}
	if c, _ := impl["public_subnet_cidr"].(string); c != "" {
		plan.PublicSubnetCIDR = c
	}

	// egress.restricted and egress.internet are ORTHOGONAL axes; capture the
	// restriction intent and cross-check it against the road AFTER the loop.
	var egressRestricted *bool
	ingressPublicDeclared := false // a contract that names ingress.public wants the posture enforced by an object
	region := ""
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "ingress.public":
			// a fresh VPC has no Internet Gateway -> private by construction. A
			// contract REQUIRING public ingress is not this capability in v0.
			ingressPublicDeclared = true
			if raw == true {
				return awsVPCPlan{}, fmt.Errorf(
					"ingress.public=true is not honored by the private-VPC driver in v0 " +
						"(it would need an Internet Gateway + public route) — refusing")
			}
		case "egress.restricted":
			// DESTINATION discipline (SG/firewall allow-list), NOT the road. Do
			// not conflate with egress.internet: =false no longer refuses (an open
			// or absent road needs no filter to permit it). =true is cross-checked
			// against the road below (we can only honor it when there is no road).
			b, ok := raw.(bool)
			if !ok {
				return awsVPCPlan{}, fmt.Errorf("egress.restricted must be a bool, got %T", raw)
			}
			er := b
			egressRestricted = &er
		case "egress.internet":
			// the ROAD mode. Absent => "none" (back-compat). nat is this slice;
			// direct is honestly refused (not built here).
			mode, _ := raw.(string)
			switch mode {
			case "none", "nat":
				plan.EgressInternet = mode
			case "direct":
				return awsVPCPlan{}, fmt.Errorf(
					"egress.internet=direct (publicly addressable workloads via an IGW " +
						"default route on their own subnet) is not built in this slice — " +
						"use nat for outbound-only egress, or none for isolation")
			default:
				return awsVPCPlan{}, fmt.Errorf(
					"egress.internet=%q is not a known road (want none|nat|direct)", mode)
			}
		case "flowLogs.enabled":
			if raw == true {
				plan.FlowLogs = true
			}
		case "interconnect.private":
			if raw == true {
				return awsVPCPlan{}, fmt.Errorf(
					"interconnect.private is not expressible in v0 (needs VPN/DX attachments)")
			}
		case "serviceAccess.private":
			// keep provider-API traffic on the private backbone via VPC endpoints.
			// =false is the default posture (no endpoints); =true builds the set.
			b, ok := raw.(bool)
			if !ok {
				return awsVPCPlan{}, fmt.Errorf("serviceAccess.private must be a bool, got %T", raw)
			}
			plan.ServiceAccess = b
		case "availability.class":
			c, _ := raw.(string)
			if c != "zonal" && c != "regional" {
				return awsVPCPlan{}, fmt.Errorf(
					"availability.class=%q is not a known class (want zonal|regional)", c)
			}
			plan.AvailabilityClass = c
		case "service.managed":
			if raw != true {
				return awsVPCPlan{}, fmt.Errorf("service.managed=false cannot be honored by a VPC")
			}
		default:
			return awsVPCPlan{}, fmt.Errorf(
				"attribute %s has no AWS VPC mapping — refusing rather than silently dropping it", path)
		}
	}
	if region == "" {
		return awsVPCPlan{}, fmt.Errorf("aws vpc requires location.region")
	}
	// availability.class -> private-subnet spread. AWS subnets are AZ-bound, so a
	// regional (multi-zone) network means >=2 subnets in >=2 AZs — what a
	// zone-redundant workload, or an internet-facing load balancer (>=2 AZ),
	// is placed on. zonal (or unset, back-compat) is one subnet, AWS-chosen AZ.
	switch plan.AvailabilityClass {
	case "regional":
		cidrs, err := regionalSubnetCIDRs(plan.SubnetCIDR, impl)
		if err != nil {
			return awsVPCPlan{}, err
		}
		azs, err := regionalAZs(region, impl, len(cidrs))
		if err != nil {
			return awsVPCPlan{}, err
		}
		for i, c := range cidrs {
			plan.PrivateSubnets = append(plan.PrivateSubnets, awsSubnet{CIDR: c, AZ: azs[i]})
		}
		// D280 (F1): a regional network's PUBLIC side spans the SAME AZs — an
		// internet-facing load balancer needs >=2 public subnets in >=2 AZs, and
		// a single-AZ public road would silently under-deliver the declared
		// regional class. One NAT (in the first public subnet) stays the
		// cost-conscious default; per-AZ NAT HA is a future knob, not assumed.
		if plan.EgressInternet == "nat" {
			pubCIDRs, err := publicSubnetCIDRs(plan.PublicSubnetCIDR, impl, len(azs))
			if err != nil {
				return awsVPCPlan{}, err
			}
			for i, c := range pubCIDRs {
				plan.PublicSubnets = append(plan.PublicSubnets, awsSubnet{CIDR: c, AZ: azs[i]})
			}
		}
	default: // "" (back-compat) or "zonal"
		plan.PrivateSubnets = []awsSubnet{{CIDR: plan.SubnetCIDR}}
		if plan.EgressInternet == "nat" {
			plan.PublicSubnets = []awsSubnet{{CIDR: plan.PublicSubnetCIDR}}
		}
	}
	// Cross-check the two egress axes. egress.restricted=true asks for a
	// destination allow-list, which needs egress security groups this slice does
	// not create. It is honored ONLY when there is no road (none): the set of
	// reachable destinations is empty, trivially within any declared allow-list.
	// With a nat/direct road, honoring it would need SG discipline -> refuse
	// rather than falsely claim a NAT road is destination-restricted.
	if egressRestricted != nil && *egressRestricted && plan.EgressInternet != "none" {
		return awsVPCPlan{}, fmt.Errorf(
			"egress.restricted=true needs egress security-group discipline (a "+
				"destination allow-list) that this slice does not create; it is only "+
				"honored with egress.internet=none, not with egress.internet=%s — "+
				"refusing rather than claiming an unfiltered NAT road is restricted",
			plan.EgressInternet)
	}
	if plan.FlowLogs {
		dst, _ := impl["flow_log_destination"].(string)
		role, _ := impl["flow_log_role_arn"].(string)
		if dst == "" || role == "" {
			return awsVPCPlan{}, fmt.Errorf(
				"flowLogs.enabled requires implementation.flow_log_destination (a " +
					"CloudWatch log group ARN) and flow_log_role_arn — refusing rather " +
					"than enabling flow logs with nowhere to write them")
		}
		plan.FlowLogDst = dst
		plan.FlowLogRole = role
	}
	// serviceAccess.private endpoint set: the canonical set, unless the operator
	// declares a bespoke one via implementation.vpc_endpoints (a list of short
	// service tokens, e.g. ["s3","sts","logs"]). The set is a realization OPERAND
	// (D26) — WHICH endpoints, not the semantic.
	if plan.ServiceAccess {
		plan.EndpointServices = append([]string(nil), defaultVPCEndpointServices...)
		if raw, ok := impl["vpc_endpoints"]; ok {
			list, ok := raw.([]any)
			if !ok {
				return awsVPCPlan{}, fmt.Errorf(
					"implementation.vpc_endpoints must be a list of service short-names (e.g. [\"s3\",\"sts\"])")
			}
			var svcs []string
			for _, e := range list {
				s, ok := e.(string)
				if !ok || s == "" {
					return awsVPCPlan{}, fmt.Errorf("implementation.vpc_endpoints entries must be non-empty strings")
				}
				svcs = append(svcs, s)
			}
			if len(svcs) == 0 {
				return awsVPCPlan{}, fmt.Errorf("implementation.vpc_endpoints, if set, must be non-empty")
			}
			sort.Strings(svcs)
			plan.EndpointServices = svcs
		}
	}
	// Baseline security group (ingress.public posture as an OBJECT). Authored when
	// the contract explicitly names ingress.public (it wants the posture enforced
	// and observable), or when the impl opts in via baseline_sg / baseline_sg_ingress.
	// A contract that names NEITHER behaves exactly as before (no SG) — back-compat.
	baselineForced := false
	if raw, ok := impl["baseline_sg"]; ok {
		b, ok := raw.(bool)
		if !ok {
			return awsVPCPlan{}, fmt.Errorf("implementation.baseline_sg must be a bool")
		}
		baselineForced = b
	}
	_, hasRules := impl["baseline_sg_ingress"]
	plan.BaselineSG = ingressPublicDeclared || baselineForced || hasRules
	if plan.BaselineSG {
		plan.BaselineIngress = defaultBaselineIngress(plan.CIDR)
		if raw, ok := impl["baseline_sg_ingress"]; ok {
			rules, err := parseBaselineIngress(raw)
			if err != nil {
				return awsVPCPlan{}, err
			}
			plan.BaselineIngress = rules
		}
		// groundhold NEVER authors a rule that opens the world: it would contradict
		// ingress.public=false (already enforced above) — refuse rather than lie.
		for _, r := range plan.BaselineIngress {
			if isOpenCIDR(r.CIDR) {
				return awsVPCPlan{}, fmt.Errorf(
					"baseline SG ingress rule opens %s to the world — that contradicts the "+
						"private-VPC posture (ingress.public=false); refusing to author a "+
						"self-contradictory baseline (a foreign rule that opens the world is "+
						"WITNESSED by observe, never authored here)", r.CIDR)
			}
		}
	}
	return plan, nil
}

// createVpcBody / createSubnetBody / createFlowLogsBody render the Query bodies.
func (p awsVPCPlan) createVpcBody() string {
	params := map[string]string{"Action": "CreateVpc", "Version": ec2Version, "CidrBlock": p.CIDR}
	for k, v := range ec2TagParams("vpc", p.Tags) {
		params[k] = v
	}
	return encodeForm(params)
}

// ec2ActionParams builds an EC2 Query body: Action + Version + optional
// tag-on-create (resourceType="" skips tagging) + caller-supplied params. Every
// resource groundhold creates carries ownership tags so groundholdTagsMatch holds.
func ec2ActionParams(action, resourceType string, tags, extra map[string]string) map[string]string {
	p := map[string]string{"Action": action, "Version": ec2Version}
	for k, v := range extra {
		p[k] = v
	}
	if resourceType != "" {
		for k, v := range ec2TagParams(resourceType, tags) {
			p[k] = v
		}
	}
	return p
}

// actionOf recovers the Action= form param (for four-valued reconcile messages).
func actionOf(body string) string {
	for _, kv := range strings.Split(body, "&") {
		if strings.HasPrefix(kv, "Action=") {
			return strings.TrimPrefix(kv, "Action=")
		}
	}
	return "ec2 action"
}
