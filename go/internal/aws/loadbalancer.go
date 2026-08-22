// AWS Elastic Load Balancing v2 reverse map (read-only slice): the semantic core
// of the AWS capability.network.loadbalancer driver. An Application/Network Load
// Balancer is the front door in front of a service; what an organization GOVERNS
// about it is its EXPOSURE posture — internet-facing vs internal, and whether it
// terminates TLS. This file is PURE: an LB's Scheme + its listeners' Protocols ->
// the three governed attributes. No network, no I/O — the same reverse map both
// observe and the discovery sweep funnel through, so a discovered LB and an
// observed one can never disagree.
//
// This slice is READ-ONLY. Provisioning an ALB/NLB is multi-resource (load
// balancer + listeners + target groups + a TLS certificate) and lands later; the
// mutating methods refuse-closed HONESTLY (spec/drivers.md) rather than pretend.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"groundhold/internal/provider"
)

// elbv2Version is the Elastic Load Balancing v2 Query-protocol API version
// (Application/Network/Gateway Load Balancers). Cited: DescribeLoadBalancers and
// DescribeListeners, API version 2015-12-01.
const elbv2Version = "2015-12-01"

// lbNameOK bounds an ELBv2 load-balancer name (1-32 chars, alphanumeric + hyphens,
// not beginning or ending with a hyphen) before it is interpolated into a
// providerId or a request.
var lbNameOK = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,30}[A-Za-z0-9])?$`)

// elbv2ProviderID is the stable handle for a load balancer: elbv2:<region>:<name>.
// The ELBv2 name is unique per account+region, so (region, name) identifies it
// without the server-assigned ARN suffix.
func elbv2ProviderID(region, name string) string { return "elbv2:" + region + ":" + name }

func splitELBv2ProviderID(providerID string) (region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "elbv2" {
		return "", "", fmt.Errorf("providerId %q is not elbv2:region:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !lbNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId load balancer name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// listenerTerminatesTLS reports whether an ELBv2 listener protocol terminates
// encryption in transit: HTTPS (ALB) or TLS (NLB). HTTP / TCP / UDP / TCP_UDP are
// plaintext at the listener.
func listenerTerminatesTLS(protocol string) bool {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "HTTPS", "TLS":
		return true
	default:
		return false
	}
}

// elbListener is one listener's encryption posture: its protocol, and — for a
// plaintext HTTP listener — whether its default action only redirects to HTTPS.
type elbListener struct {
	Protocol       string
	RedirectsToTLS bool
}

// listenersAllEncrypted reports whether EVERY listener is a TLS front door or an
// HTTP listener that only redirects to HTTPS — i.e. there is NO plaintext data path.
// The old rule was "ANY listener speaks TLS", which read encryption.inTransit=true
// over a load balancer that ALSO had an HTTP:80 listener forwarding cleartext to the
// backend (a common shape) — a false-green on the encryption constraint (D1186). An
// empty listener set is not encrypted: there is no TLS front door to speak of.
func listenersAllEncrypted(listeners []elbListener) bool {
	if len(listeners) == 0 {
		return false
	}
	for _, l := range listeners {
		if !listenerTerminatesTLS(l.Protocol) && !l.RedirectsToTLS {
			return false
		}
	}
	return true
}

// reverseMapLoadBalancer is the PURE reverse map at the heart of the driver: a
// load balancer's Scheme + its listeners -> the three governed
// capability.network.loadbalancer attributes.
//   - network.publicExposure = Scheme == "internet-facing" (else internal)
//   - encryption.inTransit  = EVERY listener is TLS or an HTTP->HTTPS redirect
//   - service.managed       = true (a cloud ELB is managed by construction)
//
// The region rides in the providerId, not the observation set — the loadbalancer
// vocabulary (v0.1) deliberately carries only the exposure posture, nothing else.
func reverseMapLoadBalancer(scheme string, listeners []elbListener) []provider.Observation {
	return []provider.Observation{
		{Path: "network.publicExposure", Value: scheme == "internet-facing", Derivation: "measured"},
		{Path: "encryption.inTransit", Value: listenersAllEncrypted(listeners), Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
}

// --- PROVISIONING (the forward map): capability attributes + operator operands ->
// the ALB composite (target group + load balancer + listener). This half is PURE:
// it parses/validates the shape and refuses BEFORE any mutation (invariant #4,
// D26). No network. The net shell drives the parsed plan through the ELBv2 API.

// elbCompositeName is the deterministic name for the composite (D29 — the pid is
// knowable before the response). Bounded to the ELBv2 32-char name limit. An ALB
// name and a target-group name live in SEPARATE ELBv2 namespaces, so the LB and its
// target group deliberately SHARE this one name: the delete path (which sees only
// the providerId, not the generation) can then recover the target-group name from
// the load-balancer name alone. A replacement (generation >= 2) coexists with its
// predecessor via a distinct hash tail.
func elbCompositeName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(cfBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	const maxLen = 32
	if len(slug)+len(tail) > maxLen {
		slug = strings.TrimRight(slug[:maxLen-len(tail)], "-")
	}
	name := slug + tail
	// must begin with an alphanumeric (not a hyphen) per the ELBv2 name grammar.
	if name == "" || name[0] == '-' {
		name = "a" + strings.TrimLeft(name, "-")
	}
	return name
}

// LoadBalancerPlan is the attribute+operand-derived shape a create assembles. The
// SHAPE (Scheme, HTTPS) is driven by CAPABILITY attributes; the placement operands
// (subnets, security groups, cert, ports, VPC, health check) are OPERATOR input
// from the candidate implementation: block (D26).
type LoadBalancerPlan struct {
	Name            string   // shared LB + target-group name (deterministic)
	Scheme          string   // "internet-facing" (publicExposure) | "internal"
	HTTPS           bool     // encryption.inTransit -> an HTTPS listener + a cert
	Port            int      // listener port (default 443 HTTPS / 80 HTTP)
	TargetPort      int      // target-group port (default 80)
	HealthCheckPath string   // target-group health check path (default /)
	VpcID           string   // target-group VPC (operand)
	Subnets         []string // >=2 for an ALB (operand)
	SecurityGroups  []string // operand (optional)
	CertificateArn  string   // ACM cert ARN — required iff HTTPS (a reference, not a secret)
}

// ListenerProtocol / TargetGroupProtocol: an inTransit listener speaks HTTPS; the
// backend target group speaks HTTP (TLS terminates AT the load balancer — the
// governed posture is the front door, not the backhaul).
func (p LoadBalancerPlan) ListenerProtocol() string {
	if p.HTTPS {
		return "HTTPS"
	}
	return "HTTP"
}

// BuildLoadBalancer maps capability.network.loadbalancer attributes + implementation
// operands to a plan, or refuses. Every error is a preflight refusal (never a
// half-build): a missing required operand — <2 subnets, no VpcId, or inTransit=true
// with no certificateArn — is refused here, before the first ELBv2 mutation.
func BuildLoadBalancer(environment, capability string,
	attrs, impl map[string]any, generation int) (LoadBalancerPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := LoadBalancerPlan{
		Name:            elbCompositeName(environment, capability, generation),
		Scheme:          "internal",
		HealthCheckPath: "/",
		TargetPort:      80,
	}
	// --- CAPABILITY attributes drive the SHAPE ---
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "network.publicExposure":
			b, ok := raw.(bool)
			if !ok {
				return LoadBalancerPlan{}, fmt.Errorf("network.publicExposure must be a bool")
			}
			if b {
				p.Scheme = "internet-facing"
			}
		case "encryption.inTransit":
			b, ok := raw.(bool)
			if !ok {
				return LoadBalancerPlan{}, fmt.Errorf("encryption.inTransit must be a bool")
			}
			p.HTTPS = b
		case "service.managed":
			if raw != true {
				return LoadBalancerPlan{}, fmt.Errorf("service.managed=false cannot be honored by an ELB (a load balancer IS managed by construction)")
			}
		case "location.region":
			// location.region scopes the create (resolved by the dispatch, not here);
			// cost.monthly is a projection — neither is a build input.
		default:
			return LoadBalancerPlan{}, fmt.Errorf(
				"attribute %s has no ELBv2 load-balancer mapping — refusing rather than silently "+
					"dropping it (the v0.1 loadbalancer vocab governs exposure + TLS posture only)", path)
		}
	}
	// --- OPERATOR operands supply the placement (implementation: block) ---
	if !lbNameOK.MatchString(p.Name) {
		return LoadBalancerPlan{}, fmt.Errorf("derived load-balancer name %q is invalid", p.Name)
	}
	p.Subnets = implStrings(impl, "subnets")
	if len(p.Subnets) < 2 {
		return LoadBalancerPlan{}, fmt.Errorf(
			"an Application Load Balancer requires implementation.subnets with >=2 subnets " +
				"in distinct availability zones — refusing to build a single-AZ front door")
	}
	p.SecurityGroups = implStrings(impl, "securityGroups")
	if v, ok := impl["vpcId"].(string); ok {
		p.VpcID = strings.TrimSpace(v)
	}
	if p.VpcID == "" {
		return LoadBalancerPlan{}, fmt.Errorf(
			"implementation.vpcId is required (the target group must be created in a VPC)")
	}
	if hp, ok := impl["healthCheckPath"].(string); ok && strings.TrimSpace(hp) != "" {
		p.HealthCheckPath = hp
	}
	// certificateArn is REQUIRED iff the contract asks for encryption.inTransit — an
	// HTTPS listener with no certificate cannot terminate TLS. The ARN is a REFERENCE
	// (it names a cert), never key material — safe to carry (D53).
	if ca, ok := impl["certificateArn"].(string); ok {
		p.CertificateArn = strings.TrimSpace(ca)
	}
	if p.HTTPS && p.CertificateArn == "" {
		return LoadBalancerPlan{}, fmt.Errorf(
			"encryption.inTransit=true requires implementation.certificateArn (an ACM certificate ARN) " +
				"for the HTTPS listener — refusing to stand up a TLS front door with no certificate")
	}
	if !p.HTTPS && p.CertificateArn != "" {
		return LoadBalancerPlan{}, fmt.Errorf(
			"implementation.certificateArn was given but encryption.inTransit is not true — " +
				"a certificate only attaches to an HTTPS listener; refusing an ambiguous shape")
	}
	// port: default 443 for HTTPS, 80 for HTTP; an operand may override.
	if p.HTTPS {
		p.Port = 443
	} else {
		p.Port = 80
	}
	// D674: an unreadable operand must not fall through to the default — that is
	// how `port: "8443"` built a listener on 80.
	if pv, ok, err := implIntOperand(impl, "port", "implementation"); err != nil {
		return LoadBalancerPlan{}, err
	} else if ok {
		p.Port = pv
	}
	if tp, ok, err := implIntOperand(impl, "targetPort", "implementation"); err != nil {
		return LoadBalancerPlan{}, err
	} else if ok {
		p.TargetPort = tp
	}
	if p.Port < 1 || p.Port > 65535 {
		return LoadBalancerPlan{}, fmt.Errorf("implementation.port %d is out of range 1-65535", p.Port)
	}
	if p.TargetPort < 1 || p.TargetPort > 65535 {
		return LoadBalancerPlan{}, fmt.Errorf("implementation.targetPort %d is out of range 1-65535", p.TargetPort)
	}
	return p, nil
}

// createTargetGroupForm is the CreateTargetGroup request (the backend + health
// check). TargetType instance is the ALB default; the target group speaks HTTP (TLS
// terminates at the load balancer). Cited: CreateTargetGroup, API version 2015-12-01.
func (p LoadBalancerPlan) createTargetGroupForm() map[string]string {
	return map[string]string{
		"Action":              "CreateTargetGroup",
		"Version":             elbv2Version,
		"Name":                p.Name,
		"Protocol":            "HTTP",
		"Port":                strconv.Itoa(p.TargetPort),
		"VpcId":               p.VpcID,
		"TargetType":          "instance",
		"HealthCheckProtocol": "HTTP",
		"HealthCheckPath":     p.HealthCheckPath,
	}
}

// createLoadBalancerForm is the CreateLoadBalancer request: Scheme (from
// publicExposure), Type application, the operand subnets (>=2) and any security
// groups. Ownership tags are added by a SEPARATE AddTags call (ownershipTagsForm).
// Cited: CreateLoadBalancer, API version 2015-12-01.
func (p LoadBalancerPlan) createLoadBalancerForm() map[string]string {
	form := map[string]string{
		"Action":  "CreateLoadBalancer",
		"Version": elbv2Version,
		"Name":    p.Name,
		"Scheme":  p.Scheme,
		"Type":    "application",
	}
	for i, s := range p.Subnets {
		form[fmt.Sprintf("Subnets.member.%d", i+1)] = s
	}
	for i, sg := range p.SecurityGroups {
		form[fmt.Sprintf("SecurityGroups.member.%d", i+1)] = sg
	}
	return form
}

// createListenerForm is the CreateListener request: Protocol (HTTPS iff inTransit,
// else HTTP), Port, a DefaultAction that forwards to the target group, and — for
// HTTPS only — the ACM certificate. The certificateArn is a REFERENCE, never key
// material. Cited: CreateListener, API version 2015-12-01.
func (p LoadBalancerPlan) createListenerForm(lbArn, tgArn string) map[string]string {
	form := map[string]string{
		"Action":                                 "CreateListener",
		"Version":                                elbv2Version,
		"LoadBalancerArn":                        lbArn,
		"Protocol":                               p.ListenerProtocol(),
		"Port":                                   strconv.Itoa(p.Port),
		"DefaultActions.member.1.Type":           "forward",
		"DefaultActions.member.1.TargetGroupArn": tgArn,
	}
	if p.HTTPS {
		form["Certificates.member.1.CertificateArn"] = p.CertificateArn
	}
	return form
}

// ownershipTagsForm is the AddTags request that marks tag-based ownership on the
// load balancer (mirroring the tag-based ownership every other AWS driver uses).
// Cited: AddTags, API version 2015-12-01.
func ownershipTagsForm(lbArn, capability, environment string) map[string]string {
	return map[string]string{
		"Action":                "AddTags",
		"Version":               elbv2Version,
		"ResourceArns.member.1": lbArn,
		"Tags.member.1.Key":     "groundhold-capability",
		"Tags.member.1.Value":   sanitizeTag(capability),
		"Tags.member.2.Key":     "groundhold-environment",
		"Tags.member.2.Value":   sanitizeTag(environment),
	}
}
