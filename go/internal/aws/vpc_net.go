// AWS VPC network shell (D86): the SigV4-signed, EC2-Query-protocol half of the
// network.private driver. Multi-resource create (VPC -> subnet -> optional flow
// logs), the providerId attached once the VPC exists so a partial is failed/
// unknown WITH the pid, never succeeded. Ownership is tags; delete is reverse
// (flow logs -> subnets -> VPC) and a VPC still holding ENIs refuses
// (DependencyViolation) — never forced.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"groundhold/internal/provider"
)

var vpcIDOK = regexp.MustCompile(`^vpc-[0-9a-f]+$`)

// ec2ErrCode pulls the code out of an EC2 Query-protocol error body. EC2 wraps
// it as <Response><Errors><Error><Code> — NOT RDS's <ErrorResponse><Error><Code>
// — so rdsErrCode never matched an EC2 error (every EC2 error branch was dead).
func ec2ErrCode(body []byte) string {
	var e struct {
		Code string `xml:"Errors>Error>Code"`
	}
	_ = xml.Unmarshal(body, &e)
	return e.Code
}

// ec2PostBase signs (region-scoped) and sends an EC2 Query-protocol request.
func (d *Driver) ec2PostBase(region, body string) (int, []byte, error) {
	base := "https://ec2." + region + ".amazonaws.com/"
	if d.EC2BaseURL != "" {
		base = d.EC2BaseURL + "/"
	}
	return d.doSigned("POST", base, "ec2", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

func awsVpcProviderID(region, vpcID string) string {
	return "vpc:" + region + ":" + vpcID
}

func splitAWSVpcProviderID(providerID string) (region, vpcID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "vpc" {
		return "", "", fmt.Errorf("providerId %q is not vpc:region:vpcId", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !vpcIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId vpc id %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// createAWSVPC: VPC -> subnet -> optional flow logs.
func (d *Driver) createAWSVPC(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAWSVPC(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}

	// create-adoption (D253): a VPC id is server-assigned, so a blind CreateVpc on a
	// lost ledger would mint a DUPLICATE. Scan for an existing VPC carrying our
	// ownership tags first; exactly one ours -> BIND it (reality; drift is the next
	// reconcile's job), never create. A FOREIGN-tagged VPC never matches (findVpcBy
	// Tags verifies tags), so it is never adopted — the scan proceeds to a fresh
	// create, which does not touch the foreign resource. Ambiguous (>1) -> refuse to
	// guess. A readable-empty or unreadable scan falls through to the normal create.
	if vpcID, n, serr := d.findVpcByTags(region, capability, environment); serr == nil && n == 1 {
		return provider.CreateResult{ProviderID: awsVpcProviderID(region, vpcID), Status: "succeeded"}
	} else if serr == nil && n > 1 {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("multiple VPCs carry our ownership tags for %s/%s — cannot pick one to adopt; reconcile manually", capability, environment)}
	}

	// ---- VPC ----
	st, body, err := d.ec2PostBase(region, plan.createVpcBody())
	if err != nil {
		return provider.CreateResult{Status: "unknown", Reason: fmt.Sprintf("create vpc outcome unknown: %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{Status: "unknown", Reason: fmt.Sprintf("create vpc HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 {
		if r := provider.MutationResult(st, ec2ErrCode(body), nil, "", "create vpc"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create vpc: HTTP %d (%s)", st, ec2ErrCode(body))}
	}
	var vpcResp struct {
		VpcID string `xml:"vpc>vpcId"`
	}
	if xml.Unmarshal(body, &vpcResp) != nil || vpcResp.VpcID == "" {
		return provider.CreateResult{Status: "unknown", Reason: "create vpc returned no id — reconcile"}
	}
	pid := awsVpcProviderID(region, vpcResp.VpcID)

	// ---- private (workload) subnet(s) ----
	// zonal = one subnet (AWS-chosen AZ); regional = >=2 subnets across >=2 AZs
	// (AWS subnets are AZ-bound). The FIRST subnet is the primary — its id drives
	// NAT and endpoint placement; the rest widen the zone spread. Only the first
	// subnet is a "failed" (nothing else stood yet); a later one failing is a
	// PARTIAL composite (VPC + earlier subnets exist) -> unknown WITH the pid.
	var privateSubnetIDs []string
	for i, sub := range plan.PrivateSubnets {
		subParams := map[string]string{"Action": "CreateSubnet", "Version": ec2Version,
			"VpcId": vpcResp.VpcID, "CidrBlock": sub.CIDR}
		if sub.AZ != "" {
			subParams["AvailabilityZone"] = sub.AZ
		}
		for k, v := range ec2TagParams("subnet", plan.Tags) {
			subParams[k] = v
		}
		st, body, err = d.ec2PostBase(region, encodeForm(subParams))
		n := i + 1
		total := len(plan.PrivateSubnets)
		if err != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("vpc created; subnet %d/%d outcome unknown — reconcile", n, total)}
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("vpc created; subnet %d/%d HTTP %d (server error) — reconcile", n, total, st)}
		}
		if st < 200 || st >= 300 { // 4xx or a 3xx redirect — this subnet did NOT land
			if r := provider.MutationResult(st, ec2ErrCode(body), nil, pid, "create subnet"); r != nil {
				return *r
			}
			status := "failed"
			if i > 0 { // a later subnet failing is a partial composite, not a bare failure
				status = "unknown"
			}
			return provider.CreateResult{ProviderID: pid, Status: status,
				Reason: fmt.Sprintf("vpc created but subnet %d/%d failed: HTTP %d (%s)", n, total, st, ec2ErrCode(body))}
		}
		var subResp struct {
			SubnetID string `xml:"subnet>subnetId"`
		}
		_ = xml.Unmarshal(body, &subResp)
		if subResp.SubnetID != "" {
			privateSubnetIDs = append(privateSubnetIDs, subResp.SubnetID)
		}
	}

	// ---- egress road: NAT (public subnet + IGW + EIP + NAT GW + routes) ----
	// The VPC + private subnet already stand, so ANY failure from here on is a
	// PARTIAL composite: unknown WITH the providerId, never a bare "failed" that
	// implies nothing was created (D29/D87), never a silent half-provision.
	if plan.EgressInternet == "nat" {
		if r := d.buildNATEgress(region, pid, vpcResp.VpcID, privateSubnetIDs, plan); r != nil {
			return *r
		}
	}

	// ---- private service access: VPC endpoints (serviceAccess.private) ----
	// Same partial-composite discipline: the VPC + subnet (+ NAT) already stand,
	// so an incomplete endpoint set is unknown WITH the pid (a network with
	// partial private service access — reconcile), never a false "succeeded".
	if plan.ServiceAccess {
		first := ""
		if len(privateSubnetIDs) > 0 {
			first = privateSubnetIDs[0]
		}
		if r := d.buildServiceEndpoints(region, pid, vpcResp.VpcID, first, plan); r != nil {
			return *r
		}
	}

	// ---- baseline security group (ingress.public posture as an OBJECT) ----
	// Same partial-composite discipline: the VPC + subnet already stand, so a
	// failure to author the baseline SG is unknown WITH the pid (a network whose
	// ingress posture object is not yet materialized — reconcile), never a false
	// "succeeded".
	if plan.BaselineSG {
		if r := d.buildBaselineSG(region, pid, vpcResp.VpcID, plan); r != nil {
			return *r
		}
	}

	// ---- flow logs (optional) ----
	if plan.FlowLogs {
		flParams := map[string]string{
			"Action": "CreateFlowLogs", "Version": ec2Version,
			"ResourceId.1": vpcResp.VpcID, "ResourceType": "VPC", "TrafficType": "ALL",
			"LogDestinationType": "cloud-watch-logs",
			"LogGroupName":       plan.FlowLogDst, "DeliverLogsPermissionArn": plan.FlowLogRole,
		}
		st, body, err = d.ec2PostBase(region, encodeForm(flParams))
		if err != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "vpc+subnet created; flow logs outcome unknown — reconcile"}
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("vpc+subnet created; flow logs HTTP %d (server error) — reconcile", st)}
		}
		// CreateFlowLogs is a BATCH API: a 200 can carry an <unsuccessful> set
		// (e.g. a bad role ARN) with NO flow log created. Require a flowLogId and
		// no unsuccessful entries — else audit is NOT on and the contract lies.
		if st >= 400 || strings.Contains(string(body), "<unsuccessful>") ||
			!strings.Contains(string(body), "<flowLogId>") {
			if r := provider.MutationResult(st, ec2ErrCode(body), nil, pid, "flow logs"); r != nil {
				return *r
			}
			return provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("vpc+subnet created but flow logs failed (audit NOT on): HTTP %d (%s) %s",
					st, ec2ErrCode(body), mutDetail(body))}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// buildNATEgress wires the outbound-only road for egress.internet=nat, in
// dependency order (D26 operands, all ownership-tagged): public subnet -> IGW +
// attach -> EIP -> NAT GW (poll to available) -> public route table (0/0 -> IGW,
// associate public subnet) -> private route table (0/0 -> NAT, associate private
// subnet). Returns nil on success; a non-nil result is a partial composite
// (unknown WITH pid — the VPC is standing). Workloads sit in the PRIVATE subnet
// with a default route to the NAT: they initiate outbound, but the internet
// cannot reach them (ingress.public stays false).
func (d *Driver) buildNATEgress(region, pid, vpcID string, privateSubnetIDs []string, plan awsVPCPlan) *provider.CreateResult {
	if len(privateSubnetIDs) == 0 {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "vpc+subnet created but the private subnet ids were not returned — " +
				"cannot wire the NAT route; reconcile the partial network"}
	}
	// public subnet(s): D280 — a regional network spans the SAME AZs on the
	// public side (an internet-facing ALB needs >=2 public subnets in >=2 AZs).
	// The FIRST public subnet is the NAT gateway's home.
	var publicSubnetIDs []string
	for _, sub := range plan.PublicSubnets {
		params := map[string]string{"VpcId": vpcID, "CidrBlock": sub.CIDR}
		if sub.AZ != "" {
			params["AvailabilityZone"] = sub.AZ
		}
		id, r := d.ec2Child(region, pid,
			encodeForm(ec2ActionParams("CreateSubnet", "subnet", plan.Tags, params)), "subnetId")
		if r != nil {
			return r
		}
		publicSubnetIDs = append(publicSubnetIDs, id)
	}
	publicSubnetID := publicSubnetIDs[0]
	// internet gateway + attach
	igwID, r := d.ec2Child(region, pid,
		encodeForm(ec2ActionParams("CreateInternetGateway", "internet-gateway", plan.Tags, nil)),
		"internetGatewayId")
	if r != nil {
		return r
	}
	if _, r = d.ec2Child(region, pid, encodeForm(ec2ActionParams("AttachInternetGateway", "", nil,
		map[string]string{"InternetGatewayId": igwID, "VpcId": vpcID})), ""); r != nil {
		return r
	}
	// elastic IP for the NAT gateway
	eipAllocID, r := d.ec2Child(region, pid,
		encodeForm(ec2ActionParams("AllocateAddress", "elastic-ip", plan.Tags,
			map[string]string{"Domain": "vpc"})), "allocationId")
	if r != nil {
		return r
	}
	// NAT gateway in the public subnet, then poll to available
	natID, r := d.ec2Child(region, pid,
		encodeForm(ec2ActionParams("CreateNatGateway", "natgateway", plan.Tags,
			map[string]string{"SubnetId": publicSubnetID, "AllocationId": eipAllocID})), "natGatewayId")
	if r != nil {
		return r
	}
	if r = d.pollNATGateway(region, pid, natID, "available"); r != nil {
		return r
	}
	// public route table: 0.0.0.0/0 -> IGW, associate EVERY public subnet
	if r = d.wireRouteTable(region, pid, vpcID, publicSubnetIDs, "GatewayId", igwID, plan.Tags); r != nil {
		return r
	}
	// private route table: 0.0.0.0/0 -> NAT, associate EVERY private subnet
	// (D280: previously only the first private subnet got the NAT route — the
	// second regional subnet silently sat on the empty main table)
	if r = d.wireRouteTable(region, pid, vpcID, privateSubnetIDs, "NatGatewayId", natID, plan.Tags); r != nil {
		return r
	}
	return nil
}

// ec2Child issues one EC2 mutation inside the NAT composite. On ANY non-success
// (transport error, non-2xx, or a missing id) it returns a partial-composite
// result — unknown WITH pid, because the VPC already stands. idTag="" skips id
// extraction (attach/associate/route return no consumed id).
func (d *Driver) ec2Child(region, pid, body, idTag string) (string, *provider.CreateResult) {
	action := actionOf(body)
	st, resp, err := d.ec2PostBase(region, body)
	if err != nil {
		return "", d.natPartial(pid, action, fmt.Sprintf("outcome unknown: %v", err))
	}
	if st < 200 || st >= 300 {
		return "", d.natPartial(pid, action, fmt.Sprintf("HTTP %d (%s)", st, ec2ErrCode(resp)))
	}
	if idTag == "" {
		return "", nil
	}
	id := between(string(resp), "<"+idTag+">", "</"+idTag+">")
	if id == "" {
		return "", d.natPartial(pid, action, "returned no "+idTag)
	}
	return id, nil
}

func (d *Driver) natPartial(pid, action, detail string) *provider.CreateResult {
	return &provider.CreateResult{ProviderID: pid, Status: "unknown",
		Reason: fmt.Sprintf("vpc created but NAT egress step %s %s — reconcile the partial network", action, detail)}
}

// wireRouteTable creates a route table, adds a 0.0.0.0/0 route to targetID
// (GatewayId for an IGW, NatGatewayId for a NAT), and associates the subnet.
func (d *Driver) wireRouteTable(region, pid, vpcID string, subnetIDs []string, targetKey, targetID string, tags map[string]string) *provider.CreateResult {
	rtID, r := d.ec2Child(region, pid,
		encodeForm(ec2ActionParams("CreateRouteTable", "route-table", tags,
			map[string]string{"VpcId": vpcID})), "routeTableId")
	if r != nil {
		return r
	}
	if _, r = d.ec2Child(region, pid, encodeForm(ec2ActionParams("CreateRoute", "", nil,
		map[string]string{"RouteTableId": rtID, "DestinationCidrBlock": "0.0.0.0/0", targetKey: targetID})), ""); r != nil {
		return r
	}
	for _, subnetID := range subnetIDs {
		if _, r = d.ec2Child(region, pid, encodeForm(ec2ActionParams("AssociateRouteTable", "", nil,
			map[string]string{"RouteTableId": rtID, "SubnetId": subnetID})), ""); r != nil {
			return r
		}
	}
	return nil
}

// pollNATGateway polls DescribeNatGateways until the NAT reaches wantState
// ("available" on create, "deleted" on delete). A terminal wrong state or the
// poll timeout is unknown (reconcile) — never a false success.
func (d *Driver) pollNATGateway(region, pid, natID, wantState string) *provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
			"Action": "DescribeNatGateways", "Version": ec2Version, "NatGatewayId.1": natID}))
		if err == nil && st == http.StatusOK {
			state := between(string(resp), "<state>", "</state>")
			if state == wantState {
				return nil
			}
			// creating -> a terminal failed/deleted is not "available"; deleting a
			// NAT that reports "failed" is fine (it is gone from service either way).
			if wantState == "available" && (state == "failed" || state == "deleted" || state == "deleting") {
				return &provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: fmt.Sprintf("vpc created but NAT gateway entered state %q (not available) — reconcile the partial network", state)}
			}
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("NAT gateway did not reach %q by poll timeout — reconcile via DescribeNatGateways", wantState)}
		}
		time.Sleep(d.PollInterval)
	}
}

// buildServiceEndpoints realizes serviceAccess.private: an S3 GATEWAY endpoint
// (associated with the VPC's route tables) plus INTERFACE endpoints (an ENI in
// the private subnet + private DNS) for the rest of the declared service set.
// gateway-vs-interface is pure mechanics (D26). Every endpoint is ownership-
// tagged. Interface endpoints go pending->available; a partial set (any not yet
// up) is unknown WITH pid — a network with incomplete private access, reconcile.
// No custom security group is created: interface endpoints fall back to the
// VPC's DEFAULT security group (keeping SG provisioning out of this slice).
func (d *Driver) buildServiceEndpoints(region, pid, vpcID, privateSubnetID string, plan awsVPCPlan) *provider.CreateResult {
	// gateway endpoints need route table ids; fetch them once if any are declared.
	needGateway := false
	for _, svc := range plan.EndpointServices {
		if isGatewayEndpointService(svc) {
			needGateway = true
			break
		}
	}
	var gatewayRTs []string
	if needGateway {
		rts, r := d.vpcRouteTableIDs(region, pid, vpcID)
		if r != nil {
			return r
		}
		if len(rts) == 0 {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "vpc created but no route tables found to associate the S3 gateway endpoint — reconcile the partial network"}
		}
		gatewayRTs = rts
	}
	for _, svc := range plan.EndpointServices {
		svcName := endpointServiceName(region, svc)
		if isGatewayEndpointService(svc) {
			extra := map[string]string{"VpcId": vpcID, "VpcEndpointType": "Gateway", "ServiceName": svcName}
			for i, rt := range gatewayRTs {
				extra[fmt.Sprintf("RouteTableId.%d", i+1)] = rt
			}
			if _, r := d.ec2Child(region, pid,
				encodeForm(ec2ActionParams("CreateVpcEndpoint", "vpc-endpoint", plan.Tags, extra)), "vpcEndpointId"); r != nil {
				return r
			}
			continue // gateway endpoints are available on creation
		}
		if privateSubnetID == "" {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "vpc created but the private subnet id was not returned — cannot place interface endpoints; reconcile the partial network"}
		}
		extra := map[string]string{"VpcId": vpcID, "VpcEndpointType": "Interface",
			"ServiceName": svcName, "SubnetId.1": privateSubnetID, "PrivateDnsEnabled": "true"}
		epID, r := d.ec2Child(region, pid,
			encodeForm(ec2ActionParams("CreateVpcEndpoint", "vpc-endpoint", plan.Tags, extra)), "vpcEndpointId")
		if r != nil {
			return r
		}
		if r := d.pollVpcEndpoint(region, pid, epID, "available"); r != nil {
			return r
		}
	}
	return nil
}

// buildBaselineSG AUTHORS the baseline security group: a fresh, ownership-tagged
// SG in the VPC whose ingress rules materialize ingress.public=false as an
// observable object (a new SG has NO ingress and an implicit allow-all egress, so
// the workload egress posture is unchanged and egress.restricted stays the
// egress-SG slice's job). It authors ONLY the declared baseline ingress rules
// (safe default: intra-VPC only) — never a 0.0.0.0/0 door (refused at build).
// author-vs-witness: groundhold owns THIS object and its declared rules; rules an
// in-cluster controller (ALB/EKS) later appends are WITNESSED by observe and
// never touched here. Returns nil on success; a non-nil result is a partial
// composite (unknown WITH pid — the VPC is standing).
func (d *Driver) buildBaselineSG(region, pid, vpcID string, plan awsVPCPlan) *provider.CreateResult {
	sgName := plan.Tags["Name"] + "-baseline"
	sgID, r := d.ec2Child(region, pid,
		encodeForm(ec2ActionParams("CreateSecurityGroup", "security-group", plan.Tags,
			map[string]string{"VpcId": vpcID, "GroupName": sgName,
				"GroupDescription": "groundhold baseline: no public ingress (ingress.public=false)"})),
		"groupId")
	if r != nil {
		return r
	}
	if len(plan.BaselineIngress) == 0 {
		return nil // an SG with no ingress rules is already closed to the world
	}
	extra := map[string]string{"GroupId": sgID}
	for i, rule := range plan.BaselineIngress {
		n := i + 1
		extra[fmt.Sprintf("IpPermissions.%d.IpProtocol", n)] = rule.Protocol
		if rule.Protocol != "-1" {
			extra[fmt.Sprintf("IpPermissions.%d.FromPort", n)] = strconv.Itoa(rule.FromPort)
			extra[fmt.Sprintf("IpPermissions.%d.ToPort", n)] = strconv.Itoa(rule.ToPort)
		}
		if strings.Contains(rule.CIDR, ":") {
			extra[fmt.Sprintf("IpPermissions.%d.Ipv6Ranges.1.CidrIpv6", n)] = rule.CIDR
		} else {
			extra[fmt.Sprintf("IpPermissions.%d.IpRanges.1.CidrIp", n)] = rule.CIDR
		}
	}
	if _, r := d.ec2Child(region, pid,
		encodeForm(ec2ActionParams("AuthorizeSecurityGroupIngress", "", nil, extra)), ""); r != nil {
		return r
	}
	return nil
}

// describeVpcSecurityGroups reports whether ANY security group in the VPC carries
// an ingress rule open to the world (0.0.0.0/0 or ::/0). This is a POSTURE read
// over EVERY SG in the VPC, not just groundhold's own baseline: it WITNESSES rules
// an in-cluster controller (ALB/EKS) appended at runtime. An open rule flips
// ingress.public to true (surfacing violated on the tray); it is NEVER
// auto-revoked. A garbled/failed read is (false,false) — never a confident
// "closed", so observe falls back rather than lying.
func (d *Driver) describeVpcSecurityGroups(region, vpcID string) (hasOpenIngress bool, err error) {
	body := encodeForm(map[string]string{"Action": "DescribeSecurityGroups", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID})
	st, resp, e := d.ec2PostBase(region, body)
	if e != nil || st != http.StatusOK {
		if e != nil {
			return false, readTransport("DescribeSecurityGroups", e)
		}
		return false, readHTTP("DescribeSecurityGroups", st, ec2ErrCode(resp))
	}
	var out struct {
		Groups []struct {
			Perms []struct {
				V4 []string `xml:"ipRanges>item>cidrIp"`
				V6 []string `xml:"ipv6Ranges>item>cidrIpv6"`
			} `xml:"ipPermissions>item"`
		} `xml:"securityGroupInfo>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return false, readBody("DescribeSecurityGroups", st)
	}
	for _, g := range out.Groups {
		for _, p := range g.Perms {
			for _, c := range p.V4 {
				if c == "0.0.0.0/0" {
					return true, nil
				}
			}
			for _, c := range p.V6 {
				if c == "::/0" {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// vpcRouteTableIDs lists every route table id in the VPC (including the AWS
// main table) so the S3 gateway endpoint routes S3 traffic from every subnet.
func (d *Driver) vpcRouteTableIDs(region, pid, vpcID string) ([]string, *provider.CreateResult) {
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeRouteTables", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID}))
	if err != nil || st != http.StatusOK {
		return nil, &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "vpc created but cannot list route tables to place the S3 gateway endpoint — reconcile the partial network"}
	}
	var out struct {
		IDs []string `xml:"routeTableSet>item>routeTableId"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return nil, &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "vpc created but route table list unparseable — reconcile the partial network"}
	}
	return out.IDs, nil
}

// pollVpcEndpoint polls DescribeVpcEndpoints until endpointID reaches wantState
// ("available" on create, "deleted" on teardown). A terminal wrong state or the
// timeout is unknown (reconcile) — never a false success.
func (d *Driver) pollVpcEndpoint(region, pid, endpointID, wantState string) *provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
			"Action": "DescribeVpcEndpoints", "Version": ec2Version, "VpcEndpointId.1": endpointID}))
		if err == nil && st == http.StatusOK {
			var out struct {
				States []string `xml:"vpcEndpointSet>item>state"`
			}
			if xml.Unmarshal(resp, &out) == nil {
				if wantState == "deleted" && len(out.States) == 0 {
					return nil // gone from the API — deleted
				}
				for _, s := range out.States {
					if s == wantState {
						return nil
					}
					if wantState == "available" && (s == "failed" || s == "rejected" || s == "deleting" || s == "deleted") {
						return &provider.CreateResult{ProviderID: pid, Status: "unknown",
							Reason: fmt.Sprintf("vpc created but endpoint %s entered state %q (not available) — reconcile the partial network", endpointID, s)}
					}
				}
			}
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("vpc endpoint %s did not reach %q by poll timeout — reconcile via DescribeVpcEndpoints", endpointID, wantState)}
		}
		time.Sleep(d.PollInterval)
	}
}

// describeVpcEndpointServiceNames returns the set of ServiceNames of AVAILABLE
// endpoints in the VPC. Only an available endpoint actually routes traffic, so a
// pending/failed one does not count towards serviceAccess.private. An unreadable
// read is (nil,false) — never a confident empty set.
func (d *Driver) describeVpcEndpointServiceNames(region, vpcID string) (map[string]bool, error) {
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeVpcEndpoints", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID}))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport("DescribeVpcEndpoints", err)
		}
		return nil, readHTTP("DescribeVpcEndpoints", st, ec2ErrCode(resp))
	}
	var out struct {
		Items []struct {
			ServiceName string `xml:"serviceName"`
			State       string `xml:"state"`
		} `xml:"vpcEndpointSet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return nil, readBody("DescribeVpcEndpoints", st)
	}
	set := map[string]bool{}
	for _, it := range out.Items {
		if it.State == "available" {
			set[it.ServiceName] = true
		}
	}
	return set, nil
}

// missingEndpoints returns the required ServiceNames absent from observed (⊇ gap).
func missingEndpoints(required []string, observed map[string]bool) []string {
	var missing []string
	for _, r := range required {
		if !observed[r] {
			missing = append(missing, r)
		}
	}
	return missing
}

// vpcDoc / describeVpc read a VPC's tags + cidr.
func (d *Driver) describeVpc(region, vpcID string) (tags map[string]string, found bool, err error) {
	const op = "DescribeVpcs"
	body := encodeForm(map[string]string{"Action": "DescribeVpcs", "Version": ec2Version, "VpcId.1": vpcID})
	st, resp, cerr := d.ec2PostBase(region, body)
	if cerr != nil {
		return nil, false, readTransport(op, cerr)
	}
	if ec2ErrCode(resp) == "InvalidVpcID.NotFound" {
		return nil, false, nil
	}
	if st != http.StatusOK {
		return nil, false, readHTTP(op, st, ec2ErrCode(resp))
	}
	var out struct {
		Tags []struct {
			Key   string `xml:"key"`
			Value string `xml:"value"`
		} `xml:"vpcSet>item>tagSet>item"`
		VpcID string `xml:"vpcSet>item>vpcId"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return nil, false, readBody(op, st) // garbled 200 is not "not found"
	}
	if out.VpcID == "" {
		return nil, false, nil
	}
	m := map[string]string{}
	for _, t := range out.Tags {
		m[t.Key] = t.Value
	}
	return m, true, nil
}

// findVpcByTags (D253) scans for VPCs carrying OUR ownership tags — the create-
// adoption lookup for a server-assigned id, where a blind CreateVpc on a lost
// ledger would mint a duplicate. Returns the count of owned VPCs and (when exactly
// one) its id. It VERIFIES the tags on each returned VPC (never trusts the
// server-side filter alone) — a match means the VPC provably carries our ownership
// tags. readable=false on any transport/HTTP/parse failure (the caller then falls
// back to a normal create rather than blocking a genuine first deploy).
func (d *Driver) findVpcByTags(region, capability, environment string) (vpcID string, count int, err error) {
	body := encodeForm(map[string]string{"Action": "DescribeVpcs", "Version": ec2Version,
		"Filter.1.Name": "tag:groundhold-capability", "Filter.1.Value.1": sanitizeTag(capability),
		"Filter.2.Name": "tag:groundhold-environment", "Filter.2.Value.1": sanitizeTag(environment)})
	st, resp, err := d.ec2PostBase(region, body)
	if err != nil || st != http.StatusOK {
		if err != nil {
			return "", 0, readTransport("DescribeVpcs", err)
		}
		return "", 0, readHTTP("DescribeVpcs", st, ec2ErrCode(resp))
	}
	var out struct {
		Items []struct {
			VpcID string `xml:"vpcId"`
			Tags  []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"vpcSet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return "", 0, readBody("DescribeVpcs", st)
	}
	var owned []string
	for _, v := range out.Items {
		m := map[string]string{}
		for _, t := range v.Tags {
			m[t.Key] = t.Value
		}
		if v.VpcID != "" && groundholdTagsMatch(m, capability, environment) {
			owned = append(owned, v.VpcID)
		}
	}
	if len(owned) == 1 {
		return owned[0], 1, nil
	}
	return "", len(owned), nil
}

// describeHasIGW: is an Internet Gateway attached to this VPC? A garbled/failed
// read is (false, false) — never a confident "no gateway".
func (d *Driver) describeHasIGW(region, vpcID string) (hasIGW bool, err error) {
	body := encodeForm(map[string]string{"Action": "DescribeInternetGateways", "Version": ec2Version,
		"Filter.1.Name": "attachment.vpc-id", "Filter.1.Value.1": vpcID})
	st, resp, e := d.ec2PostBase(region, body)
	if e != nil || st != http.StatusOK {
		if e != nil {
			return false, readTransport("DescribeInternetGateways", e)
		}
		return false, readHTTP("DescribeInternetGateways", st, ec2ErrCode(resp))
	}
	var igw struct {
		IDs []string `xml:"internetGatewaySet>item>internetGatewayId"`
	}
	if xml.Unmarshal(resp, &igw) != nil {
		return false, readBody("DescribeInternetGateways", st)
	}
	return len(igw.IDs) > 0, nil
}

// describeVpcRoutes reports whether any route table in the VPC carries a
// 0.0.0.0/0 default route to a NAT gateway (nat road) and/or to an IGW (direct
// road). Local routes (gatewayId=local, non-default CIDR) are ignored.
func (d *Driver) describeVpcRoutes(region, vpcID string) (hasNatRoute, hasIgwRoute bool, err error) {
	body := encodeForm(map[string]string{"Action": "DescribeRouteTables", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID})
	st, resp, e := d.ec2PostBase(region, body)
	if e != nil || st != http.StatusOK {
		if e != nil {
			return false, false, readTransport("DescribeRouteTables", e)
		}
		return false, false, readHTTP("DescribeRouteTables", st, ec2ErrCode(resp))
	}
	var out struct {
		Routes []struct {
			Dest string `xml:"destinationCidrBlock"`
			Nat  string `xml:"natGatewayId"`
			Gw   string `xml:"gatewayId"`
		} `xml:"routeTableSet>item>routeSet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return false, false, readBody("DescribeRouteTables", st)
	}
	for _, r := range out.Routes {
		if r.Dest != "0.0.0.0/0" {
			continue
		}
		if strings.HasPrefix(r.Nat, "nat-") {
			hasNatRoute = true
		}
		if strings.HasPrefix(r.Gw, "igw-") {
			hasIgwRoute = true
		}
	}
	return hasNatRoute, hasIgwRoute, nil
}

// observeAWSVPC reverse-maps a live VPC.
func (d *Driver) observeAWSVPC(capability, providerID string) ([]provider.Observation, []string, error) {
	region, vpcID, err := splitAWSVpcProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	_, found, rerr := d.describeVpc(region, vpcID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"vpc not found — nothing to observe"}, nil
	}
	var obs []provider.Observation
	var diags []string
	obs = append(obs,
		provider.Observation{Path: "location.region", Value: region, Derivation: "measured"},
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
	)
	// The egress ROAD is read from the route tables; the two axes are unravelled.
	hasIGW, igwErr := d.describeHasIGW(region, vpcID)
	hasNatRoute, hasIgwRoute, rtErr := d.describeVpcRoutes(region, vpcID)

	// egress.internet: nat if a private default route points at a NAT gateway;
	// direct if a default route points at the IGW (and no NAT); none otherwise.
	if rtErr == nil {
		road := "none"
		switch {
		case hasNatRoute:
			road = "nat"
		case hasIgwRoute:
			road = "direct"
		}
		obs = append(obs, provider.Observation{Path: "egress.internet", Value: road, Derivation: "measured"})
		// egress.restricted (DESTINATION discipline) is orthogonal to the road and
		// lives in security groups, which this slice neither creates nor audits.
		// The one honest static claim: with no road at all, the reachable set is
		// empty -> restricted=true; with a road, this slice installs no egress
		// filter -> restricted=false (config-intent; a full SG audit is a later
		// slice, hence the diag rather than a "measured" claim).
		obs = append(obs, provider.Observation{Path: "egress.restricted", Value: road == "none", Derivation: "config-intent"})
		if road != "none" {
			diags = append(diags, "egress.restricted derived from the road only (no egress security-group audit in this slice)")
		}
	} else {
		diags = append(diags, "egress.internet/egress.restricted not observed: "+rtErr.Error())
	}

	// ingress.public: is a path from the internet INTO the network present? Two
	// independent doors, OR-combined (the posture is public if EITHER is open):
	//   (a) a ROUTE door — a direct IGW default route on the workload path. An IGW
	//       that serves only a NAT's public subnet does NOT count: workloads behind
	//       the NAT are not addressable, so a nat road keeps this false.
	//   (b) an SG door — ANY security group in the VPC with a 0.0.0.0/0 (or ::/0)
	//       ingress rule. This WITNESSES rules an in-cluster controller (ALB/EKS)
	//       appended at runtime, not just groundhold's baseline: an open rule flips the
	//       posture (violated on the tray) and is NEVER auto-revoked.
	// An open SG rule is a definitive public door regardless of routes. When the SG
	// read is unreadable, observe FALLS BACK to the route derivation (back-compat)
	// and diags that SGs were not audited — it never falsely claims closure from an
	// unreadable SG. When neither door is readable enough to derive, ingress.public
	// is OMITTED (the verifier blocks on the absent value) rather than guessed.
	sgOpen, sgErr := d.describeVpcSecurityGroups(region, vpcID)
	routePublic, routeKnown := false, false
	switch {
	case igwErr == nil && !hasIGW:
		routePublic, routeKnown = false, true // no gateway => no route door
	case igwErr == nil && rtErr == nil:
		routePublic, routeKnown = hasIgwRoute && !hasNatRoute, true
	}
	switch {
	case sgErr == nil && sgOpen:
		// a world-open SG rule is a definitive public door, whatever the routes say
		obs = append(obs, provider.Observation{Path: "ingress.public", Value: true, Derivation: "measured"})
	case sgErr == nil && routeKnown:
		// no open SG rule AND the route door is derivable — both audited (OR)
		obs = append(obs, provider.Observation{Path: "ingress.public", Value: routePublic, Derivation: "measured"})
	case sgErr != nil && routeKnown:
		// SG posture unreadable: fall back to the route derivation (back-compat),
		// never a false claim of closure — diag that SGs were not audited.
		obs = append(obs, provider.Observation{Path: "ingress.public", Value: routePublic, Derivation: "measured"})
		diags = append(diags, "ingress.public: security-group posture not audited ("+sgErr.Error()+") — derived from IGW routes only")
	default:
		diags = append(diags, "ingress.public not observed: neither door could be read "+
			"(security groups: "+sgErr.Error()+")")
	}
	// flowLogs.enabled: any flow log on this VPC?
	flBody := encodeForm(map[string]string{"Action": "DescribeFlowLogs", "Version": ec2Version,
		"Filter.1.Name": "resource-id", "Filter.1.Value.1": vpcID})
	if st, resp, e := d.ec2PostBase(region, flBody); e == nil && st == http.StatusOK {
		var fl struct {
			IDs []string `xml:"flowLogSet>item>flowLogId"`
		}
		if xml.Unmarshal(resp, &fl) != nil {
			diags = append(diags, "flowLogs.enabled not observed: "+readBody("DescribeFlowLogs", st).Error())
		} else {
			obs = append(obs, provider.Observation{Path: "flowLogs.enabled",
				Value: len(fl.IDs) > 0, Derivation: "measured"})
		}
	} else if e != nil {
		diags = append(diags, "flowLogs.enabled not observed: "+readTransport("DescribeFlowLogs", e).Error())
	} else {
		diags = append(diags, "flowLogs.enabled not observed: "+
			readHTTP("DescribeFlowLogs", st, ec2ErrCode(resp)).Error())
	}
	// serviceAccess.private: does provider-API traffic stay on the private
	// backbone? The driver KNOWS the required canonical endpoint set; observe
	// gathers the AVAILABLE endpoint ServiceNames and emits true iff the observed
	// set is a SUPERSET of the required set. An incomplete set is a MEASURED false
	// (not unknown) with a diag naming exactly which endpoints are missing —
	// a network whose private access is only partially wired (reconcile).
	required := requiredEndpointServiceNames(region)
	if observed, eerr := d.describeVpcEndpointServiceNames(region, vpcID); eerr == nil {
		missing := missingEndpoints(required, observed)
		obs = append(obs, provider.Observation{Path: "serviceAccess.private",
			Value: len(missing) == 0, Derivation: "measured"})
		if len(missing) > 0 {
			diags = append(diags, "serviceAccess.private=false: missing private endpoints for "+strings.Join(missing, ", "))
		}
	} else {
		diags = append(diags, "serviceAccess.private not observed: "+eerr.Error())
	}
	return obs, diags, nil
}

// deleteAWSVPC: ownership + reverse delete (flow logs -> subnets -> vpc).
func (d *Driver) deleteAWSVPC(capability, environment, providerID string) provider.CreateResult {
	region, vpcID, err := splitAWSVpcProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	tags, found, rerr := d.describeVpc(region, vpcID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if tags["groundhold-capability"] != sanitizeTag(capability) ||
		tags["groundhold-environment"] != sanitizeTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "vpc tags do not match — refusing to delete a resource that is not ours"}
	}
	// delete flow logs on this VPC. An unreadable list, or a child delete whose
	// outcome we cannot confirm, refuses the whole delete (never claim the VPC
	// retired while a child mutation's outcome is unknown).
	flBody := encodeForm(map[string]string{"Action": "DescribeFlowLogs", "Version": ec2Version,
		"Filter.1.Name": "resource-id", "Filter.1.Value.1": vpcID})
	fst, flResp, fe := d.ec2PostBase(region, flBody)
	if fe != nil || fst != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "cannot list flow logs — refusing to delete a VPC with unknown children"}
	}
	for _, flID := range allBetween(string(flResp), "<flowLogId>", "</flowLogId>") {
		st, dr, e := d.ec2PostBase(region, encodeForm(map[string]string{
			"Action": "DeleteFlowLogs", "Version": ec2Version, "FlowLogId.1": flID}))
		if e != nil || st >= 500 {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "flow log delete outcome unknown — reconcile"}
		}
		if st >= 400 {
			if r := provider.MutationResult(st, ec2ErrCode(dr), nil, providerID, "flow log delete"); r != nil {
				return *r
			}
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("flow log delete failed: %s", ec2ErrCode(dr))}
		}
		// DeleteFlowLogs is a BATCH: a 200 can carry an <unsuccessful> set meaning
		// the flow log was NOT deleted. Symmetric with the create-side partial
		// check — never claim a child removed on an unsuccessful batch item.
		for _, u := range allBetween(string(dr), "<unsuccessful>", "</unsuccessful>") {
			if strings.Contains(u, "<item>") || strings.Contains(u, flID) {
				return provider.CreateResult{Status: "failed",
					Reason: fmt.Sprintf("flow log %s not deleted (batch unsuccessful): %s", flID, ec2ErrCode(dr))}
			}
		}
	}
	// delete VPC endpoints BEFORE route tables (gateway endpoints associate with
	// them) and subnets (interface endpoints hold ENIs) — ownership-tag-gated and
	// four-valued, symmetric with the create-side composite.
	if r := d.deleteVpcEndpoints(region, providerID, vpcID, capability, environment); r != nil {
		return *r
	}
	// tear down the NAT egress road (reverse dependency order) BEFORE the subnets:
	// route tables (disassociate + delete) -> NAT gateways (delete + poll deleted)
	// -> elastic IPs (release) -> internet gateways (detach + delete). Every step
	// is ownership-tag-gated and four-valued; an unreadable child list refuses the
	// whole delete rather than orphan resources or claim a false retirement.
	if r := d.deleteNATEgress(region, providerID, vpcID, capability, environment); r != nil {
		return *r
	}
	// delete the baseline security group(s) we OWN (the ingress.public posture
	// object). Ownership-tag-gated (the AWS default SG is untagged and foreign/
	// controller SGs are skipped — never touched, so we do not fight the LB
	// controller) and four-valued; an SG still attached to workload ENIs refuses
	// with DependencyViolation (never forced).
	if r := d.deleteSecurityGroups(region, providerID, vpcID, capability, environment); r != nil {
		return *r
	}

	// delete subnets in this VPC
	subBody := encodeForm(map[string]string{"Action": "DescribeSubnets", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID})
	sst, subResp, se := d.ec2PostBase(region, subBody)
	if se != nil || sst != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "cannot list subnets — refusing to delete a VPC with unknown children"}
	}
	for _, sid := range allBetween(string(subResp), "<subnetId>", "</subnetId>") {
		st, dresp, e := d.ec2PostBase(region, encodeForm(map[string]string{
			"Action": "DeleteSubnet", "Version": ec2Version, "SubnetId": sid}))
		if e != nil || st >= 500 {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "subnet delete outcome unknown — reconcile"}
		}
		if st >= 400 {
			if ec2ErrCode(dresp) == "DependencyViolation" {
				return provider.CreateResult{Status: "failed",
					Reason: "a subnet has attached resources (ENIs) — remove them first (never forced)"}
			}
			if r := provider.MutationResult(st, ec2ErrCode(dresp), nil, providerID, "subnet delete"); r != nil {
				return *r
			}
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("subnet delete failed: %s", ec2ErrCode(dresp))}
		}
	}
	// delete the VPC
	st, dresp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DeleteVpc", "Version": ec2Version, "VpcId": vpcID}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete vpc outcome unknown: %v", err)}
	}
	if ec2ErrCode(dresp) == "InvalidVpcID.NotFound" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete vpc HTTP %d (server error) — reconcile", st)}
	}
	if ec2ErrCode(dresp) == "DependencyViolation" {
		return provider.CreateResult{Status: "failed",
			Reason: "vpc still has dependencies (ENIs/gateways) — remove them first (never forced)"}
	}
	if st < 200 || st >= 300 { // any other non-2xx (incl a 3xx redirect) is not a confirmed delete
		if r := provider.MutationResult(st, ec2ErrCode(dresp), nil, providerID, "delete vpc"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete vpc: HTTP %d (%s)", st, ec2ErrCode(dresp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// ec2Tag is the EC2 Query-protocol tag shape (<tagSet><item><key>/<value>).
type ec2Tag struct {
	Key   string `xml:"key"`
	Value string `xml:"value"`
}

// tagsOwn is the delete-side ownership gate: groundhold only ever deletes children
// that carry BOTH ownership tags. AWS-created main route tables (untagged) and
// any foreign resource are skipped, never touched.
func (d *Driver) tagsOwn(tags []ec2Tag, capability, environment string) bool {
	m := map[string]string{}
	for _, t := range tags {
		m[t.Key] = t.Value
	}
	return m["groundhold-capability"] == sanitizeTag(capability) &&
		m["groundhold-environment"] == sanitizeTag(environment)
}

// ec2Delete issues one delete/detach/disassociate mutation, four-valued: a
// transport error or 5xx is unknown (reconcile); a NotFound is idempotent
// success; a DependencyViolation or other 4xx is a refusal (never forced).
func (d *Driver) ec2Delete(region, providerID, action string, extra map[string]string) *provider.CreateResult {
	st, resp, err := d.ec2PostBase(region, encodeForm(ec2ActionParams(action, "", nil, extra)))
	if err != nil || st >= 500 {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s outcome unknown — reconcile", action)}
	}
	if st >= 400 {
		if strings.Contains(ec2ErrCode(resp), "NotFound") {
			return nil // idempotent: already gone
		}
		if ec2ErrCode(resp) == "DependencyViolation" {
			return &provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("%s: a dependency still holds this resource — remove it first (never forced)", action)}
		}
		if r := provider.MutationResult(st, ec2ErrCode(resp), nil, providerID, action); r != nil {
			return r
		}
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s failed: %s", action, ec2ErrCode(resp))}
	}
	return nil
}

// deleteVpcEndpoints removes the owned VPC endpoints (serviceAccess.private) in
// one batch, then polls each to "deleted" so interface-endpoint ENIs release
// before the subnets are deleted. Ownership-tag-gated (foreign/untagged
// endpoints are never touched); an unreadable list refuses the whole delete.
func (d *Driver) deleteVpcEndpoints(region, providerID, vpcID, capability, environment string) *provider.CreateResult {
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeVpcEndpoints", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID}))
	if err != nil || st != http.StatusOK {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "cannot list vpc endpoints — refusing to delete a VPC with unknown children"}
	}
	var out struct {
		Items []struct {
			ID   string   `xml:"vpcEndpointId"`
			Tags []ec2Tag `xml:"tagSet>item"`
		} `xml:"vpcEndpointSet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "vpc endpoint list unparseable — refusing to delete a VPC with unknown children"}
	}
	var owned []string
	for _, e := range out.Items {
		if e.ID != "" && d.tagsOwn(e.Tags, capability, environment) {
			owned = append(owned, e.ID)
		}
	}
	if len(owned) == 0 {
		return nil
	}
	params := map[string]string{"Action": "DeleteVpcEndpoints", "Version": ec2Version}
	for i, id := range owned {
		params[fmt.Sprintf("VpcEndpointId.%d", i+1)] = id
	}
	dst, dr, de := d.ec2PostBase(region, encodeForm(params))
	if de != nil || dst >= 500 {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "vpc endpoint delete outcome unknown — reconcile"}
	}
	if dst >= 400 {
		if r := provider.MutationResult(dst, ec2ErrCode(dr), nil, providerID, "vpc endpoint delete"); r != nil {
			return r
		}
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("vpc endpoint delete failed: %s", ec2ErrCode(dr))}
	}
	// DeleteVpcEndpoints is a BATCH: a 200 can carry an <unsuccessful> set meaning
	// an endpoint was NOT deleted — never claim a child removed on that.
	if strings.Contains(string(dr), "<unsuccessful>") {
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("some vpc endpoints not deleted (batch unsuccessful): %s", mutDetail(dr))}
	}
	for _, id := range owned {
		if r := d.pollVpcEndpoint(region, providerID, id, "deleted"); r != nil {
			return r
		}
	}
	return nil
}

// deleteNATEgress tears the egress road down in reverse dependency order. A nil
// return means the road (or the absence of one) is fully cleared.
func (d *Driver) deleteNATEgress(region, providerID, vpcID, capability, environment string) *provider.CreateResult {
	if r := d.deleteRouteTables(region, providerID, vpcID, capability, environment); r != nil {
		return r
	}
	if r := d.deleteNatGateways(region, providerID, vpcID, capability, environment); r != nil {
		return r
	}
	if r := d.releaseEIPs(region, providerID, capability, environment); r != nil {
		return r
	}
	return d.deleteIGWs(region, providerID, vpcID, capability, environment)
}

func (d *Driver) deleteRouteTables(region, providerID, vpcID, capability, environment string) *provider.CreateResult {
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeRouteTables", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID}))
	if err != nil || st != http.StatusOK {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "cannot list route tables — refusing to delete a VPC with unknown children"}
	}
	var out struct {
		Items []struct {
			ID           string   `xml:"routeTableId"`
			Tags         []ec2Tag `xml:"tagSet>item"`
			Associations []struct {
				ID   string `xml:"routeTableAssociationId"`
				Main string `xml:"main"`
			} `xml:"associationSet>item"`
		} `xml:"routeTableSet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "route table list unparseable — refusing to delete a VPC with unknown children"}
	}
	for _, rt := range out.Items {
		if !d.tagsOwn(rt.Tags, capability, environment) {
			continue // main table (AWS-created, untagged) or foreign — never touched
		}
		for _, a := range rt.Associations {
			if a.Main == "true" || a.ID == "" {
				continue
			}
			if r := d.ec2Delete(region, providerID, "DisassociateRouteTable",
				map[string]string{"AssociationId": a.ID}); r != nil {
				return r
			}
		}
		if r := d.ec2Delete(region, providerID, "DeleteRouteTable",
			map[string]string{"RouteTableId": rt.ID}); r != nil {
			return r
		}
	}
	return nil
}

func (d *Driver) deleteNatGateways(region, providerID, vpcID, capability, environment string) *provider.CreateResult {
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeNatGateways", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID}))
	if err != nil || st != http.StatusOK {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "cannot list NAT gateways — refusing to delete a VPC with unknown children"}
	}
	var out struct {
		Items []struct {
			ID    string   `xml:"natGatewayId"`
			State string   `xml:"state"`
			Tags  []ec2Tag `xml:"tagSet>item"`
		} `xml:"natGatewaySet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "NAT gateway list unparseable — refusing to delete a VPC with unknown children"}
	}
	for _, n := range out.Items {
		if !d.tagsOwn(n.Tags, capability, environment) {
			continue
		}
		if n.State == "deleted" || n.State == "deleting" {
			continue // already going/gone
		}
		if r := d.ec2Delete(region, providerID, "DeleteNatGateway",
			map[string]string{"NatGatewayId": n.ID}); r != nil {
			return r
		}
		// poll to "deleted" so the EIP frees and the public subnet can delete
		if r := d.pollNATGateway(region, providerID, n.ID, "deleted"); r != nil {
			return r
		}
	}
	return nil
}

func (d *Driver) releaseEIPs(region, providerID, capability, environment string) *provider.CreateResult {
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeAddresses", "Version": ec2Version,
		"Filter.1.Name": "tag:groundhold-capability", "Filter.1.Value.1": sanitizeTag(capability),
		"Filter.2.Name": "tag:groundhold-environment", "Filter.2.Value.1": sanitizeTag(environment)}))
	if err != nil || st != http.StatusOK {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "cannot list elastic IPs — refusing to delete a VPC with unknown children"}
	}
	var out struct {
		Items []struct {
			AllocationID  string   `xml:"allocationId"`
			AssociationID string   `xml:"associationId"`
			Tags          []ec2Tag `xml:"tagSet>item"`
		} `xml:"addressesSet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "elastic IP list unparseable — refusing to delete a VPC with unknown children"}
	}
	for _, a := range out.Items {
		if !d.tagsOwn(a.Tags, capability, environment) || a.AllocationID == "" {
			continue
		}
		if a.AssociationID != "" {
			// still bound to the NAT — its delete has not released the EIP yet
			return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "elastic IP still associated — the NAT gateway has not released it yet; reconcile"}
		}
		if r := d.ec2Delete(region, providerID, "ReleaseAddress",
			map[string]string{"AllocationId": a.AllocationID}); r != nil {
			return r
		}
	}
	return nil
}

func (d *Driver) deleteIGWs(region, providerID, vpcID, capability, environment string) *provider.CreateResult {
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeInternetGateways", "Version": ec2Version,
		"Filter.1.Name": "attachment.vpc-id", "Filter.1.Value.1": vpcID}))
	if err != nil || st != http.StatusOK {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "cannot list internet gateways — refusing to delete a VPC with unknown children"}
	}
	var out struct {
		Items []struct {
			ID   string   `xml:"internetGatewayId"`
			Tags []ec2Tag `xml:"tagSet>item"`
		} `xml:"internetGatewaySet>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "internet gateway list unparseable — refusing to delete a VPC with unknown children"}
	}
	for _, g := range out.Items {
		if !d.tagsOwn(g.Tags, capability, environment) {
			continue
		}
		if r := d.ec2Delete(region, providerID, "DetachInternetGateway",
			map[string]string{"InternetGatewayId": g.ID, "VpcId": vpcID}); r != nil {
			return r
		}
		if r := d.ec2Delete(region, providerID, "DeleteInternetGateway",
			map[string]string{"InternetGatewayId": g.ID}); r != nil {
			return r
		}
	}
	return nil
}

// deleteSecurityGroups removes the baseline security group(s) groundhold owns.
// Ownership-tag-gated (the AWS-created default SG is untagged and every foreign/
// controller SG is skipped — never touched, so converge does not fight the
// LB/EKS controllers). An unreadable list refuses the whole delete; a still-
// attached SG surfaces DependencyViolation (a refusal, never forced) via ec2Delete.
func (d *Driver) deleteSecurityGroups(region, providerID, vpcID, capability, environment string) *provider.CreateResult {
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeSecurityGroups", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID}))
	if err != nil || st != http.StatusOK {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "cannot list security groups — refusing to delete a VPC with unknown children"}
	}
	var out struct {
		Items []struct {
			ID   string   `xml:"groupId"`
			Name string   `xml:"groupName"`
			Tags []ec2Tag `xml:"tagSet>item"`
		} `xml:"securityGroupInfo>item"`
	}
	if xml.Unmarshal(resp, &out) != nil {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "security group list unparseable — refusing to delete a VPC with unknown children"}
	}
	for _, g := range out.Items {
		if g.Name == "default" || g.ID == "" || !d.tagsOwn(g.Tags, capability, environment) {
			continue // the AWS default SG (undeletable) or a foreign SG — never touched
		}
		if r := d.ec2Delete(region, providerID, "DeleteSecurityGroup",
			map[string]string{"GroupId": g.ID}); r != nil {
			return r
		}
	}
	return nil
}

// allBetween returns every substring between a and b in s.
func allBetween(s, a, b string) []string {
	var out []string
	for {
		i := strings.Index(s, a)
		if i < 0 {
			return out
		}
		s = s[i+len(a):]
		j := strings.Index(s, b)
		if j < 0 {
			return out
		}
		out = append(out, s[:j])
		s = s[j+len(b):]
	}
}
