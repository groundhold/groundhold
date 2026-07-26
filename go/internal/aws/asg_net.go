// Auto Scaling group network shell (D371): auth, HTTP, the two preflight
// cross-checks and the reverse mapping. No semantics here — those are in asg.go.
//
// The honesty rules the executor depends on (D29): a transport error or a 5xx on
// a MUTATING call is `unknown`, never `failed`, because a 502 can front a group
// that exists. Only a definitive 4xx is `failed`. Every one is reconcilable,
// because the group NAME is deterministic — a lost create can be found again
// rather than duplicated.
//
// TWO CHECKS RUN BEFORE ANY MUTATION, and both exist because the attribute they
// guard is not a property of the group resource:
//
//   - the subnets' availability zones must be DISTINCT when the contract says
//     `regional`. Two subnets in one zone would create a group that looks spread
//     and survives nothing. The pure core counts subnets; only this layer can
//     resolve them to zones.
//   - the launch template's addressing must match `network.publicExposure`. The
//     group cannot set it and the template is an operand groundhold does not
//     author, so the only honest options are to read it or to ignore the
//     contract. This reads it.
//
// A create is TWO mutations when a policy is wanted: the group, then the policy.
// The group is created first and the policy attached second, so a failure between
// them leaves a real group with a real capacity floor — under-scaled but running,
// which is the survivable half. The reverse order is not possible (a policy needs
// its group), and the outcome is reported honestly rather than rolled back.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

// asgProviderID is region-scoped: a group name is unique per region.
func asgProviderID(region, account, name string) string {
	return "asg:" + region + ":" + account + ":" + name
}

func splitASGProviderID(providerID string) (region, account, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "asg" {
		return "", "", "", fmt.Errorf("providerId %q is not an asg id (want asg:<region>:<account>:<name>)", providerID)
	}
	region, account, name = parts[1], parts[2], parts[3]
	if region == "" || name == "" || strings.ContainsAny(name, "/\\ ") {
		return "", "", "", fmt.Errorf("providerId %q has no valid region/group name", providerID)
	}
	return region, account, name, nil
}

// asgPost signs and sends an Auto Scaling Query-protocol request.
func (d *Driver) asgPost(region, body string) (int, []byte, error) {
	base := "https://autoscaling." + region + ".amazonaws.com/"
	if d.AutoScalingBaseURL != "" {
		base = d.AutoScalingBaseURL + "/"
	}
	return d.doSigned("POST", base, "autoscaling", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

// asgGroup is the slice of DescribeAutoScalingGroups this driver reads.
type asgGroup struct {
	Name              string
	MinSize           int
	MaxSize           int
	AvailabilityZones []string
	LaunchTemplateID  string
	Tags              map[string]string
}

func (d *Driver) describeASG(region, name string) (asgGroup, bool, error) {
	st, body, err := d.asgPost(region, encodeForm(map[string]string{
		"Action": "DescribeAutoScalingGroups", "Version": asgVersion,
		"AutoScalingGroupNames.member.1": name,
	}))
	if err != nil {
		return asgGroup{}, false, readTransport("DescribeAutoScalingGroups", err)
	}
	if st != http.StatusOK {
		return asgGroup{}, false, readHTTP("DescribeAutoScalingGroups", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			Name    string   `xml:"AutoScalingGroupName"`
			MinSize int      `xml:"MinSize"`
			MaxSize int      `xml:"MaxSize"`
			Zones   []string `xml:"AvailabilityZones>member"`
			LT      struct {
				ID string `xml:"LaunchTemplateId"`
			} `xml:"LaunchTemplate"`
			Tags []struct {
				Key   string `xml:"Key"`
				Value string `xml:"Value"`
			} `xml:"Tags>member"`
		} `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return asgGroup{}, false, readBody("DescribeAutoScalingGroups", st)
	}
	if len(resp.Items) == 0 {
		return asgGroup{}, false, nil
	}
	it := resp.Items[0]
	g := asgGroup{Name: it.Name, MinSize: it.MinSize, MaxSize: it.MaxSize,
		AvailabilityZones: it.Zones, LaunchTemplateID: it.LT.ID, Tags: map[string]string{}}
	for _, t := range it.Tags {
		g.Tags[t.Key] = t.Value
	}
	return g, true, nil
}

// asgHasPolicy reports whether any scaling policy targets the group. Returns
// (has, known): `known=false` means the read did not answer, and the caller must
// report the attribute unread rather than choose a value for it.
func (d *Driver) asgHasPolicy(region, name string) (has bool, err error) {
	st, body, cerr := d.asgPost(region, encodeForm(map[string]string{
		"Action": "DescribePolicies", "Version": asgVersion, "AutoScalingGroupName": name,
	}))
	if cerr != nil {
		return false, readTransport("DescribePolicies", cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP("DescribePolicies", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			PolicyName string `xml:"PolicyName"`
		} `xml:"DescribePoliciesResult>ScalingPolicies>member"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return false, readBody("DescribePolicies", st)
	}
	return len(resp.Items) > 0, nil
}

// subnetZones resolves subnet ids to their availability zones. Returns
// (zones, known): a read that did not answer is `known=false`, and the caller
// refuses rather than guessing — the whole point of the check is that a guess
// would certify zone survivability.
func (d *Driver) subnetZones(region string, subnets []string) (zones []string, err error) {
	params := map[string]string{"Action": "DescribeSubnets", "Version": ec2Version}
	for i, s := range subnets {
		params[fmt.Sprintf("SubnetId.%d", i+1)] = s
	}
	st, body, cerr := d.ec2PostBase(region, encodeForm(params))
	if cerr != nil {
		return nil, readTransport("DescribeSubnets", cerr)
	}
	if st != http.StatusOK {
		return nil, readHTTP("DescribeSubnets", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			SubnetID string `xml:"subnetId"`
			Zone     string `xml:"availabilityZone"`
		} `xml:"subnetSet>item"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return nil, readBody("DescribeSubnets", st)
	}
	if len(resp.Items) != len(subnets) {
		// A partial answer cannot prove distinctness: the missing subnet might be
		// the one that shares a zone.
		return nil, fmt.Errorf("DescribeSubnets named %d of %d subnets — a partial answer "+
			"cannot prove the zones are distinct", len(resp.Items), len(subnets))
	}
	for _, it := range resp.Items {
		zones = append(zones, it.Zone)
	}
	return zones, nil
}

// launchTemplateAssignsPublicIP reads the addressing the template will give every
// machine. Returns (public, known); an unread template is refused upstream rather
// than assumed either way.
func (d *Driver) launchTemplateAssignsPublicIP(region, templateID, version string) (public bool, err error) {
	params := map[string]string{
		"Action": "DescribeLaunchTemplateVersions", "Version": ec2Version,
		"LaunchTemplateId": templateID,
	}
	if version == "" {
		version = "$Default"
	}
	params["LaunchTemplateVersion.1"] = version
	st, body, cerr := d.ec2PostBase(region, encodeForm(params))
	if cerr != nil {
		return false, readTransport("DescribeLaunchTemplateVersions", cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP("DescribeLaunchTemplateVersions", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			Data struct {
				NICs []struct {
					AssociatePublicIP string `xml:"associatePublicIpAddress"`
				} `xml:"networkInterfaceSet>item"`
			} `xml:"launchTemplateData"`
		} `xml:"launchTemplateVersionSet>item"`
	}
	if xml.Unmarshal(body, &resp) != nil || len(resp.Items) == 0 {
		return false, readBody("DescribeLaunchTemplateVersions", st)
	}
	for _, nic := range resp.Items[0].Data.NICs {
		if strings.EqualFold(nic.AssociatePublicIP, "true") {
			return true, nil
		}
	}
	// No interface asks for a public address. On AWS that means the subnet's
	// auto-assign setting decides, which is a property of the network rather than
	// of the fleet — reported as "the template does not add one", which is what the
	// group's own configuration can honestly claim.
	return false, nil
}

func (d *Driver) createASG(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {

	plan, err := BuildASGCreate(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := asgProviderID(region, account, plan.Name)

	// --- preflight 1: the zone spread the contract claims must be real ---
	if plan.Regional {
		zones, zerr := d.subnetZones(region, plan.SubnetIDs)
		if zerr != nil {
			return provider.CreateResult{Status: "failed",
				Reason: "availability.class=regional could not be verified (" + zerr.Error() +
					") — creating the group anyway would certify zone survivability nobody has checked"}
		}
		distinct := map[string]bool{}
		for _, z := range zones {
			distinct[z] = true
		}
		if len(distinct) < 2 {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("availability.class=regional but every subnet is in the same "+
					"availability zone (%v) — the group would survive nothing a zonal group does not",
					zones)}
		}
	}

	// --- preflight 2: the template's addressing must match the contract ---
	if plan.PublicDeclared {
		public, terr := d.launchTemplateAssignsPublicIP(region, plan.LaunchTemplateID, plan.TemplateVersion)
		if terr != nil {
			return provider.CreateResult{Status: "failed",
				Reason: "network.publicExposure could not be verified for launch template " +
					plan.LaunchTemplateID + " (" + terr.Error() +
					") — the group cannot set addressing itself"}
		}
		if public != plan.WantPublic {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("network.publicExposure=%v contradicts launch template %s, which "+
					"assigns public addresses = %v — the group inherits the template's addressing and "+
					"cannot override it, so the contract would be reported satisfied by a fleet that "+
					"violates it", plan.WantPublic, plan.LaunchTemplateID, public)}
		}
	}

	st, body, cerr := d.asgPost(region, plan.createBody())
	switch {
	case cerr != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; the group name is deterministic): %v", cerr)}
	case st == http.StatusOK:
		// fall through to the policy
	case strings.Contains(awsErrCodeOf(body), "AlreadyExists"):
		// The deterministic name already names a group. It is ours only if the tags
		// say so — otherwise we would bind somebody else's fleet to this contract.
		g, found, rerr := d.describeASG(region, plan.Name)
		if rerr != nil || !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing group gave no answer — reconcile"}
		}
		if !groundholdTagsMatch(g.Tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a group with this name exists and is not ours (tags do not match) — refusing to bind it"}
		}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, awsErrCodeOf(body), nil, pid, "create"); r != nil {
			// The group NAME is deterministic, so the handle is knowable even when the
			// outcome is not — dropping it would leave an operator with a fleet they
			// cannot name, and a retry is how a second one gets created.
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s)", st, awsErrCodeOf(body))}
	}

	if !plan.AutoscalingWanted {
		return d.pollASG(region, account, plan.Name)
	}
	pst, pbody, perr := d.asgPost(region, plan.policyBody())
	switch {
	case perr != nil || pst >= 500:
		// The group EXISTS and holds its floor; only the policy is uncertain. Saying
		// `unknown` names exactly that, and the deterministic policy name makes it
		// reconcilable — reporting `failed` would invite a retry of the whole create.
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "the group was created but the scaling policy outcome is unknown — " +
				"the fleet holds its floor and does not scale; reconcile"}
	case pst != http.StatusOK:
		// A throttle or a permission gap on the POLICY is not a refusal of it: the
		// call never reached a decision, so the outcome is unresolved and `unknown`
		// is the honest verdict. Only a definitive 4xx means the policy was refused,
		// and only then is autoscaling.enabled provably unsatisfied.
		if r := provider.MutationResult(pst, awsErrCodeOf(pbody), nil, pid, "create"); r != nil {
			r.Reason = "the group was created but the scaling policy did not resolve (" +
				r.Reason + ") — the fleet holds its floor and does not scale; reconcile"
			return *r
		}
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("the group was created but the scaling policy was refused (HTTP %d, %s) "+
				"— autoscaling.enabled is not satisfied", pst, awsErrCodeOf(pbody))}
	}
	return d.pollASG(region, account, plan.Name)
}

// pollASG confirms the group is readable before calling the create done. A group
// the API cannot name back is not a group anybody can verify.
func (d *Driver) pollASG(region, account, name string) provider.CreateResult {
	pid := asgProviderID(region, account, name)
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.describeASG(region, name); rerr == nil && found {
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "group not readable at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// observeASG is the reverse mapping. availability.class is MEASURED from the
// zones the group reports, never inferred from what was asked for — the whole
// reason the create-time check exists is that the two can differ.
func (d *Driver) observeASG(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, name, err := splitASGProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	g, found, rerr := d.describeASG(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"auto scaling group not found — nothing to observe"}, nil
	}
	class := "zonal"
	if len(g.AvailabilityZones) > 1 {
		class = "regional"
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "availability.class", Value: class, Derivation: "measured"},
		{Path: "replicas.minimum", Value: g.MinSize, Derivation: "measured"},
		{Path: "replicas.maximum", Value: g.MaxSize, Derivation: "measured"},
	}
	var unread []string
	if has, perr := d.asgHasPolicy(region, name); perr == nil {
		obs = append(obs, provider.Observation{
			Path: "autoscaling.enabled", Value: has, Derivation: "measured"})
	} else {
		// A silent false would report a scaling fleet as fixed-size, and a silent
		// true the reverse. Neither is a reading.
		unread = append(unread, "autoscaling.enabled unread: "+perr.Error())
	}
	if g.LaunchTemplateID == "" {
		unread = append(unread, "group reports no launch template — network.publicExposure unread")
	} else if public, terr := d.launchTemplateAssignsPublicIP(region, g.LaunchTemplateID, ""); terr == nil {
		obs = append(obs, provider.Observation{
			Path: "network.publicExposure", Value: public, Derivation: "measured"})
	} else {
		unread = append(unread, "network.publicExposure unread for launch template "+
			g.LaunchTemplateID+": "+terr.Error())
	}
	return obs, unread, nil
}

// deleteASG retires the group AND the fleet it manages. That is what retiring a
// group MEANS (D363: the machines are cattle by construction), so ForceDelete is
// correct rather than aggressive — and it is stated here because the alternative,
// a delete that fails whenever the group is non-empty, would leave every real
// retirement stuck.
//
// A group holding irreplaceable state on its members has stepped outside what the
// type means; a volume that must survive is a capability.storage.block (D361),
// which IS stateful and IS gated.
func (d *Driver) deleteASG(capability, environment, providerID string) provider.CreateResult {
	region, _, name, err := splitASGProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	g, found, rerr := d.describeASG(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(g.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "group tags do not match — refusing to terminate a fleet that is not ours"}
	}
	st, body, e := d.asgPost(region, encodeForm(map[string]string{
		"Action": "DeleteAutoScalingGroup", "Version": asgVersion,
		"AutoScalingGroupName": name, "ForceDelete": "true",
	}))
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case strings.Contains(awsErrCodeOf(body), "NotFound"):
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, awsErrCodeOf(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("delete HTTP %d (%s)", st, awsErrCodeOf(body))}
	}
}

// discoverASGs enumerates the groups in the region. A fleet that scales itself
// and nobody is watching is a bill that grows on its own, which is a blind spot
// worth closing.
func (d *Driver) discoverASGs(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("asg: %v", err)
	}
	st, body, cerr := d.asgPost(region, encodeForm(map[string]string{
		"Action": "DescribeAutoScalingGroups", "Version": asgVersion,
	}))
	if cerr != nil {
		return nil, nil, readTransport("DescribeAutoScalingGroups", cerr)
	}
	if st != http.StatusOK {
		return nil, nil, readHTTP("DescribeAutoScalingGroups", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			Name string `xml:"AutoScalingGroupName"`
		} `xml:"DescribeAutoScalingGroupsResult>AutoScalingGroups>member"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return nil, nil, readBody("DescribeAutoScalingGroups", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, it := range resp.Items {
		if it.Name == "" {
			continue
		}
		pid := asgProviderID(region, account, it.Name)
		obs, odiags, oerr := d.observeASG("", pid)
		if oerr != nil {
			diags = append(diags, it.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, it.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.compute.autoscaling",
			Observations: obs,
		})
	}
	return out, diags, nil
}
