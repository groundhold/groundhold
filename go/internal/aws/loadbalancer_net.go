// AWS ELBv2 network shell (D26): the SigV4-signed, Query-protocol half of the AWS
// capability.network.loadbalancer driver. Two reads compose one observation —
// DescribeLoadBalancers (Scheme) + DescribeListeners (Protocol) -> the reverse map.
// Provisioning is the ALB composite (an Application Load Balancer + a Target Group
// + a Listener), so a create is FOUR mutating calls in dependency order —
// CreateTargetGroup -> CreateLoadBalancer -> (wait active) -> CreateListener — plus
// AddTags for tag-based ownership. Any ambiguity AFTER the load balancer lands is
// unknown WITH the providerId, never a silent success that leaves a target-less or
// listener-less exposed front door (D29/D87). Delete tears down in reverse order
// (DeleteListener -> DeleteLoadBalancer -> DeleteTargetGroup), ownership-guarded.
// Signing service is "elasticloadbalancing". API version 2015-12-01.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) elbv2Base(region string) string {
	if d.ELBv2BaseURL != "" {
		return d.ELBv2BaseURL
	}
	return "https://elasticloadbalancing." + region + ".amazonaws.com"
}

// elbv2Post signs + sends an ELBv2 Query-protocol request (Version 2015-12-01),
// SigV4-signed for service "elasticloadbalancing".
func (d *Driver) elbv2Post(region, body string) (int, []byte, error) {
	return d.doSigned("POST", d.elbv2Base(region)+"/", "elasticloadbalancing", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

// elbv2LB is the subset of a LoadBalancer object the driver reads. Scheme drives
// network.publicExposure; the ARN is needed to address the listeners.
type elbv2LB struct {
	Arn    string `xml:"LoadBalancerArn"`
	Name   string `xml:"LoadBalancerName"`
	Scheme string `xml:"Scheme"`
	Type   string `xml:"Type"`
	VpcID  string `xml:"VpcId"`
	State  string `xml:"State>Code"`
}

// describeLoadBalancer resolves one LB by name. found=false + readable=true is an
// authoritative "does not exist" (LoadBalancerNotFound, or absent from the set);
// readable=false is a transport/HTTP/parse failure (unknown, never fabricated
// absence).
func (d *Driver) describeLoadBalancer(region, name string) (lb elbv2LB, found bool, err error) {
	const op = "DescribeLoadBalancers"
	st, body, cerr := d.elbv2Post(region, encodeForm(map[string]string{
		"Action": "DescribeLoadBalancers", "Version": elbv2Version, "Names.member.1": name}))
	if cerr != nil {
		return elbv2LB{}, false, readTransport(op, cerr)
	}
	if rdsErrCode(body) == "LoadBalancerNotFound" {
		return elbv2LB{}, false, nil // authoritatively gone
	}
	if st != http.StatusOK {
		return elbv2LB{}, false, readHTTP(op, st, rdsErrCode(body))
	}
	var out struct {
		LBs []elbv2LB `xml:"DescribeLoadBalancersResult>LoadBalancers>member"`
	}
	if xml.Unmarshal(body, &out) != nil {
		return elbv2LB{}, false, readBody(op, st) // garbled 200 is not "not found"
	}
	for _, l := range out.LBs {
		if l.Name == name {
			return l, true, nil
		}
	}
	return elbv2LB{}, false, nil // not in the set — does not exist
}

// listenerProtocols reads a load balancer's listener protocols. readable=false on
// any transport/HTTP/parse failure — an unreadable listener list must NOT silently
// become "no TLS listener" (a false plaintext claim); the caller turns it into
// unknown.
func (d *Driver) listenerProtocols(region, lbArn string) (protocols []string, err error) {
	const op = "DescribeListeners"
	st, body, cerr := d.elbv2Post(region, encodeForm(map[string]string{
		"Action": "DescribeListeners", "Version": elbv2Version, "LoadBalancerArn": lbArn}))
	if cerr != nil {
		return nil, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return nil, readHTTP(op, st, rdsErrCode(body))
	}
	var out struct {
		Listeners []struct {
			Protocol string `xml:"Protocol"`
		} `xml:"DescribeListenersResult>Listeners>member"`
	}
	if xml.Unmarshal(body, &out) != nil {
		return nil, readBody(op, st)
	}
	for _, l := range out.Listeners {
		protocols = append(protocols, l.Protocol)
	}
	return protocols, nil
}

// observeLoadBalancer reverse-maps a live load balancer: DescribeLoadBalancers for
// the Scheme, then DescribeListeners for the encryption posture, then the SAME
// pure reverse map the sweep uses.
func (d *Driver) observeLoadBalancer(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitELBv2ProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	lb, found, rerr := d.describeLoadBalancer(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return []provider.Observation{
			// F-LC3 (D802): a BOUND resource the API authoritatively 404s is GONE. An
			// empty return leaves the last good observations standing as the freshest
			// word, so posture reads managed-ok and audit stays satisfied about a
			// resource that does not exist (D513/D518, fixed here last).
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"load balancer not found — bound resource is gone (will re-create)"}, nil
	}
	// encryption.inTransit is only knowable from the listeners; an unreadable
	// listener list is UNKNOWN (an error), never a fabricated inTransit=false that
	// would falsely call a TLS front door plaintext.
	protocols, lerr := d.listenerProtocols(region, lb.Arn)
	if lerr != nil {
		return nil, nil, fmt.Errorf("cannot determine encryption.inTransit: %w", lerr)
	}
	obs := reverseMapLoadBalancer(lb.Scheme, protocols)
	// location.region: a load balancer is regional and the create requires it, but
	// the observe omitted it — so a reconcile of a bound ALB refused
	// "location.region: no observation". The region is the balancer's own (from its
	// providerId); emit it so a bound-ALB reconcile confirms the declared region.
	obs = append(obs, provider.Observation{Path: "location.region", Value: region, Derivation: "measured"})
	return obs, nil, nil
}

// --- provisioning reads (ownership + teardown resolution) ---

// describeTags reads a load balancer's tags (DescribeTags). readable=false on any
// transport/HTTP/parse failure — an unreadable ownership tag set must NOT silently
// become "no owner"; the caller turns it into unknown.
func (d *Driver) describeTags(region, lbArn string) (map[string]string, error) {
	const op = "DescribeTags"
	st, body, err := d.elbv2Post(region, encodeForm(map[string]string{
		"Action": "DescribeTags", "Version": elbv2Version, "ResourceArns.member.1": lbArn}))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, rdsErrCode(body))
	}
	var out struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"DescribeTagsResult>TagDescriptions>member>Tags>member"`
	}
	if xml.Unmarshal(body, &out) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

// listenerARNs reads a load balancer's listener ARNs (DescribeListeners) — the
// teardown needs the ARNs, not just the protocols. readable=false on any failure.
func (d *Driver) listenerARNs(region, lbArn string) (arns []string, err error) {
	const op = "DescribeListeners"
	st, body, cerr := d.elbv2Post(region, encodeForm(map[string]string{
		"Action": "DescribeListeners", "Version": elbv2Version, "LoadBalancerArn": lbArn}))
	if cerr != nil {
		return nil, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return nil, readHTTP(op, st, rdsErrCode(body))
	}
	var out struct {
		Listeners []struct {
			ListenerArn string `xml:"ListenerArn"`
		} `xml:"DescribeListenersResult>Listeners>member"`
	}
	if xml.Unmarshal(body, &out) != nil {
		return nil, readBody(op, st)
	}
	for _, l := range out.Listeners {
		arns = append(arns, l.ListenerArn)
	}
	return arns, nil
}

// describeTargetGroupArn resolves a target group's ARN by name (DescribeTargetGroups
// Names.member.1). found=false + readable=true is an authoritative "does not exist"
// (TargetGroupNotFound); readable=false is a transport/HTTP/parse failure. The LB and
// its target group SHARE a name (separate ELBv2 namespaces), so the delete path
// recovers the target group from the load-balancer name in the providerId alone.
func (d *Driver) describeTargetGroupArn(region, name string) (arn string, found bool, err error) {
	const op = "DescribeTargetGroups"
	st, body, cerr := d.elbv2Post(region, encodeForm(map[string]string{
		"Action": "DescribeTargetGroups", "Version": elbv2Version, "Names.member.1": name}))
	if cerr != nil {
		return "", false, readTransport(op, cerr)
	}
	if rdsErrCode(body) == "TargetGroupNotFound" {
		return "", false, nil
	}
	if st != http.StatusOK {
		return "", false, readHTTP(op, st, rdsErrCode(body))
	}
	var out struct {
		TGs []struct {
			Arn  string `xml:"TargetGroupArn"`
			Name string `xml:"TargetGroupName"`
		} `xml:"DescribeTargetGroupsResult>TargetGroups>member"`
	}
	if xml.Unmarshal(body, &out) != nil {
		return "", false, readBody(op, st)
	}
	for _, t := range out.TGs {
		if t.Name == name {
			return t.Arn, true, nil
		}
	}
	return "", false, nil
}

// waitLBActive polls DescribeLoadBalancers until State.Code is "active" (a create
// that is still "provisioning" at the poll timeout is UNKNOWN, never a false
// succeeded — the listener cannot attach to a load balancer that is not yet up).
func (d *Driver) waitLBActive(region, name string) (arn string, ok bool) {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		lb, found, rerr := d.describeLoadBalancer(region, name)
		if rerr == nil && found && lb.State == "active" {
			return lb.Arn, true
		}
		if d.Now().After(deadline) {
			return "", false
		}
		time.Sleep(d.PollInterval)
	}
}

// createLoadBalancer provisions the ALB composite in dependency order:
// CreateTargetGroup (with health check) -> CreateLoadBalancer (Scheme, Subnets,
// SecurityGroups) -> AddTags (ownership) -> wait active -> CreateListener (Protocol
// from inTransit, DefaultAction forward to the target group, cert iff HTTPS). Four-
// valued: once the load balancer lands, ANY later ambiguity (AddTags / wait /
// CreateListener) is unknown WITH the providerId — never a silent success that
// leaves a target-less or listener-less exposed front door.
func (d *Driver) createLoadBalancer(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildLoadBalancer(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := elbv2ProviderID(region, plan.Name)

	// ownership pre-read: refuse to touch a foreign load balancer already at our
	// (deterministic) name. Not-found continues to a fresh create.
	if lb, found, rerr := d.describeLoadBalancer(region, plan.Name); rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create ownership read gave no answer — reconcile before provisioning: " + rerr.Error()}
	} else if found {
		tags, terr := d.describeTags(region, lb.Arn)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "a load balancer with this name exists; ownership tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a load balancer with this name exists and is not ours (tags do not match) — refusing to adopt it"}
		}
		// ours already — ensure the listener exists (repair a prior partial), else done.
		return d.ensureListener(region, pid, lb.Arn, plan)
	}

	// (1) CreateTargetGroup — the backend + health check. Must precede the listener
	// (the listener's DefaultAction forwards to it). Idempotent on a prior partial:
	// DuplicateTargetGroupName means the target group already landed — resolve it.
	tgArn, res := d.createTargetGroup(region, pid, plan)
	if res != nil {
		return *res
	}

	// (2) CreateLoadBalancer — Scheme, Subnets, SecurityGroups. The pid is knowable
	// before this response (deterministic name), so transport/5xx ambiguity carries it.
	st, body, err := d.elbv2Post(region, encodeForm(plan.createLoadBalancerForm()))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateLoadBalancer outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// created (state "provisioning") — fall through
	case rdsErrCode(body) == "DuplicateLoadBalancerName":
		// raced with another actor since our pre-read; the LB exists — carry the pid.
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreateLoadBalancer says the name now exists — reconcile ownership"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateLoadBalancer HTTP %d (server error — may have landed): %s", st, mutDetail(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateLoadBalancer HTTP %d (%s): %s", st, rdsErrCode(body), mutDetail(body))}
	}
	var created struct {
		Arn   string `xml:"CreateLoadBalancerResult>LoadBalancers>member>LoadBalancerArn"`
		State string `xml:"CreateLoadBalancerResult>LoadBalancers>member>State>Code"`
	}
	if xml.Unmarshal(body, &created) != nil || created.Arn == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreateLoadBalancer returned 200 but no LoadBalancerArn — reconcile"}
	}
	lbArn := created.Arn

	// (3) AddTags — tag-based ownership on the load balancer. The LB is up now, so a
	// failure here is unknown WITH the pid (an unmarked LB that a reconcile must
	// finish), never failed.
	st, _, err = d.elbv2Post(region, encodeForm(ownershipTagsForm(lbArn, capability, environment)))
	if err != nil || st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "load balancer created but ownership AddTags outcome unknown — reconcile"}
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("load balancer created but AddTags failed (HTTP %d) — reconcile ownership", st)}
	}

	// (4) wait active, then CreateListener (forward to the target group; cert iff HTTPS).
	activeArn, ok := d.waitLBActive(region, plan.Name)
	if !ok {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "load balancer still provisioning at poll timeout — reconcile via DescribeLoadBalancers, then attach the listener"}
	}
	return d.createListener(region, pid, activeArn, tgArn, plan)
}

// createTargetGroup issues CreateTargetGroup and returns the target-group ARN. A
// DuplicateTargetGroupName (a prior partial) is idempotent: resolve the existing
// ARN by name. Failures before the load balancer exists are failed (nothing is
// exposed) unless ambiguous (transport/5xx), which is unknown WITH the pid so a
// reconcile can clean the orphaned target group.
func (d *Driver) createTargetGroup(region, pid string, plan LoadBalancerPlan) (string, *provider.CreateResult) {
	st, body, err := d.elbv2Post(region, encodeForm(plan.createTargetGroupForm()))
	switch {
	case err != nil:
		return "", &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateTargetGroup outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		var out struct {
			Arn string `xml:"CreateTargetGroupResult>TargetGroups>member>TargetGroupArn"`
		}
		if xml.Unmarshal(body, &out) != nil || out.Arn == "" {
			return "", &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "CreateTargetGroup returned 200 but no TargetGroupArn — reconcile"}
		}
		return out.Arn, nil
	case rdsErrCode(body) == "DuplicateTargetGroupName":
		arn, found, rerr := d.describeTargetGroupArn(region, plan.Name)
		if rerr != nil {
			return "", &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "target group name conflict but the existing group gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return "", &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "CreateTargetGroup said the name exists but describe found nothing — reconcile"}
		}
		return arn, nil
	case st >= 500:
		return "", &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateTargetGroup HTTP %d (server error — may have landed): %s", st, mutDetail(body))}
	default:
		return "", &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateTargetGroup HTTP %d (%s): %s", st, rdsErrCode(body), mutDetail(body))}
	}
}

// createListener attaches the listener (DefaultAction forward to the target group;
// Certificates iff HTTPS). The load balancer is ALREADY up, so EVERY failure here —
// transport, 5xx, OR a 4xx — is unknown WITH the pid: a load balancer with no
// listener is a target-less exposed front door that a reconcile/delete must resolve,
// NEVER a silent success and never a bare "failed" that hides the standing LB.
func (d *Driver) createListener(region, pid, lbArn, tgArn string, plan LoadBalancerPlan) provider.CreateResult {
	st, body, err := d.elbv2Post(region, encodeForm(plan.createListenerForm(lbArn, tgArn)))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("load balancer up but CreateListener outcome unknown — reconcile: %v", err)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("load balancer up but CreateListener HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("load balancer up but the listener could not be attached (HTTP %d: %s) — "+
				"the front door has no listener; reconcile or delete rather than leaving it target-less",
				st, rdsErrCode(body))}
	}
}

// ensureListener completes an already-ours load balancer that may be missing its
// listener (idempotent re-create / partial repair). If a listener already exists,
// the composite is complete (succeeded); otherwise resolve the target group and
// attach the listener.
func (d *Driver) ensureListener(region, pid, lbArn string, plan LoadBalancerPlan) provider.CreateResult {
	arns, lerr := d.listenerARNs(region, lbArn)
	if lerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "load balancer exists and is ours but its listeners gave no answer — reconcile: " + lerr.Error()}
	}
	if len(arns) > 0 {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // idempotent — already complete
	}
	tgArn, found, tgErr := d.describeTargetGroupArn(region, plan.Name)
	if tgErr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "load balancer exists but its target group gave no answer — reconcile: " + tgErr.Error()}
	}
	if !found {
		// the load balancer is ours but the target group is gone — rebuild it.
		var res *provider.CreateResult
		tgArn, res = d.createTargetGroup(region, pid, plan)
		if res != nil {
			return *res
		}
	}
	return d.createListener(region, pid, lbArn, tgArn, plan)
}

// deleteLoadBalancer tears the composite down in REVERSE dependency order, ownership-
// guarded: pre-read the ownership tags (refuse a foreign LB), DeleteListener (each) ->
// DeleteLoadBalancer -> DeleteTargetGroup. Idempotent on already-gone (404); a 5xx
// mid-teardown is unknown (reconcile), never a claimed success.
func (d *Driver) deleteLoadBalancer(capability, environment, providerID string) provider.CreateResult {
	region, name, err := splitELBv2ProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	lb, found, rerr := d.describeLoadBalancer(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if found {
		// ownership guard: refuse a foreign load balancer at our name.
		tags, terr := d.describeTags(region, lb.Arn)
		if terr != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete ownership tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "load balancer tags do not match — refusing to delete a resource that is not ours"}
		}
		// (1) DeleteListener for each — a load balancer with listeners deletes cleanly,
		// but removing them first keeps the teardown in strict reverse order.
		arns, lerr := d.listenerARNs(region, lb.Arn)
		if lerr != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete listener list gave no answer — reconcile: " + lerr.Error()}
		}
		for _, la := range arns {
			if res := d.deleteOne(region, providerID, "DeleteListener", "ListenerArn", la); res != nil {
				return *res
			}
		}
		// (2) DeleteLoadBalancer.
		if res := d.deleteOne(region, providerID, "DeleteLoadBalancer", "LoadBalancerArn", lb.Arn); res != nil {
			return *res
		}
		// ---- poll to absence (D968 class, D980) ----
		// DeleteLoadBalancer is async: the LB lingers in a deleting state (and still
		// references its target group, which cannot be deleted meanwhile). Reporting
		// succeeded here tombstones an hourly-billable LB still live. Poll to a
		// confirmed absence before the target-group cleanup; unknown on timeout.
		deadline := d.Now().Add(d.PollTimeout)
		for {
			if _, stillThere, rerr := d.describeLoadBalancer(region, name); rerr == nil && !stillThere {
				break // LB fully gone — safe to delete the target group
			}
			if d.Now().After(deadline) {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: "load balancer still deleting at poll timeout — reconcile via DescribeLoadBalancers"}
			}
			time.Sleep(d.PollInterval)
		}
	}
	// (3) DeleteTargetGroup — resolved by the shared name (independent of the LB, so a
	// partial where the LB is gone but the target group leaked is still cleaned).
	tgArn, tgFound, tgErr := d.describeTargetGroupArn(region, name)
	if tgErr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete target group gave no answer — reconcile: " + tgErr.Error()}
	}
	if tgFound {
		if res := d.deleteOne(region, providerID, "DeleteTargetGroup", "TargetGroupArn", tgArn); res != nil {
			return *res
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// deleteOne issues one ELBv2 delete (DeleteListener / DeleteLoadBalancer /
// DeleteTargetGroup) and maps the outcome four-valued: nil on success or an
// idempotent already-gone (404 / *NotFound); a non-nil unknown on transport/5xx
// (reconcile); a non-nil failed on a 4xx. Returning non-nil aborts the teardown.
func (d *Driver) deleteOne(region, providerID, action, arnParam, arn string) *provider.CreateResult {
	st, body, err := d.elbv2Post(region, encodeForm(map[string]string{
		"Action": action, "Version": elbv2Version, arnParam: arn}))
	if err != nil {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("%s outcome unknown: %v", action, err)}
	}
	switch code := rdsErrCode(body); code {
	case "LoadBalancerNotFound", "ListenerNotFound", "TargetGroupNotFound":
		return nil // idempotent — already gone
	}
	if st >= 500 {
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("%s HTTP %d (server error) — reconcile", action, st)}
	}
	if st != http.StatusOK {
		return &provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("%s HTTP %d (%s): %s", action, st, rdsErrCode(body), mutDetail(body))}
	}
	return nil
}

// updateLoadBalancer refuses in-place: the governed attributes (scheme, inTransit)
// are immutable on an ALB (see classifyLBChange) — the compiler routes them to a
// replacement, so an in-place Update is never reached for them. Refuse honestly
// rather than pretend a patch happened.
func (d *Driver) updateLoadBalancer() provider.CreateResult {
	return provider.CreateResult{Status: "failed",
		Reason: "aws loadbalancer in-place update is not supported — the governed attributes " +
			"(scheme, encryption.inTransit) are fixed at creation and route to a replacement"}
}

// classifyLBChange (D46): PURE — can a capability.network.loadbalancer transition be
// honored in place? network.publicExposure (Scheme) and encryption.inTransit
// (HTTPS-vs-HTTP listener) are fixed at creation on an ALB — a change is a
// REPLACEMENT (create-before-destroy), never an in-place patch. The health-check
// path is a mutable target-group attribute. Never a silent "mutable".
func classifyLBChange(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "network.publicExposure":
		return "immutable", "an ALB's scheme (internet-facing vs internal) is fixed at creation — a change is a replacement"
	case "encryption.inTransit":
		// D832: the sentence names the LISTENER and the verdict destroyed the LOAD BALANCER.
		// ModifyListener takes Protocol, SslPolicy and Certificates, and AWS documents the
		// switch itself — "Changing the protocol from HTTPS to HTTP, or from TLS to TCP,
		// removes the security policy and default certificate". Replacing the balancer
		// changes its DNS name, which is the address every client and every DNS record
		// holds; the listener change does not touch it.
		return "unsupported", "in-place TLS switch is not wired for this load balancer in " +
			"this slice — AWS does support it (ModifyListener takes Protocol, SslPolicy and " +
			"Certificates on the existing listener), so this is a gap in groundhold rather " +
			"than a reason to replace the balancer and change its DNS name"
	case "healthCheckPath":
		return "mutable", "the target-group health-check path is modifiable in place (ModifyTargetGroup)"
	case "location.region", "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no ELBv2 load-balancer in-place mapping for " + path
	}
}
