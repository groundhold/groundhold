// ECS network shell (D86): the SigV4-signed, JSON-protocol half of the AWS
// workload.container driver. Multi-resource create (cluster -> register task
// definition -> create service), the providerId attached once the service
// exists so a partial is failed/unknown WITH the pid, never succeeded. The
// service is polled to a stable deployment (still-deploying at timeout is
// unknown). Ownership is tags; delete is reverse (service -> cluster).
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) ecsBase(region string) string {
	if d.ECSBaseURL != "" {
		return d.ECSBaseURL
	}
	return "https://ecs." + region + ".amazonaws.com"
}

func ecsProviderID(region, name string) string {
	return "ecs:" + region + ":" + name
}

func splitECSProviderID(providerID string) (region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "ecs" {
		return "", "", fmt.Errorf("providerId %q is not ecs:region:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !ecsNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// ecsCall signs and sends a JSON-protocol request (X-Amz-Target = <api>.<action>).
func (d *Driver) ecsCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": ecsTarget + "." + action,
	}
	return d.doSigned("POST", d.ecsBase(region)+"/", "ecs", region, h, []byte(body))
}

// ecsErr pulls a human string out of an ECS JSON error body. It joins __type
// AND message because the "already exists" resume signal lives in the MESSAGE
// ("Creation of service was not idempotent."), not the __type
// (InvalidParameterException) — returning only the type broke the resume match.
func ecsErr(body []byte) string {
	var e struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	msg := e.Message
	if msg == "" {
		msg = e.Msg
	}
	s := strings.TrimSpace(e.Type + " " + msg)
	if s == "" {
		// D309: never the raw body — this string reaches a persisted, signed
		// receipt. An unrecognised shape yields the status alone at the call site.
		return ""
	}
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return strings.ReplaceAll(s, "\n", " ")
}

// createECS: cluster -> task def -> service, then poll to a stable deployment.
func (d *Driver) createECS(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildECSRequests(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := ecsProviderID(region, plan.Name)

	// ---- cluster (idempotent: CreateCluster on an existing name returns it) ----
	st, body, err := d.ecsCall(region, "CreateCluster", plan.CreateClusterBody)
	if err != nil {
		// cluster name == pid name component; an ambiguous outcome may have landed
		// the cluster, so carry the pid (as the register-task-def step below does).
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("cluster outcome unknown: %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("cluster: HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 {
		if r := provider.MutationResult(st, ecsErr(body), nil, pid, "cluster"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("cluster: HTTP %d (%s)", st, ecsErr(body))}
	}

	// ---- register task definition -> taskDefinitionArn ----
	st, body, err = d.ecsCall(region, "RegisterTaskDefinition", plan.RegisterTaskBody)
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("register task def outcome unknown: %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("register task def HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 {
		if r := provider.MutationResult(st, ecsErr(body), nil, pid, "register task def"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("cluster exists but register task def failed: HTTP %d (%s)", st, ecsErr(body))}
	}
	var reg struct {
		TaskDefinition struct {
			Arn string `json:"taskDefinitionArn"`
		} `json:"taskDefinition"`
	}
	if json.Unmarshal(body, &reg) != nil || reg.TaskDefinition.Arn == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "register task def returned no arn — reconcile"}
	}

	// ---- create service (or continue if ours) ----
	st, body, err = d.ecsCall(region, "CreateService", plan.CreateServiceFn(reg.TaskDefinition.Arn))
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create service outcome unknown: %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create service HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 {
		// Continue ONLY on the specific "already exists" error — any OTHER 4xx
		// (e.g. InvalidParameter for a bad subnet) is a real failure. Otherwise a
		// stale owned service with the same name would be polled and reported
		// succeeded for the NEW, rejected desired config (adversarial review).
		et := ecsErr(body)
		if !strings.Contains(et, "already exists") && !strings.Contains(et, "Creation of service was not idempotent") {
			if r := provider.MutationResult(st, et, nil, pid, "create service"); r != nil {
				return *r
			}
			return provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("cluster+taskdef created but create service failed: HTTP %d (%s)", st, et)}
		}
		// service already exists — verify it is ours before adopting it
		svc, found, rerr := d.describeService(region, plan.Cluster, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "service exists but gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !groundholdTagsMatch(svc.tags(), capability, environment) {
			return provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: "a service with this name exists but is not ours (tags do not match)"}
		}
		// ours — fall through to poll
	}

	// ---- poll to stable ----
	deadline := d.Now().Add(d.PollTimeout)
	for {
		svc, found, rerr := d.describeService(region, plan.Cluster, plan.Name)
		if rerr == nil && found {
			if svc.RunningCount >= plan.DesiredCount && svc.rolloutComplete() {
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			}
			if svc.rolloutFailed() {
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "service deployment failed to stabilize"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "service still deploying at poll timeout — reconcile via DescribeServices"}
		}
		time.Sleep(d.PollInterval)
	}
}

type ecsService struct {
	ServiceArn           string `json:"serviceArn"`
	Status               string `json:"status"`
	RunningCount         int    `json:"runningCount"`
	DesiredCount         int    `json:"desiredCount"`
	LaunchType           string `json:"launchType"`
	NetworkConfiguration struct {
		AwsvpcConfiguration struct {
			AssignPublicIP string `json:"assignPublicIp"`
		} `json:"awsvpcConfiguration"`
	} `json:"networkConfiguration"`
	Deployments []struct {
		RolloutState string `json:"rolloutState"`
	} `json:"deployments"`
	LoadBalancers []struct {
		TargetGroupArn string `json:"targetGroupArn"`
	} `json:"loadBalancers"`
	Tags []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"tags"`
}

func (s ecsService) tags() map[string]string {
	m := map[string]string{}
	for _, t := range s.Tags {
		m[t.Key] = t.Value
	}
	return m
}
func (s ecsService) rolloutComplete() bool {
	for _, dep := range s.Deployments {
		if dep.RolloutState == "COMPLETED" {
			return true
		}
	}
	return len(s.Deployments) == 0
}
func (s ecsService) rolloutFailed() bool {
	for _, dep := range s.Deployments {
		if dep.RolloutState == "FAILED" {
			return true
		}
	}
	return false
}

func (d *Driver) describeService(region, cluster, name string) (svc ecsService, found bool, err error) {
	body := jsonBody(map[string]any{"cluster": cluster, "services": []any{name}, "include": []any{"TAGS"}})
	st, resp, err := d.ecsCall(region, "DescribeServices", body)
	if err != nil {
		return ecsService{}, false, readTransport("DescribeServices", err)
	}
	if st != http.StatusOK {
		// a deleted cluster is a definitive "the service is gone" (readable),
		// not an unreadable error — so post-retirement resume/observe settle.
		if strings.Contains(ecsErr(resp), "ClusterNotFound") {
			return ecsService{}, false, nil
		}
		return ecsService{}, false, readHTTP("DescribeServices", st, ecsErr(resp))
	}
	var out struct {
		Services []ecsService `json:"services"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return ecsService{}, false, readBody("DescribeServices", st) // garbled 200 is not "not found"
	}
	if len(out.Services) == 0 {
		return ecsService{}, false, nil
	}
	if out.Services[0].Status == "INACTIVE" || out.Services[0].Status == "" {
		return out.Services[0], false, nil
	}
	return out.Services[0], true, nil
}

func groundholdTagsMatch(tags map[string]string, capability, environment string) bool {
	return tags["groundhold-capability"] == sanitizeTag(capability) &&
		tags["groundhold-environment"] == sanitizeTag(environment)
}

// clusterTags reads a cluster's tags (a non-nil error on any failure — a cluster
// that gave no answer is never treated as "not ours" for a DESTRUCTIVE act).
func (d *Driver) clusterTags(region, cluster string) (tags map[string]string, err error) {
	const op = "DescribeClusters"
	st, resp, cerr := d.ecsCall(region, "DescribeClusters",
		jsonBody(map[string]any{"clusters": []any{cluster}, "include": []any{"TAGS"}}))
	if cerr != nil {
		return nil, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		Clusters []struct {
			Tags []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"tags"`
		} `json:"clusters"`
	}
	if json.Unmarshal(resp, &out) != nil || len(out.Clusters) == 0 {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.Clusters[0].Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

// observeECS reverse-maps a live service.
func (d *Driver) observeECS(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitECSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	svc, found, rerr := d.describeService(region, name, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"service not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "availability.class", Value: "regional", Derivation: "config-intent"},
		{Path: "network.publicExposure",
			Value:      svc.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIP == "ENABLED",
			Derivation: "measured"},
	}
	if svc.DesiredCount > 0 {
		obs = append(obs, provider.Observation{Path: "replicas.minimum",
			Value: float64(svc.DesiredCount), Derivation: "measured"})
	}
	// tls.enforced: the service is TLS-fronted iff it registers behind a target
	// group whose load balancer has an HTTPS/TLS listener. Trace the target group
	// to its LB (DescribeTargetGroups) then the LB to its listeners
	// (DescribeListeners) — the create trusts the operand, observe measures the
	// real listener protocol so a plaintext front door is caught as violated.
	var diags []string
	if len(svc.LoadBalancers) > 0 && svc.LoadBalancers[0].TargetGroupArn != "" {
		tgArn := svc.LoadBalancers[0].TargetGroupArn
		if lbArn, ok := d.targetGroupLB(region, tgArn); !ok {
			diags = append(diags, "tls.enforced not observed: DescribeTargetGroups on the "+
				"service's target group gave no answer — probe/reconcile")
		} else if protocols, lerr := d.listenerProtocols(region, lbArn); lerr != nil {
			diags = append(diags, "tls.enforced not observed: "+lerr.Error()+
				" on the fronting load balancer — probe/reconcile")
		} else {
			obs = append(obs, provider.Observation{Path: "tls.enforced",
				Value: hasTLSListener(protocols), Derivation: "measured"})
		}
	}
	return obs, diags, nil
}

// targetGroupLB resolves a target group ARN to the ARN of the load balancer
// fronting it (DescribeTargetGroups). ok=false on any unreadable/parse failure —
// an unreadable trace must become a diag, never a fabricated tls.enforced=false.
func (d *Driver) targetGroupLB(region, tgArn string) (lbArn string, ok bool) {
	st, body, err := d.elbv2Post(region, encodeForm(map[string]string{
		"Action": "DescribeTargetGroups", "Version": elbv2Version,
		"TargetGroupArns.member.1": tgArn}))
	if err != nil || st != http.StatusOK {
		return "", false
	}
	var out struct {
		Groups []struct {
			LoadBalancerArns []string `xml:"LoadBalancerArns>member"`
		} `xml:"DescribeTargetGroupsResult>TargetGroups>member"`
	}
	if xml.Unmarshal(body, &out) != nil || len(out.Groups) == 0 {
		return "", false
	}
	if len(out.Groups[0].LoadBalancerArns) == 0 {
		return "", false
	}
	return out.Groups[0].LoadBalancerArns[0], true
}

// hasTLSListener reports whether any listener terminates TLS (HTTPS or TLS).
func hasTLSListener(protocols []string) bool {
	for _, p := range protocols {
		if p == "HTTPS" || p == "TLS" {
			return true
		}
	}
	return false
}

// deleteECS: ownership pre-check, then delete the service (force) and the
// cluster. Reverse of create; each ours-by-tags.
func (d *Driver) deleteECS(capability, environment, providerID string) provider.CreateResult {
	region, name, err := splitECSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	svc, found, rerr := d.describeService(region, name, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if found {
		if !groundholdTagsMatch(svc.tags(), capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "service tags do not match — refusing to delete a resource that is not ours"}
		}
		st, body, err := d.ecsCall(region, "DeleteService",
			jsonBody(map[string]any{"cluster": name, "service": name, "force": true}))
		if err != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete service outcome unknown: %v", err)}
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete service HTTP %d (server error) — reconcile", st)}
		}
		if st >= 400 && !strings.Contains(ecsErr(body), "ServiceNotFound") {
			if r := provider.MutationResult(st, ecsErr(body), nil, providerID, "delete service"); r != nil {
				return *r
			}
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete service: HTTP %d (%s)", st, ecsErr(body))}
		}
		// DeleteService is async — the service DRAINS and its tasks stop over
		// ~30s. Poll until the service is READABLY gone so the cluster delete
		// below does not race a still-draining task (ClusterContainsTasks). A
		// drain that does not complete before the timeout is UNKNOWN (the
		// workload may still be running), never a silent success.
		deadline := d.Now().Add(d.PollTimeout)
		drained := false
		for {
			_, stillThere, r := d.describeService(region, name, name)
			if r == nil && !stillThere { // break ONLY on a readable "gone"
				drained = true
				break
			}
			if d.Now().After(deadline) {
				break
			}
			time.Sleep(d.PollInterval)
		}
		if !drained {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "service still draining at poll timeout — reconcile before cluster delete"}
		}
	}
	// delete the cluster ONLY if it is ours (a same-name FOREIGN/shared cluster
	// must never be deleted). The workload (service) is already retired above, so
	// a cluster we can't prove is ours is simply left standing.
	cTags, cErr := d.clusterTags(region, name)
	if cErr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
			Reason: "workload (service) retired; cluster ownership gave no answer (" +
				cErr.Error() + ") — left standing"}
	}
	if !groundholdTagsMatch(cTags, capability, environment) {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
			Reason: "workload (service) retired; cluster is not ours — left standing"}
	}
	// The SERVICE — the running workload — is the capability's retirement and is
	// already gone; a cluster that still holds FOREIGN tasks is left standing.
	st, body, err := d.ecsCall(region, "DeleteCluster", jsonBody(map[string]any{"cluster": name}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete cluster outcome unknown: %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("cluster delete HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 && !strings.Contains(ecsErr(body), "ClusterNotFound") {
		// our service is confirmed drained (the poll above), so a remaining
		// ClusterContainsTasks/Services is FOREIGN — the workload IS retired;
		// leave the shared cluster standing rather than force it.
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
			Reason: "workload (service) retired; shared cluster left standing: " + ecsErr(body)}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
