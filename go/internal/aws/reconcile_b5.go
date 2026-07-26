// AWS receipt reconciliation, BATCH 5 (D57): the read-only Reconciler for
// ecs, loadbalancer, eks-addon, cloudwatch (alarm) and cloudwatchdash. Each
// concludes a PENDING create receipt by reading live state at the resource's
// DETERMINISTIC identity (TIER 2 — the name is recomputed with the SAME func the
// create used, so the pid is knowable without the lost response). STRICTLY
// READ-ONLY: not one of these issues a mutation. Four-valued honesty via the
// shared concludeByStatus: succeeded ONLY on found+ready+ours; failed on a
// readable absence or a terminal-failed state; unknown on unreadable /
// still-provisioning / found-but-not-ours — never a fabricated verdict.
package aws

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

// reconcileECS concludes a pending Fargate service create. The service (and its
// cluster, which shares the name) live at ECSName(account, ...); the read is
// region-scoped. Ready = the deployment stabilized (runningCount >= desiredCount
// AND a COMPLETED rollout); a FAILED rollout is terminal-failed. Ownership is the
// service's tags.
func (d *Driver) reconcileECS(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("ecs")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "ecs reconcile could not resolve the AWS account: " + err.Error()}
	}
	name := ECSName(account, environment, capability, generation)
	pid := ecsProviderID(region, name)
	svc, found, rerr := d.describeService(region, name, name)
	ours := found && groundholdTagsMatch(svc.tags(), capability, environment)
	ready := svc.RunningCount >= svc.DesiredCount && svc.rolloutComplete()
	failed := svc.rolloutFailed()
	return concludeByStatus(pid, "ecs service "+name, found, rerr, ours, ready, failed)
}

// reconcileLambda concludes a pending capability.function.serverless create — the
// confirmed Acme blocker: a converge/apply KILLED mid-create of a VPC-attached
// Lambda (ENI provisioning routinely exceeds a foreground timeout) stranded a
// pending receipt, and every later apply then STALEd ("in-flight must be reconciled
// first", D29) with resume unable to conclude it (lambda was unwired here). The
// function name is DETERMINISTIC (ECSName — the SAME func createLambda derives it
// from), so reconcile RECOMPUTES it and reads the OBSERVABLE GetFunction state (never
// an operation-by-id path, D273); this works even for the write-ahead receipt that
// predates any persisted id. The create's contract is State=Active AND
// LastUpdateStatus=Successful, so reconcile mirrors it — and mirrors the create's OWN
// bounded poll (waitLambdaActive), because a still-Pending function is the exact case
// that stranded the receipt. Ownership is TAGS. Four-valued, STRICTLY READ-ONLY.
func (d *Driver) reconcileLambda(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("lambda")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "lambda reconcile could not resolve the AWS account: " + err.Error()}
	}
	name := ECSName(account, environment, capability, generation)
	pid := lambdaProviderID(region, account, name)
	what := "lambda function " + name
	// mirror the create poll's bounded LRO window (waitLambdaActive): a VPC-attached
	// function stays Pending while its ENIs provision, so resume polls to a terminal
	// state rather than bouncing straight back to "still provisioning".
	deadline := d.Now().Add(d.PollTimeout)
	for {
		cfg, tags, found, rerr := d.getLambdaFunction(region, name)
		switch {
		case rerr != nil:
			// D306 diagnosable read: getLambdaFunction returns a typed awsReadError
			// that NAMES the HTTP status + Lambda error code — never a bare
			// "unreadable". Keep the deterministic pid so the operator (and a re-run)
			// can find the function.
			return provider.ReconcileResult{Status: "unknown", ProviderID: pid,
				Reason: what + " read gave no answer — cannot conclude the pending create: " + rerr.Error()}
		case !found:
			// a 404 is a readable ABSENCE — the create did not land (never a
			// fabricated success). concludeByStatus renders the exact verdict.
			return concludeByStatus(pid, what, false, nil, false, false, false)
		case !groundholdTagsMatch(tags, capability, environment):
			// found but not ours — refuse to attribute a foreign function (D273).
			return concludeByStatus(pid, what, true, nil, false, false, false)
		case cfg.State == "Failed" || cfg.LastUpdateStatus == "Failed":
			reason := cfg.StateReason
			if cfg.LastUpdateStatus == "Failed" && cfg.LastUpdateStatusReason != "" {
				reason = cfg.LastUpdateStatusReason
			}
			r := concludeByStatus(pid, what, true, nil, true, false, true)
			if reason != "" {
				r.Reason += ": " + reason
			}
			return r
		case cfg.State == "Active" && (cfg.LastUpdateStatus == "Successful" || cfg.LastUpdateStatus == ""):
			// the create SUCCEEDED — conclude WITH the recomputed pid, exactly as
			// concludeByStatus renders a found+ready+owned resource.
			return concludeByStatus(pid, what, true, nil, true, true, false)
		}
		// State=Pending or LastUpdateStatus=InProgress — still provisioning.
		if d.Now().After(deadline) {
			return provider.ReconcileResult{Status: "unknown", ProviderID: pid,
				Reason: what + " is still provisioning at the reconcile deadline — resume again once it settles"}
		}
		d.progress("function provisioning — waiting for Active")
		time.Sleep(d.PollInterval)
	}
}

// reconcileLoadBalancer concludes a pending ALB composite create. The load
// balancer lives at elbCompositeName; State.Code "active" is ready, "provisioning"
// is still-provisioning (unknown), "failed" is terminal-failed. Ownership is the
// load balancer's tags.
func (d *Driver) reconcileLoadBalancer(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("loadbalancer")
	}
	name := elbCompositeName(environment, capability, generation)
	pid := elbv2ProviderID(region, name)
	lb, found, rerr := d.describeLoadBalancer(region, name)
	if rerr != nil || !found {
		return concludeByStatus(pid, "load balancer "+name, found, rerr, false, false, false)
	}
	tags, terr := d.describeTags(region, lb.Arn)
	if terr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "a load balancer exists at our name but its ownership tags are gave no answer — cannot conclude the pending create: " + terr.Error()}
	}
	ours := groundholdTagsMatch(tags, capability, environment)
	ready := lb.State == "active"
	failed := lb.State == "failed"
	return concludeByStatus(pid, "load balancer "+name, true, nil, ours, ready, failed)
}

// reconcileEKSAddon concludes a pending managed-addon create. An addon is a
// sub-resource under a cluster (the cluster is an OPERAND, absent from a create
// receipt), so the identity cannot be recomputed from capability alone: enumerate
// the region's clusters + their addons and match OWNERSHIP TAGS (the bedrock
// pattern). The pid is then the deterministic eks-addon:region:cluster/addon.
// ACTIVE=ready; CREATE_FAILED/DEGRADED=terminal-failed; anything unreadable is
// unknown (it could be ours — never a fabricated absence).
func (d *Driver) reconcileEKSAddon(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("eks-addon")
	}
	const listOp = "ListClusters"
	st, resp, err := d.eksDo("GET", region, "/clusters", nil)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
			"pending addon create: " + readTransport(listOp, err).Error()}
	}
	if st != http.StatusOK {
		return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
			"pending addon create: " + readHTTP(listOp, st, eksErr(resp)).Error()}
	}
	var cl struct {
		Clusters []string `json:"clusters"`
	}
	if json.Unmarshal(resp, &cl) != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
			"pending addon create: " + readBody(listOp, st).Error()}
	}
	for _, cluster := range cl.Clusters {
		const addonsOp = "ListAddons"
		st, resp, err := d.eksDo("GET", region, "/clusters/"+cluster+"/addons", nil)
		if err != nil {
			return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
				"pending addon create: " + readTransport(addonsOp, err).Error()}
		}
		if st != http.StatusOK {
			return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
				"pending addon create: " + readHTTP(addonsOp, st, eksErr(resp)).Error()}
		}
		var al struct {
			Addons []string `json:"addons"`
		}
		if json.Unmarshal(resp, &al) != nil {
			return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
				"pending addon create: " + readBody(addonsOp, st).Error()}
		}
		for _, name := range al.Addons {
			a, found, rerr := d.describeEKSAddon(region, cluster, name)
			if rerr != nil {
				return provider.ReconcileResult{Status: "unknown",
					Reason: "an eks addon read was gave no answer — cannot conclude the pending create: " + rerr.Error()}
			}
			if !found || !groundholdTagsMatch(a.Tags, capability, environment) {
				continue
			}
			pid := eksAddonProviderID(region, cluster, name)
			switch a.Status {
			case "ACTIVE":
				return provider.ReconcileResult{Status: "succeeded", ProviderID: pid}
			case "CREATE_FAILED", "DEGRADED":
				return provider.ReconcileResult{Status: "failed",
					Reason: "eks addon " + name + " reached " + a.Status + " — the create did not land cleanly"}
			default:
				return provider.ReconcileResult{Status: "unknown",
					Reason: "eks addon " + name + " is still " + a.Status + " — resume again once it settles"}
			}
		}
	}
	return provider.ReconcileResult{Status: "failed",
		Reason: "no eks addon carries our ownership tags — the create did not land"}
}

// reconcileCloudWatchAlarm concludes a pending alarm create. PutMetricAlarm is
// SYNCHRONOUS, so found+owned is ready. The alarm lives at alarmName; ownership is
// its tags (ListTagsForResource, keyed by the derivable ARN). Region-scoped.
func (d *Driver) reconcileCloudWatchAlarm(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("cloudwatch")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "cloudwatch reconcile could not resolve the AWS account: " + err.Error()}
	}
	name := alarmName(environment, capability, generation)
	pid := cwAlarmProviderID(region, account, name)
	_, found, rerr := d.describeAlarm(region, name)
	if rerr != nil {
		return concludeByStatus(pid, "cloudwatch alarm "+name, false, rerr, false, false, false)
	}
	if !found {
		return concludeByStatus(pid, "cloudwatch alarm "+name, false, nil, false, false, false)
	}
	tags, terr := d.cwListTags(region, cwAlarmArn(region, account, name))
	if terr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "an alarm exists at our name but its ownership tags are gave no answer — cannot conclude the pending create: " + terr.Error()}
	}
	ours := groundholdTagsMatch(tags, capability, environment)
	// synchronous: an owned alarm is ready the moment it exists.
	return concludeByStatus(pid, "cloudwatch alarm "+name, true, nil, ours, ours, false)
}

// reconcileCWDashboard concludes a pending dashboard create. Dashboards are GLOBAL
// (no region) and untagged, so the deterministic dashboard NAME is the ownership
// handle — a dashboard present at cwDashName is ours by construction. PutDashboard
// is SYNCHRONOUS, so found is ready.
func (d *Driver) reconcileCWDashboard(capability, environment string, generation int) provider.ReconcileResult {
	name := cwDashName(environment, capability, generation)
	pid := cwDashProviderID(name)
	found, rerr := d.rc5DashExists(name)
	// name-only ownership: the deterministic name IS the ownership handle, so
	// found => ours (and, synchronously, ready).
	return concludeByStatus(pid, "cloudwatch dashboard "+name, found, rerr, found, found, false)
}

// rc5DashExists reports whether the named dashboard exists (GetDashboard).
// readable=false on any transport/HTTP/parse failure; a *NotFound is an
// authoritative absence (found=false, readable=true).
func (d *Driver) rc5DashExists(name string) (found bool, err error) {
	st, resp, e := d.cwDashPost(encodeForm(map[string]string{
		"Action": "GetDashboard", "Version": cwDashVersion, "DashboardName": name}))
	if e != nil {
		return false, readTransport("GetDashboard", e)
	}
	if strings.Contains(rdsErrCode(resp), "NotFound") {
		return false, nil
	}
	if st != http.StatusOK {
		return false, readHTTP("GetDashboard", st, rdsErrCode(resp))
	}
	return true, nil
}
