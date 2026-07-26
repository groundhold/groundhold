// AWS receipt reconciliation, BATCH 2 (F19, D57): wires the read-only Reconciler
// for five more services — secretsmanager, cwlogs, cwlogfilter, cloudtrail,
// backupvault. Each is a TIER-2 identity: the create derives a DETERMINISTIC name
// from (environment, capability, generation) [+account for the backup vault], so a
// pending create left by a lost/false-"unknown" response (D29) is concluded by
// RECOMPUTING that same name and reading live state — never a guess, never a
// mutation. The shared helpers (receiptGeneration / regionlessReconcile /
// concludeByStatus / the groundholdTagsMatch ownership gate) are reused verbatim from
// reconcile_aws.go + ecs_net.go — the four-valued honesty is identical everywhere:
// succeeded ONLY when found+ready+ours; a readable absence → failed; an unreadable
// read or a found-but-not-ours → unknown. Ownership mirrors each create's own
// re-check (groundhold tags), except the metric filter, which carries NO tags: its
// deterministic name inside our reserved metric namespace IS the ownership handle
// (see reconcileCWLogFilter).
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// reconcileSecretsManager concludes a pending capability.secret create. A secret is
// SYNCHRONOUS (no async provisioning, no terminal-failed state), so found+owned is
// ready. Ownership mirrors createASM's re-check: groundhold tags on the secret.
func (d *Driver) reconcileSecretsManager(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("secretsmanager")
	}
	name := ASMSecretName(environment, capability, generation)
	pid := asmProviderID(region, name)
	doc, found, rerr := d.describeASM(region, name)
	ours := found && groundholdTagsMatch(doc.tagMap(), capability, environment)
	return concludeByStatus(pid, "secret "+name, found, rerr, ours, found, false)
}

// reconcileCWLogs concludes a pending capability.monitoring.logs create. A log group
// is SYNCHRONOUS (ready the moment it exists), so found+owned is ready. Ownership
// mirrors createCWLogs: groundhold tags read via the group's own ARN (a second call,
// so a tags-unreadable read is itself unknown — never treated as "not ours").
func (d *Driver) reconcileCWLogs(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("cwlogs")
	}
	name := CWLogGroupName(environment, capability, generation)
	pid := cwLogsProviderID(region, name)
	desc, found, rerr := d.describeCWLogGroup(region, name)
	if rerr != nil || !found {
		return concludeByStatus(pid, "log group "+name, found, rerr, false, false, false)
	}
	tags, terr := d.cwlogsTags(region, desc.Arn)
	if terr != nil {
		return concludeByStatus(pid, "log group "+name, true, terr, false, false, false)
	}
	ours := groundholdTagsMatch(tags, capability, environment)
	return concludeByStatus(pid, "log group "+name, true, nil, ours, true, false)
}

// reconcileCloudTrail concludes a pending capability.audit.trail create. found+owned
// is ready: the create's second step (StartLogging) is a best-effort logging posture,
// so a standing owned trail concludes the create (a wrong logging posture is squared
// away by the normal converge loop, not by holding the receipt pending). Ownership
// mirrors createCloudTrail: groundhold tags read via the trail ARN.
func (d *Driver) reconcileCloudTrail(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("cloudtrail")
	}
	name := CloudTrailName(environment, capability, generation)
	pid := cloudTrailProviderID(region, name)
	desc, found, rerr := d.getTrail(region, name)
	if rerr != nil || !found {
		return concludeByStatus(pid, "trail "+name, found, rerr, false, false, false)
	}
	tags, terr := d.trailTags(region, desc.TrailARN)
	if terr != nil {
		return concludeByStatus(pid, "trail "+name, true, terr, false, false, false)
	}
	ours := groundholdTagsMatch(tags, capability, environment)
	return concludeByStatus(pid, "trail "+name, true, nil, ours, true, false)
}

// reconcileBackupVault concludes a pending capability.backup.vault create. The pid
// carries the account (bkv:region:account:name), so the reconcile resolves the
// account before recomputing. A vault is SYNCHRONOUS, so found+owned is ready.
// Ownership mirrors createBackupVault: groundhold tags read via ListTags on the ARN.
func (d *Driver) reconcileBackupVault(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("backupvault")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "backupvault reconcile could not resolve the AWS account: " + err.Error()}
	}
	name := BackupVaultName(environment, capability, generation)
	pid := bkvProviderID(region, account, name)
	_, found, rerr := d.describeBkv(region, name)
	if rerr != nil || !found {
		return concludeByStatus(pid, "backup vault "+name, found, rerr, false, false, false)
	}
	tags, terr := d.bkvTags(region, bkvArn(region, account, name))
	if terr != nil {
		return concludeByStatus(pid, "backup vault "+name, true, terr, false, false, false)
	}
	ours := groundholdTagsMatch(tags, capability, environment)
	return concludeByStatus(pid, "backup vault "+name, true, nil, ours, true, false)
}

// reconcileCWLogFilter concludes a pending capability.monitoring.logmetric create.
// SURPRISE (see the batch note): a metric filter's log group and region are IMPL
// operands (implementation.log_group / implementation.region), NOT derivable from
// (environment, capability, generation), so the providerId is not recomputable
// directly. And a metric filter carries NO tags. So identity + ownership are the
// DETERMINISTIC filter name (logFilterName) inside our reserved metric namespace
// (groundhold/logmetrics): the reconcile discovers the log group by a region-wide
// DescribeMetricFilters on that filter-name prefix, then builds the pid from the live
// logGroupName. A name hit in a foreign namespace is not ours (unknown); a readable,
// complete list with no name match is a create that did not land (failed).
func (d *Driver) reconcileCWLogFilter(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return regionlessReconcile("cwlogfilter")
	}
	filterName := logFilterName(environment, capability, generation)
	body, _ := json.Marshal(map[string]any{"filterNamePrefix": filterName})
	st, resp, err := d.logsCall(region, "DescribeMetricFilters", string(body))
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "DescribeMetricFilters gave no answer — cannot conclude the pending metric-filter create: " + err.Error()}
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return provider.ReconcileResult{Status: "failed",
			Reason: "metric filter " + filterName + " does not exist — the create did not land"}
	}
	if st != http.StatusOK {
		return provider.ReconcileResult{Status: "unknown",
			Reason: fmt.Sprintf("DescribeMetricFilters HTTP %d — cannot conclude the pending metric-filter create", st)}
	}
	var r struct {
		MetricFilters []struct {
			FilterName            string `json:"filterName"`
			LogGroupName          string `json:"logGroupName"`
			MetricTransformations []struct {
				MetricNamespace string `json:"metricNamespace"`
			} `json:"metricTransformations"`
		} `json:"metricFilters"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "DescribeMetricFilters unparseable — cannot conclude the pending metric-filter create"}
	}
	for _, mf := range r.MetricFilters {
		if mf.FilterName != filterName {
			continue // a prefix search may return neighbours — the exact name is the identity
		}
		ours := len(mf.MetricTransformations) > 0 &&
			mf.MetricTransformations[0].MetricNamespace == logMetricNamespace
		if !ours {
			return provider.ReconcileResult{Status: "unknown",
				Reason: "a metric filter named " + filterName + " exists but not in our namespace — cannot conclude the pending create"}
		}
		if !logGroupOK.MatchString(mf.LogGroupName) {
			return provider.ReconcileResult{Status: "unknown",
				Reason: "metric filter " + filterName + " log group is unrepresentable as a providerId — cannot conclude the pending create"}
		}
		return provider.ReconcileResult{Status: "succeeded",
			ProviderID: cwLogFilterProviderID(region, mf.LogGroupName, filterName)}
	}
	return provider.ReconcileResult{Status: "failed",
		Reason: "no metric filter named " + filterName + " exists — the create did not land"}
}
