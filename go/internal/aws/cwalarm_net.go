// CloudWatch alarm network shell (D106): the SigV4-signed (regional) half of the AWS
// capability.monitoring.alert driver. The alarm name is deterministic and its ARN is
// derivable from (region, account, name), so the pid is knowable before the response
// (D29). PutMetricAlarm is an upsert, so an ownership pre-read (DescribeAlarms +
// ListTagsForResource) refuses to overwrite a foreign alarm at our name. Ownership is
// tags (applied at create). observe reverse-maps the single alarm condition.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"groundhold/internal/provider"
)

const cwVersion = "2010-08-01"

func (d *Driver) cwBase(region string) string {
	if d.CloudWatchBaseURL != "" {
		return d.CloudWatchBaseURL
	}
	return "https://monitoring." + region + ".amazonaws.com"
}

func (d *Driver) cwPost(region, body string) (int, []byte, error) {
	return d.doSigned("POST", d.cwBase(region)+"/", "monitoring", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

func cwAlarmArn(region, account, name string) string {
	return "arn:aws:cloudwatch:" + region + ":" + account + ":alarm:" + name
}

func cwAlarmProviderID(region, account, name string) string {
	return "awsalert:" + region + ":" + account + ":" + name
}

func splitCWAlarmProviderID(providerID string) (region, account, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "awsalert" {
		return "", "", "", fmt.Errorf("providerId %q is not awsalert:region:account:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !alarmNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId alarm name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

type cwMetricAlarm struct {
	Namespace          string   `xml:"Namespace"`
	MetricName         string   `xml:"MetricName"`
	Threshold          string   `xml:"Threshold"`
	ComparisonOperator string   `xml:"ComparisonOperator"`
	AlarmActions       []string `xml:"AlarmActions>member"`
}

// describeAlarm reads one alarm. found=false + readable=true is "does not exist".
func (d *Driver) describeAlarm(region, name string) (cwMetricAlarm, bool, error) {
	const op = "DescribeAlarms"
	st, resp, err := d.cwPost(region, encodeForm(map[string]string{
		"Action": "DescribeAlarms", "Version": cwVersion, "AlarmNames.member.1": name}))
	if err != nil || st != http.StatusOK {
		return cwMetricAlarm{}, false, readTransport(op, err)
	}
	var r struct {
		Alarms []cwMetricAlarm `xml:"DescribeAlarmsResult>MetricAlarms>member"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return cwMetricAlarm{}, false, readBody(op, st)
	}
	if len(r.Alarms) == 0 {
		return cwMetricAlarm{}, false, nil
	}
	return r.Alarms[0], true, nil
}

func (d *Driver) cwListTags(region, arn string) (map[string]string, error) {
	const op = "ListTagsForResource"
	st, resp, err := d.cwPost(region, encodeForm(map[string]string{
		"Action": "ListTagsForResource", "Version": cwVersion, "ResourceARN": arn}))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, rdsErrCode(resp))
	}
	var r struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"ListTagsForResourceResult>Tags>member"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range r.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

func (d *Driver) createCloudWatchAlarm(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCloudWatchAlarm(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := cwAlarmArn(region, account, plan.AlarmName)
	pid := cwAlarmProviderID(region, account, plan.AlarmName)
	// ownership pre-read: PutMetricAlarm is an upsert, so refuse to overwrite a
	// foreign alarm at our (deterministic) name.
	if _, found, rerr := d.describeAlarm(region, plan.AlarmName); rerr == nil && found {
		tags, terr := d.cwListTags(region, arn)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "an alarm with this name exists; ownership tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			if tags["groundhold-capability"] == "" {
				return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "an untagged alarm with this name exists — adopt it explicitly; refusing to overwrite"}
			}
			return provider.CreateResult{Status: "failed", Reason: "an alarm with this name exists tagged for a different groundhold capability — refusing"}
		}
	}
	form := map[string]string{
		"Action": "PutMetricAlarm", "Version": cwVersion,
		"AlarmName":           plan.AlarmName,
		"Namespace":           plan.Namespace,
		"MetricName":          plan.MetricName,
		"Statistic":           "Average",
		"Period":              "300",
		"EvaluationPeriods":   "1",
		"Threshold":           strconv.FormatFloat(plan.Threshold, 'f', -1, 64),
		"ComparisonOperator":  plan.ComparisonOperator,
		"ActionsEnabled":      "true",
		"Tags.member.1.Key":   "groundhold-capability",
		"Tags.member.1.Value": sanitizeTag(capability),
		"Tags.member.2.Key":   "groundhold-environment",
		"Tags.member.2.Value": sanitizeTag(environment),
	}
	if plan.Notify {
		form["AlarmActions.member.1"] = plan.TopicArn
	}
	st, resp, e := d.cwPost(region, encodeForm(form))
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("PutMetricAlarm outcome unknown: %v", e)}
	}
	if st == http.StatusOK {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("PutMetricAlarm HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	}
	if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "create"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("PutMetricAlarm HTTP %d (%s): %s", st, rdsErrCode(resp), mutDetail(resp))}
}

func (d *Driver) observeCloudWatchAlarm(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, name, err := splitCWAlarmProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	alarm, found, rerr := d.describeAlarm(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"alarm not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "alert.metric", Value: alarm.Namespace + "/" + alarm.MetricName, Derivation: "measured"},
		{Path: "alert.notify", Value: len(alarm.AlarmActions) > 0, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if f, err := strconv.ParseFloat(alarm.Threshold, 64); err == nil {
		obs = append(obs, provider.Observation{Path: "alert.threshold", Value: f, Derivation: "measured"})
	}
	switch alarm.ComparisonOperator {
	case "GreaterThanThreshold":
		obs = append(obs, provider.Observation{Path: "alert.comparison", Value: "greater-than", Derivation: "measured"})
	case "LessThanThreshold":
		obs = append(obs, provider.Observation{Path: "alert.comparison", Value: "less-than", Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteCloudWatchAlarm(capability, environment, providerID string) provider.CreateResult {
	region, account, name, err := splitCWAlarmProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := cwAlarmArn(region, account, name)
	_, found, rerr := d.describeAlarm(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.cwListTags(region, arn)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed", Reason: "alarm tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.cwPost(region, encodeForm(map[string]string{
		"Action": "DeleteAlarms", "Version": cwVersion, "AlarmNames.member.1": name}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "delete"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, rdsErrCode(resp))}
}
