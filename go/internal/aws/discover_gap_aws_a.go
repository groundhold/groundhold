// D86 stack-coverage gap sweeps (batch A): read-only discovery for services the
// driver already provisions + observes but never swept — so `discover --provider
// aws` sees them in a brownfield estate. Each sweep mirrors discoverECS /
// discoverLoadBalancers exactly: LIST gives the ids, the SAME reverse-map observe
// gives the real attributes (the two-step). A non-200 / transport / parse failure
// returns (nil, nil, error) — never a fabricated empty list; a per-resource observe
// failure is a diagnostic + skip, never an all-unknown record. Strictly read-only.
// D53: no sweep here reads a secret/key value — only existence + posture.
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"groundhold/internal/provider"
)

// discoverACM enumerates ACM certificates in the region as
// capability.certificate.tls. ListCertificates returns ARNs the region + account +
// cert id are parsed from; observeACM reads DescribeCertificate (the private key
// never transits groundhold, D53). Per-cert isolation: one unreadable cert never sinks
// the others.
func (d *Driver) discoverACM(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.acmCall(region, "ListCertificates", "{}")
	if err != nil {
		return nil, nil, fmt.Errorf("acm ListCertificates: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("acm ListCertificates: HTTP %d: %s", st, acmErr(body))
	}
	var r struct {
		Summaries []struct {
			CertificateArn string `json:"CertificateArn"`
		} `json:"CertificateSummaryList"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("acm ListCertificates", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, s := range r.Summaries {
		// arn:aws:acm:region:account:certificate/<uuid>
		parts := strings.Split(s.CertificateArn, ":")
		certID := acmCertIDFromARN(s.CertificateArn)
		if len(parts) != 6 || parts[2] != "acm" || certID == "" {
			diags = append(diags, s.CertificateArn+": not an acm certificate arn")
			continue
		}
		pid := acmProviderID(parts[3], parts[4], certID)
		obs, odiags, oerr := d.observeACM("", pid)
		if oerr != nil {
			diags = append(diags, certID+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, certID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.certificate.tls",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverAPIGateway enumerates HTTP/WebSocket APIs in the region as
// capability.apigateway.http. GET /v2/apis (region-scoped) returns ApiIds; the
// account (for the pid) is resolved once via STS. observeApiGWv2 reverse-maps each.
func (d *Driver) discoverAPIGateway(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("apigateway: %v", err)
	}
	st, body, err := d.apigwDo("GET", region, apigwPath, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("apigateway GetApis: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("apigateway GetApis: HTTP %d: %s", st, apigwErr(body))
	}
	// restJson1 camelCase wire names (D878): a PascalCase Items/ApiId parses every
	// entry to an empty ApiId, and the loop below skips them — discovery would report
	// ZERO apis on a real account that has them, the dangerous false-absence direction.
	var r struct {
		Items []struct {
			ApiId string `json:"apiId"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("apigateway GetApis", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, api := range r.Items {
		if api.ApiId == "" {
			continue
		}
		pid := apigwProviderID(region, account, api.ApiId)
		obs, odiags, oerr := d.observeApiGWv2("", pid)
		if oerr != nil {
			diags = append(diags, api.ApiId+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, api.ApiId+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.apigateway.http",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverBackupVaults enumerates AWS Backup vaults in the region as
// capability.backup.vault. GET /backup-vaults (region-scoped) returns names; the
// account (for the pid) is resolved once via STS. observeBackupVault reverse-maps
// each. A vault whose name is not representable as bkv:region:account:name (fails
// the pid validation inside observe) becomes a diagnostic, never a fabricated record.
func (d *Driver) discoverBackupVaults(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("backup: %v", err)
	}
	st, body, err := d.backupCall("GET", region, "/backup-vaults", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("backup ListBackupVaults: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("backup ListBackupVaults: HTTP %d: %s", st, ecsErr(body))
	}
	var r struct {
		BackupVaultList []struct {
			BackupVaultName string `json:"BackupVaultName"`
		} `json:"BackupVaultList"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("backup ListBackupVaults", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, v := range r.BackupVaultList {
		if v.BackupVaultName == "" {
			continue
		}
		pid := bkvProviderID(region, account, v.BackupVaultName)
		obs, odiags, oerr := d.observeBackupVault("", pid)
		if oerr != nil {
			diags = append(diags, v.BackupVaultName+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, v.BackupVaultName+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.backup.vault",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverCloudFront enumerates distributions as capability.cdn.distribution.
// CloudFront is GLOBAL (signed us-east-1), so `region` is ignored for the endpoint;
// ListDistributions returns distribution ids, the account (for the pid) is resolved
// once via STS, and observeCloudFront reverse-maps each.
func (d *Driver) discoverCloudFront(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("cloudfront: %v", err)
	}
	st, body, _, err := d.cfDo("GET", cloudFrontPath+"/distribution", "")
	if err != nil {
		return nil, nil, fmt.Errorf("cloudfront ListDistributions: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("cloudfront ListDistributions: HTTP %d: %s", st, cfErrCode(body))
	}
	// the response root element is <DistributionList>.
	var r struct {
		Summaries []struct {
			Id string `xml:"Id"`
		} `xml:"Items>DistributionSummary"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("cloudfront ListDistributions: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, s := range r.Summaries {
		if s.Id == "" {
			continue
		}
		pid := cfProviderID(account, s.Id)
		obs, odiags, oerr := d.observeCloudFront("", pid)
		if oerr != nil {
			diags = append(diags, s.Id+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, s.Id+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.cdn.distribution",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverCloudWatchDashboards enumerates dashboards as
// capability.monitoring.dashboard. CloudWatch dashboards are GLOBAL (signed
// us-east-1), so `region` is ignored for the endpoint; ListDashboards returns names
// and observeCWDashboard reverse-maps each (GetDashboard -> the metric set).
func (d *Driver) discoverCloudWatchDashboards(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.cwDashPost(encodeForm(map[string]string{
		"Action": "ListDashboards", "Version": cwDashVersion}))
	if err != nil {
		return nil, nil, fmt.Errorf("cloudwatch ListDashboards: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("cloudwatch ListDashboards: HTTP %d: %s", st, rdsErrCode(body))
	}
	var r struct {
		Names []string `xml:"ListDashboardsResult>DashboardEntries>member>DashboardName"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("cloudwatch ListDashboards: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, name := range r.Names {
		if name == "" {
			continue
		}
		pid := cwDashProviderID(name)
		obs, odiags, oerr := d.observeCWDashboard("", pid)
		if oerr != nil {
			diags = append(diags, name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.monitoring.dashboard",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverCustomPolicies enumerates customer-managed IAM policies as
// capability.authorization.role. IAM is GLOBAL (signed us-east-1); ListPolicies with
// Scope=Local returns ONLY customer-managed policy ARNs (AWS-managed policies are not
// this capability), and observeCustomPolicy reverse-maps each (the flat action set).
func (d *Driver) discoverCustomPolicies(region string) ([]provider.Discovered, []string, error) {
	// D809: FOLLOW the pages. ListPolicies answers 100 at a time and says so with
	// IsTruncated + Marker; reading the first page and stopping made an account with 140
	// customer policies look like an account with 100 — and every policy past the
	// hundredth invisible to a verb whose whole job is to show what is there.
	var r struct {
		Arns        []string `xml:"ListPoliciesResult>Policies>member>Arn"`
		IsTruncated bool     `xml:"ListPoliciesResult>IsTruncated"`
		Marker      string   `xml:"ListPoliciesResult>Marker"`
	}
	var arns []string
	marker := ""
	for {
		form := map[string]string{
			"Action": "ListPolicies", "Version": iamVersion, "Scope": "Local"}
		if marker != "" {
			form["Marker"] = marker
		}
		st, body, err := d.iamPost(encodeForm(form))
		if err != nil {
			return nil, nil, fmt.Errorf("iam ListPolicies: %v", err)
		}
		if st != http.StatusOK {
			return nil, nil, fmt.Errorf("iam ListPolicies: HTTP %d: %s", st, rdsErrCode(body))
		}
		r.Arns = nil
		r.IsTruncated = false
		r.Marker = ""
		if err := xml.Unmarshal(body, &r); err != nil {
			return nil, nil, fmt.Errorf("iam ListPolicies: %w", err)
		}
		arns = append(arns, r.Arns...)
		if !r.IsTruncated || r.Marker == "" {
			break
		}
		marker = r.Marker
	}
	r.Arns = arns
	var out []provider.Discovered
	var diags []string
	for _, arn := range r.Arns {
		if arn == "" {
			continue
		}
		pid := customPolicyProviderID(arn)
		obs, odiags, oerr := d.observeCustomPolicy("", pid)
		if oerr != nil {
			diags = append(diags, arn+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, arn+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.authorization.role",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverEFS enumerates EFS file systems in the region as
// capability.storage.filesystem. DescribeFileSystems (region-scoped) returns ids;
// the account (for the pid) is resolved once via STS. observeEFS reverse-maps each.
func (d *Driver) discoverEFS(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("efs: %v", err)
	}
	// D817: FOLLOW the pages. DescribeFileSystems answers TEN file systems at a time by
	// default — the smallest default page in the AWS surface this driver touches — and
	// hands back a NextMarker (botocore efs/2015-02-01: input Marker, output NextMarker).
	type efsFS struct {
		FileSystemId string `json:"FileSystemId"`
	}
	var fileSystems []efsFS
	marker := ""
	for page := 0; ; page++ {
		if page >= maxAWSListPages {
			return nil, nil, fmt.Errorf("efs DescribeFileSystems: more than %d pages", maxAWSListPages)
		}
		path := efsPath + "/file-systems"
		if marker != "" {
			path += "?Marker=" + url.QueryEscape(marker)
		}
		st, body, err := d.efsDo("GET", region, path, "")
		if err != nil {
			return nil, nil, fmt.Errorf("efs DescribeFileSystems: %v", err)
		}
		if st != http.StatusOK {
			return nil, nil, fmt.Errorf("efs DescribeFileSystems: HTTP %d: %s", st, efsErr(body))
		}
		var r struct {
			FileSystems []efsFS `json:"FileSystems"`
			NextMarker  string  `json:"NextMarker"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, nil, readBody("efs DescribeFileSystems", st)
		}
		fileSystems = append(fileSystems, r.FileSystems...)
		if r.NextMarker == "" {
			break
		}
		marker = r.NextMarker
	}
	var out []provider.Discovered
	var diags []string
	for _, fs := range fileSystems {
		if fs.FileSystemId == "" {
			continue
		}
		pid := efsProviderID(region, account, fs.FileSystemId)
		obs, odiags, oerr := d.observeEFS("", pid)
		if oerr != nil {
			diags = append(diags, fs.FileSystemId+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, fs.FileSystemId+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.storage.filesystem",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverEventBridgeSchedulers enumerates EventBridge Scheduler schedules in the
// region as capability.scheduler.cron. ListSchedules (region-scoped) returns names;
// observeEventBridgeScheduler reverse-maps each (GetSchedule -> the enabled state).
func (d *Driver) discoverEventBridgeSchedulers(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.ebsCall("GET", region, "/schedules", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("scheduler ListSchedules: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("scheduler ListSchedules: HTTP %d: %s", st, ecsErr(body))
	}
	var r struct {
		Schedules []struct {
			Name string `json:"Name"`
		} `json:"Schedules"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("scheduler ListSchedules", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, s := range r.Schedules {
		if s.Name == "" {
			continue
		}
		pid := ebsProviderID(region, s.Name)
		obs, odiags, oerr := d.observeEventBridgeScheduler("", pid)
		if oerr != nil {
			diags = append(diags, s.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, s.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.scheduler.cron",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// discoverKinesis enumerates Kinesis data streams in the region as
// capability.streaming.pipe. ListStreams (region-scoped) returns names; the account
// (for the pid) is resolved once via STS. observeKinesis reverse-maps each
// (DescribeStreamSummary -> retention + encryption posture).
func (d *Driver) discoverKinesis(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("kinesis: %v", err)
	}
	// D818: FOLLOW the pages. ListStreams says HasMoreStreams and hands back a NextToken
	// (botocore kinesis/2013-12-02). The legacy shape has no token and restarts from
	// ExclusiveStartStreamName; both are sent, so an older endpoint pages too.
	var streams []string
	token, lastName := "", ""
	for page := 0; ; page++ {
		if page >= maxAWSListPages {
			return nil, nil, fmt.Errorf("kinesis ListStreams: more than %d pages", maxAWSListPages)
		}
		req := "{}"
		if token != "" || lastName != "" {
			b, _ := json.Marshal(struct {
				NextToken                string `json:"NextToken,omitempty"`
				ExclusiveStartStreamName string `json:"ExclusiveStartStreamName,omitempty"`
			}{token, lastName})
			req = string(b)
		}
		st, body, err := d.kinesisCall(region, "ListStreams", req)
		if err != nil {
			return nil, nil, fmt.Errorf("kinesis ListStreams: %v", err)
		}
		if st != http.StatusOK {
			return nil, nil, fmt.Errorf("kinesis ListStreams: HTTP %d: %s", st, ecsErr(body))
		}
		var r struct {
			StreamNames    []string `json:"StreamNames"`
			HasMoreStreams bool     `json:"HasMoreStreams"`
			NextToken      string   `json:"NextToken"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, nil, readBody("kinesis ListStreams", st)
		}
		streams = append(streams, r.StreamNames...)
		if !r.HasMoreStreams || len(r.StreamNames) == 0 {
			break
		}
		token = r.NextToken
		lastName = r.StreamNames[len(r.StreamNames)-1]
	}
	var out []provider.Discovered
	var diags []string
	for _, name := range streams {
		if name == "" {
			continue
		}
		pid := kinesisProviderID(region, account, name)
		obs, odiags, oerr := d.observeKinesis("", pid)
		if oerr != nil {
			diags = append(diags, name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.streaming.pipe",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
