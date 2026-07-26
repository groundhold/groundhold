package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"groundhold/internal/provider"
)

// List enumerates existing resources in the region as vocabulary
// capabilities — the aws half of the D52 brownfield path (discover ->
// adopt). Strictly read-only. It sweeps each supported service
// independently: a service the identity cannot list (or that errors)
// becomes a diagnostic, never a hard failure of the whole discovery, so a
// missing permission on one service never hides another's resources.
func (d *Driver) List(region string) ([]provider.Discovered, []string, error) {
	if region == "" {
		return nil, nil, fmt.Errorf("aws discovery requires a region")
	}
	var out []provider.Discovered
	var diags []string
	reg := d.serviceDiscoverers()
	for _, tok := range d.DiscoverableServices() { // sorted, deterministic
		found, ds, err := reg[tok](region)
		if err != nil {
			diags = append(diags, err.Error())
			continue
		}
		out = append(out, found...)
		diags = append(diags, ds...)
	}
	return out, diags, nil
}

// serviceDiscoverers maps each SERVICE token (the D76 dispatch key) to its
// read-only sweep. List iterates it; TestCertifyAWSDriver asserts via
// provider.CertifyDiscoverability that every certified service is either a key
// here or a declared non-listable exemption — so no Observe can ship without
// becoming discoverable (spec/drivers.md §2). Adding a service = adding a key.
func (d *Driver) serviceDiscoverers() map[string]func(string) ([]provider.Discovered, []string, error) {
	return map[string]func(string) ([]provider.Discovered, []string, error){
		// original D86 stack coverage
		"s3": d.discoverS3, "rds": d.discoverRDS, "dynamodb": d.discoverDynamoDB,
		"elasticache": d.discoverElastiCache, "elasticache-serverless": d.discoverElastiCacheServerless,
		"sns": d.discoverSNS, "sqs": d.discoverSQS,
		"ecs": d.discoverECS, "apprunner": d.discoverAppRunner, "vpc": d.discoverVPC, "iam": d.discoverIAM,
		"secretsmanager": d.discoverSecrets, "cloudwatch": d.discoverCloudWatch,
		"ecr": d.discoverECR, "loadbalancer": d.discoverLoadBalancers,
		"eks":             d.discoverEKS,            // D147 cluster substrate (observe/discover; provisioning slice 2)
		"ses-sending":     d.discoverSESSending,     // D148 outbound email (SESv2)
		"ses-inbound":     d.discoverSESInbound,     // inbound email (SES receiving, deal mailbox)
		"eks-addon":       d.discoverEKSAddon,       // D149 managed EKS addon
		"eks-podidentity": d.discoverEKSPodIdentity, // D149 pod identity association
		"aurora":          d.discoverAurora,         // D152 Aurora PostgreSQL Serverless v2
		"bedrock":         d.discoverBedrock,        // D150 Bedrock inference profile
		"budgets":         d.discoverBudgets,        // D151 cost budget
		"cloudtrail":      d.discoverCloudTrail,     // audit trail (CloudTrail)
		"backupplan":      d.discoverBackupPlans,    // D153 backup plan (DR-policy over the vault)
		"guardduty":       d.discoverGuardDuty,      // threat-detection posture (GuardDuty)
		"cwlogs":          d.discoverCWLogs,         // log group + retention (capability.monitoring.logs)
		// discoverability backfill — every observed service is now listable
		"acm": d.discoverACM, "apigateway": d.discoverAPIGateway,
		"backupvault": d.discoverBackupVaults, "cloudfront": d.discoverCloudFront,
		"cloudwatchdash": d.discoverCloudWatchDashboards, "custompolicy": d.discoverCustomPolicies,
		"ec2": d.discoverEC2Instances, "efs": d.discoverEFS, "eventbridgescheduler": d.discoverEventBridgeSchedulers,
		"kinesis": d.discoverKinesis, "kms": d.discoverKMS, "msk": d.discoverMSK,
		"opensearch": d.discoverOpenSearch, "opensearch-serverless": d.discoverOpenSearchServerless,
		"redshiftserverless": d.discoverRedshiftServerless,
		"route53":            d.discoverRoute53, "route53health": d.discoverRoute53Health,
		"vpngateway": d.discoverVpnGateway, "waf": d.discoverWAF,
		"lambda": d.discoverLambda, // capability.function.serverless (scale-to-zero)
	}
}

// DiscoverableServices reports the tokens serviceDiscoverers covers (sorted), so
// the discoverability gate proves coverage rather than trusting it.
func (d *Driver) DiscoverableServices() []string {
	reg := d.serviceDiscoverers()
	out := make([]string, 0, len(reg))
	for tok := range reg {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// NonListableServices names the certified services that are NOT standalone
// listable resources, each with a categorical reason from the closed set — the
// only sanctioned exemption from the discoverability gate.
func (d *Driver) NonListableServices() map[string]string {
	return map[string]string{
		"changefeed":    "provisioned-feed", // the EventBridge feed groundhold PROVISIONS, not a resource it lists
		"rolepolicy":    "sub-resource",     // a role<->policy attachment, enumerated under its role
		"cwlogfilter":   "sub-resource",     // a metric filter on a log group, enumerated under it
		"route53record": "sub-resource",     // a record set, enumerated only under its parent hosted zone
	}
}

// s3ServiceBase is the service-level (no bucket) S3 endpoint for ListBuckets.
func (d *Driver) s3ServiceBase(region string) string {
	if d.S3BaseURL != "" {
		return d.S3BaseURL
	}
	return "https://s3." + region + ".amazonaws.com"
}

// discoverS3 enumerates buckets in the region as capability.storage.object:
// ListBuckets, then GetBucketLocation to keep only in-region buckets, then
// the SAME reverse map observe uses.
func (d *Driver) discoverS3(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.doSigned("GET", d.s3ServiceBase(region)+"/", "s3", region, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("s3 ListBuckets: HTTP %d: %s", st, awsErrCode(body))
	}
	var lb struct {
		Buckets struct {
			Bucket []struct {
				Name string `xml:"Name"`
			} `xml:"Bucket"`
		} `xml:"Buckets"`
	}
	if err := xml.Unmarshal(body, &lb); err != nil {
		return nil, nil, fmt.Errorf("s3 ListBuckets: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, b := range lb.Buckets.Bucket {
		loc, ok, err := d.s3BucketRegion(region, b.Name)
		if err != nil {
			diags = append(diags, b.Name+": location gave no answer: "+err.Error())
			continue
		}
		if !ok || loc != region {
			continue // lives in another region — not this sweep
		}
		pid := s3ProviderID(region, b.Name)
		obs, odiags, err := d.observeS3("", pid)
		if err != nil {
			diags = append(diags, b.Name+": observe: "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, b.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.storage.object",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// s3BucketRegion resolves a bucket's region via GetBucketLocation signed at
// signRegion. A cross-region bucket answers with a non-200 (the endpoint is
// wrong for it); that is "not here", not an error.
func (d *Driver) s3BucketRegion(signRegion, bucket string) (region string, ok bool, err error) {
	st, body, err := d.s3Do("GET", signRegion, bucket, "/?location", "")
	if err != nil {
		return "", false, err
	}
	if st != http.StatusOK {
		return "", false, nil
	}
	var lc struct {
		Value string `xml:",chardata"`
	}
	_ = xml.Unmarshal(body, &lc)
	switch lc.Value {
	case "":
		return "us-east-1", true, nil // legacy: empty constraint means us-east-1
	case "EU":
		return "eu-west-1", true, nil
	default:
		return lc.Value, true, nil
	}
}

// discoverRDS enumerates DB instances in the region as
// capability.database.relational. DescribeDBInstances is region-scoped, so
// every instance it returns is in this region.
func (d *Driver) discoverRDS(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.rdsPost(region, rdsSimpleBody("DescribeDBInstances", nil))
	if err != nil {
		return nil, nil, fmt.Errorf("rds DescribeDBInstances: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("rds DescribeDBInstances: HTTP %d: %s", st, awsErrCode(body))
	}
	var r struct {
		Instances []struct {
			Identifier string `xml:"DBInstanceIdentifier"`
		} `xml:"DescribeDBInstancesResult>DBInstances>DBInstance"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("rds DescribeDBInstances: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, inst := range r.Instances {
		if inst.Identifier == "" {
			continue
		}
		pid := rdsProviderID(region, inst.Identifier)
		obs, odiags, err := d.observeRDS("", pid)
		if err != nil {
			diags = append(diags, inst.Identifier+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, inst.Identifier+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.database.relational",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverDynamoDB enumerates tables in the region as
// capability.database.nosql. The providerId pins the account (ListTables is
// account+region scoped), resolved once via STS.
func (d *Driver) discoverDynamoDB(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("dynamodb: %v", err)
	}
	st, body, err := d.dynamoCall(region, "ListTables", "{}")
	if err != nil {
		return nil, nil, fmt.Errorf("dynamodb ListTables: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("dynamodb ListTables: HTTP %d", st)
	}
	var r struct {
		TableNames []string `json:"TableNames"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("ListTables", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, tbl := range r.TableNames {
		pid := dynamoProviderID(region, account, tbl)
		obs, odiags, err := d.observeDynamoDB("", pid)
		if err != nil {
			diags = append(diags, tbl+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, tbl+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.database.nosql",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverElastiCache enumerates Redis replication groups in the region as
// capability.cache.keyvalue. DescribeReplicationGroups is region-scoped;
// the account (for the providerId) is resolved once via STS.
func (d *Driver) discoverElastiCache(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("elasticache: %v", err)
	}
	st, body, err := d.ecachePost(region, encodeForm(map[string]string{
		"Action": "DescribeReplicationGroups", "Version": elastiCacheVersion}))
	if err != nil {
		return nil, nil, fmt.Errorf("elasticache DescribeReplicationGroups: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("elasticache DescribeReplicationGroups: HTTP %d: %s", st, rdsErrCode(body))
	}
	var r struct {
		Groups []struct {
			ID string `xml:"ReplicationGroupId"`
		} `xml:"DescribeReplicationGroupsResult>ReplicationGroups>ReplicationGroup"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("elasticache DescribeReplicationGroups: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, g := range r.Groups {
		if g.ID == "" {
			continue
		}
		pid := ecacheProviderID(region, account, g.ID)
		obs, odiags, err := d.observeElastiCache("", pid)
		if err != nil {
			diags = append(diags, g.ID+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, g.ID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.cache.keyvalue",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverSNS enumerates SNS topics in the region as
// capability.messaging.topic. ListTopics returns ARNs the providerId is
// parsed from directly (region+account+name).
func (d *Driver) discoverSNS(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.snsPost(region, encodeForm(map[string]string{
		"Action": "ListTopics", "Version": snsVersion}))
	if err != nil {
		return nil, nil, fmt.Errorf("sns ListTopics: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("sns ListTopics: HTTP %d", st)
	}
	var r struct {
		Arns []string `xml:"ListTopicsResult>Topics>member>TopicArn"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("sns ListTopics: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, arn := range r.Arns {
		// arn:aws:sns:region:account:name
		parts := strings.Split(arn, ":")
		if len(parts) != 6 || parts[2] != "sns" {
			diags = append(diags, arn+": not an sns topic arn")
			continue
		}
		pid := snsProviderID(parts[3], parts[4], parts[5])
		obs, odiags, err := d.observeSNS("", pid)
		if err != nil {
			diags = append(diags, parts[5]+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, parts[5]+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.messaging.topic",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverSQS enumerates SQS queues in the region as
// capability.messaging.queue. ListQueues returns URLs the account and name
// are parsed from (.../<account>/<name>).
func (d *Driver) discoverSQS(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.sqsPost(region, encodeForm(map[string]string{
		"Action": "ListQueues", "Version": sqsVersion}))
	if err != nil {
		return nil, nil, fmt.Errorf("sqs ListQueues: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("sqs ListQueues: HTTP %d", st)
	}
	var r struct {
		URLs []string `xml:"ListQueuesResult>QueueUrl"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("sqs ListQueues: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, u := range r.URLs {
		// https://sqs.<region>.amazonaws.com/<account>/<name>
		seg := strings.Split(u, "/")
		if len(seg) < 2 {
			diags = append(diags, u+": not a queue url")
			continue
		}
		account, name := seg[len(seg)-2], seg[len(seg)-1]
		pid := sqsProviderID(region, account, name)
		obs, odiags, err := d.observeSQS("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.messaging.queue",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverLoadBalancers enumerates Application/Network Load Balancers in the
// region as capability.network.loadbalancer. DescribeLoadBalancers (region-scoped)
// -> per-LB DescribeListeners -> the SAME reverse map observe uses, mirroring
// discoverECS's two-step. This is the sweep that makes the vendor-broker's
// public ALB visible — it had no driver and so was invisible to groundhold. Per-LB
// isolation: one LB's unreadable listener list never sinks the others.
func (d *Driver) discoverLoadBalancers(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.elbv2Post(region, encodeForm(map[string]string{
		"Action": "DescribeLoadBalancers", "Version": elbv2Version}))
	if err != nil {
		return nil, nil, fmt.Errorf("elbv2 DescribeLoadBalancers: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("elbv2 DescribeLoadBalancers: HTTP %d: %s", st, rdsErrCode(body))
	}
	var r struct {
		LBs []elbv2LB `xml:"DescribeLoadBalancersResult>LoadBalancers>member"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("elbv2 DescribeLoadBalancers: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, lb := range r.LBs {
		if lb.Name == "" {
			continue
		}
		// the encryption posture needs the listeners; an unreadable list is a
		// diagnostic (skip), never a fabricated inTransit=false.
		protocols, lerr := d.listenerProtocols(region, lb.Arn)
		if lerr != nil {
			diags = append(diags, lb.Name+": "+lerr.Error()+" — skipped (cannot determine encryption.inTransit)")
			continue
		}
		out = append(out, provider.Discovered{
			ProviderID:   elbv2ProviderID(region, lb.Name),
			ResourceType: "capability.network.loadbalancer",
			Observations: reverseMapLoadBalancer(lb.Scheme, protocols),
		})
	}
	return out, diags, nil
}

// discoverAccount resolves and caches the acting account id via STS —
// shared by the sweeps whose providerId pins the account but whose list
// call does not return it.
func (d *Driver) discoverAccount() (string, error) {
	if d.Account != "" {
		return d.Account, nil
	}
	acct, _, err := d.CallerIdentity()
	if err != nil {
		return "", fmt.Errorf("resolve account: %v", err)
	}
	d.Account = acct
	return acct, nil
}

// arnLastSegment returns the final "/"-delimited segment of an ARN's resource
// part (…:service/<a>/<b> -> b) — the cluster/service name in an ECS ARN.
func arnLastSegment(arn string) string {
	i := strings.LastIndex(arn, "/")
	if i < 0 {
		return ""
	}
	return arn[i+1:]
}

// discoverECS enumerates Fargate services in the region as
// capability.workload.container. ListClusters -> ListServices per cluster ->
// the SAME reverse map observe uses. observeECS addresses a service by a single
// name used as BOTH cluster and service (ecs:region:name), which is exactly how
// groundhold creates them; a foreign service whose cluster and service names differ
// is not representable by that id, so it becomes a diagnostic, never a
// fabricated/empty resource.
func (d *Driver) discoverECS(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.ecsCall(region, "ListClusters", "{}")
	if err != nil {
		return nil, nil, fmt.Errorf("ecs ListClusters: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("ecs ListClusters: HTTP %d: %s", st, ecsErr(body))
	}
	var lc struct {
		ClusterArns []string `json:"clusterArns"`
	}
	if err := json.Unmarshal(body, &lc); err != nil {
		return nil, nil, readBody("ecs ListClusters", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, cArn := range lc.ClusterArns {
		cluster := arnLastSegment(cArn)
		if cluster == "" {
			diags = append(diags, cArn+": not a cluster arn")
			continue
		}
		// per-cluster isolation: one cluster's unreadable service list does not
		// sink the others in this region.
		sst, sbody, serr := d.ecsCall(region, "ListServices", jsonBody(map[string]any{"cluster": cluster}))
		if serr != nil {
			diags = append(diags, cluster+": "+readTransport("ListServices", serr).Error())
			continue
		}
		if sst != http.StatusOK {
			diags = append(diags, cluster+": "+readHTTP("ListServices", sst, ecsErr(sbody)).Error())
			continue
		}
		var ls struct {
			ServiceArns []string `json:"serviceArns"`
		}
		if json.Unmarshal(sbody, &ls) != nil {
			diags = append(diags, cluster+": ListServices unparseable")
			continue
		}
		for _, sArn := range ls.ServiceArns {
			svc := arnLastSegment(sArn)
			if svc == "" {
				continue
			}
			if svc != cluster {
				diags = append(diags, fmt.Sprintf(
					"%s: service in cluster %s is not representable as ecs:region:name (cluster and service names differ) — needs adoption by explicit id", svc, cluster))
				continue
			}
			pid := ecsProviderID(region, svc)
			obs, odiags, oerr := d.observeECS("", pid)
			if oerr != nil {
				diags = append(diags, svc+": "+oerr.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, svc+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.workload.container",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}

// discoverVPC enumerates VPCs in the region as capability.network.private.
// DescribeVpcs is region-scoped; the default VPC is surfaced too (brownfield is
// honest about what exists). Each is reverse-mapped by the SAME observe.
func (d *Driver) discoverVPC(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeVpcs", "Version": ec2Version}))
	if err != nil {
		return nil, nil, fmt.Errorf("ec2 DescribeVpcs: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("ec2 DescribeVpcs: HTTP %d: %s", st, ec2ErrCode(body))
	}
	var r struct {
		IDs []string `xml:"vpcSet>item>vpcId"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("ec2 DescribeVpcs: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, vpcID := range r.IDs {
		if vpcID == "" {
			continue
		}
		pid := awsVpcProviderID(region, vpcID)
		obs, odiags, oerr := d.observeAWSVPC("", pid)
		if oerr != nil {
			diags = append(diags, vpcID+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, vpcID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.network.private",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverIAM enumerates IAM roles as capability.identity.serviceaccount and
// each role's attached managed policies as capability.authorization.grant, both
// through the SAME reverse maps observe uses. IAM is GLOBAL (signed us-east-1),
// so the account rides in each role's ARN. ListRoles is single-page here (as the
// other sweeps are); a truncated list is a shared limitation, not a per-call
// fabricated absence.
func (d *Driver) discoverIAM(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.iamPost(encodeForm(map[string]string{
		"Action": "ListRoles", "Version": iamVersion}))
	if err != nil {
		return nil, nil, fmt.Errorf("iam ListRoles: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("iam ListRoles: HTTP %d: %s", st, rdsErrCode(body))
	}
	var r struct {
		Roles []struct {
			RoleName string `xml:"RoleName"`
			Arn      string `xml:"Arn"`
		} `xml:"ListRolesResult>Roles>member"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("iam ListRoles: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, role := range r.Roles {
		if role.RoleName == "" {
			continue
		}
		// account rides in arn:aws:iam::<account>:role/<name>
		parts := strings.Split(role.Arn, ":")
		if len(parts) < 5 || !account12.MatchString(parts[4]) {
			diags = append(diags, role.RoleName+": role arn has no account — skipped")
			continue
		}
		account := parts[4]
		pid := iamRoleProviderID(account, role.RoleName)
		obs, odiags, oerr := d.observeIAMRole("", pid)
		if oerr != nil {
			diags = append(diags, role.RoleName+": "+oerr.Error())
		} else {
			for _, dg := range odiags {
				diags = append(diags, role.RoleName+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.identity.serviceaccount",
				Observations: obs,
			})
		}
		// grants: this role's attached managed policies. Per-role isolation — an
		// unreadable attachment list on one role never sinks the others.
		gfound, gdiags := d.discoverRoleGrants(role.RoleName)
		out = append(out, gfound...)
		diags = append(diags, gdiags...)
	}
	return out, diags, nil
}

// discoverRoleGrants lists a role's attached managed policies and reverse-maps
// each as capability.authorization.grant through observeRolePolicyAttachment.
func (d *Driver) discoverRoleGrants(roleName string) ([]provider.Discovered, []string) {
	const op = "ListAttachedRolePolicies"
	st, resp, err := d.iamPost(encodeForm(map[string]string{
		"Action": "ListAttachedRolePolicies", "Version": iamVersion, "RoleName": roleName}))
	if err != nil {
		return nil, []string{roleName + ": " + readTransport(op, err).Error()}
	}
	if st != http.StatusOK {
		return nil, []string{roleName + ": " + readHTTP(op, st, rdsErrCode(resp)).Error()}
	}
	var r struct {
		Arns []string `xml:"ListAttachedRolePoliciesResult>AttachedPolicies>member>PolicyArn"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return nil, []string{roleName + ": ListAttachedRolePolicies unparseable"}
	}
	var out []provider.Discovered
	var diags []string
	for _, arn := range r.Arns {
		pid := rolePolicyProviderID(roleName, arn)
		obs, odiags, oerr := d.observeRolePolicyAttachment("", pid)
		if oerr != nil {
			diags = append(diags, roleName+" grant "+arn+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, roleName+" grant "+arn+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.authorization.grant",
			Observations: obs,
		})
	}
	return out, diags
}

// discoverSecrets enumerates Secrets Manager secrets in the region as
// capability.secret. ListSecrets returns NAMES + metadata; observeASM reads
// DescribeSecret + the resource policy and NEVER GetSecretValue — the secret
// VALUE is structurally out of reach (D53). Existence + metadata only.
func (d *Driver) discoverSecrets(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.asmCall(region, "ListSecrets", "{}")
	if err != nil {
		return nil, nil, fmt.Errorf("secretsmanager ListSecrets: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("secretsmanager ListSecrets: HTTP %d: %s", st, ecsErr(body))
	}
	var r struct {
		SecretList []struct {
			Name string `json:"Name"`
		} `json:"SecretList"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("secretsmanager ListSecrets", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, s := range r.SecretList {
		if s.Name == "" {
			continue
		}
		pid := asmProviderID(region, s.Name)
		obs, odiags, oerr := d.observeASM("", pid)
		if oerr != nil {
			diags = append(diags, s.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, s.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.secret",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverCloudWatch enumerates metric alarms in the region as
// capability.monitoring.alert. DescribeAlarms (MetricAlarm type) is region-
// scoped; the account (for the providerId) is resolved once via STS. Each alarm
// is reverse-mapped by the SAME observe.
func (d *Driver) discoverCloudWatch(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("cloudwatch: %v", err)
	}
	st, body, err := d.cwPost(region, encodeForm(map[string]string{
		"Action": "DescribeAlarms", "Version": cwVersion, "AlarmTypes.member.1": "MetricAlarm"}))
	if err != nil {
		return nil, nil, fmt.Errorf("cloudwatch DescribeAlarms: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("cloudwatch DescribeAlarms: HTTP %d: %s", st, rdsErrCode(body))
	}
	var r struct {
		Names []string `xml:"DescribeAlarmsResult>MetricAlarms>member>AlarmName"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("cloudwatch DescribeAlarms: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, name := range r.Names {
		if name == "" {
			continue
		}
		pid := cwAlarmProviderID(region, account, name)
		obs, odiags, oerr := d.observeCloudWatchAlarm("", pid)
		if oerr != nil {
			diags = append(diags, name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.monitoring.alert",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverECR enumerates repositories in the region as capability.registry.image.
// DescribeRepositories (no name filter) lists the account's repos; the account
// (for the providerId) is resolved once via STS. Each is reverse-mapped by the
// SAME observe.
func (d *Driver) discoverECR(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("ecr: %v", err)
	}
	st, body, err := d.ecrCall(region, "DescribeRepositories", "{}")
	if err != nil {
		return nil, nil, fmt.Errorf("ecr DescribeRepositories: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("ecr DescribeRepositories: HTTP %d: %s", st, ecsErr(body))
	}
	var r struct {
		Repositories []struct {
			RepositoryName string `json:"repositoryName"`
		} `json:"repositories"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, nil, readBody("ecr DescribeRepositories", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, repo := range r.Repositories {
		if repo.RepositoryName == "" {
			continue
		}
		pid := ecrProviderID(region, account, repo.RepositoryName)
		obs, odiags, oerr := d.observeECR("", pid)
		if oerr != nil {
			diags = append(diags, repo.RepositoryName+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, repo.RepositoryName+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.registry.image",
			Observations: obs,
		})
	}
	return out, diags, nil
}
