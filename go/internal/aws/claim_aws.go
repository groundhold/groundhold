// AWS takeover claim (D140/D145): the AWS driver opts into provider.Claimer,
// mirroring the GCP/Azure slices. Once the driver is a Claimer, the compiler emits
// a one-time `claim` for every adopted-but-unclaimed AWS capability. Claim STAMPS
// groundhold's ownership marker (the same tags the driver applies on create) on the
// adopted resource so a later drift pre-read recognises it as ours — closing the
// orphan gap (Q5): a converged no-op is a READ-ONLY proof of takeover, so an
// operator who ran `terraform state rm` after it left the resource with no groundhold
// marker, and the next real drift refused "not ours" with no writer left to repair
// it.
//
// D145 broadens the claim from rds-only to EVERY tag-markable service. Three shapes:
//
//   - The GENERIC path (claimByARN) via the Resource Groups Tagging API's
//     TagResources — one signed call that tags ANY supported resource by ARN. The
//     stamp is ADDITIVE server-side (a merge by key, never a full-map replace), so
//     the operator's tags survive; a per-resource failure rides in FailedResourcesMap
//     (four-valued: an InternalService/throttle entry is `unknown` WITH the pid, a
//     NotFound/InvalidParameter entry is a clean `failed`). Every service whose
//     providerID yields a taggable ARN (directly, or with the cached STS account)
//     rides this one shape.
//   - A service-NATIVE tag API where the ARN is not derivable from the providerID:
//     rds (AddTagsToResource, keyed on the DB ARN we can build) and secretsmanager
//     (TagResource keyed on the secret NAME — the ARN carries a server-assigned
//     random suffix, so the name-keyed native call is the honest choice).
//   - HONEST-REFUSE (failed) for services groundhold cannot yet claim: the ones that
//     mark ownership by NAME/identity (IAM roles, role/custom policies, Route 53
//     zones + health checks), the read-only loadbalancer, the untaggable ones
//     (dashboards, log-metric filters), AND the tag-markable services whose
//     providerID does not yield a taggable ARN without a describe round-trip (ecs,
//     msk, waf, redshiftserverless) — deferred, incremental follow-ups. A failed
//     claim stops the converge before the takeover signal, so the resource stays
//     externally owned rather than orphaned (safer than a silent success). An unknown
//     service fails closed via the shared service gate.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

var _ provider.Claimer = (*Driver)(nil)

// Claim dispatches per service (D76, fail-closed). rds/secretsmanager take their
// service-native additive tag API; every ARN-derivable service rides the generic
// Resource Groups Tagging API; everything else refuses honestly.
func (d *Driver) Claim(service, capability, environment, providerID string) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	switch service {
	case "rds":
		return d.claimRDS(capability, environment, providerID)
	case "secretsmanager":
		return d.claimSecretsManager(capability, environment, providerID)
	case "route53":
		return d.claimRoute53(capability, environment, providerID)
	case "lambda":
		return d.claimLambda(capability, environment, providerID)
	case "s3", "sqs", "sns", "dynamodb", "ecr", "efs", "opensearch", "kinesis",
		"elasticache", "acm", "cloudwatch", "backupvault", "apigateway",
		"cloudfront", "vpc", "vpngateway", "kms", "eks", "ses-sending", "aurora",
		"guardduty", "cwlogs",
		// describe-to-resolve-ARN services (the ARN is read, not built from the pid):
		"ecs", "apprunner", "msk", "redshiftserverless", "waf":
		return d.claimTagResources(service, capability, environment, providerID)
	default:
		return provider.CreateResult{Status: "failed", Reason: honestRefuseReason(service)}
	}
}

// claimRoute53 stamps ownership tags on a hosted zone via route53's NATIVE tagging API
// (ChangeTagsForResource) — the same path create uses (r53Tag), not the generic RGT,
// because route53 is a global service with its own tagging surface. F23: route53 claim
// was unwired, so adopting a zone then applying refused ("cannot yet claim").
func (d *Driver) claimRoute53(capability, environment, providerID string) provider.CreateResult {
	if !d.hasCreds() {
		return provider.CreateResult{Status: "failed",
			Reason: "no AWS credentials — refusing before any mutation"}
	}
	id, err := splitR53ProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if res := d.r53Tag(id, capability, environment); res != nil {
		return *res // unknown/failed, carrying the pid — never a fabricated success
	}
	return provider.CreateResult{ProviderID: r53ProviderID(id), Status: "succeeded"}
}

// claimLambda takes ownership of an adopted-but-unclaimed Lambda function (the Acme
// field gap: a brownfield function could be neither updated nor have its resource
// policy touched for a CDN/OAC invoke grant — adoption stopped at a READ-ONLY no-op,
// so the first update/AddPermission hit the driver's "not ours" tag guard and forced
// a delete+recreate). The Lambda function ARN is fully derivable from the providerId,
// so the stamp itself rides the generic additive RGT path (ARN in the body, never a
// full-map clobber, consistent with every other ARN-derivable service). What lambda
// adds over the pure generic path is a service-NATIVE pre-claim identity guard: a
// GetFunction confirms the function exists AND that its live FunctionArn is the one
// the providerId names — never tag a foreign function the acting account happens to
// hold under the same name. Four-valued: an unreadable pre-read is unknown WITH the
// pid; a vanished function or an identity mismatch is a clean failed; an already-owned
// function is an idempotent success (no re-write).
func (d *Driver) claimLambda(capability, environment, providerID string) provider.CreateResult {
	region, account, name, err := splitLambdaProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// refuse-before-mutate: a missing credential is a config error, not an ambiguous
	// outcome (which the GetFunction below would mislabel "unknown").
	if !d.hasCreds() {
		return provider.CreateResult{Status: "failed",
			Reason: "no AWS credentials — refusing before any mutation"}
	}
	// pre-claim read (identity guard). An unreadable read is ambiguous -> unknown WITH
	// the pid; a readable 404 is a clean failure (never a fabricated success).
	cfg, tags, found, rerr := d.getLambdaFunction(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-claim read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "function no longer exists — cannot claim"}
	}
	// honesty guard: the name resolved to a function, but is it THE one the providerId
	// names? A FunctionArn that is not the derivable ARN is a foreign resource in the
	// acting account — refuse rather than stamp ownership onto someone else's function.
	want := lambdaArn(region, account, name)
	if cfg.FunctionArn != "" && cfg.FunctionArn != want {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("function identity mismatch (live %s != adopted %s) — refusing to claim a foreign function",
				cfg.FunctionArn, want)}
	}
	// already ours: idempotent success, no re-write (Claim is idempotent by contract).
	if groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	// stamp the SAME ownership tags create applies, via the additive RGT path — the
	// function ARN is deterministic, so no describe-to-resolve is needed here.
	return d.claimByARN(region, want, capability, environment, providerID)
}

func honestRefuseReason(service string) string {
	return fmt.Sprintf("aws cannot yet claim ownership of a %q resource — "+
		"it stays externally owned; adoption is not takeover for this service "+
		"until claim is wired", service)
}

// claimTagResources resolves the service's taggable ARN from its providerID and
// stamps the ownership tags through the generic Resource Groups Tagging API.
func (d *Driver) claimTagResources(service, capability, environment, providerID string) provider.CreateResult {
	// refuse-before-mutate: a missing credential is a config error, not an ambiguous
	// outcome (which the send below would mislabel "unknown — may have landed").
	if !d.hasCreds() {
		return provider.CreateResult{Status: "failed",
			Reason: "no AWS credentials — refusing before any mutation"}
	}
	region, arn, early := d.claimARN(service, providerID)
	if early != nil {
		return *early
	}
	return d.claimByARN(region, arn, capability, environment, providerID)
}

// claimARN maps a service + providerID to (region-for-the-RGT-endpoint, taggable
// ARN). A malformed providerID is a clean `failed`; the region-only providerIDs
// complete their ARN with the cached STS account — an STS failure there is a read
// failure, so ambiguous -> `unknown` WITH the pid (never a fabricated success).
// D487 — the account boundary on the claim path. D468 established it for
// delete/update/observe: no legitimate flow produces a providerId naming another
// account, so a mismatch is a forged or stale binding. Claim needed it MORE than any
// of them and had it in exactly one place — claimLambda, whose comment states the
// concern precisely ("never tag a foreign function the acting account happens to hold
// under the same name") — while thirteen other paths built an ARN straight from the
// providerId's account.
//
// Why it matters more here: claim STAMPS OUR OWNERSHIP MARKER. A delete that reaches
// the wrong resource destroys it and the damage is visible; a claim that reaches the
// wrong resource makes every subsequent ownership check in this runtime agree the
// resource is ours (D461). It is the one write that manufactures its own permission.
//
// This applies the existing boundary. It does NOT answer the open question of whether
// claim should verify that the resource is the one the binding NAMES — that is the
// ratcheted gap D461 records, and it is a design decision, not a missing line.
func (d *Driver) claimARN(service, providerID string) (region, arn string, early *provider.CreateResult) {
	fail := func(msg string) (string, string, *provider.CreateResult) {
		return "", "", &provider.CreateResult{Status: "failed", Reason: msg}
	}
	acctUnknown := func(e error) (string, string, *provider.CreateResult) {
		return "", "", &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("resolve account for claim ARN: %v", e)}
	}
	// describe-to-resolve-ARN services: an unreadable pre-claim read is ambiguous
	// (-> unknown WITH the pid); a vanished resource is a clean failed.
	readUnknown := func(what string) (string, string, *provider.CreateResult) {
		return "", "", &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-claim %s read failed (transport or permission) — reconcile", what)}
	}
	switch service {
	case "s3":
		region, bucket, err := splitS3ProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		// PutBucketTagging is a full-map REPLACE (a clobber risk); the RGT stamp is
		// additive, so it is the honest choice for the bucket. ARN carries no
		// region/account, but the RGT endpoint is region-scoped.
		return region, "arn:aws:s3:::" + bucket, nil
	case "sqs":
		region, account, name, err := splitSQSProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, sqsARN(region, account, name), nil
	case "sns":
		region, account, name, err := splitSNSProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, snsARN(region, account, name), nil
	case "dynamodb":
		region, account, table, err := splitDynamoProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, dynamoARN(region, account, table), nil
	case "ecr":
		region, account, name, err := splitECRProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, ecrArn(region, account, name), nil
	case "efs":
		region, account, id, err := splitEFSProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, "arn:aws:elasticfilesystem:" + region + ":" + account + ":file-system/" + id, nil
	case "opensearch":
		region, account, domain, err := splitOpenSearchProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, openSearchARN(region, account, domain), nil
	case "kinesis":
		region, account, stream, err := splitKinesisProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, "arn:aws:kinesis:" + region + ":" + account + ":stream/" + stream, nil
	case "elasticache":
		region, account, id, err := splitECacheProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, ecacheARN(region, account, id), nil
	case "acm":
		region, account, certID, err := splitACMProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, acmARN(region, account, certID), nil
	case "cloudwatch":
		region, account, name, err := splitCWAlarmProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, cwAlarmArn(region, account, name), nil
	case "backupvault":
		region, account, name, err := splitBkvProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, bkvArn(region, account, name), nil
	case "apigateway":
		region, _, apiID, err := splitApiGWProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		return region, "arn:aws:apigateway:" + region + "::/apis/" + apiID, nil
	case "cloudfront":
		account, distID, err := splitCFProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		// CloudFront is global: its ARN carries no region and its RGT endpoint is
		// us-east-1.
		return "us-east-1", "arn:aws:cloudfront::" + account + ":distribution/" + distID, nil
	case "vpc":
		region, vpcID, err := splitAWSVpcProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		account, aerr := d.resolveAccount()
		if aerr != nil {
			return acctUnknown(aerr)
		}
		return region, "arn:aws:ec2:" + region + ":" + account + ":vpc/" + vpcID, nil
	case "vpngateway":
		region, vgwID, err := splitVgwProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		account, aerr := d.resolveAccount()
		if aerr != nil {
			return acctUnknown(aerr)
		}
		return region, "arn:aws:ec2:" + region + ":" + account + ":vpn-gateway/" + vgwID, nil
	case "kms":
		region, keyID, err := splitAWSKMSProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		account, aerr := d.resolveAccount()
		if aerr != nil {
			return acctUnknown(aerr)
		}
		return region, "arn:aws:kms:" + region + ":" + account + ":key/" + keyID, nil
	case "eks":
		region, name, err := splitEKSProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		account, aerr := d.resolveAccount()
		if aerr != nil {
			return acctUnknown(aerr)
		}
		// EKS cluster ARN is deterministic (no random suffix) — built, not read.
		return region, "arn:aws:eks:" + region + ":" + account + ":cluster/" + name, nil
	case "ses-sending":
		region, domain, err := splitSESSendingProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		account, aerr := d.resolveAccount()
		if aerr != nil {
			return acctUnknown(aerr)
		}
		// SES identity ARN is deterministic (identity/<domain>) — built, not read.
		return region, "arn:aws:ses:" + region + ":" + account + ":identity/" + domain, nil
	case "aurora":
		region, id, err := splitAuroraProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		account, aerr := d.resolveAccount()
		if aerr != nil {
			return acctUnknown(aerr)
		}
		// Aurora cluster ARN is deterministic (cluster:<id>) — built, not read.
		return region, "arn:aws:rds:" + region + ":" + account + ":cluster:" + id, nil
	case "guardduty":
		region, id, err := splitGuardDutyProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		account, aerr := d.resolveAccount()
		if aerr != nil {
			return acctUnknown(aerr)
		}
		// detector ARN is deterministic (detector/<id>) — built, not read.
		return region, "arn:aws:guardduty:" + region + ":" + account + ":detector/" + id, nil
	case "cwlogs":
		region, name, err := splitCWLogsProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		account, aerr := d.resolveAccount()
		if aerr != nil {
			return acctUnknown(aerr)
		}
		// log-group ARN is deterministic (log-group:<name>) — built, not read.
		return region, "arn:aws:logs:" + region + ":" + account + ":log-group:" + name, nil

	// describe-to-resolve-ARN services: the providerId does not carry a taggable
	// ARN (a random suffix / UUID / cluster path), so a read resolves the ARN the
	// tag call keys on — never a fabricated ARN.
	case "ecs":
		region, name, err := splitECSProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		svc, found, rerr := d.describeService(region, name, name)
		if rerr != nil {
			return readUnknown("ecs service")
		}
		if !found || svc.ServiceArn == "" {
			return fail("ecs service no longer exists — cannot claim")
		}
		return region, svc.ServiceArn, nil
	case "apprunner":
		region, arn, early := d.claimAppRunnerARN(providerID)
		if early != nil {
			return "", "", early
		}
		return region, arn, nil
	case "msk":
		region, _, cluster, err := splitMSKProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		c, found, rerr := d.getMSKByName(region, cluster)
		if rerr != nil {
			return readUnknown("msk cluster")
		}
		if !found || c.ClusterArn == "" {
			return fail("msk cluster no longer exists — cannot claim")
		}
		return region, c.ClusterArn, nil
	case "redshiftserverless":
		region, name, err := splitRSSProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		wg, found, rerr := d.getWorkgroup(region, name)
		if rerr != nil {
			return readUnknown("redshift-serverless workgroup")
		}
		if !found || wg.WorkgroupArn == "" {
			return fail("redshift-serverless workgroup no longer exists — cannot claim")
		}
		return region, wg.WorkgroupArn, nil
	case "waf":
		_, name, err := splitWAFProviderID(providerID)
		if err != nil {
			return fail(err.Error())
		}
		s, found, rerr := d.wafListByName(name)
		if rerr != nil {
			return readUnknown("waf web ACL")
		}
		if !found || s.ARN == "" {
			return fail("waf web ACL no longer exists — cannot claim")
		}
		// CLOUDFRONT-scope WAF is global; the RGT endpoint is us-east-1.
		return "us-east-1", s.ARN, nil
	}
	return fail(fmt.Sprintf("no claim ARN mapping for service %q", service))
}

// rgtBase is the region-scoped Resource Groups Tagging API endpoint (tests override).
func (d *Driver) rgtBase(region string) string {
	if d.RGTBaseURL != "" {
		return d.RGTBaseURL
	}
	if region == "" {
		region = d.Region
	}
	return "https://tagging." + region + ".amazonaws.com"
}

// claimByARN stamps groundhold's ownership tags on an adopted resource via the Resource
// Groups Tagging API TagResources (AWS JSON 1.1). TagResources MERGES the given tags
// by key — additive, so the operator's tags survive (no read-modify-write clobber).
// Four-valued on the wire: a transport error or a 5xx (or a retryable per-resource
// entry) is `unknown` WITH the providerId (never a silent success), a clear 4xx or a
// NotFound/InvalidParameter per-resource entry is a clean `failed`, an empty
// FailedResourcesMap is `succeeded` WITH the providerId.
func (d *Driver) claimByARN(region, arn, capability, environment, providerID string) provider.CreateResult {
	// D487 — the account boundary, checked ONCE, where the ARN is consumed.
	//
	// The first version put the check in each case of claimARN that binds an account
	// from the providerId: twelve copies, which is precisely the shape that let those
	// twelve drift apart from claimLambda's guard in the first place. The Azure twin
	// does it right and has done all along — every claim case calls claimURLFor and the
	// subscription check lives THERE, once.
	//
	// The ARN itself carries the account (field 5), so one check covers every case,
	// including the ones that build it from d.resolveAccount() (where it is a no-op by
	// construction) and any case added later. An account-less ARN — s3, whose ARN is
	// arn:aws:s3:::bucket — yields "" and is skipped: there is nothing to compare, and
	// the bucket name is global.
	if err := d.sameAccount(arnAccount(arn)); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// stamp the SAME ownership tags the create builders apply (groundhold-capability /
	// groundhold-environment). ResourceARNList carries exactly the one ARN.
	body := fmt.Sprintf(`{"ResourceARNList":[%q],"Tags":{"groundhold-capability":%q,"groundhold-environment":%q}}`,
		arn, sanitizeTag(capability), sanitizeTag(environment))
	st, resp, err := d.doSigned("POST", d.rgtBase(region)+"/", "tagging", region,
		map[string]string{
			"Content-Type": "application/x-amz-json-1.1",
			"X-Amz-Target": "ResourceGroupsTaggingAPI_20170126.TagResources",
		}, []byte(body))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim outcome unknown (may have landed) — reconcile: %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st != http.StatusOK {
		// 4xx. A throttle is ambiguous (a retry may land the tag); every other 4xx
		// (bad ARN, access denied, malformed request) is a clean failure.
		if code := ecsErr(resp); strings.Contains(code, "Throttl") {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("claim throttled (HTTP %d) — reconcile", st)}
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("claim failed: HTTP %d (%s)", st, ecsErr(resp))}
	}
	// 200: a per-resource failure rides in FailedResourcesMap, keyed by the ARN.
	var out struct {
		Failed map[string]struct {
			ErrorCode  string `json:"ErrorCode"`
			StatusCode int    `json:"StatusCode"`
		} `json:"FailedResourcesMap"`
	}
	if json.Unmarshal(resp, &out) != nil {
		// a garbled 200 is ambiguous — never a fabricated success.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "the claim response did not parse — reconcile: " + readBody("claim", st).Error()}
	}
	for _, f := range out.Failed {
		if f.StatusCode >= 500 || strings.Contains(f.ErrorCode, "InternalService") ||
			strings.Contains(f.ErrorCode, "Throttl") {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("claim ambiguous (%s) — reconcile", f.ErrorCode)}
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("claim failed: %s", f.ErrorCode)}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// claimSecretsManager stamps groundhold's ownership tags on an adopted secret. The
// secret ARN carries a server-assigned random suffix that the providerId does not
// hold, so the ARN cannot be built — but TagResource accepts the secret NAME as
// SecretId and is ADDITIVE (merges by key), so the name-keyed native call is the
// honest choice. Four-valued exactly as claimRDS.
func (d *Driver) claimSecretsManager(capability, environment, providerID string) provider.CreateResult {
	region, name, err := splitASMProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !d.hasCreds() {
		return provider.CreateResult{Status: "failed",
			Reason: "no AWS credentials — refusing before any mutation"}
	}
	// pre-claim existence read (reuses the shared describe plumbing). An unreadable
	// read is ambiguous -> unknown WITH the pid; a vanished secret is a clean failure.
	_, found, rerr := d.describeASM(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-claim read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "secret no longer exists — cannot claim"}
	}
	body := fmt.Sprintf(`{"SecretId":%q,"Tags":[{"Key":"groundhold-capability","Value":%q},{"Key":"groundhold-environment","Value":%q}]}`,
		name, sanitizeTag(capability), sanitizeTag(environment))
	st, resp, err := d.asmCall(region, "TagResource", body)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim outcome unknown (may have landed) — reconcile: %v", err)}
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return provider.CreateResult{Status: "failed",
			Reason: "secret vanished mid-claim — cannot claim"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("claim failed: HTTP %d (%s)", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// claimRDS stamps groundhold's ownership tags on an adopted DB instance. Unlike the
// GCP/Azure label/tag PATCH (a full-map replace that MUST read-modify-write to keep
// the operator's tags), RDS AddTagsToResource is ADDITIVE by nature — it merges the
// given tags by key without touching the operator's other tags, so no read-modify-
// write is needed to avoid a clobber. The pre-read is only an existence check (so a
// vanished instance fails cleanly rather than 4xx-ing on the tag call) and to keep
// the same describe plumbing every RDS mutation uses. Four-valued on the wire: a
// transport error or a 5xx is `unknown` WITH the providerId (never a silent
// success), a vanished instance or a clear 4xx is a clean `failed`, a 2xx is
// `succeeded` WITH the providerId.
func (d *Driver) claimRDS(capability, environment, providerID string) provider.CreateResult {
	region, id, err := splitRDSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// refuse-before-mutate: a missing credential is a config error, not an
	// ambiguous outcome (which the describe below would mislabel "unknown").
	if !d.hasCreds() {
		return provider.CreateResult{Status: "failed",
			Reason: "no AWS credentials — refusing before any mutation"}
	}
	// pre-claim existence read (reuses the shared describe plumbing). An
	// unreadable read is ambiguous -> unknown WITH the providerId; a vanished
	// instance is a clean failure (never a fabricated success).
	inst, found, rerr := d.describeDB(region, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-claim read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "instance no longer exists — cannot claim"}
	}
	_ = inst // existence is what we need; ownership tags are what we are ABOUT to write.

	// AddTagsToResource keys on the DB instance ARN. The account completes the ARN;
	// resolveAccount caches it (an STS failure is ambiguous -> unknown WITH the pid).
	account, err := d.resolveAccount()
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("resolve account for claim ARN: %v", err)}
	}
	arn := fmt.Sprintf("arn:aws:rds:%s:%s:db:%s", region, account, id)

	// stamp the SAME ownership tags the create builder applies (BuildRDSCreate:
	// groundhold-capability / groundhold-environment). AddTagsToResource is additive.
	st, resp, err := d.rdsPost(region, rdsSimpleBody("AddTagsToResource", map[string]string{
		"ResourceName":        arn,
		"Tags.member.1.Key":   "groundhold-capability",
		"Tags.member.1.Value": sanitizeTag(capability),
		"Tags.member.2.Key":   "groundhold-environment",
		"Tags.member.2.Value": sanitizeTag(environment),
	}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim outcome unknown (may have landed) — reconcile: %v", err)}
	}
	if rdsErrCode(resp) == "DBInstanceNotFound" {
		return provider.CreateResult{Status: "failed",
			Reason: "instance vanished mid-claim — cannot claim"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st < 200 || st >= 300 || st == http.StatusNotFound {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("claim failed: HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
