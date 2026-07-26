// AWS receipt reconciliation, BATCH 1 (D57): the read-only Reconciler wiring for
// five TIER-2 services (sns, sqs, ecr, dynamodb, kinesis). Every one derives a
// DETERMINISTIC resource name from (environment, capability, generation) — and,
// for the regional Query-protocol pair, the account — so a pending create whose
// response was lost (D29) is concludable by RECOMPUTING that name and reading the
// live resource by it. STRICTLY READ-ONLY: not one of these paths mutates.
//
// The shared conclusion machinery here is rc1-prefixed to stay collision-free with
// any other batch that lands its own reconcile helpers before a common base exists.
package aws

import (
	"net/http"
	"strconv"
	"strings"

	"groundhold/internal/provider"
)

// rc1Generation is a tolerant int read of receipt["generation"] — the value may
// arrive as int/int64/float64 (loader-dependent) or a string; anything absent or
// unparseable defaults to generation 1 (the create's own floor).
func rc1Generation(receipt map[string]any) int {
	switch v := receipt["generation"].(type) {
	case int:
		if v >= 1 {
			return v
		}
	case int64:
		if v >= 1 {
			return int(v)
		}
	case float64:
		if v >= 1 && v == float64(int64(v)) {
			return int(v)
		}
	case string:
		if n, err := strconv.Atoi(v); err == nil && n >= 1 {
			return n
		}
	}
	return 1
}

// rc1Regionless is the honest refusal for a region-scoped service reconciled with
// no region on the driver — an unknown that keeps the receipt pending rather than
// guessing against the wrong (or no) endpoint.
func rc1Regionless(service string) provider.ReconcileResult {
	return provider.ReconcileResult{Status: "unknown",
		Reason: service + " reconcile needs a region but the driver has none — cannot conclude the pending create"}
}

// rc1ConcludeByStatus maps a single live read to a four-valued verdict. succeeded
// ONLY when found+ours+ready+!failed; failed on a readable absence or a terminal-
// failed state; unknown on a read that gave no answer, a still-provisioning resource, or a
// found-but-not-ours resource. It never fabricates a conclusion.
func rc1ConcludeByStatus(pid, what string, found bool, rerr error, ours, ready, failed bool) provider.ReconcileResult {
	if rerr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: what + " read gave no answer — cannot conclude the pending create: " + rerr.Error()}
	}
	if !found {
		return provider.ReconcileResult{Status: "failed",
			Reason: what + " does not exist — the create did not land"}
	}
	if !ours {
		return provider.ReconcileResult{Status: "unknown",
			Reason: what + " exists but is not ours (ownership tags do not match) — cannot conclude the pending create"}
	}
	if failed {
		return provider.ReconcileResult{Status: "failed",
			Reason: what + " reached a terminal-failed state"}
	}
	if ready {
		return provider.ReconcileResult{Status: "succeeded", ProviderID: pid}
	}
	return provider.ReconcileResult{Status: "unknown",
		Reason: what + " is still provisioning — cannot conclude the pending create yet"}
}

// reconcileSNS concludes a pending messaging.topic create. An SNS topic is
// synchronous — found+owned IS ready. The topic name is deterministic from
// (account, environment, capability, generation); ownership is the birth tags.
func (d *Driver) reconcileSNS(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("sns")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	name := TopicName(account, environment, capability, generation)
	arn := snsARN(region, account, name)
	pid := snsProviderID(region, account, name)
	tags, found, rerr := d.snsListTags(region, arn)
	ours := found && groundholdTagsMatch(tags, capability, environment)
	return rc1ConcludeByStatus(pid, "sns topic", found, rerr, ours, true, false)
}

// reconcileSQS concludes a pending messaging.queue create. The queue name is
// deterministic but the FIFO suffix is NOT recoverable from (environment,
// capability, generation) alone — so BOTH the standard and the .fifo variants are
// recomputed and read. A queue is synchronous (found+owned IS ready). An
// unreadable read or a found-but-not-ours queue keeps the receipt pending
// (unknown); only a readable absence of BOTH variants concludes failed.
func (d *Driver) reconcileSQS(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("sqs")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	sawUnknown := false
	for _, fifo := range []bool{false, true} {
		name := QueueName(account, environment, capability, generation, fifo)
		queueURL := sqsQueueURL(d.sqsBase(region), account, name)
		tags, found, terr := d.sqsListTags(region, queueURL)
		if terr != nil {
			sawUnknown = true
			continue
		}
		if !found {
			continue // this variant is a readable absence — try the other
		}
		if groundholdTagsMatch(tags, capability, environment) {
			return provider.ReconcileResult{Status: "succeeded",
				ProviderID: sqsProviderID(region, account, name)}
		}
		sawUnknown = true // found but not ours — cannot conclude
	}
	if sawUnknown {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "an sqs queue with our deterministic name exists but is not ours, or a tag " +
				"read gave no answer — cannot conclude the pending create"}
	}
	return provider.ReconcileResult{Status: "failed",
		Reason: "no sqs queue with our deterministic name exists — the create did not land"}
}

// reconcileECR concludes a pending registry.image create. The repository name is
// deterministic from (environment, capability, generation) — account salts only
// the pid, not the name. A repository is synchronous (found+owned IS ready).
func (d *Driver) reconcileECR(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("ecr")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	name := ecrRepoName(environment, capability, generation)
	arn := ecrArn(region, account, name)
	pid := ecrProviderID(region, account, name)

	found, rerr := d.rc1ecrExists(region, name)
	if rerr != nil {
		return rc1ConcludeByStatus(pid, "ecr repository", false, rerr, false, false, false)
	}
	if !found {
		return rc1ConcludeByStatus(pid, "ecr repository", false, nil, false, false, false)
	}
	// exists — ownership is a separate tag read (readable=false there is "cannot
	// confirm ownership", which is unknown, never a takeover).
	tags, terr := d.ecrTags(region, arn)
	if terr != nil {
		return rc1ConcludeByStatus(pid, "ecr repository", true, terr, false, false, false)
	}
	ours := groundholdTagsMatch(tags, capability, environment)
	return rc1ConcludeByStatus(pid, "ecr repository", true, nil, ours, true, false)
}

// rc1ecrExists distinguishes a live repository from a readable absence
// (RepositoryNotFound) from an unreadable read — ecrTags alone collapses absence
// and unreadability, so DescribeRepositories is the authoritative existence read
// (mirrors deleteECR's disambiguation).
func (d *Driver) rc1ecrExists(region, name string) (found bool, err error) {
	const op = "DescribeRepositories"
	st, resp, cerr := d.ecrCall(region, "DescribeRepositories", `{"repositoryNames":["`+name+`"]}`)
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if strings.Contains(ecsErr(resp), "RepositoryNotFound") {
		return false, nil
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, ecsErr(resp))
	}
	return true, nil
}

// reconcileDynamoDB concludes a pending database.nosql create. The table name is
// deterministic from (environment, capability, generation). TableStatus=ACTIVE is
// ready; CREATING is still-provisioning (unknown); there is no terminal-failed
// table state a create leaves behind, so failed=false. Ownership is a separate
// ListTagsOfResource read.
func (d *Driver) reconcileDynamoDB(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("dynamodb")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	table := DynamoTableName(environment, capability, generation)
	pid := dynamoProviderID(region, account, table)

	desc, found, rerr := d.describeTable(region, table)
	if rerr != nil {
		return rc1ConcludeByStatus(pid, "dynamodb table", false, rerr, false, false, false)
	}
	if !found {
		return rc1ConcludeByStatus(pid, "dynamodb table", false, nil, false, false, false)
	}
	tags, terr := d.dynamoTags(region, account, table)
	if terr != nil {
		return rc1ConcludeByStatus(pid, "dynamodb table", true, terr, false, false, false)
	}
	ours := groundholdTagsMatch(tags, capability, environment)
	ready := desc.TableStatus == "ACTIVE"
	return rc1ConcludeByStatus(pid, "dynamodb table", true, nil, ours, ready, false)
}

// reconcileKinesis concludes a pending streaming.pipe create. The stream name is
// deterministic from (environment, capability, generation). StreamStatus=ACTIVE is
// ready; CREATING is still-provisioning (unknown). Ownership tags are added AFTER
// the stream reaches ACTIVE (a separate AddTagsToStream), so an active-but-untagged
// stream is found-but-not-ours => unknown, exactly the honest verdict.
func (d *Driver) reconcileKinesis(capability, environment string, generation int) provider.ReconcileResult {
	region := d.Region
	if region == "" {
		return rc1Regionless("kinesis")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: err.Error()}
	}
	stream := KinesisStreamName(environment, capability, generation)
	pid := kinesisProviderID(region, account, stream)

	s, found, rerr := d.describeStream(region, stream)
	if rerr != nil {
		return rc1ConcludeByStatus(pid, "kinesis stream", false, rerr, false, false, false)
	}
	if !found {
		return rc1ConcludeByStatus(pid, "kinesis stream", false, nil, false, false, false)
	}
	tags, terr := d.kinesisTags(region, stream)
	if terr != nil {
		return rc1ConcludeByStatus(pid, "kinesis stream", true, terr, false, false, false)
	}
	ours := groundholdTagsMatch(tags, capability, environment)
	ready := s.StreamStatus == "ACTIVE"
	return rc1ConcludeByStatus(pid, "kinesis stream", true, nil, ours, ready, false)
}
