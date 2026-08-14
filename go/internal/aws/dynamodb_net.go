// DynamoDB network shell (D112): the SigV4-signed, JSON-protocol half of the AWS
// capability.database.nosql driver. CreateTable is polled to ACTIVE, then (if the
// candidate asks) point-in-time recovery is enabled by a SEPARATE
// UpdateContinuousBackups call — a partial there is unknown/failed WITH the pid,
// never a silent success. The table name is deterministic, so the providerId is
// knowable before the response (D29). Ownership is TAGS (ListTagsOfResource on the
// table ARN). D29/D87 honesty throughout.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"groundhold/internal/provider"
)

const dynamoTarget = "DynamoDB_20120810"

func (d *Driver) dynamoBase(region string) string {
	if d.DynamoDBBaseURL != "" {
		return d.DynamoDBBaseURL
	}
	return "https://dynamodb." + region + ".amazonaws.com"
}

func dynamoProviderID(region, account, table string) string {
	return "dynamodb:" + region + ":" + account + ":" + table
}

func splitDynamoProviderID(providerID string) (region, account, table string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "dynamodb" {
		return "", "", "", fmt.Errorf("providerId %q is not dynamodb:region:account:table", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !dynamoNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId table %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func dynamoARN(region, account, table string) string {
	return "arn:aws:dynamodb:" + region + ":" + account + ":table/" + table
}

// dynamoCall signs and sends a JSON-protocol request (X-Amz-Target).
func (d *Driver) dynamoCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.0",
		"X-Amz-Target": dynamoTarget + "." + action,
	}
	return d.doSigned("POST", d.dynamoBase(region)+"/", "dynamodb", region, h, []byte(body))
}

type dynamoTableDesc struct {
	TableStatus               string `json:"TableStatus"`
	TableArn                  string `json:"TableArn"`
	DeletionProtectionEnabled bool   `json:"DeletionProtectionEnabled"`
	SSEDescription            struct {
		Status          string `json:"Status"`
		SSEType         string `json:"SSEType"`
		KMSMasterKeyArn string `json:"KMSMasterKeyArn"`
	} `json:"SSEDescription"`
	// D799: a table can be a GLOBAL TABLE, replicated into other regions. The driver
	// did not read this and called "regional" a platform invariant, so a table with
	// copies of its data in three continents satisfied an EU-residency constraint.
	Replicas []struct {
		RegionName string `json:"RegionName"`
	} `json:"Replicas"`
}

// dynamoAvailability answers from the replica list rather than from the type of the
// service (D799). "Regional" was written as a platform-invariant — a claim that a
// DynamoDB table CANNOT be anything else — and Global Tables are exactly that something
// else. The observation is measured now, because the API says which one this is.
func dynamoAvailability(desc dynamoTableDesc) string {
	if len(dynamoReplicaRegions(desc)) > 0 {
		return "multi-regional"
	}
	return "regional"
}

func dynamoReplicaRegions(desc dynamoTableDesc) []string {
	var out []string
	for _, r := range desc.Replicas {
		if r.RegionName != "" {
			out = append(out, r.RegionName)
		}
	}
	sort.Strings(out)
	return out
}

// describeTable reads a table. found=false + readable=true is an authoritative
// "does not exist"; readable=false is a transport/HTTP/parse failure.
func (d *Driver) describeTable(region, table string) (dynamoTableDesc, bool, error) {
	const op = "DescribeTable"
	st, resp, err := d.dynamoCall(region, "DescribeTable", jsonBody(map[string]any{"TableName": table}))
	if err != nil {
		return dynamoTableDesc{}, false, readTransport(op, err)
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFoundException") {
		return dynamoTableDesc{}, false, nil
	}
	if st != http.StatusOK {
		return dynamoTableDesc{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		Table dynamoTableDesc `json:"Table"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return dynamoTableDesc{}, false, readBody(op, st)
	}
	return out.Table, true, nil
}

// dynamoTags reads the table's ownership tags. readable=false on any failure.
func (d *Driver) dynamoTags(region, account, table string) (map[string]string, error) {
	const op = "ListTagsOfResource"
	st, resp, err := d.dynamoCall(region, "ListTagsOfResource",
		jsonBody(map[string]any{"ResourceArn": dynamoARN(region, account, table)}))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		Tags []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

// pitrEnabled reads the continuous-backups/PITR status.
func (d *Driver) pitrEnabled(region, table string) (bool, bool) {
	st, resp, err := d.dynamoCall(region, "DescribeContinuousBackups",
		jsonBody(map[string]any{"TableName": table}))
	if err != nil || st != http.StatusOK {
		return false, false
	}
	var out struct {
		ContinuousBackupsDescription struct {
			PointInTimeRecoveryDescription struct {
				PointInTimeRecoveryStatus string `json:"PointInTimeRecoveryStatus"`
			} `json:"PointInTimeRecoveryDescription"`
		} `json:"ContinuousBackupsDescription"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return false, false
	}
	return out.ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == "ENABLED", true
}

func (d *Driver) createDynamoDB(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildDynamoDB(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := dynamoProviderID(region, account, plan.Table)
	adopted := false
	st, resp, err := d.dynamoCall(region, "CreateTable", jsonBody(plan.createBody(capability, environment)))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// creating — poll below
	case strings.Contains(ecsErr(resp), "ResourceInUseException"):
		tags, terr := d.dynamoTags(region, account, plan.Table)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing table tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a table with this name exists and is not ours (tags do not match)"}
		}
		// ours — the CreateTable body (SSE, deletion protection) did NOT apply to the
		// pre-existing table; only the separate PITR call below re-asserts. Mark adopted
		// so the inline-set controls are re-checked against the live table before we
		// report succeeded (D1058).
		adopted = true
		// fall through to poll + adopt-reconcile + PITR
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s): %s", st, ecsErr(resp), mutDetail(resp))}
	}

	// poll to ACTIVE
	deadline := d.Now().Add(d.PollTimeout)
	var liveDesc dynamoTableDesc
	active := false
	for {
		desc, found, rerr := d.describeTable(region, plan.Table)
		if rerr == nil && found {
			if desc.TableStatus == "ACTIVE" {
				liveDesc = desc
				active = true
				break
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "table still creating at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
	_ = active

	// D1058: an ADOPTED table (409 ResourceInUse, ours) never received the CreateTable
	// body's inline controls — SSE/customer-key and deletion protection. S3's 409-adopt
	// re-asserts every declared control idempotently; DynamoDB re-asserted only PITR, so
	// a table adopted with the wrong encryption or protection reported succeeded for a
	// control that did not land (the D1047/D1048 class). Re-check them against the live
	// table read we already have and refuse rather than lie; a later converge patches the
	// mutable drift (classifyDynamoDBChange), but create must not claim what is not there.
	if adopted {
		// Only the DANGEROUS direction is a lie: a declared control that the live table
		// LACKS. A table more protected/encrypted than declared is the safe direction and
		// adopts cleanly (a later converge reconciles the declared-lower drift in place).
		if plan.DeletionProtection && !liveDesc.DeletionProtectionEnabled {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "adopted an " +
				"existing table with deletion protection OFF, but the candidate declares it on " +
				"— reconcile (create did not protect it)"}
		}
		if plan.CMEK && liveDesc.SSEDescription.SSEType != "KMS" {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "adopted an " +
				"existing table with no SSE-KMS encryption, but the candidate declares a " +
				"customer-managed key — reconcile (create did not encrypt it)"}
		}
	}

	// point-in-time recovery is a SEPARATE call — a partial is unknown WITH the pid.
	if plan.PITR {
		st, resp, err := d.dynamoCall(region, "UpdateContinuousBackups", jsonBody(map[string]any{
			"TableName":                        plan.Table,
			"PointInTimeRecoverySpecification": map[string]any{"PointInTimeRecoveryEnabled": true},
		}))
		if err != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("table created but PITR outcome unknown: %v", err)}
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("table created but PITR HTTP %d (server error) — reconcile", st)}
		}
		if st != http.StatusOK {
			if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "PITR"); r != nil {
				return *r
			}
			return provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("table created but enabling PITR failed: HTTP %d (%s)", st, ecsErr(resp))}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) observeDynamoDB(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, table, err := splitDynamoProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	desc, found, rerr := d.describeTable(region, table)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"table not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "availability.class", Value: dynamoAvailability(desc), Derivation: "measured"},
		{Path: "deletion.protection", Value: desc.DeletionProtectionEnabled, Derivation: "measured"},
	}
	// SSEType=KMS means KMS encryption is on, but DescribeTable reports the key as
	// an opaque ARN — the AWS-managed aws/dynamodb key and a customer key are
	// indistinguishable without a KMS DescribeKey (KeyManager) lookup, exactly the
	// case RDS refuses. Emit a diagnostic, never a false customerManagedKeys=true
	// (which would certify BYOK on a managed-key table at adoption).
	var diags []string
	// D799: residency is the reason this matters. A global table's rows live in every
	// replica region, so naming ONE region as location.region and stopping there let an
	// EU-only contract verify against a table that also stores its data elsewhere. The
	// region stays (it is where THIS table endpoint is), and the replicas are said out
	// loud rather than being invisible.
	if regions := dynamoReplicaRegions(desc); len(regions) > 0 {
		diags = append(diags, "location.region names this table's own region, but the table "+
			"is a GLOBAL TABLE replicating into: "+strings.Join(regions, ", ")+
			" — its data is resident in those regions too")
	}
	// D1057: encryption.customerManagedKeys — DynamoDB was the lone AWS driver that
	// emitted this path NOWHERE. An SSE-KMS table reports a key ARN whether it is the
	// AWS-managed aws/dynamodb key or a customer key; trace it to KMS (DescribeKey ->
	// KeyManager) the way RDS/OpenSearch/EFS do, so a real CMK is measured rather than
	// punted. The default owned-key table (SSEType != "KMS", no ARN) is definitively
	// NOT customer-managed, read straight from DescribeTable → a MEASURED false, not an
	// absence. Omitting it let a `customerManagedKeys: true` candidate be adopted over
	// a default-key table (the broad case: owned-key is DynamoDB's default).
	if desc.SSEDescription.SSEType == "KMS" && desc.SSEDescription.KMSMasterKeyArn != "" {
		if customer, kerr := d.kmsKeyIsCustomerManaged(region, desc.SSEDescription.KMSMasterKeyArn); kerr == nil {
			obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
				Value: customer, Derivation: "measured"})
		} else {
			diags = append(diags, "encryption.customerManagedKeys not observed on the "+
				"table's KMS key: "+kerr.Error()+" — probe/reconcile")
		}
	} else {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: false, Derivation: "measured"})
	}
	if enabled, ok := d.pitrEnabled(region, table); ok {
		obs = append(obs, provider.Observation{Path: "backup.pointInTimeRecovery", Value: enabled, Derivation: "measured"})
	}
	return obs, diags, nil
}

// updateDynamoDB patches a LIVE table in place for the mutable paths (D1004):
// backup.pointInTimeRecovery via UpdateContinuousBackups, deletion.protection via
// UpdateTable. Ownership is re-checked (tags) BEFORE any mutation; unreadable -> unknown,
// vanished -> failed. Four-valued: a transport/5xx is unknown WITH the pid; a clean 4xx
// is failed. Only the two attributes classifyDynamoDBChange marks mutable reach here (the
// compiler routes an immutable change to replacement), so no other path is touched.
func (d *Driver) updateDynamoDB(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, account, table, err := splitDynamoProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, found, rerr := d.describeTable(region, table)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "table no longer exists — re-observe and re-plan"}
	}
	tags, terr := d.dynamoTags(region, account, table)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-update tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "table tags do not match — refusing to patch a resource that is not ours"}
	}
	plan, berr := BuildDynamoDB(environment, capability, attrs, impl, 1)
	if berr != nil {
		return provider.CreateResult{Status: "failed", Reason: berr.Error()}
	}
	plan.Table = table
	for _, path := range changes {
		switch path {
		case "backup.pointInTimeRecovery":
			st, resp, e := d.dynamoCall(region, "UpdateContinuousBackups", jsonBody(map[string]any{
				"TableName":                        table,
				"PointInTimeRecoverySpecification": map[string]any{"PointInTimeRecoveryEnabled": plan.PITR},
			}))
			if r := dynamoPatchOutcome(st, resp, e, providerID, "UpdateContinuousBackups"); r != nil {
				return *r
			}
		case "deletion.protection":
			st, resp, e := d.dynamoCall(region, "UpdateTable", jsonBody(map[string]any{
				"TableName":                 table,
				"DeletionProtectionEnabled": plan.DeletionProtection,
			}))
			if r := dynamoPatchOutcome(st, resp, e, providerID, "UpdateTable"); r != nil {
				return *r
			}
		default:
			// classifyDynamoDBChange routes everything else to replacement; a path here
			// would be a wiring bug, not a silent no-op.
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("dynamodb in-place update does not handle %q (it should have been a replacement)", path)}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// dynamoPatchOutcome folds one patch call into the four-valued shape: nil = keep going
// (2xx), non-nil is terminal. A transport error / 5xx is unknown WITH the pid; a throttle
// or live-403 routes through MutationResult (unknown); a clean 4xx is failed.
func dynamoPatchOutcome(st int, resp []byte, err error, pid, op string) *provider.CreateResult {
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("%s outcome unknown: %v", op, err)}
	case st == http.StatusOK:
		return nil
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("%s HTTP %d (server error) — reconcile", op, st)}
	default:
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, op); r != nil {
			return r
		}
		return &provider.CreateResult{ProviderID: pid, Status: "failed", Reason: fmt.Sprintf("%s HTTP %d: %s", op, st, ecsErr(resp))}
	}
}

func (d *Driver) deleteDynamoDB(capability, environment, providerID string) provider.CreateResult {
	region, account, table, err := splitDynamoProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	desc, found, rerr := d.describeTable(region, table)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.dynamoTags(region, account, table)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "table tags do not match — refusing to delete a resource that is not ours"}
	}
	// deletion protection blocks a destroy — surfaced, never forced (the flag IS
	// the guarantee the contract asked for).
	if desc.DeletionProtectionEnabled {
		return provider.CreateResult{Status: "failed",
			Reason: "the table has deletion protection enabled — retirement is blocked until it is " +
				"disabled; never forced (the protection is the capability)"}
	}
	st, resp, e := d.dynamoCall(region, "DeleteTable", jsonBody(map[string]any{"TableName": table}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFoundException") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, ecsErr(resp))}
	}
	// ---- poll to absence (D968 class) ----
	// The delete is async: a 200 means the table entered DELETING, not that it is
	// gone. Concluding "succeeded" here tombstones a table still live and billing;
	// if the async deletion then fails, it is orphaned from a ledger that says it
	// is gone. Poll to a confirmed ResourceNotFound as createDynamoDB polls to
	// ACTIVE; unknown on timeout keeps the handle for a reconcile.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.describeTable(region, table); rerr == nil && !found {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // confirmed gone
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "table still deleting at poll timeout — reconcile via DescribeTable"}
		}
		time.Sleep(d.PollInterval)
	}
}
