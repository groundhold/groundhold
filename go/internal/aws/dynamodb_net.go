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
		// ours — fall through to poll + PITR
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
	active := false
	for {
		desc, found, rerr := d.describeTable(region, plan.Table)
		if rerr == nil && found {
			if desc.TableStatus == "ACTIVE" {
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
		return nil, []string{"table not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a single-region DynamoDB table is zonally-redundant within the region.
		{Path: "availability.class", Value: "regional", Derivation: "config-intent"},
		{Path: "deletion.protection", Value: desc.DeletionProtectionEnabled, Derivation: "measured"},
	}
	// SSEType=KMS means KMS encryption is on, but DescribeTable reports the key as
	// an opaque ARN — the AWS-managed aws/dynamodb key and a customer key are
	// indistinguishable without a KMS DescribeKey (KeyManager) lookup, exactly the
	// case RDS refuses. Emit a diagnostic, never a false customerManagedKeys=true
	// (which would certify BYOK on a managed-key table at adoption).
	var diags []string
	if desc.SSEDescription.SSEType == "KMS" && desc.SSEDescription.KMSMasterKeyArn != "" {
		diags = append(diags, "encryption.customerManagedKeys not observed: DescribeTable "+
			"reports a KMS key ARN but cannot distinguish the AWS-managed aws/dynamodb key "+
			"from a customer key without a KMS DescribeKey (KeyManager) lookup — probe/reconcile")
	}
	if enabled, ok := d.pitrEnabled(region, table); ok {
		obs = append(obs, provider.Observation{Path: "backup.pointInTimeRecovery", Value: enabled, Derivation: "measured"})
	}
	return obs, diags, nil
}

func (d *Driver) deleteDynamoDB(capability, environment, providerID string) provider.CreateResult {
	region, account, table, err := splitDynamoProviderID(providerID)
	if err != nil {
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
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
