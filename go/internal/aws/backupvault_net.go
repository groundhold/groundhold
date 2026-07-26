// AWS Backup Vault network shell (D127): the SigV4-signed, REST-JSON half of the AWS
// capability.backup.vault driver. CreateBackupVault is PUT /backup-vaults/{name};
// GET/DELETE follow; the retention lock is PUT /backup-vaults/{name}/vault-lock. The
// name is deterministic, so the pid is knowable BEFORE the response (D29). Ownership is
// tags read via ListTags (GET /tags/{arn}) — the ARN is pre-encoded into the path so
// the wire and the SigV4 canonical URI agree. Delete refuses a non-empty or
// compliance-locked vault (never forced). No live AWS Backup validation in this env —
// code + honesty-harness certified.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func (d *Driver) backupBase(region string) string {
	if d.BackupBaseURL != "" {
		return d.BackupBaseURL
	}
	return "https://backup." + region + ".amazonaws.com"
}

func (d *Driver) backupCall(method, region, path string, body []byte) (int, []byte, error) {
	h := map[string]string{"Content-Type": "application/json"}
	return d.doSigned(method, d.backupBase(region)+path, "backup", region, h, body)
}

func bkvProviderID(region, account, name string) string {
	return "bkv:" + region + ":" + account + ":" + name
}

func splitBkvProviderID(providerID string) (region, account, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "bkv" {
		return "", "", "", fmt.Errorf("providerId %q is not bkv:region:account:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !backupVaultNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId vault name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func bkvArn(region, account, name string) string {
	return fmt.Sprintf("arn:aws:backup:%s:%s:backup-vault:%s", region, account, name)
}

type bkvDescribe struct {
	BackupVaultArn   string `json:"BackupVaultArn"`
	EncryptionKeyArn string `json:"EncryptionKeyArn"`
	Locked           bool   `json:"Locked"`
	MinRetentionDays int    `json:"MinRetentionDays"`
}

// describeBkv reads a vault. found=false + readable=true is authoritative "does not
// exist"; readable=false is transport/HTTP/parse failure.
func (d *Driver) describeBkv(region, name string) (bkvDescribe, bool, error) {
	const op = "DescribeBackupVault"
	st, resp, err := d.backupCall("GET", region, "/backup-vaults/"+name, nil)
	if err != nil {
		return bkvDescribe{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound || strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return bkvDescribe{}, false, nil
	}
	if st != http.StatusOK {
		return bkvDescribe{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var doc bkvDescribe
	if json.Unmarshal(resp, &doc) != nil {
		return bkvDescribe{}, false, readBody(op, st)
	}
	return doc, true, nil
}

// bkvTags reads ownership tags via ListTags (GET /tags/{arn}). The ARN is rfc3986-
// encoded into the path so it signs and transmits identically.
func (d *Driver) bkvTags(region, arn string) (map[string]string, error) {
	const op = "ListTags"
	st, resp, err := d.backupCall("GET", region, "/tags/"+rfc3986(arn), nil)
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Tags map[string]string `json:"Tags"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	return r.Tags, nil
}

func (d *Driver) createBackupVault(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBackupVault(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Region != "" {
		region = plan.Region
	}
	pid := bkvProviderID(region, account, plan.Name)
	body, _ := json.Marshal(plan.createBody(capability, environment))
	st, resp, err := d.backupCall("PUT", region, "/backup-vaults/"+plan.Name, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateBackupVault outcome unknown (may have landed): %v", err)}
	case st >= 200 && st < 300:
		// created — apply the retention lock below
	case strings.Contains(ecsErr(resp), "AlreadyExists"):
		tags, terr := d.bkvTags(region, bkvArn(region, account, plan.Name))
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing vault tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a vault with this name exists and is not ours (tags do not match)"}
		}
		// ours — fall through to (idempotently) ensure the lock
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateBackupVault HTTP %d (server error — may have landed): %s", st, ecsErr(resp))}
	default:
		// D237: throttle/503/live-403 -> unknown WITH the pid (the vault name is
		// deterministic, keep the handle); only a clean 4xx refusal fails.
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "CreateBackupVault"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateBackupVault HTTP %d: %s", st, ecsErr(resp))}
	}

	// ---- retention lock (only when retention.minimum was asked) ----
	if lb := plan.lockBody(); lb != nil {
		lbody, _ := json.Marshal(lb)
		st, resp, err := d.backupCall("PUT", region, "/backup-vaults/"+plan.Name+"/vault-lock", lbody)
		if err != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "vault created; retention lock outcome unknown — reconcile"}
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("vault created; retention lock HTTP %d (server error) — reconcile", st)}
		}
		if st < 200 || st >= 300 {
			// D237: a throttle/503/live-403 on the lock step is unknown WITH the pid
			// (vault created, lock unconfirmed — reconcile), never failed.
			if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "vault retention lock"); r != nil {
				return *r
			}
			return provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("vault created but retention lock failed (retention NOT enforced): HTTP %d (%s)", st, ecsErr(resp))}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) observeBackupVault(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, name, err := splitBkvProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.describeBkv(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"backup vault not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if doc.MinRetentionDays > 0 {
		obs = append(obs, provider.Observation{Path: "retention.minimum",
			Value: fmt.Sprintf("%dh", doc.MinRetentionDays*24), Derivation: "measured"})
	}
	if doc.Locked {
		// a vault-lock in force enforces the minimum immutably (compliance). The
		// governance grace window is a transient state Describe does not distinguish.
		obs = append(obs, provider.Observation{Path: "retention.lockMode", Value: "compliance", Derivation: "measured"})
	}
	if doc.EncryptionKeyArn != "" && !strings.Contains(doc.EncryptionKeyArn, "aws/backup") {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteBackupVault(capability, environment, providerID string) provider.CreateResult {
	region, account, name, err := splitBkvProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, found, rerr := d.describeBkv(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.bkvTags(region, bkvArn(region, account, name))
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "ownership tags gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "vault tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, err := d.backupCall("DELETE", region, "/backup-vaults/"+name, nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if st == http.StatusNotFound || strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if strings.Contains(ecsErr(resp), "InvalidRequest") || strings.Contains(string(resp), "recovery points") {
		return provider.CreateResult{Status: "failed",
			Reason: "vault still holds recovery points (or is compliance-locked) — recovery points are data; they must age out or be deleted first (never forced)"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		// D237: throttle/503/live-403 -> unknown WITH the pid, never failed.
		if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
