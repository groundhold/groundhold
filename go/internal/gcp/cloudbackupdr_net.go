// Backup and DR network shell (D127): the httptest-covered half of the GCP
// capability.backup.vault driver. backupVaults.create is a googleapis LRO (poll the
// operation to done, mirroring memorystore). The vault id is deterministic, so the
// providerId is knowable BEFORE the response (D29). Ownership is LABELS. Delete is an
// LRO; a vault still within its enforced retention (holding backups) refuses — recovery
// points are data, never force-deleted.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

const backupDRBaseURL = "https://backupdr.googleapis.com/v1"

func (d *Driver) backupDRBase() string {
	if d.BackupDRBaseURL != "" {
		return d.BackupDRBaseURL
	}
	return backupDRBaseURL
}

func backupDRProviderID(project, location, vaultID string) string {
	return "gbkv:" + project + ":" + location + ":" + vaultID
}

func splitBackupDRProviderID(providerID string) (project, location, vaultID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "gbkv" {
		return "", "", "", fmt.Errorf("providerId %q is not gbkv:project:location:vaultId", providerID)
	}
	for i, p := range parts[1:] {
		if !gcpName.MatchString(p) {
			return "", "", "", fmt.Errorf("providerId component %d (%q) is not a valid GCP identifier", i+1, p)
		}
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) backupDRVaultURL(project, location, vaultID string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/backupVaults/%s", d.backupDRBase(), project, location, vaultID)
}

// pollBackupDROperation polls a googleapis LRO to done.
func (d *Driver) pollBackupDROperation(opName string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, body, err := d.call("GET", d.backupDRBase()+"/"+opName, nil)
		if err == nil && st == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Done {
				if op.Error != nil {
					return provider.CreateResult{Status: "failed", OperationID: opName,
						Reason: "operation failed: " + op.Error.Message}
				}
				return provider.CreateResult{Status: "succeeded", OperationID: opName}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{Status: "unknown", OperationID: opName,
				Reason: "backupdr operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

type backupDRDoc struct {
	Labels                                 map[string]string `json:"labels"`
	BackupMinimumEnforcedRetentionDuration string            `json:"backupMinimumEnforcedRetentionDuration"`
}

func (doc backupDRDoc) ours(capability, environment string) bool {
	return doc.Labels["groundhold-capability"] == sanitizeLabel(capability) &&
		doc.Labels["groundhold-environment"] == sanitizeLabel(environment)
}

func (d *Driver) backupDRGet(project, location, vaultID string) (backupDRDoc, bool, error) {
	const op = "backupDRGet.get"
	st, body, err := d.call("GET", d.backupDRVaultURL(project, location, vaultID), nil)
	if err != nil {
		return backupDRDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return backupDRDoc{}, false, nil
	}
	if st != http.StatusOK {
		return backupDRDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc backupDRDoc
	if json.Unmarshal(body, &doc) != nil {
		return backupDRDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createBackupDR(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBackupDRVault(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := backupDRProviderID(d.Project, plan.Location, plan.VaultID)
	url := fmt.Sprintf("%s/projects/%s/locations/%s/backupVaults?backupVaultId=%s",
		d.backupDRBase(), d.Project, plan.Location, plan.VaultID)
	st, body, err := d.call("POST", url, plan.createBody())
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("backupVaults.create outcome unknown (may have landed): %v", err)}
	case st == http.StatusConflict:
		doc, found, rerr := d.backupDRGet(d.Project, plan.Location, plan.VaultID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict, existing vault gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !doc.ours(capability, environment) {
			return provider.CreateResult{Status: "failed", Reason: "a vault with this id exists and is not ours (labels do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("backupVaults.create HTTP %d (server error — may have landed): %s", st, mutDetail(body))}
	case st >= 400:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "backupVaults.create"); r != nil {
			return *r // D237: 429/403 is a wire fact, not an orphan — unknown+pid
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("backupVaults.create HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "create response carried no operation — reconcile"}
	}
	res := d.pollBackupDROperation(op.Name)
	res.ProviderID = pid
	return res
}

func (d *Driver) observeBackupDR(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, vaultID, err := splitBackupDRProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.backupDRGet(project, location, vaultID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"backup vault not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a GCP backup vault's enforced retention is immutable by construction.
		{Path: "retention.lockMode", Value: "compliance", Derivation: "measured"},
	}
	if s := doc.BackupMinimumEnforcedRetentionDuration; s != "" {
		obs = append(obs, provider.Observation{Path: "retention.minimum", Value: s, Derivation: "measured"})
	}
	return obs, []string{"encryption.customerManagedKeys not observed: Backup and DR vaults use Google-managed encryption"}, nil
}

func (d *Driver) deleteBackupDR(capability, environment, providerID string) provider.CreateResult {
	project, location, vaultID, err := splitBackupDRProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.backupDRGet(project, location, vaultID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !doc.ours(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "vault labels do not match — refusing to delete a resource that is not ours"}
	}
	st, body, err := d.call("DELETE", d.backupDRVaultURL(project, location, vaultID), nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st == http.StatusConflict || strings.Contains(string(body), "FAILED_PRECONDITION") || strings.Contains(string(body), "not empty") {
		return provider.CreateResult{Status: "failed",
			Reason: "vault still holds backups within its enforced retention — recovery points are data; they must age out first (never forced)"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r // D237: 429/403 is a wire fact, not authoritative absence — unknown+pid
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollBackupDROperation(op.Name)
	res.ProviderID = providerID
	return res
}
