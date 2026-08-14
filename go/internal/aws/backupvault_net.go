// AWS Backup Vault network shell (D127): the SigV4-signed, REST-JSON half of the AWS
// capability.backup.vault driver. CreateBackupVault is PUT /backup-vaults/{name};
// GET/DELETE follow; the retention lock is PUT /backup-vaults/{name}/vault-lock. The
// name is deterministic, so the pid is knowable BEFORE the response (D29). Ownership is
// tags read via ListTags (GET /tags/{arn}/) — the ARN is single-encoded on the wire and
// the SigV4 signer double-encodes its canonical to match (D880). Delete refuses a non-empty
// or compliance-locked vault (never forced). D880 proved on a real account: create → retire
// deletes; before it, retire returned unknown forever and leaked the vault.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/adoptcheck"
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
	// LockDate is the moment the lock becomes immutable. AWS: "If you applied Vault
	// Lock to your vault without specifying a lock date, you can change any of your
	// Vault Lock settings, or delete Vault Lock from the vault entirely, at any time."
	// It is the ONLY field that tells the two modes apart — `Locked` is true for both
	// (D724).
	LockDate         float64 `json:"LockDate"`
	MinRetentionDays int     `json:"MinRetentionDays"`
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

// bkvTags reads ownership tags via ListTags (GET /tags/{resourceArn}/). D880: the ARN is
// single-encoded on the wire (rfc3986: %3A) with the model's trailing slash, EXACTLY as
// botocore serializes it — and the SigV4 signer double-encodes the canonical (%253A) to
// match what AWS computes from the received request. The original 403 was the signer
// single-encoding its canonical while the wire carried %3A; a delete/adopt that cannot
// read ownership tags returns unknown forever, leaking every backup vault and plan it made.
// encoded into the path so it signs and transmits identically.
func (d *Driver) bkvTags(region, arn string) (map[string]string, error) {
	const op = "ListTags"
	st, resp, err := d.backupCall("GET", region, "/tags/"+rfc3986(arn)+"/", nil)
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

// bkvAdoptControls: the vault's EncryptionKeyArn (customer key) is set INLINE in the
// create body and is fixed at create (D1062), so on a 409-adopt it never applied — a
// missing customer key FAILS the adopt. The retention lock is re-asserted on the adopt
// path already (clean), so retention is not an adopt control here.
var bkvAdoptControls = []adoptcheck.Control{
	{Path: "encryption.customerManagedKeys", Direction: adoptcheck.SecureTrue, ImmutableAtCreate: true},
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
	adopted := false
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
		// ours — fall through to (idempotently) ensure the lock, then re-check controls (D1062)
		adopted = true
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
	// D1062: an ADOPTED vault (409, ours) never received the create body's inline
	// EncryptionKeyArn — the customer key is fixed at create. The retention lock above
	// is re-asserted on both paths (clean), but the key is not; re-check it against this
	// driver's OWN measured observation before reporting succeeded. A missing customer
	// key is immutable and fails rather than lying that BYOK is in place.
	if adopted {
		obs, _, oerr := d.observeBackupVault(capability, pid)
		if oerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "adopted vault re-observe gave no answer — reconcile: " + oerr.Error()}
		}
		switch v := adoptcheck.Compare(attrs, obs, bkvAdoptControls); v.Status {
		case "failed":
			return provider.CreateResult{Status: "failed", Reason: v.Reason}
		case "unknown":
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: v.Reason}
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
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"backup vault not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if doc.MinRetentionDays > 0 {
		obs = append(obs, provider.Observation{Path: "retention.minimum",
			Value: fmt.Sprintf("%dh", doc.MinRetentionDays*24), Derivation: "measured"})
	}
	if doc.Locked {
		// D724: `Locked` alone said COMPLIANCE, and it is true in BOTH modes — so a
		// vault any administrator could unlock read as immutable WORM, and a contract
		// demanding compliance was satisfied by a vault that gives none. LockDate is
		// what separates them, and it was in this response all along.
		switch {
		case doc.LockDate == 0:
			// no lock date: deletable at any time — governance, and that is measured.
			obs = append(obs, provider.Observation{Path: "retention.lockMode",
				Value: "governance", Derivation: "measured"})
		case int64(doc.LockDate) <= d.Now().Unix():
			// the lock date has passed: immutable, by the vendor's own words.
			obs = append(obs, provider.Observation{Path: "retention.lockMode",
				Value: "compliance", Derivation: "measured"})
		default:
			// compliance-CONFIGURED but still inside the cooling-off window, so the
			// WORM guarantee is not in force yet. Claiming it now is the false reading
			// this entry exists to remove: withhold the value and say why (D29).
			diags = append(diags, fmt.Sprintf("retention.lockMode not observed: the vault "+
				"lock is configured for compliance but becomes immutable only at %s — "+
				"until then it can still be deleted",
				time.Unix(int64(doc.LockDate), 0).UTC().Format(time.RFC3339)))
		}
	}
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
		Value: doc.EncryptionKeyArn != "" && !strings.Contains(doc.EncryptionKeyArn, "aws/backup"), Derivation: "measured"})
	return obs, diags, nil
}

func (d *Driver) deleteBackupVault(capability, environment, providerID string) provider.CreateResult {
	region, account, name, err := splitBkvProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
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
