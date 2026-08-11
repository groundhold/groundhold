// Azure Backup policy network shell (D76 fala 4): the ARM half of the Azure
// capability.backup.plan driver (Microsoft.DataProtection/backupVaults/
// backupPolicies). A backupPolicy is a lightweight CONFIG child of an existing
// backupVault: the PUT is SYNCHRONOUS (no LRO poll — unlike the flexible server),
// create-or-update to a deterministic name. Ownership is the deterministic NAME (a
// DataProtection policy carries no tags); the vault is the substrate groundhold does not
// create, so location.region is VERIFIED against the live vault before the policy is
// written, never mutated. A lost PUT is unknown WITH the pid (create-or-update
// idempotates the retry); a 4xx is failed.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

// backupPolicyProviderID encodes sub + rg + vault + policy (5 segments).
func backupPolicyProviderID(sub, rg, vault, policy string) string {
	return "backuppolicy:" + sub + ":" + rg + ":" + vault + ":" + policy
}

func splitBackupPolicyProviderID(providerID string) (sub, rg, vault, policy string, err error) {
	parts := strings.SplitN(providerID, ":", 5)
	if len(parts) != 5 || parts[0] != "backuppolicy" {
		return "", "", "", "", fmt.Errorf("providerId %q is not backuppolicy:sub:rg:vault:policy", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid subscription", providerID)
	}
	if !rgOK.MatchString(parts[2]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid resource group", providerID)
	}
	if !backupVaultNameOK.MatchString(parts[3]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid vault name", providerID)
	}
	if !backupPolicyNameOK.MatchString(parts[4]) {
		return "", "", "", "", fmt.Errorf("providerId policy name %q is invalid — refusing to interpolate it into an ARM path", parts[4])
	}
	return parts[1], parts[2], parts[3], parts[4], nil
}

// backupPolicyURL builds the management-plane URL for one policy, bounding the vault
// and policy names (the D73 injection boundary; armURL bounds sub/rg).
func (d *Driver) backupPolicyURL(rg, vault, policy string) (string, error) {
	if !backupVaultNameOK.MatchString(vault) {
		return "", fmt.Errorf("backup vault name %q is invalid", vault)
	}
	if !backupPolicyNameOK.MatchString(policy) {
		return "", fmt.Errorf("backup policy name %q is invalid", policy)
	}
	return d.armURL(rg, "Microsoft.DataProtection/backupVaults/"+vault+"/backupPolicies/"+policy, dataProtectionAPIVersion)
}

func (d *Driver) backupVaultURL(rg, vault string) (string, error) {
	if !backupVaultNameOK.MatchString(vault) {
		return "", fmt.Errorf("backup vault name %q is invalid", vault)
	}
	return d.armURL(rg, "Microsoft.DataProtection/backupVaults/"+vault, dataProtectionAPIVersion)
}

// backupPolicyStartAnchor is the recurrence anchor (midnight UTC of the coordination
// clock's day) — a time-of-day fact the vocab does not carry, derived deterministically
// from d.Now, never a silent default.
func backupPolicyStartAnchor(now time.Time) string {
	u := now.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC).Format("2006-01-02T15:04:05Z")
}

// vaultLocation reads the backup vault's location (the policy's effective region).
// found=false with a nil error is an authoritative 404; a non-nil error names the
// transport/HTTP/parse failure.
func (d *Driver) vaultLocation(rg, vault string) (location string, found bool, err error) {
	const op = "backupVaults.get"
	vURL, uerr := d.backupVaultURL(rg, vault)
	if uerr != nil {
		return "", false, &armReadError{Op: op, Cause: "scope", Detail: uerr.Error()}
	}
	var doc struct {
		Location string `json:"location"`
	}
	found, err = d.armGetURLInto(op, vURL, &doc)
	if err != nil || !found {
		return "", false, err
	}
	return doc.Location, true, nil
}

type bkpPolicyDoc struct {
	Name       string `json:"name"`
	Properties struct {
		DatasourceTypes []string `json:"datasourceTypes"`
		PolicyRules     []struct {
			Name       string `json:"name"`
			ObjectType string `json:"objectType"`
			Trigger    struct {
				Schedule struct {
					RepeatingTimeIntervals []string `json:"repeatingTimeIntervals"`
				} `json:"schedule"`
			} `json:"trigger"`
			Lifecycles []struct {
				DeleteAfter struct {
					Duration string `json:"duration"`
				} `json:"deleteAfter"`
			} `json:"lifecycles"`
		} `json:"policyRules"`
	} `json:"properties"`
}

// getBackupPolicy reads a policy. found=false + readable=true is authoritative "does
// not exist"; readable=false is transport/HTTP/parse failure.
// getBackupPolicy reads the resource. D295: a read that produced nothing names its
// CAUSE (status + the provider's own code) instead of collapsing four
// different failures into one word; a 404 stays an authoritative absence.
func (d *Driver) getBackupPolicy(rg, vault, policy string) (bkpPolicyDoc, bool, error) {
	var doc bkpPolicyDoc
	pURL, uerr := d.backupPolicyURL(rg, vault, policy)
	if uerr != nil {
		return doc, false, &armReadError{Op: "backupPolicies.get", Cause: "scope", Detail: uerr.Error()}
	}
	found, err := d.armGetURLInto("backupPolicies.get", pURL, &doc)
	return doc, found, err
}

func (d *Driver) createBackupPolicy(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildBackupPolicy(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := backupPolicyProviderID(d.Subscription, plan.ResourceGroup, plan.VaultName, plan.Name)

	// refuse-before-mutate: the vault is substrate groundhold does not create. It MUST
	// exist, and location.region is VERIFIED against it (the D99 substrate trap), never
	// silently mutated on someone else's vault.
	loc, found, verr := d.vaultLocation(plan.ResourceGroup, plan.VaultName)
	if verr != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: "pre-create backup vault read gave no answer — cannot verify the vault before writing the policy; reconcile: " + verr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("backup vault %q not found in resource group %q — the vault is a separate capability.backup.vault that must exist first",
				plan.VaultName, plan.ResourceGroup)}
	}
	if azRegion(loc) != azRegion(plan.Region) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("location.region %q does not match the backup vault's region %q — the policy lives in the vault's region; refusing rather than silently disagreeing",
				plan.Region, loc)}
	}

	pURL, err := d.backupPolicyURL(plan.ResourceGroup, plan.VaultName, plan.Name)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	body, _ := json.Marshal(plan.createBody(backupPolicyStartAnchor(d.Now())))
	st, resp, e := d.doARM("PUT", pURL, body)
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("policy PUT outcome unknown (may have landed; create-or-update idempotates the retry): %v", e)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("policy PUT HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("policy PUT HTTP %d: %s", st, mutDetailAz(resp))}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// backupPolicyObservations reverse-maps a live policy (schedule + retention) plus the
// vault's region into vocabulary paths. copy.crossRegion is ALWAYS false measured — a
// DataProtection policy cannot express a cross-region copy (it is a vault concern), so
// reporting false is honest, not an omission.
func (d *Driver) backupPolicyObservations(rg, vault string, doc bkpPolicyDoc) ([]provider.Observation, []string) {
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "copy.crossRegion", Value: false, Derivation: "measured"},
	}
	var diags []string

	// location.region is the VAULT's region (the policy carries no location).
	loc, vfound, verr := d.vaultLocation(rg, vault)
	switch {
	case verr != nil:
		diags = append(diags, "location.region omitted: the vault read gave no answer: "+verr.Error())
	case !vfound || loc == "":
		diags = append(diags, "location.region omitted: the vault carries no location")
	default:
		obs = append(obs, provider.Observation{Path: "location.region", Value: azRegion(loc), Derivation: "measured"})
	}

	var haveSchedule, haveRetention bool
	for _, rule := range doc.Properties.PolicyRules {
		switch rule.ObjectType {
		case "AzureBackupRule":
			ivals := rule.Trigger.Schedule.RepeatingTimeIntervals
			if len(ivals) == 0 {
				continue
			}
			interval := ivals[0]
			if i := strings.LastIndex(interval, "/"); i >= 0 {
				interval = interval[i+1:]
			}
			if freq, ok := intervalToFrequency(interval); ok {
				obs = append(obs, provider.Observation{Path: "schedule.frequency", Value: freq, Derivation: "measured"})
				haveSchedule = true
			} else if interval != "" {
				diags = append(diags, "schedule interval "+interval+" is a bespoke recurrence with no canonical cadence — schedule.frequency omitted (RPO not derivable)")
			}
		case "AzureRetentionRule":
			if len(rule.Lifecycles) == 0 {
				continue
			}
			iso := rule.Lifecycles[0].DeleteAfter.Duration
			if hours, ok := retentionISOToHours(iso); ok {
				obs = append(obs, provider.Observation{Path: "retention.duration",
					Value: fmt.Sprintf("%dh", hours), Derivation: "measured"})
				haveRetention = true
			} else if iso != "" {
				diags = append(diags, "retention deleteAfter "+iso+" is not a plain day/week duration — retention.duration omitted")
			}
		}
	}
	if !haveSchedule {
		diags = append(diags, "policy has no schedule-based backup rule — schedule.frequency (RPO) unobservable")
	}
	if !haveRetention {
		diags = append(diags, "policy has no retention rule — retention.duration unobservable")
	}
	return obs, diags
}

func (d *Driver) observeBackupPolicy(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, vault, policy, err := splitBackupPolicyProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getBackupPolicy(rg, vault, policy)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return []provider.Observation{
			// F-LC3 (D802): a BOUND resource the API authoritatively 404s is GONE. An
			// empty return leaves the last good observations standing as the freshest
			// word, so posture reads managed-ok and audit stays satisfied about a
			// resource that does not exist (D513/D518, fixed here last).
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"backup policy not found — bound resource is gone (will re-create)"}, nil
	}
	obs, diags := d.backupPolicyObservations(rg, vault, doc)
	return obs, diags, nil
}

func (d *Driver) updateBackupPolicy(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	sub, rg, vault, policy, err := splitBackupPolicyProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	// ownership: the deterministic NAME is the marker (no tags on the object).
	if !backupPolicyOurs(policy, environment, capability) {
		return provider.CreateResult{Status: "failed",
			Reason: "backup policy name does not carry our ownership marker — refusing to patch a resource that is not ours"}
	}
	// only the wired mutable paths may reach the updater (fail closed on anything else).
	for _, path := range changes {
		if kind, _ := classifyBackupPolicyChange(path); kind != "mutable" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("azure backup policy in-place update does not honor %q — reconcile", path)}
		}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape.
	plan, err := BuildBackupPolicy(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, found, rerr := d.getBackupPolicy(rg, vault, policy)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "backup policy to update no longer exists — reconcile"}
	}
	pURL, err := d.backupPolicyURL(rg, vault, policy)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// a full PUT replaces the rule set — cadence + retention both live in policyRules.
	body, _ := json.Marshal(plan.createBody(backupPolicyStartAnchor(d.Now())))
	st, resp, e := d.doARM("PUT", pURL, body)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("patch outcome unknown (may have landed): %v", e)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("patch HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("patch HTTP %d: %s", st, mutDetailAz(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

func (d *Driver) deleteBackupPolicy(capability, environment, providerID string) provider.CreateResult {
	sub, rg, vault, policy, err := splitBackupPolicyProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	// ownership: the deterministic NAME is the marker. A name that does not carry our
	// (env, cap) owner token is never deleted.
	if !backupPolicyOurs(policy, environment, capability) {
		return provider.CreateResult{Status: "failed",
			Reason: "backup policy name does not carry our ownership marker — refusing to delete a resource that is not ours"}
	}
	_, found, rerr := d.getBackupPolicy(rg, vault, policy)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	pURL, err := d.backupPolicyURL(rg, vault, policy)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// A policy is a SCHEDULE, not a store (stateful: false) — deleting it stops future
	// backups but never deletes recovery points already in the vault, so no data-loss gate.
	if r := d.deleteAndConfirm(pURL, providerID, "backup policy"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverBackupPolicy enumerates DataProtection backup policies in the region as
// capability.backup.plan: list backupVaults, keep the in-region ones, list each
// vault's policies, then the same reverse map observe uses. A policy whose name is
// not representable as a providerId becomes a diagnostic, never a fabricated record.
func (d *Driver) discoverBackupPolicy(region string) ([]provider.Discovered, []string, error) {
	listURL := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.DataProtection/backupVaults?api-version=%s",
		d.BaseURL, d.Subscription, dataProtectionAPIVersion)
	st, resp, err := d.doARM("GET", listURL, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("backupVaults.list: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("backupVaults.list: HTTP %d", st)
	}
	var vaults struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &vaults) != nil {
		return nil, nil, &armReadError{Op: "backupVaults.list", Cause: "body", Status: st}
	}
	want := azRegion(region)
	var out []provider.Discovered
	var diags []string
	for _, v := range vaults.Value {
		if azRegion(v.Location) != want {
			continue
		}
		rg := resourceGroupOf(v.ID)
		if rg == "" {
			diags = append(diags, v.Name+": resource group unparseable from id")
			continue
		}
		if !backupVaultNameOK.MatchString(v.Name) {
			diags = append(diags, v.Name+": vault name not representable as a providerId")
			continue
		}
		polURL, perr := d.armURL(rg, "Microsoft.DataProtection/backupVaults/"+v.Name+"/backupPolicies", dataProtectionAPIVersion)
		if perr != nil {
			diags = append(diags, v.Name+": "+perr.Error())
			continue
		}
		pst, presp, perr := d.doARM("GET", polURL, nil)
		if perr != nil {
			diags = append(diags, v.Name+": "+armTransport("backupPolicies.list", perr).Error())
			continue
		}
		if pst != http.StatusOK {
			diags = append(diags, v.Name+": "+armHTTP("backupPolicies.list", pst, presp).Error())
			continue
		}
		var pols struct {
			Value []struct {
				Name string `json:"name"`
			} `json:"value"`
		}
		_ = json.Unmarshal(presp, &pols)
		for _, pol := range pols.Value {
			if !backupPolicyNameOK.MatchString(pol.Name) {
				diags = append(diags, v.Name+"/"+pol.Name+": policy name not representable as a providerId")
				continue
			}
			pid := backupPolicyProviderID(d.Subscription, rg, v.Name, pol.Name)
			obs, odiags, oerr := d.observeBackupPolicy("", pid)
			if oerr != nil {
				diags = append(diags, v.Name+"/"+pol.Name+": "+oerr.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, v.Name+"/"+pol.Name+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.backup.plan",
				Observations: provider.WithoutAbsence(obs),
			})
		}
	}
	return out, diags, nil
}
