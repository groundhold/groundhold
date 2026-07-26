// Azure PostgreSQL Flexible Server network shell (D99): the ARM half of the Azure
// database.relational driver. A single ARM resource (no server+db composite); PUT
// is async, polled to properties.state == Ready. Ownership is tags; encryption in
// transit is enforced by default (no field to set), so observe reports it as
// config-intent true. Admin credentials come from the impl block and are never
// echoed into a receipt.
package azure

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"groundhold/internal/caplens"
	"groundhold/internal/provider"
)

func flexProviderID(sub, rg, name string) string {
	return "flexpg:" + sub + ":" + rg + ":" + name
}

func splitFlexProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "flexpg" {
		return "", "", "", fmt.Errorf("providerId %q is not flexpg:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !azNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) flexPath(name string) string {
	return "Microsoft.DBforPostgreSQL/flexibleServers/" + name
}

func (d *Driver) createFlexServer(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildFlexServer(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed", Reason: "azure flexible server requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := flexProviderID(d.Subscription, rg, plan.Name)

	sku, _ := impl["sku"].(string)
	if sku == "" {
		sku = "Standard_B1ms"
	}
	pubAccess := "Disabled"
	if plan.PublicAccess {
		pubAccess = "Enabled"
	}
	props := map[string]any{
		"version":                    plan.Version,
		"administratorLogin":         plan.AdminUser,
		"administratorLoginPassword": plan.AdminPassword,
		"storage":                    map[string]any{"storageSizeGB": 32},
		"network":                    map[string]any{"publicNetworkAccess": pubAccess},
	}
	if plan.BackupRetentionDays > 0 {
		props["backup"] = map[string]any{"backupRetentionDays": plan.BackupRetentionDays}
	}
	if plan.ZoneRedundant {
		props["highAvailability"] = map[string]any{"mode": "ZoneRedundant"}
	} else {
		props["highAvailability"] = map[string]any{"mode": "Disabled"}
	}
	if plan.KmsKeyURI != "" {
		props["dataEncryption"] = map[string]any{
			"type":                          "AzureKeyVault",
			"primaryKeyURI":                 plan.KmsKeyURI,
			"primaryUserAssignedIdentityId": plan.KmsIdentity,
		}
	}
	url, _ := d.armURL(rg, d.flexPath(plan.Name), pgAPIVersion)
	body, _ := json.Marshal(map[string]any{
		"location":   plan.Region,
		"tags":       d.tags(capability, environment),
		"sku":        map[string]any{"name": sku, "tier": "Burstable"},
		"properties": props,
	})
	// D254/D256: refuse a foreign server; and — because the create body carries the
	// administratorLoginPassword, which cannot be observed to make a reality-exact
	// candidate — ADOPT an existing OURS server (bind, no re-PUT) rather than reset
	// its password to the declared value on a lost-ledger self-adopt.
	if r := d.refuseForeignOrAdopt(url, body, pid); r != nil {
		return *r
	}
	st, resp, err := d.doARM("PUT", url, body)
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		// D237: throttle/503/live-403 -> unknown (keep the deterministic pid),
		// never a terminal failed.
		if r := provider.MutationResult(st, azErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetailAz(resp))}
	}
	// poll to Ready
	deadline := d.Now().Add(d.PollTimeout)
	for {
		state, readable := d.flexState(rg, plan.Name)
		if readable {
			switch state {
			case "Ready":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "Failed", "Dropping", "Disabled":
				return provider.CreateResult{ProviderID: pid, Status: "failed", Reason: "server entered state " + state}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "server still provisioning at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

type flexDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		State   string `json:"state"`
		Version string `json:"version"`
		Network struct {
			PublicNetworkAccess string `json:"publicNetworkAccess"`
		} `json:"network"`
		Backup struct {
			BackupRetentionDays int `json:"backupRetentionDays"`
		} `json:"backup"`
		HighAvailability struct {
			Mode string `json:"mode"`
		} `json:"highAvailability"`
		DataEncryption struct {
			Type string `json:"type"`
		} `json:"dataEncryption"`
	} `json:"properties"`
}

// getFlex reads the resource. D295: a read that produced nothing names its
// CAUSE (status + the provider's own code) instead of collapsing four
// different failures into one word; a 404 stays an authoritative absence.
func (d *Driver) getFlex(rg, name string) (flexDoc, bool, error) {
	var doc flexDoc
	url, uerr := d.armURL(rg, d.flexPath(name), pgAPIVersion)
	if uerr != nil {
		return doc, false, &armReadError{Op: "flexibleServers.get", Cause: "scope", Detail: uerr.Error()}
	}
	found, err := d.armGetURLInto("flexibleServers.get", url, &doc)
	return doc, found, err
}

func (d *Driver) flexState(rg, name string) (string, bool) {
	doc, found, rerr := d.getFlex(rg, name)
	if rerr != nil || !found {
		// a poll helper answers (state, ok) — the CAUSE travels through the
		// observe/reconcile paths that need it; here "not ready yet" is the
		// honest reduction (D295 keeps the four-valued meaning intact).
		return "", false
	}
	return doc.Properties.State, true
}

func (d *Driver) observeFlexServer(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitFlexProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getFlex(rg, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"flexible server not found — nothing to observe"}, nil
	}
	var obs []provider.Observation
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	obs = append(obs,
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		provider.Observation{Path: "encryption.atRest", Value: true, Derivation: "config-intent"},
		// TLS is enforced by default on Flexible Server (require_secure_transport).
		provider.Observation{Path: "encryption.inTransit", Value: true, Derivation: "config-intent"},
	)
	if doc.Properties.Version != "" {
		obs = append(obs, provider.Observation{Path: "engine.protocol",
			Value: caplens.EngineProtocol(caplens.EnginePostgres, doc.Properties.Version), Derivation: "measured"})
	}
	var diags []string
	// an absent/unreadable network block must not collapse to a measured false
	// (the false-safe direction) — absent publicNetworkAccess is unknown.
	switch doc.Properties.Network.PublicNetworkAccess {
	case "Enabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: true, Derivation: "measured"})
	case "Disabled":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	default:
		diags = append(diags, "network.publicExposure not observed: publicNetworkAccess absent from the server's network block")
	}
	class := caplens.AvailabilityClass(doc.Properties.HighAvailability.Mode == "ZoneRedundant")
	obs = append(obs, provider.Observation{Path: "availability.class", Value: class, Derivation: "measured"})
	if doc.Properties.Backup.BackupRetentionDays > 0 {
		obs = append(obs, provider.Observation{Path: "recovery.rpo",
			Value: fmt.Sprintf("%dd", doc.Properties.Backup.BackupRetentionDays), Derivation: "measured"})
	}
	if doc.Properties.DataEncryption.Type == "AzureKeyVault" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	return obs, diags, nil
}

func (d *Driver) deleteFlexServer(capability, environment, providerID string) provider.CreateResult {
	_, rg, name, err := splitFlexProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getFlex(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "flexible server tags do not match — refusing to delete a resource that is not ours"}
	}
	url, _ := d.armURL(rg, d.flexPath(name), pgAPIVersion)
	if r := d.deleteAndConfirm(url, providerID, "flexible server"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
