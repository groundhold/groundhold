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

	// D947: availability.class=regional maps to ZoneRedundant HA, but zone-redundant HA
	// is a per-region/subscription capability — where it is Disabled, Azure ACCEPTS the
	// PUT (202) and then rolls the server back ~20 minutes later, leaving the operator
	// with a converge that returns `unknown` and no server. Preflight the region's
	// capabilities and refuse UP FRONT with a clear reason. Skip-loudly: a capabilities
	// read that does not conclude (transport/parse/absent) lets the create proceed
	// rather than blocking on an inconclusive check (D75 stance).
	if plan.ZoneRedundant {
		if supported, known := d.flexZoneRedundantSupported(plan.Region); known && !supported {
			return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf(
				"availability.class=regional (zone-redundant HA) is not offered by PostgreSQL "+
					"Flexible Server in %s for this subscription — the region's capabilities report "+
					"zoneRedundantHaSupported=Disabled, so Azure accepts the create then rolls it back "+
					"after ~20 minutes. Refusing up front; choose a region that supports zone-redundant "+
					"HA (or availability.class=zonal)", plan.Region)}
		}
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
		"sku":        map[string]any{"name": plan.Sku, "tier": plan.Tier},
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

// flexZoneRedundantSupported reads the PostgreSQL Flexible Server capabilities for a
// region and reports whether zone-redundant HA is offered there for this subscription.
// known=false means the check did NOT conclude (transport/HTTP/parse/absent) — the
// caller proceeds rather than blocking a create on an inconclusive read (D947/D75).
func (d *Driver) flexZoneRedundantSupported(region string) (supported, known bool) {
	url := d.BaseURL + "/subscriptions/" + d.Subscription +
		"/providers/Microsoft.DBforPostgreSQL/locations/" + region + "/capabilities?api-version=" + pgAPIVersion
	// listAllARMPages follows nextLink — the capabilities envelope is a `value` list, so
	// read it as one (the region's FlexibleServerCapabilities descriptor is its first
	// element and carries the flag).
	err := d.listAllARMPages("flex.capabilities", url, func(body []byte) error {
		var doc struct {
			Value []struct {
				ZoneRedundantHaSupported string `json:"zoneRedundantHaSupported"`
			} `json:"value"`
		}
		if json.Unmarshal(body, &doc) != nil {
			return fmt.Errorf("flex capabilities page did not parse")
		}
		for _, v := range doc.Value {
			if v.ZoneRedundantHaSupported != "" && !known {
				known = true
				supported = v.ZoneRedundantHaSupported == "Enabled"
			}
		}
		return nil
	})
	if err != nil {
		return false, false // inconclusive read — do not block the create
	}
	return supported, known
}

type flexDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		State   string `json:"state"`
		Version string `json:"version"`
		Network struct {
			PublicNetworkAccess         string `json:"publicNetworkAccess"`
			DelegatedSubnetResourceID   string `json:"delegatedSubnetResourceId"`
			PrivateDNSZoneArmResourceID string `json:"privateDnsZoneArmResourceId"`
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
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"flexible server not found — bound resource is gone (will re-create)"}, nil
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	var diags []string
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
	}
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	obs = append(obs,
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		provider.Observation{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
	)
	// D761. This asserted `encryption.inTransit: true` with the comment "TLS is enforced
	// by DEFAULT on Flexible Server (require_secure_transport)" — and a default is not a
	// guarantee. require_secure_transport is a server PARAMETER an operator can set to
	// off, and then the server accepts plaintext while this driver reports encrypted
	// transit. Found by D760, which asked of every asserted constant whether it is true
	// of EVERY instance; this one is the answer that was no.
	switch v, readable := d.flexRequireSecureTransport(rg, name); {
	case !readable:
		diags = append(diags, "encryption.inTransit not observed: the server parameter "+
			"require_secure_transport could not be read, and its DEFAULT is not evidence "+
			"about this server")
	default:
		obs = append(obs, provider.Observation{Path: "encryption.inTransit",
			Value: v, Derivation: "measured"})
	}
	if doc.Properties.Version != "" {
		obs = append(obs, provider.Observation{Path: "engine.protocol",
			Value: caplens.EngineProtocol(caplens.EnginePostgres, doc.Properties.Version), Derivation: "measured"})
	}
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
	// recovery.rpo is NOT observed here, and the reason is the whole point (D796):
	// backupRetentionDays says how far BACK a restore can reach, not how much data a
	// failure can lose. Flexible Server takes transaction-log backups continuously and
	// restores to any point inside that window, so its data-loss window is a MEASUREMENT
	// — a probe's job, exactly as the GCP driver already says when PITR is on. Echoing
	// the retention days as the RPO reported a 7-day loss window for a server that loses
	// minutes, and the direction of that lie is what makes it a defect: a contract asking
	// for a tighter RPO looked violated, and the way to "fix" it was to SHORTEN backup
	// retention.
	if doc.Properties.Backup.BackupRetentionDays > 0 {
		diags = append(diags, fmt.Sprintf("recovery.rpo not observed: backup retention is "+
			"%d day(s), which is how far back a restore reaches, not the data-loss window; "+
			"Flexible Server restores to any point in that window, so its RPO is a probe's "+
			"measurement rather than a config read",
			doc.Properties.Backup.BackupRetentionDays))
	}
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: doc.Properties.DataEncryption.Type == "AzureKeyVault", Derivation: "measured"})
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

// flexRequireSecureTransport reads the server parameter that decides whether this
// PostgreSQL Flexible Server accepts an unencrypted connection (D761). Returns
// (enforced, readable); readable=false is "we could not tell", never "off" and never a
// fall back to the default — a default describes the service, and this attribute is a
// claim about THIS server.
func (d *Driver) flexRequireSecureTransport(rg, name string) (enforced, readable bool) {
	url, uerr := d.armURL(rg,
		d.flexPath(name)+"/configurations/require_secure_transport", pgAPIVersion)
	if uerr != nil {
		return false, false
	}
	var doc struct {
		Properties struct {
			Value string `json:"value"`
		} `json:"properties"`
	}
	found, err := d.armGetURLInto("flexibleServers.configurations.get", url, &doc)
	if err != nil || !found {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(doc.Properties.Value)) {
	case "on", "true", "1":
		return true, true
	case "off", "false", "0":
		return false, true
	}
	return false, false // a value we cannot read is not a value we can vouch for
}

// classifyFlexServerChange decides whether a drift on a PostgreSQL Flexible Server is
// reconciled in place or is a replacement. Before D1205 the driver had NO classify for
// flexpostgres, so EVERY attribute fell to the driver-level default of "immutable" — and
// for a DATABASE, immutable means the reconcile is a destroy-and-recreate that loses every
// row. That is the honest classification when a knob truly is fixed at creation, but it is
// a catastrophic one to apply to a knob that Azure changes online.
//
// D1205: network.publicExposure is patched in place. publicNetworkAccess is Enabled/Disabled
// in ServerPropertiesForUpdate.network (not readOnly in the 2023-06-01-preview swagger), so a
// server that was discovered PUBLIC is turned PRIVATE by a PATCH — never by replacing the
// database. Everything else stays "immutable" with the same honest replacement reason the
// driver default gives, so the change in behaviour is scoped to the one exposure knob.
func classifyFlexServerChange(path string) (string, string) {
	switch path {
	case "network.publicExposure":
		return "mutable", "network.publicExposure is patched in place: publicNetworkAccess " +
			"Enabled/Disabled on the server, so a public database is made private without " +
			"replacing it (and destroying its data)"
	case "encryption.inTransit":
		// D1210: inTransit is observed from the require_secure_transport server PARAMETER (D761),
		// a DYNAMIC configuration (patchable online, no restart). So a server accepting plaintext
		// is made TLS-only by a configuration PATCH — never by replacing the database.
		return "mutable", "encryption.inTransit is patched in place: the require_secure_transport " +
			"server parameter, so a database accepting plaintext is made TLS-only without replacing it"
	default:
		return "immutable", fmt.Sprintf(
			"PostgreSQL Flexible Server has no in-place update path for %q — reconciling a drift is a replacement", path)
	}
}

// updateFlexServer remediates the server's online-patchable security knobs in place:
// network.publicExposure via network.publicNetworkAccess (D1205) and encryption.inTransit via
// the require_secure_transport configuration (D1210). Ownership is re-checked first (never
// patch a server that is not ours). The publicExposure PATCH preserves the VNet-integration
// fields (delegatedSubnetResourceId / privateDnsZoneArmResourceId) it read, so narrowing
// exposure on a VNet-injected server can never blank out its subnet. Four-valued: an ambiguous
// PATCH keeps the deterministic providerID (a terminal 4xx from Azure — e.g. a private-access
// server that cannot take a public endpoint — is an honest unknown, never a data-losing
// replacement).
func (d *Driver) updateFlexServer(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	sub, rg, name, err := splitFlexProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	doc, found, rerr := d.getFlex(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "flexible server no longer exists — cannot update"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "flexible server tags do not match — refusing to patch a resource that is not ours"}
	}

	url, _ := d.armURL(rg, d.flexPath(name), pgAPIVersion)
	for _, path := range changes {
		switch path {
		case "network.publicExposure":
			public, ok := attrs["network.publicExposure"].(bool)
			if !ok {
				return provider.CreateResult{Status: "failed", Reason: "network.publicExposure must be a bool"}
			}
			access := "Disabled"
			if public {
				access = "Enabled"
			}
			// Preserve the VNet-integration fields the pre-read saw — a PATCH that sent only
			// publicNetworkAccess could be treated as a full replace of the network object and
			// blank the subnet on a VNet-injected server.
			network := map[string]any{"publicNetworkAccess": access}
			if doc.Properties.Network.DelegatedSubnetResourceID != "" {
				network["delegatedSubnetResourceId"] = doc.Properties.Network.DelegatedSubnetResourceID
			}
			if doc.Properties.Network.PrivateDNSZoneArmResourceID != "" {
				network["privateDnsZoneArmResourceId"] = doc.Properties.Network.PrivateDNSZoneArmResourceID
			}
			body, _ := json.Marshal(map[string]any{"properties": map[string]any{"network": network}})
			if r := d.patchSetting(url, body, providerID, "flexible server publicNetworkAccess"); r != nil {
				return *r
			}
		case "encryption.inTransit":
			inTransit, ok := attrs["encryption.inTransit"].(bool)
			if !ok {
				return provider.CreateResult{Status: "failed", Reason: "encryption.inTransit must be a bool"}
			}
			// require_secure_transport is the server parameter the observe reads inTransit from
			// (D761): on => TLS-only, off => plaintext accepted. It is a DYNAMIC config, so the
			// PATCH applies online without a restart. A user-override source pins the operator's
			// intent over the platform default.
			value := "off"
			if inTransit {
				value = "on"
			}
			cfgURL, _ := d.armURL(rg, d.flexPath(name)+"/configurations/require_secure_transport", pgAPIVersion)
			body, _ := json.Marshal(map[string]any{"properties": map[string]any{"value": value, "source": "user-override"}})
			if r := d.patchSetting(cfgURL, body, providerID, "require_secure_transport"); r != nil {
				return *r
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: "no azure flexpostgres in-place mapping for " + path}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
