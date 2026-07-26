// Azure takeover claim (D140/D145): the Azure driver opts into provider.Claimer,
// mirroring the GCP slice. Once the driver is a Claimer, the compiler emits a
// one-time `claim` for every adopted-but-unclaimed Azure capability. Claim STAMPS
// groundhold's ownership marker (the same tags the driver applies on create) on the
// adopted ARM resource so a later drift pre-read recognises it as ours — closing the
// orphan gap (Q5): a converged no-op is a READ-ONLY proof of takeover, so an operator
// who runs `terraform state rm` after it left a resource with no groundhold marker, and
// the next real drift refused "not ours" with no writer left to repair it.
//
// D145 generalisation: unlike AWS (per-service ARNs) and GCP (per-service label
// APIs), Azure ARM `tags` are UNIFORM across EVERY resource type — a top-level map on
// the resource JSON, mutated by a full-map PATCH. So ONE generic helper
// (claimARMTags) claims them all; the ONLY per-service work is turning a service's
// providerID into (resourceURL, apiVersion). Every tag-bearing ARM service (the ones
// whose create builder stamps d.tags) routes through the same read-modify-write.
// Services that carry NO groundhold tag — RBAC role assignments/definitions, the
// change-feed proxy resource, the observe-only L4 load balancer groundhold never
// created — refuse HONESTLY (failed, "externally owned"), which stops the converge
// before the takeover signal so an unclaimable resource stays externally owned rather
// than orphaned. Unknown services fail closed via the shared service gate.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

var _ provider.Claimer = (*Driver)(nil)

// Claim dispatches per service (D76, fail-closed). A tag-bearing ARM service resolves
// its providerID to the ARM resource that carries the ownership tags and stamps them
// via the generic claimARMTags read-modify-write. A non-tag-bearing service refuses
// HONESTLY (a failed claim is safer than a silent one — no orphan).
func (d *Driver) Claim(service, capability, environment, providerID string) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url, reason, err := d.claimTarget(service, providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if reason != "" {
		return provider.CreateResult{Status: "failed", Reason: reason}
	}
	return d.claimARMTags(url, capability, environment, providerID)
}

// claimARMTags is the GENERIC read-modify-write tag stamp for ANY tag-bearing ARM
// resource. ARM `tags` is a MAP and a PATCH REPLACES the whole map, so this GETs the
// resource, MERGES groundhold's ownership tags into the operator's existing tags, and
// PATCHes back the UNION (the operator's TF-applied tags survive — a full-map patch
// would clobber them, metadata data-loss). It is provider-neutral over the resource
// URL (which already carries the api-version); the per-service resolver produced it.
// Reuses the exact d.tags(capability, environment) keys/values the create builders
// stamp, so a later drift pre-read's tag check recognises the resource as ours.
// Four-valued on the wire: a transport error or a server error is `unknown` WITH the
// providerId (never a silent success), a vanished resource or a clear 4xx is a clean
// `failed`, a 2xx is `succeeded` WITH the providerId.
func (d *Driver) claimARMTags(resourceURL, capability, environment, providerID string) provider.CreateResult {
	// READ: fetch the current tag map so the PATCH carries the UNION.
	st, body, err := d.doARM("GET", resourceURL, nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-claim read failed: %v", err)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{Status: "failed",
			Reason: "resource no longer exists — cannot claim"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-claim read HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("pre-claim read HTTP %d", st)}
	}
	var doc struct {
		Tags map[string]string `json:"tags"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return provider.CreateResult{Status: "failed", Reason: "pre-claim read unparseable"}
	}

	// MERGE groundhold's ownership tags into the operator's existing set (additive;
	// never a clobber). Reuses the exact keys/values the driver stamps on create.
	merged := map[string]any{}
	for k, v := range doc.Tags {
		merged[k] = v
	}
	for k, v := range d.tags(capability, environment) {
		merged[k] = v
	}

	patch, _ := json.Marshal(map[string]any{"tags": merged})
	pst, presp, perr := d.doARM("PATCH", resourceURL, patch)
	if perr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim outcome unknown (may have landed): %v", perr)}
	}
	if pst >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim HTTP %d (server error — may have landed) — reconcile", pst)}
	}
	if pst < 200 || pst >= 300 {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("claim HTTP %d: %s", pst, mutDetailAz(presp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// claimTarget turns a service's providerID into the ARM resource URL that carries the
// ownership tags (the resource whose delete-time tag check is the authority — for the
// substrate composites blob/azurefiles/servicebus/eventhubs/azurecdn/keyvaultkey that
// is the account/namespace/profile/vault, NOT the leaf). Three outcomes: a non-empty
// url proceeds to claimARMTags; a non-empty reason is an HONEST refuse (the service
// carries no groundhold tag); a non-nil err is a providerId parse/scope failure.
func (d *Driver) claimTarget(service, providerID string) (url, reason string, err error) {
	notTagged := func() (string, string, error) {
		return "", fmt.Sprintf("azure cannot claim ownership of a %q resource — it is not a "+
			"tag-bearing ARM resource (RBAC/proxy/observe-only resources carry no groundhold "+
			"tag); it stays externally owned; adoption is not takeover for this service", service), nil
	}
	switch service {
	// --- NOT tag-bearing ARM resources: honest refuse ---
	// defender (per-subscription pricings), consumptionbudget (proxy) and activitylog
	// (diagnostic setting) carry no tags — config/observe-only, ownership is a marker.
	case "roleassignment", "customroledef", "changefeed", "defender", "consumptionbudget", "activitylog",
		"aks-addon", "aks-workloadidentity", "backuppolicy":
		// aks-addon = a flag on someone else's cluster; aks-workloadidentity = a federated
		// credential with no tags; backuppolicy = a DataProtection proxy child (deterministic
		// name marker) — all structural, no ARM tag to stamp.
		return notTagged()

	// --- email.sending: tag-bearing ARM emailService root ---
	case "acsemail":
		sub, rg, name, e := splitACSEmailProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.acsEmailPath(name), acsEmailAPIVersion)

	// --- cluster: tag-bearing managed cluster ---
	case "aks":
		sub, rg, name, e := splitAKSProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.aksPath(name), aksAPIVersion)

	// --- posture parity: tag-bearing ARM resources ---
	case "loganalytics":
		sub, rg, name, e := splitLAProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.laPath(name), laAPIVersion)
	case "azureopenai":
		sub, rg, account, e := splitAzureOpenAIProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.aoiAccountPath(account), cognitiveAPIVersion)

	// --- database.relational: PostgreSQL Flexible Server ---
	case "flexpostgres":
		sub, rg, name, e := splitFlexProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.flexPath(name), pgAPIVersion)
	case "backupvault":
		sub, rg, vault, e := splitBackupVaultProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.DataProtection/backupVaults/"+vault, dataProtectionAPIVersion)

	// --- storage account substrate (tags on the account, not the leaf) ---
	case "blob":
		sub, rg, account, _, e := splitBlobProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.acctPath(account), storageAPIVersion)
	case "azurefiles":
		sub, rg, account, _, e := splitAzFilesProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.Storage/storageAccounts/"+account, storageAPIVersion)

	// --- network ---
	case "vnet":
		sub, rg, name, e := splitVNetProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.Network/virtualNetworks/"+name, networkAPIVersion)
	case "dnszone":
		sub, rg, kind, domain, e := splitAzureDNSProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		path, apiVersion := dnsTypePath(kind, domain)
		return d.claimURLFor(sub, rg, path, apiVersion)
	case "frontdoorwaf":
		sub, rg, name, e := splitFrontDoorWAFProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.frontDoorWAFPath(name), frontDoorWAFAPIVersion)
	case "azurecdn":
		sub, rg, profile, _, e := splitAzureCDNProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.cdnProfilePath(profile), azureCDNAPIVersion)
	case "loadbalancer":
		// L7 Application Gateway groundhold CREATED (tagged) is claimable; the L4
		// loadBalancers layer is OBSERVE-ONLY — groundhold never created it, so it refuses
		// to stamp ownership on it (the delete-side discipline, mirrored).
		kind, sub, rg, name, e := splitLBProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		if kind != "appgateway" {
			return "", fmt.Sprintf("azure cannot claim ownership of an observe-only %q resource — "+
				"this driver never created the L4 load balancer, so it will not stamp ownership; "+
				"it stays externally owned", kind), nil
		}
		return d.claimURLFor(sub, rg, "Microsoft.Network/applicationGateways/"+name, networkAPIVersion)

	// --- workload / container ---
	case "containerapps":
		sub, rg, app, e := splitACAProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.App/containerApps/"+app, appAPIVersion)
	case "containerappsjob":
		sub, rg, name, e := splitContainerAppsJobProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.containerAppsJobPath(name), containerAppsJobsAPIVersion)
	case "acr":
		sub, rg, name, e := splitAzureACRProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.ContainerRegistry/registries/"+name, acrAPIVersion)

	// --- messaging / streaming (tags on the namespace, not the entity) ---
	case "servicebusqueue", "servicebustopic":
		_, sub, rg, ns, _, e := splitSBProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.sbNamespacePath(ns), serviceBusAPIVersion)
	case "eventhubs":
		sub, rg, ns, _, e := splitEventHubsProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.ehNamespacePath(ns), eventHubsAPIVersion)
	case "azkafka":
		sub, rg, ns, e := splitAzKafkaProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.azKafkaPath(ns), azKafkaAPIVersion)

	// --- secret / key (tags on the vault) ---
	case "keyvault":
		sub, rg, vault, e := splitKeyVaultProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.vaultPath(vault), keyVaultAPIVersion)
	case "keyvaultkey":
		sub, rg, _, vault, _, e := splitAzureKeyProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.vaultPath(vault), keyVaultAPIVersion)

	// --- cache / database.nosql / search ---
	case "rediscache":
		sub, rg, name, e := splitRedisAzureProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.redisPath(name), redisAPIVersion)
	case "cosmos":
		sub, rg, account, e := splitCosmosProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.cosmosPath(account), cosmosAPIVersion)
	case "aisearch":
		sub, rg, name, e := splitAISearchProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.aiSearchPath(name), searchAPIVersion)

	// --- apigateway / identity ---
	case "apim":
		sub, rg, name, e := splitAPIMProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, d.apimPath(name), apimAPIVersion)
	case "managedidentity":
		sub, rg, name, e := splitUAMIProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.ManagedIdentity/userAssignedIdentities/"+name, managedIdentityAPIVersion)

	// --- monitoring (all four stamp d.tags at create, all taggable ARM types) ---
	case "metricalert":
		sub, rg, name, e := splitAzureAlertProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.Insights/metricAlerts/"+name, metricAlertAPIVersion)
	case "portaldash":
		sub, rg, name, e := splitAzureDashProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.Portal/dashboards/"+name, portalDashAPIVersion)
	case "webtest":
		sub, rg, name, e := splitAzureWebtestProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.Insights/webtests/"+name, webtestAPIVersion)
	case "scheduledquery":
		sub, rg, name, e := splitAzureSQProviderID(providerID)
		if e != nil {
			return "", "", e
		}
		return d.claimURLFor(sub, rg, "Microsoft.Insights/scheduledQueryRules/"+name, scheduledQueryAPIVersion)

	default:
		// A known-but-unrouted service: fail closed rather than guess a resource type.
		return "", fmt.Sprintf("azure service %q has no claim mapping — refusing (no default)", service), nil
	}
}

// claimURLFor validates the providerId's subscription against the driver's, then
// builds the ARM resource URL (bounding rg + subscription at the D73 injection
// boundary). armURL appends the api-version, so the returned URL is ready for GET/PATCH.
func (d *Driver) claimURLFor(sub, rg, providerPath, apiVersion string) (url, reason string, err error) {
	if sub != d.Subscription && d.Subscription != "" {
		return "", "", fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	u, e := d.armURL(rg, providerPath, apiVersion)
	if e != nil {
		return "", "", e
	}
	return u, "", nil
}
