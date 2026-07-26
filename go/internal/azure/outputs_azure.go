// Typed create outputs (D226/D275/D283) — the Azure half of the F13 wiring
// (D284), the same OutputProducer/OutputReader pair as AWS (D276) and GCP,
// mapped per-cloud honestly. Everything derives from the provider id except
// managedidentity's principalId/clientId — server-assigned GUIDs a consumer
// (a role assignment, a federated credential) genuinely needs — which come
// from one read of the standing identity. An underivable output demotes the
// create to unknown, mirroring the executor's receipt gate.
package azure

import (
	"fmt"
	"strings"

	"groundhold/internal/provider"
)

// azureOutputs declares ONLY what every succeeded create path can truthfully
// derive. Names are Azure-native (ARM ids, vault URIs) — per-cloud honesty
// over forced symmetry.
var azureOutputs = map[string][]provider.OutputSpec{
	"vnet": {
		{Name: "resourceGroup", Kind: "string", Sample: "gh-preflight-rg"},
		{Name: "vnetId", Kind: "string", Sample: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gh-preflight-rg/providers/Microsoft.Network/virtualNetworks/gh-preflight"},
		{Name: "vnetName", Kind: "string", Sample: "gh-preflight"},
	},
	"blob": {
		{Name: "blobEndpoint", Kind: "string", Sample: "https://ghpreflight.blob.core.windows.net"},
		{Name: "containerName", Kind: "string", Sample: "gh-preflight"},
		{Name: "storageAccount", Kind: "string", Sample: "ghpreflight"},
	},
	"servicebustopic": {
		{Name: "namespace", Kind: "string", Sample: "gh-preflight-ns"},
		{Name: "topicId", Kind: "string", Sample: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gh-preflight-rg/providers/Microsoft.ServiceBus/namespaces/gh-preflight-ns/topics/gh-preflight"},
		{Name: "topicName", Kind: "string", Sample: "gh-preflight"},
	},
	"managedidentity": {
		{Name: "clientId", Kind: "string", Sample: "00000000-0000-0000-0000-00000000000c"},
		{Name: "identityId", Kind: "string", Sample: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gh-preflight-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/gh-preflight"},
		{Name: "identityName", Kind: "string", Sample: "gh-preflight"},
		{Name: "principalId", Kind: "string", Sample: "00000000-0000-0000-0000-00000000000p"},
	},
	"keyvaultkey": {
		{Name: "keyUri", Kind: "string", Sample: "https://gh-preflight.vault.azure.net/keys/gh-preflight"},
		{Name: "vaultUri", Kind: "string", Sample: "https://gh-preflight.vault.azure.net"},
	},
	"aks": {
		{Name: "aksId", Kind: "string", Sample: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gh-preflight-rg/providers/Microsoft.ContainerService/managedClusters/gh-preflight"},
		{Name: "clusterName", Kind: "string", Sample: "gh-preflight"},
		{Name: "resourceGroup", Kind: "string", Sample: "gh-preflight-rg"},
	},
	// acr (capability.registry.image, F-registry): repositoryUri is the login
	// server — the Docker push base a workload.container/function.serverless
	// consumer wires as image: {$ref: {capability: <acr>, output: repositoryUri}}.
	// Azure login servers are always lowercase, so it is name-lowered — fully in
	// the acr:sub:rg:name pid, no read.
	"acr": {{Name: "repositoryUri", Kind: "string", Sample: "ghpreflight.azurecr.io"}},
	// backupvault (capability.backup.vault): a backup.plan (Data Protection
	// backupPolicy) is a CHILD of an existing vault — a consumer wires its
	// backupVaultName + resource_group operands as {$ref: {capability: <vault>,
	// output: vaultName | resourceGroup}}. All fields are fully in the
	// backupvault:sub:rg:vault pid — no read.
	"backupvault": {
		{Name: "resourceGroup", Kind: "string", Sample: "gh-preflight-rg"},
		{Name: "vaultId", Kind: "string", Sample: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gh-preflight-rg/providers/Microsoft.DataProtection/backupVaults/gh-preflight"},
		{Name: "vaultName", Kind: "string", Sample: "gh-preflight"},
	},
	// containerapps (capability.workload.container): fqdn is the ingress FQDN a
	// consumer wires by $ref and the post-apply reachability probe (D330) targets —
	// the Azure twin of GCP cloudrun's uri (a bare host, not a full URL). It is
	// SERVER-ASSIGNED (not pid-derivable), so it comes from ONE containerApps.get,
	// the honest source for a created AND an adopted app alike. It is published
	// regardless of ingress exposure (it IS the app's ingress host); the probe
	// gates PUBLIC-only separately (network.publicExposure), so an internal app
	// still exposes its fqdn for a same-network $ref without being probed —
	// mirroring internal Cloud Run, never a false unknown.
	"containerapps": {{Name: "fqdn", Kind: "string", Sample: "gh-preflight.happyhill-1a2b3c4d.westeurope.azurecontainerapps.io"}},
}

// OutputsFor implements provider.OutputProducer (D226).
func (d *Driver) OutputsFor(service string) []provider.OutputSpec {
	return azureOutputs[service]
}

// ReadOutputs implements provider.OutputReader (D283).
func (d *Driver) ReadOutputs(service, providerID string) (map[string]any, error) {
	if len(azureOutputs[service]) == 0 {
		return nil, nil
	}
	return d.deriveOutputs(service, providerID)
}

// attachOutputs fills cr.Outputs for a succeeded create of a declaring
// service; a derivation failure demotes to unknown with the cause named.
func (d *Driver) attachOutputs(service string, cr *provider.CreateResult) {
	if cr.Status != "succeeded" || len(azureOutputs[service]) == 0 {
		return
	}
	outs, err := d.deriveOutputs(service, cr.ProviderID)
	if err != nil {
		cr.Status = "unknown"
		cr.Reason = fmt.Sprintf("%s create succeeded but its declared outputs "+
			"are underivable — reconcile: %v", service, err)
		return
	}
	cr.Outputs = outs
}

func (d *Driver) deriveOutputs(service, pid string) (map[string]any, error) {
	switch service {
	case "vnet":
		sub, rg, name, err := splitVNetProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"resourceGroup": rg,
			"vnetName":      name,
			"vnetId": "/subscriptions/" + sub + "/resourceGroups/" + rg +
				"/providers/Microsoft.Network/virtualNetworks/" + name,
		}, nil
	case "blob":
		_, _, account, container, err := splitBlobProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"storageAccount": account,
			"containerName":  container,
			"blobEndpoint":   "https://" + account + ".blob.core.windows.net",
		}, nil
	case "servicebustopic":
		kind, sub, rg, ns, entity, err := splitSBProviderID(pid)
		if err != nil {
			return nil, err
		}
		if kind != "sbt" {
			return nil, fmt.Errorf("providerId %q is not a service bus TOPIC", pid)
		}
		return map[string]any{
			"namespace": ns,
			"topicName": entity,
			"topicId": "/subscriptions/" + sub + "/resourceGroups/" + rg +
				"/providers/Microsoft.ServiceBus/namespaces/" + ns + "/topics/" + entity,
		}, nil
	case "managedidentity":
		sub, rg, name, err := splitUAMIProviderID(pid)
		if err != nil {
			return nil, err
		}
		// principalId/clientId are server-assigned — one read of the standing
		// identity is the only honest source (the same read observe uses).
		doc, found, rerr := d.getUAMI(rg, name)
		if rerr != nil {
			return nil, rerr
		}
		if !found {
			return nil, fmt.Errorf("identity %s: not found", name)
		}
		if doc.Properties.PrincipalID == "" || doc.Properties.ClientID == "" {
			return nil, fmt.Errorf("identity %s: principalId/clientId absent from the read", name)
		}
		return map[string]any{
			"identityName": name,
			"identityId": "/subscriptions/" + sub + "/resourceGroups/" + rg +
				"/providers/Microsoft.ManagedIdentity/userAssignedIdentities/" + name,
			"principalId": doc.Properties.PrincipalID,
			"clientId":    doc.Properties.ClientID,
		}, nil
	case "keyvaultkey":
		_, _, _, vault, key, err := splitAzureKeyProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"vaultUri": "https://" + vault + ".vault.azure.net",
			"keyUri":   "https://" + vault + ".vault.azure.net/keys/" + key,
		}, nil
	case "aks":
		sub, rg, name, err := splitAKSProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"clusterName":   name,
			"resourceGroup": rg,
			"aksId": "/subscriptions/" + sub + "/resourceGroups/" + rg +
				"/providers/Microsoft.ContainerService/managedClusters/" + name,
		}, nil
	case "acr":
		_, _, name, err := splitAzureACRProviderID(pid)
		if err != nil {
			return nil, err
		}
		// Azure login servers are always lowercase, regardless of the registry
		// name's casing — lower it so the derived URI matches what ACR returns.
		return map[string]any{
			"repositoryUri": strings.ToLower(name) + ".azurecr.io",
		}, nil
	case "backupvault":
		sub, rg, vault, err := splitBackupVaultProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"resourceGroup": rg,
			"vaultName":     vault,
			"vaultId": "/subscriptions/" + sub + "/resourceGroups/" + rg +
				"/providers/Microsoft.DataProtection/backupVaults/" + vault,
		}, nil
	case "containerapps":
		_, rg, app, err := splitACAProviderID(pid)
		if err != nil {
			return nil, err
		}
		// one containerApps.get for the server-assigned ingress fqdn — the GCP
		// cloudrun uri twin. A transport error, non-200 or unparseable body is an
		// ERROR (reconcile), never a fabricated absence. An app with ingress
		// DISABLED has no fqdn: it is omitted (an empty output set, no demotion),
		// since — unlike Cloud Run, which always has a uri — Container Apps ingress
		// is optional. The reachability probe gates PUBLIC-only from the candidate's
		// network.publicExposure, so an internal app's fqdn still travels for a
		// same-network $ref without being probed.
		fqdn, err := d.acaIngressFQDN(rg, app)
		if err != nil {
			return nil, err
		}
		out := map[string]any{}
		if fqdn != "" {
			out["fqdn"] = fqdn
		}
		return out, nil
	}
	return nil, fmt.Errorf("service %q declares outputs but has no derivation", service)
}
