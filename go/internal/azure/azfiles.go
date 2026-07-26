// Azure Files request building (D111): the semantic core of the Azure
// capability.storage.filesystem driver — the SAME vocabulary GCP Filestore and
// AWS EFS fulfil. Azure puts the file share under a STORAGE ACCOUNT, so — exactly
// like Blob (D99) — the binding is a CONSTITUTIVE COMPOSITE: a storage account +
// its fileServices/default + one share, one binding (the share is the leaf; the
// account is the substrate we create/tag/retire). Azure is the ONE cloud that
// speaks SMB natively, so it honors protocol smb AND nfs (NFS needs a Premium
// FileStorage account); GCP/AWS refuse smb. It creates the account, so it can
// also honor customer-managed keys (account Key Vault encryption).
package azure

import (
	"fmt"
	"sort"
	"strings"
)

// AzFilesPlan is the attribute-derived shape a create assembles into ARM bodies.
type AzFilesPlan struct {
	Account        string
	Share          string
	Region         string
	Kind           string // StorageV2 (SMB) | FileStorage (NFS/Premium)
	SKU            string // Standard_LRS|Standard_ZRS | Premium_LRS|Premium_ZRS
	Protocol       string // SMB | NFS (share enabledProtocols)
	QuotaGiB       int    // sizing (impl); default 100
	KmsKeyVaultURI string // CMEK, from impl; "" = provider-managed
	KmsIdentity    string // user-assigned identity resource id, from impl
}

// azFilesShareName is the leaf share name (3-63, lowercase alnum + hyphen).
func azFilesShareName(environment, capability string, generation int) string {
	return azResourceName("pv-fs", environment, capability, generation)
}

// BuildAzFiles maps capability.storage.filesystem attributes to an Azure Files
// plan. Every error is a refusal apply surfaces in preflight.
func BuildAzFiles(environment, capability string,
	attrs, impl map[string]any, generation int) (AzFilesPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := AzFilesPlan{
		Account:  azStorageName(environment, capability, generation),
		Share:    azFilesShareName(environment, capability, generation),
		Protocol: "SMB", // Azure's native default
		Kind:     "StorageV2",
		SKU:      "Standard_LRS", // zonal baseline unless availability says otherwise
		QuotaGiB: 100,
	}
	availClass := "zonal"

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "protocol":
			proto, _ := raw.(string)
			engine, _, ok := strings.Cut(proto, "/")
			switch {
			case !ok:
				return AzFilesPlan{}, fmt.Errorf("protocol %q is not a protocol/version", proto)
			case strings.ToLower(engine) == "smb":
				p.Protocol = "SMB"
			case strings.ToLower(engine) == "nfs":
				p.Protocol = "NFS" // requires a Premium FileStorage account
			default:
				return AzFilesPlan{}, fmt.Errorf("protocol %q has no Azure Files mapping (nfs|smb)", proto)
			}
		case "availability.class":
			switch raw {
			case "zonal", "regional":
				availClass, _ = raw.(string)
			default:
				return AzFilesPlan{}, fmt.Errorf("availability.class %v has no Azure Files mapping (zonal|regional)", raw)
			}
		case "encryption.atRest":
			if raw != true {
				return AzFilesPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Azure Storage (SSE is always on)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyVaultURI, _ = impl["key_vault_key_uri"].(string)
				p.KmsIdentity, _ = impl["user_assigned_identity"].(string)
				if p.KmsKeyVaultURI == "" || p.KmsIdentity == "" {
					return AzFilesPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.key_vault_key_uri " +
							"AND implementation.user_assigned_identity")
				}
			}
		case "service.managed":
			if raw != true {
				return AzFilesPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Files")
			}
		default:
			return AzFilesPlan{}, fmt.Errorf(
				"attribute %s has no Azure Files mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Region == "" {
		return AzFilesPlan{}, fmt.Errorf("azure files requires location.region")
	}
	// NFS shares require a Premium FileStorage account; SMB uses StorageV2.
	if p.Protocol == "NFS" {
		p.Kind = "FileStorage"
		p.SKU = "Premium_LRS"
		if availClass == "regional" {
			p.SKU = "Premium_ZRS"
		}
	} else {
		p.Kind = "StorageV2"
		p.SKU = "Standard_LRS"
		if availClass == "regional" {
			p.SKU = "Standard_ZRS"
		}
	}
	if !storageNameOK.MatchString(p.Account) {
		return AzFilesPlan{}, fmt.Errorf("derived storage account name %q is invalid", p.Account)
	}
	if q, ok := impl["quota_gib"]; ok {
		switch v := q.(type) {
		case float64:
			p.QuotaGiB = int(v)
		case int:
			p.QuotaGiB = v
		}
	}
	if p.QuotaGiB < 1 {
		p.QuotaGiB = 100
	}
	return p, nil
}

// accountBody is the storage-account PUT body (the constitutive substrate).
func (p AzFilesPlan) accountBody(tags map[string]any) map[string]any {
	props := map[string]any{
		"minimumTlsVersion":     "TLS1_2",
		"allowBlobPublicAccess": false,
		"largeFileSharesState":  "Enabled",
	}
	if p.KmsKeyVaultURI != "" {
		props["encryption"] = map[string]any{
			"keySource":          "Microsoft.Keyvault",
			"keyvaultproperties": map[string]any{"keyvaulturi": p.KmsKeyVaultURI},
			"identity":           map[string]any{"userAssignedIdentity": p.KmsIdentity},
		}
	}
	return map[string]any{
		"location":   p.Region,
		"kind":       p.Kind,
		"sku":        map[string]any{"name": p.SKU},
		"tags":       tags,
		"properties": props,
	}
}

// shareBody is the fileShares PUT body (the leaf).
func (p AzFilesPlan) shareBody() map[string]any {
	return map[string]any{
		"properties": map[string]any{
			"enabledProtocols": p.Protocol,
			"shareQuota":       p.QuotaGiB,
		},
	}
}
