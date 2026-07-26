// Azure Key Vault key request building (D102): the Azure half of the
// capability.key.encryption driver — the SAME vocabulary GCP Cloud KMS and AWS KMS
// fulfil, but a CONSTITUTIVE COMPOSITE like Cloud KMS: an Azure key lives in a
// vault, so the driver creates vault + key under one binding. Two honest Azure
// realities: a standard/premium Key Vault holds RSA/EC keys (symmetric keys are
// Managed-HSM-only), so the CMK-style "encryption key" is realized as an RSA key
// (the vocab left algorithm as impl); and protection.level=hsm needs a PREMIUM
// vault + an RSA-HSM key, so the vault SKU forks on it. This is distinct from the
// Azure Key Vault SECRET driver (keyvault service) — a key, not a secret.
package azure

import (
	"fmt"
	"sort"

	"groundhold/internal/scalars"
)

// AzureKeyPlan is the attribute-derived shape a create assembles.
type AzureKeyPlan struct {
	Vault        string
	Key          string
	Region       string
	TenantID     string
	Kty          string // RSA | RSA-HSM
	VaultSku     string // standard | premium (premium required for RSA-HSM)
	RotationDays int    // 0 = no automatic rotation
}

// BuildAzureKey maps capability.key.encryption attributes + impl to a vault+key
// plan. Every error is a preflight refusal, never a silent drop.
func BuildAzureKey(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureKeyPlan, error) {
	p := AzureKeyPlan{
		Vault:    keyVaultName(environment, capability, generation),
		Key:      azResourceName("pv-key", environment, capability, generation),
		Kty:      "RSA",
		VaultSku: "standard",
	}
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
		case "rotation.period":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Duration {
				return AzureKeyPlan{}, fmt.Errorf("rotation.period is not a duration")
			}
			ms, ok := s.Value.(float64)
			if !ok {
				return AzureKeyPlan{}, fmt.Errorf("rotation.period is not a duration")
			}
			days := int(ms / 86400000)
			if days < 7 {
				return AzureKeyPlan{}, fmt.Errorf(
					"rotation.period below 7 days cannot be honored (Azure Key Vault rotation minimum is P7D)")
			}
			p.RotationDays = days
		case "protection.level":
			switch raw {
			case "software":
				p.Kty, p.VaultSku = "RSA", "standard"
			case "hsm":
				p.Kty, p.VaultSku = "RSA-HSM", "premium"
			default:
				return AzureKeyPlan{}, fmt.Errorf("protection.level %v has no Azure Key Vault mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return AzureKeyPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Key Vault")
			}
		default:
			return AzureKeyPlan{}, fmt.Errorf(
				"attribute %s has no Azure Key Vault key mapping — refusing rather than silently "+
					"dropping it (the key material is never exported, key size is impl)", path)
		}
	}
	if p.Region == "" {
		return AzureKeyPlan{}, fmt.Errorf("key requires location.region")
	}
	p.TenantID, _ = impl["tenant_id"].(string)
	if !subOK.MatchString(p.TenantID) {
		return AzureKeyPlan{}, fmt.Errorf(
			"azure key vault requires implementation.tenant_id (the AAD tenant GUID)")
	}
	if !vaultNameOK.MatchString(p.Vault) {
		return AzureKeyPlan{}, fmt.Errorf("derived vault name %q is invalid", p.Vault)
	}
	return p, nil
}

// vaultCreateBody is the vault PUT body (SKU forks on protection.level).
func (p AzureKeyPlan) vaultCreateBody(tags map[string]any) map[string]any {
	return map[string]any{
		"location": p.Region,
		"tags":     tags,
		"properties": map[string]any{
			"tenantId":                p.TenantID,
			"sku":                     map[string]any{"family": "A", "name": p.VaultSku},
			"enableRbacAuthorization": true,
			"enableSoftDelete":        true,
		},
	}
}

// keyCreateBody is the keys PUT body: an RSA(-HSM) encryption key, with an optional
// rotation policy (timeAfterCreate in ISO-8601, e.g. P90D).
func (p AzureKeyPlan) keyCreateBody() map[string]any {
	props := map[string]any{
		"kty":     p.Kty,
		"keySize": 2048,
		"keyOps":  []any{"encrypt", "decrypt", "wrapKey", "unwrapKey"},
	}
	if p.RotationDays > 0 {
		props["rotationPolicy"] = map[string]any{
			"lifetimeActions": []any{map[string]any{
				"trigger": map[string]any{"timeAfterCreate": fmt.Sprintf("P%dD", p.RotationDays)},
				"action":  map[string]any{"type": "Rotate"},
			}},
		}
	}
	return map[string]any{"properties": props}
}
