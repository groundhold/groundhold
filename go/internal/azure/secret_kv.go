// Azure Key Vault request building (D97): the Azure half of the capability.secret
// driver — the SAME thin vocabulary GCP Secret Manager and AWS Secrets Manager
// fulfil. Azure has no "secret handle without a value": a Key Vault secret is a
// data-plane object that REQUIRES a value on write. So the honest binding is the
// VAULT itself (Microsoft.KeyVault/vaults, a constitutive parent), which carries
// the residency/exposure/encryption semantics; the secret's VALUE is supplied out
// of band via the data plane and groundhold NEVER writes it (never fabricates one).
// The reserved secret name is surfaced in the plan but not created.
//
// One honest one-cloud refusal: encryption.customerManagedKeys. Key Vault IS the
// key-management service; a vault's own secret storage is encrypted with a
// Microsoft-managed key and does not expose a customer-CMK knob the way an S3
// bucket or a GCP secret does. Rather than pretend, the Azure driver refuses CMK
// on a secret and says why (use Key Vault to HOLD your CMK for other services).
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
)

const keyVaultAPIVersion = "2023-07-01"

// KeyVaultPlan is the attribute-derived shape a create assembles into an ARM body.
type KeyVaultPlan struct {
	Vault        string
	ReservedName string // the secret name reserved for the out-of-band value
	Region       string
	Environment  string
	Capability   string
	TenantID     string
	Public       bool
}

// keyVaultName is the deterministic, globally-unique vault name. Vault names are
// 3-24 chars, must start with a letter, alphanumeric + hyphens; "pv" + 20 hex
// (22 chars) satisfies all of it and never collides across env/capability/gen.
func keyVaultName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv" + hex.EncodeToString(sum[:])[:20]
}

// vaultNameOK bounds a Key Vault name (3-24, start with a letter, alphanumeric +
// hyphens, end alphanumeric) before it is interpolated into an ARM path.
var vaultNameOK = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$`)

// BuildKeyVault maps capability.secret attributes + the impl block to a Key Vault
// create plan. Every error is a refusal apply surfaces in preflight, before any
// mutation — never a silently dropped attribute.
func BuildKeyVault(environment, capability string,
	attrs, impl map[string]any, generation int) (KeyVaultPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := KeyVaultPlan{
		Environment: environment, Capability: capability,
		Vault:        keyVaultName(environment, capability, generation),
		ReservedName: azResourceName("pv-sec", environment, capability, generation),
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
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return KeyVaultPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Key Vault (always encrypted)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				return KeyVaultPlan{}, fmt.Errorf(
					"encryption.customerManagedKeys cannot be honored on an Azure Key Vault secret: " +
						"Key Vault IS the key-management service and encrypts a vault's secrets with a " +
						"Microsoft-managed key — there is no customer-CMK knob for a secret's storage " +
						"(hold your CMK in this vault for OTHER services instead). An honest one-cloud refusal")
			}
		case "service.managed":
			if raw != true {
				return KeyVaultPlan{}, fmt.Errorf("service.managed=false cannot be honored by Key Vault")
			}
		default:
			return KeyVaultPlan{}, fmt.Errorf(
				"attribute %s has no Key Vault mapping — refusing rather than silently dropping it "+
					"(the value is data supplied out of band, rotation is the producer's job, "+
					"access is RBAC — all out of scope by design)", path)
		}
	}

	if p.Region == "" {
		return KeyVaultPlan{}, fmt.Errorf("azure key vault requires location.region")
	}
	p.TenantID, _ = impl["tenant_id"].(string)
	if !subOK.MatchString(p.TenantID) {
		return KeyVaultPlan{}, fmt.Errorf(
			"azure key vault requires implementation.tenant_id (the AAD tenant GUID) — " +
				"a vault is bound to a tenant at creation")
	}
	if !vaultNameOK.MatchString(p.Vault) {
		return KeyVaultPlan{}, fmt.Errorf("derived vault name %q is invalid", p.Vault)
	}
	return p, nil
}

// createBody is the vaults PUT body. RBAC authorization (the modern access model,
// no legacy access policies); publicNetworkAccess gates the exposure; soft-delete
// is on (Azure's default and non-disablable on new vaults). Standard SKU: secrets
// need no HSM (that is a Premium/keys concern).
func (p KeyVaultPlan) createBody(tags map[string]any) map[string]any {
	access := "Enabled"
	if !p.Public {
		access = "Disabled"
	}
	return map[string]any{
		"location": p.Region,
		"tags":     tags,
		"properties": map[string]any{
			"tenantId":                p.TenantID,
			"sku":                     map[string]any{"family": "A", "name": "standard"},
			"enableRbacAuthorization": true,
			"enableSoftDelete":        true,
			"publicNetworkAccess":     access,
			"networkAcls": map[string]any{
				"defaultAction": defaultActionFor(p.Public),
				"bypass":        "AzureServices",
			},
		},
	}
}

func defaultActionFor(public bool) string {
	if public {
		return "Allow"
	}
	return "Deny"
}
