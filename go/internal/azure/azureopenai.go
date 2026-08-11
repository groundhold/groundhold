// Azure OpenAI inference driver (parity with D150/D76): the PURE half of the Azure
// capability.ai.inference vocab — the THIRD service (alongside AWS Bedrock and GCP
// Vertex AI) fulfilling capability.ai.inference, so the EU-residency rule (D1) is a
// CROSS-CLOUD parity property, not one cloud's quirk. The resource is an Azure
// OpenAI account (Microsoft.CognitiveServices/accounts, kind=OpenAI) — ARM, regional.
//
// The residency crux is the SAME trap in the Azure shape: an Azure OpenAI account is
// REGIONAL (data is processed in the account's region), so a standard/regional model
// DEPLOYMENT routes to THAT region. But a deployment can carry a GLOBAL sku
// (GlobalStandard, GlobalProvisionedManaged, GlobalBatch) that routes to ANY region
// worldwide, or a DATA-ZONE sku (DataZoneStandard...) that routes across a multi-region
// data zone. Those are exactly the Bedrock eu-south-2 / Vertex "global" trap: they can
// leave a single EU region. groundhold catches it DETERMINISTICALLY — the driver OBSERVES
// the destination regions from the account's REAL deployment skus (network in observe,
// never in the verifier, #6): a global sku reduces to the ["global"] sentinel, a
// data-zone sku to a ["datazone-<zone>"] sentinel, neither of which is a bounded EU
// region, so a contract asserting
//
//	inference.destinationRegions subset-of [<EU allowlist>]
//
// with the EXISTING subset-of operator becomes a `violated` verdict before any traffic.
// model.access is a MANUAL-GATE: Azure OpenAI model access has historically required an
// application/approval — the driver OBSERVES it (from a model being deployed), CREATE
// refuses to fake it. This file is PURE (identity + forward map + change classification
// + resource-name parsing); the net shell (azureopenai_net.go) drives ARM.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// cognitiveAPIVersion pins the Microsoft.CognitiveServices control-plane version used
// for both the account and its deployments sub-resource.
const cognitiveAPIVersion = "2023-05-01"

// aoiAccountNameOK bounds a Cognitive Services account name (2-64 alphanumerics +
// hyphen, no leading/trailing hyphen; it doubles as the custom subdomain, globally
// unique). Bounded before interpolation into an ARM path (D73 boundary).
var aoiAccountNameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`)

// aoiDeploymentNameOK bounds a model-deployment name (an operand; a REFERENCE, never a
// secret, D53). Azure permits alnum, dot, underscore, hyphen.
var aoiDeploymentNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// aoiModelNameOK bounds a model name operand (e.g. gpt-4o); a REFERENCE, never a secret.
var aoiModelNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// azureEURegions is the (conservative) set of Azure regions that sit in the EU data
// zone. It is used ONLY to name a data-zone deployment's zone honestly
// ("datazone-eu" vs "datazone-us"); it is NEVER used to fabricate a residency verdict
// (the verifier does that, deterministically, from the observed sentinel).
var azureEURegions = map[string]bool{
	"swedencentral": true, "francecentral": true, "francesouth": true,
	"germanywestcentral": true, "germanynorth": true, "norwayeast": true,
	"norwaywest": true, "switzerlandnorth": true, "switzerlandwest": true,
	"westeurope": true, "northeurope": true, "polandcentral": true,
	"italynorth": true, "spaincentral": true,
}

var azureUSRegions = map[string]bool{
	"eastus": true, "eastus2": true, "westus": true, "westus2": true, "westus3": true,
	"centralus": true, "northcentralus": true, "southcentralus": true, "westcentralus": true,
}

// azureDataZone names the multi-region data zone an account's region belongs to. A
// data-zone deployment routes across THAT zone (broader than the single account
// region) — the sentinel keeps the observation honest without pretending to know the
// exact region a call landed in.
func azureDataZone(accountRegion string) string {
	r := azRegion(accountRegion)
	switch {
	case azureEURegions[r]:
		return "eu"
	case azureUSRegions[r]:
		return "us"
	default:
		return "unknown"
	}
}

// aoiImpl reads a string operand from the free-form implementation block (D26).
func aoiImpl(impl map[string]any, key string) string {
	s, _ := impl[key].(string)
	return s
}

// aoiProviderID pins the identity: azureopenai:<sub>:<rg>:<account>. Service-PREFIXED
// (D76) — the token qualifies the identity so a forged/stale binding cannot route
// another service's id into CognitiveServices paths (or vice-versa).
func aoiProviderID(sub, rg, account string) string {
	return "azureopenai:" + sub + ":" + rg + ":" + account
}

// splitAzureOpenAIProviderID validates every component BEFORE it is interpolated into
// an ARM path (D73 confused-deputy boundary). The service token is matched by exact
// string, never interpolated.
func splitAzureOpenAIProviderID(providerID string) (sub, rg, account string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "azureopenai" {
		return "", "", "", fmt.Errorf("providerId %q is not azureopenai:sub:rg:account", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId %q has an invalid sub/rg", providerID)
	}
	if !aoiAccountNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId account name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// aoiAccountName is a deterministic, globally-unique account name (pure hash; the
// account is the constitutive substrate and doubles as a globally-unique custom
// subdomain, so its name is never author-visible). generation salts a replacement (D48).
func aoiAccountName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-" + hex.EncodeToString(sum[:])[:20] // "pv-" + 20 hex = 23 chars
}

// aoiDeploymentName derives a deterministic deployment name from the model when the
// operator does not name it, so a re-run is idempotent.
func aoiDeploymentName(model string, generation int) string {
	hashInput := model
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "dep-" + hex.EncodeToString(sum[:])[:12]
}

// destinationRegionsForScaleType reduces ONE deployment's sku (scale type) to its
// residency surface — the D1 verifier-rule input, MEASURED from the real sku, never
// declared. Regional -> [account region]; a Global sku -> the ["global"] sentinel
// (routes anywhere, the direct twin of Vertex's global endpoint and Bedrock's
// cross-region set); a DataZone sku -> ["datazone-<zone>"] (routes across a multi-region
// zone, broader than a single region). Neither sentinel is a bounded EU region, so
// subset-of an EU allowlist yields `violated` — the trap, caught deterministically.
func destinationRegionsForScaleType(scaleType, accountRegion string) []string {
	n := strings.ToLower(strings.TrimSpace(scaleType))
	switch {
	case strings.HasPrefix(n, "global"):
		return []string{"global"}
	case strings.HasPrefix(n, "datazone"):
		return []string{"datazone-" + azureDataZone(accountRegion)}
	default:
		return []string{azRegion(accountRegion)}
	}
}

// destinationRegionsFromDeployments reduces an account's deployments to the SORTED,
// UNIQUE union of destination-region surfaces — the residency surface the subset-of
// contract asserts against. An account with NO deployments is a regional account: its
// surface is the account's own region (data is processed where the account lives).
func destinationRegionsFromDeployments(scaleTypes []string, accountRegion string) []string {
	seen := map[string]bool{}
	if len(scaleTypes) == 0 {
		seen[azRegion(accountRegion)] = true
	}
	for _, st := range scaleTypes {
		for _, r := range destinationRegionsForScaleType(st, accountRegion) {
			seen[r] = true
		}
	}
	out := make([]string, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

// providerFromModelFormat maps a deployment model's format to the vocab's model.provider
// (Azure OpenAI deployments carry format "OpenAI" -> "openai"). "" when unknown, so
// observe omits rather than fabricates model.provider.
func providerFromModelFormat(format string) string {
	return strings.ToLower(strings.TrimSpace(format))
}

// AzureOpenAIPlan is the operand-derived shape a CREATE assembles. The routing
// (destination regions) is DETERMINED by the deployment sku — it is observed + verified
// after create (the subset-of contract), never a build input. A create may stand up the
// account alone (a bare regional account) or the account + one model deployment.
type AzureOpenAIPlan struct {
	Account           string // Cognitive Services account name (derived, or the account_name operand)
	Region            string // the account's home region (from attrs; scopes the create)
	DeploymentName    string // model-deployment name (operand or derived); "" = account only
	DeploymentModel   string // the model to deploy, e.g. gpt-4o (operand)
	DeploymentVersion string // optional model version (operand)
	DeploymentSku     string // the deployment scale type (operand; default Standard = regional)
	NeedsAccess       bool   // model.access=true was required — a MANUAL-GATE the create must not fake
}

// BuildAzureOpenAI maps capability.ai.inference attributes + implementation operands to
// an Azure OpenAI plan, or REFUSES. Every error is a preflight refusal (never a
// half-build): an unmapped attribute, or an invalid operand, is refused here, before the
// first ARM mutation (invariant #4, D26). model.access is NOT a build input that can be
// honored — a true requirement is recorded as NeedsAccess so the create can
// honest-refuse the manual-gate. This is the exact shape of BuildBedrock/BuildVertexAI,
// the parity twins.
func BuildAzureOpenAI(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureOpenAIPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := AzureOpenAIPlan{Account: aoiAccountName(environment, capability, generation)}

	// --- CAPABILITY attributes (refuse any unmapped attribute) ---
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
		case "model.access":
			b, ok := raw.(bool)
			if !ok {
				return AzureOpenAIPlan{}, fmt.Errorf("model.access must be a bool")
			}
			p.NeedsAccess = b
		case "service.managed":
			if raw != true {
				return AzureOpenAIPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — groundhold manages the Azure OpenAI account it stands up")
			}
		case "inference.destinationRegions":
			// the destination regions are DETERMINED by the deployment skus — an account
			// cannot set a separate routing set. Observed + verified after create (the
			// subset-of contract), never a build input; accept without acting on it.
		case "model.provider":
			// determined by the model deployed on the account; informational at create
			// time (observed live from the deployment).
		default:
			return AzureOpenAIPlan{}, fmt.Errorf(
				"attribute %s has no Azure OpenAI inference mapping — refusing rather than silently dropping it "+
					"(the ai.inference vocab governs location.region, inference.destinationRegions, model.provider, model.access)", path)
		}
	}

	if p.Region == "" {
		return AzureOpenAIPlan{}, fmt.Errorf("azure openai requires location.region (the account's region)")
	}

	// --- OPERATOR operands (implementation: block, D26) ---
	// account_name is OPTIONAL: an operator may pin the globally-unique subdomain;
	// otherwise the deterministic hash name is used.
	if an := strings.TrimSpace(aoiImpl(impl, "account_name")); an != "" {
		if !aoiAccountNameOK.MatchString(an) {
			return AzureOpenAIPlan{}, fmt.Errorf("implementation.account_name %q is not a valid Azure OpenAI account name", an)
		}
		p.Account = an
	}
	if !aoiAccountNameOK.MatchString(p.Account) {
		return AzureOpenAIPlan{}, fmt.Errorf("derived account name %q is invalid", p.Account)
	}

	// deployment operands are OPTIONAL (a bare account is valid): if a model is named,
	// a deployment is created; the sku (scale type) determines the routing observe
	// measures. Standard = regional (the residency-safe default).
	p.DeploymentModel = strings.TrimSpace(aoiImpl(impl, "deployment_model"))
	if p.DeploymentModel != "" {
		if !aoiModelNameOK.MatchString(p.DeploymentModel) {
			return AzureOpenAIPlan{}, fmt.Errorf("implementation.deployment_model %q is not a valid model name", p.DeploymentModel)
		}
		p.DeploymentVersion = strings.TrimSpace(aoiImpl(impl, "deployment_version"))
		p.DeploymentSku = strings.TrimSpace(aoiImpl(impl, "deployment_sku"))
		if p.DeploymentSku == "" {
			p.DeploymentSku = "Standard" // regional by default
		}
		p.DeploymentName = strings.TrimSpace(aoiImpl(impl, "deployment_name"))
		if p.DeploymentName == "" {
			p.DeploymentName = aoiDeploymentName(p.DeploymentModel, generation)
		}
		if !aoiDeploymentNameOK.MatchString(p.DeploymentName) {
			return AzureOpenAIPlan{}, fmt.Errorf("implementation.deployment_name %q is not a valid deployment name", p.DeploymentName)
		}
	}
	return p, nil
}

// classifyAzureOpenAIChange (parity with classifyBedrockChange/classifyVertexChange):
// PURE — can a capability.ai.inference transition be honored in place? An account's
// ROUTING is fixed by its region + deployment skus, so inference.destinationRegions,
// location.region and model.provider are IMMUTABLE (a change is a new account/deployment,
// not an in-place patch). model.access is UNSUPPORTED (a manual-gate groundhold observes,
// never provisions). service.managed is a projection.
func classifyAzureOpenAIChange(path string) (string, string) {
	switch path {
	case "inference.destinationRegions":
		// D828: the driver's own build comment says these are "DETERMINED by the deployment
		// skus", and a deployment is replaced with a PUT. "a new account/deployment" put
		// both on one side of a slash; only one of them is required, and it is not the
		// account.
		return "unsupported", "in-place routing change is not wired for Azure OpenAI in " +
			"this slice — the destination regions follow the deployment skus, and a " +
			"deployment is replaced by its own PUT without touching the account"
	case "location.region":
		return "immutable", "an Azure OpenAI account is region-bound — a region change is a new account, not a patch"
	case "model.provider":
		// D828: the sentence already says "a new DEPLOYMENT" — and a deployment is a child
		// resource with its own PUT and DELETE
		// (Microsoft.CognitiveServices/accounts/{name}/deployments/{deploymentName}, present
		// at the api-version this driver pins). The verdict destroyed the ACCOUNT for it.
		return "unsupported", "in-place model swap is not wired for Azure OpenAI in this " +
			"slice — Azure does support it (the deployment is a child resource with its own " +
			"PUT and DELETE, and the account is untouched), so this is a gap in groundhold " +
			"rather than a reason to replace the account"
	case "model.access":
		return "unsupported", "model access is a manual-gate — Azure OpenAI model access is granted by an application/approval, never an API patch; groundhold observes it, does not provision it"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Azure OpenAI inference in-place mapping for " + path
	}
}
