// AWS Bedrock inference driver (D150): the PURE half of the AWS
// capability.ai.inference vocab — managed LLM inference as a governed capability.
// The crux is a residency trap AWS documents: a Bedrock EU cross-region inference
// profile (eu.anthropic.*) routes calls across SEVERAL EU regions, and the set
// INCLUDES eu-south-2 (Spain); if that region is outside the account's allowlist,
// calls fail at random. groundhold catches it DETERMINISTICALLY: the driver OBSERVES
// the profile's destination regions (network in observe, never in verify), and a
// contract asserts `inference.destinationRegions subset-of [<EU allowlist>]` with
// the EXISTING subset-of operator — the trap becomes a `violated` verdict before
// any traffic. model.access is a MANUAL-GATE: Bedrock model access is granted by a
// use-case form, never an API create — the driver OBSERVES it, never fabricates it,
// and CREATE refuses to fake it. This file is PURE (identity + forward map +
// change classification + ARN parsing); the net shell (bedrock_net.go) drives the
// Bedrock control-plane REST-JSON API. Bedrock runtime is a SEPARATE endpoint we do
// NOT call.
package aws

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// bedrockProfileIDOK bounds an inference-profile id. System (cross-region) profiles
// carry a geo prefix and dots (eu.anthropic.claude-sonnet); application profiles are
// AWS-assigned ids. Permit alnum, dot, hyphen, underscore — the id is the terminal
// segment of the pid, so dots are legal.
var bedrockProfileIDOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$`)

// bedrockSystemPrefixes are the geo prefixes AWS assigns to SYSTEM_DEFINED
// cross-region inference profiles. A system profile is AWS-managed — groundhold can
// observe it but never owns it (delete honest-refuses).
var bedrockSystemPrefixes = []string{"eu.", "us.", "apac.", "us-gov.", "ap.", "ca."}

// bedrockProviderID pins the identity: bedrock:<region>:<inferenceProfileId>. The id
// carries dots — it is the terminal segment, so a SplitN(…,3) recovers it whole.
func bedrockProviderID(region, profileID string) string {
	return "bedrock:" + region + ":" + profileID
}

// bedrockIDFromArn extracts the inference-profile id from an ARN's last path
// segment (arn:aws:bedrock:…:application-inference-profile/<id>). AWS's
// CreateInferenceProfile returns the ARN, not a bare id, so a create that required
// inferenceProfileId false-negatived a real success as "unknown" (F18).
func bedrockIDFromArn(arn string) string {
	if i := strings.LastIndex(arn, "/"); i >= 0 {
		return arn[i+1:]
	}
	return ""
}

func splitBedrockProviderID(providerID string) (region, profileID string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "bedrock" {
		return "", "", fmt.Errorf("providerId %q is not bedrock:region:inferenceProfileId", providerID)
	}
	region, profileID = parts[1], parts[2]
	if !regionOK.MatchString(region) {
		return "", "", fmt.Errorf("providerId region %q is invalid", region)
	}
	if !bedrockProfileIDOK.MatchString(profileID) {
		return "", "", fmt.Errorf("providerId inference-profile id %q is invalid", profileID)
	}
	return region, profileID, nil
}

// isSystemProfileID reports whether an inference-profile id names a SYSTEM_DEFINED
// cross-region profile (a geo prefix). These are AWS-managed; groundhold never owns
// them (the delete honest-refuses even before the tag gate).
func isSystemProfileID(profileID string) bool {
	for _, p := range bedrockSystemPrefixes {
		if strings.HasPrefix(profileID, p) {
			return true
		}
	}
	return false
}

// regionFromModelArn extracts the AUTHORITATIVE routing region from a Bedrock model
// ARN: arn:aws:bedrock:<REGION>::foundation-model/<provider>.<model>. The region is
// the 4th colon-field of the ARN (index 3) — stable regardless of the version colon
// inside the resource tail (…-v2:0). Returns "" when it is not a valid region.
func regionFromModelArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 4 {
		return ""
	}
	region := parts[3]
	if !regionOK.MatchString(region) {
		return ""
	}
	return region
}

// providerFromModelArn extracts the model provider/family from a Bedrock model ARN:
// the token before the first dot of the foundation-model resource
// (…/anthropic.claude-3-5-sonnet -> "anthropic"). Returns "" when unparseable.
func providerFromModelArn(arn string) string {
	i := strings.Index(arn, "foundation-model/")
	if i < 0 {
		return ""
	}
	rest := arn[i+len("foundation-model/"):]
	if dot := strings.Index(rest, "."); dot >= 0 {
		return rest[:dot]
	}
	return rest
}

// destinationRegionsFromModels reduces a profile's models[].modelArn set to the
// SORTED, UNIQUE set of routing regions — the residency surface the subset-of
// contract asserts against. This is the D1 verifier-rule input.
func destinationRegionsFromModels(arns []string) []string {
	seen := map[string]bool{}
	for _, a := range arns {
		if r := regionFromModelArn(a); r != "" {
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

// providerFromModels picks the model provider common to a profile's models (the
// first parseable one — a profile serves one family). Returns "" when none parse.
func providerFromModels(arns []string) string {
	for _, a := range arns {
		if p := providerFromModelArn(a); p != "" {
			return p
		}
	}
	return ""
}

// BedrockPlan is the operand-derived shape a CREATE of an APPLICATION inference
// profile assembles. The routing (destination regions, provider) is INHERITED from
// the modelSource — an application profile cannot set its own routing — so the plan
// carries only what a create supplies: the name, the source, and ownership.
type BedrockPlan struct {
	ProfileName string // application inference-profile name (operand, required)
	ModelSource string // source ARN: a system inference profile or a foundation model (operand, required)
	NeedsAccess bool   // model.access=true was required — a MANUAL-GATE the create must not fake
}

// bedrockNameOK bounds an application inference-profile name (AWS: 1-64 chars).
var bedrockNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._:/=+@-]{0,63}$`)

// bedrockSourceArnOK bounds the modelSource operand: a Bedrock inference-profile OR
// foundation-model ARN. It is a REFERENCE (names a resource), never a secret (D53).
var bedrockSourceArnOK = regexp.MustCompile(`^arn:aws[A-Za-z0-9-]*:bedrock:[a-z0-9-]*:[0-9]*:(inference-profile|foundation-model)/.+$`)

// BuildBedrock maps capability.ai.inference attributes + implementation operands to
// an application-inference-profile plan, or REFUSES. Every error is a preflight
// refusal (never a half-build): an unmapped attribute, or a missing/invalid required
// operand, is refused here, before the first Bedrock mutation (invariant #4, D26).
// model.access is NOT a build input that can be honored — a true requirement is
// recorded as NeedsAccess so the create can honest-refuse the manual-gate.
func BuildBedrock(environment, capability string,
	attrs, impl map[string]any, generation int) (BedrockPlan, error) {
	p := BedrockPlan{}

	// --- CAPABILITY attributes (refuse any unmapped attribute) ---
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "model.access":
			b, ok := raw.(bool)
			if !ok {
				return BedrockPlan{}, fmt.Errorf("model.access must be a bool")
			}
			p.NeedsAccess = b
		case "service.managed":
			if raw != true {
				return BedrockPlan{}, fmt.Errorf("service.managed=false cannot be honored — groundhold manages the inference profile it stands up")
			}
		case "inference.destinationRegions":
			// routing is INHERITED from the modelSource — an application profile cannot
			// set its own destination regions. It is observed + verified after create
			// (the subset-of contract), never a build input; accept without acting on it.
		case "model.provider":
			// likewise determined by the modelSource; informational at create time.
		case "location.region":
			// location.region scopes the create (resolved by the dispatch, not here);
			// cost.monthly is a projection — neither is a build input.
		default:
			return BedrockPlan{}, fmt.Errorf(
				"attribute %s has no Bedrock inference mapping — refusing rather than silently dropping it "+
					"(the ai.inference vocab governs location.region, inference.destinationRegions, model.provider, model.access)", path)
		}
	}

	// --- OPERATOR operands (implementation: block, D26) ---
	p.ProfileName = strings.TrimSpace(implString(impl, "inferenceProfileName"))
	if p.ProfileName == "" {
		return BedrockPlan{}, fmt.Errorf(
			"implementation.inferenceProfileName is required — the NAME this create " +
				"gives the application inference profile it provisions (a naming input " +
				"like clusterName, NOT a pre-existing resource)")
	}
	if !bedrockNameOK.MatchString(p.ProfileName) {
		return BedrockPlan{}, fmt.Errorf("implementation.inferenceProfileName %q is not a valid inference-profile name", p.ProfileName)
	}
	p.ModelSource = strings.TrimSpace(implString(impl, "modelSource"))
	if p.ModelSource == "" {
		return BedrockPlan{}, fmt.Errorf(
			"implementation.modelSource is required (a source inference-profile or foundation-model ARN — a separate capability the create routes to)")
	}
	if !bedrockSourceArnOK.MatchString(p.ModelSource) {
		return BedrockPlan{}, fmt.Errorf("implementation.modelSource %q is not a valid Bedrock inference-profile or foundation-model ARN", p.ModelSource)
	}
	return p, nil
}

// classifyBedrockChange (D46): PURE — can a capability.ai.inference transition be
// honored in place? A profile's ROUTING is fixed at creation (inherited from its
// source), so inference.destinationRegions and model.provider are IMMUTABLE (a
// change is a new profile, not a patch). model.access is UNSUPPORTED (a manual-gate
// groundhold observes, never provisions). service.managed is a projection.
func classifyBedrockChange(path string) (string, string) {
	switch path {
	case "inference.destinationRegions":
		return "immutable", "an inference profile's routing set is fixed at creation (inherited from its model source) — a change is a new profile, not an in-place patch"
	case "model.provider":
		return "immutable", "the model provider/family is fixed by the profile's model source — a change is a new profile, not an in-place patch"
	case "location.region":
		return "immutable", "an inference profile is region-bound — a region change is a new profile, not a patch"
	case "model.access":
		return "unsupported", "model access is a manual-gate — granted via the Bedrock console use-case form, never an API patch; groundhold observes it, does not provision it"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Bedrock inference in-place mapping for " + path
	}
}
