// OpenSearch Serverless request building: a SECOND AWS backend for
// capability.search.index, alongside the provisioned `opensearch` domain.
// Serverless is the pay-per-use cost lever — no instance type, no node/shard/
// replica count, no EBS sizing: capacity auto-scales in OCUs, so every
// provisioned sizing operand is a REFUSAL or is simply absent, never a silent
// clamp. Dispatched by the service token `opensearch-serverless`; speaks the AWS
// JSON-1.0 protocol (X-Amz-Target = OpenSearchServerless.<Op>) at
// aoss.<region>.amazonaws.com, SigV4 service name "aoss".
//
// CRITICAL: an OpenSearch Serverless collection is a COMPOSITE (like EKS/VPC, not
// a single resource). A collection CANNOT be created without a matching
// ENCRYPTION security policy (SecurityPolicy type=encryption) whose Rule covers
// collection/<name>, and — for reachability — a NETWORK security policy
// (type=network). So the create orchestrates: ensure encryption policy -> ensure
// network policy -> CreateCollection -> poll to ACTIVE; the delete tears the owned
// sub-resources down in REVERSE: DeleteCollection -> poll-gone -> delete network
// policy -> delete encryption policy. Ownership is TAGS on the collection plus a
// deterministic name marker on the two owned policies.
//
// A serverless collection always encrypts at rest (AWS-owned KMS key or a CMK via
// the encryption policy) and is TLS-only in transit, and is regional (multi-AZ) by
// construction — so encryption.atRest=false, encryption.inTransit=false and a
// non-regional availability.class are honest refusals, and the always-on
// guarantees are satisfied by construction (no field to toggle), exactly as the
// provisioned domain's EnforceHTTPS.
package aws

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// jsonString marshals an arbitrary value to a compact JSON string — used for the
// aoss security-policy documents, which are JSON STRINGS (an object for encryption,
// an array of rule blocks for network) nested inside the request body.
func jsonString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

const openSearchServerlessTarget = "OpenSearchServerless"

// aossPolicyOK bounds an OpenSearch Serverless security-policy name (3-32:
// lowercase letter start, then lowercase letters, digits, hyphens) before it is
// interpolated into a request body.
var aossPolicyOK = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)

// aossEncPolicyName / aossNetPolicyName derive the two owned policy names from the
// deterministic collection name (the name IS the ownership marker; policies carry
// no tags). The collection name is <=28, so a "-enc"/"-net" suffix stays within
// the 32-char policy bound.
func aossEncPolicyName(collection string) string { return collection + "-enc" }
func aossNetPolicyName(collection string) string { return collection + "-net" }

// OpenSearchServerlessPlan is the attribute-derived shape a create assembles into
// the CreateCollection body plus the two derived security-policy bodies. No sizing
// fields exist — capacity auto-scales in OCUs, which is the point of the backend.
type OpenSearchServerlessPlan struct {
	Name           string
	Region         string
	Public         bool
	VPCEndpointIDs []string // network policy SourceVPCEs when private
	CMEK           bool
	KmsKeyArn      string // encryption policy KmsARN; "" = AWS-owned key
}

// BuildOpenSearchServerless maps capability.search.index attributes + impl to a
// serverless-collection plan. Every error is a preflight refusal apply surfaces
// before any mutation, never a silent drop or clamp.
func BuildOpenSearchServerless(environment, capability string,
	attrs, impl map[string]any, generation int) (OpenSearchServerlessPlan, error) {
	p := OpenSearchServerlessPlan{
		// the collection name obeys the same 3-28/leading-letter rule as an
		// OpenSearch domain name, so the deterministic generator is shared; the
		// aoss:<...> providerId prefix keeps the two namespaces distinct.
		Name:   OpenSearchDomainName(environment, capability, generation),
		Public: true, // aoss default reachability is a public network policy; the vocab attr overrides it
	}
	var atRestSeen bool
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "availability.class":
			switch raw {
			case "regional":
				// satisfied by construction — a serverless collection is multi-AZ.
			case "zonal":
				return OpenSearchServerlessPlan{}, fmt.Errorf(
					"availability.class=zonal cannot be honored by OpenSearch Serverless " +
						"(it is multi-AZ/regional by construction — no single-AZ mode)")
			default:
				return OpenSearchServerlessPlan{}, fmt.Errorf(
					"availability.class %v has no OpenSearch Serverless mapping", raw)
			}
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			atRestSeen = true
			if raw != true {
				return OpenSearchServerlessPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored — OpenSearch Serverless always " +
						"encrypts at rest via a required encryption policy (never an unencrypted collection)")
			}
		case "encryption.inTransit":
			if raw != true {
				return OpenSearchServerlessPlan{}, fmt.Errorf(
					"encryption.inTransit=false cannot be honored — OpenSearch Serverless is TLS-only (HTTPS) in transit")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.CMEK = true
				p.KmsKeyArn, _ = impl["kms_key_arn"].(string)
				if p.KmsKeyArn == "" {
					p.KmsKeyArn, _ = impl["kms_key_id"].(string)
				}
				if p.KmsKeyArn == "" {
					return OpenSearchServerlessPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_arn (a customer KMS key)")
				}
			}
		case "service.managed":
			if raw != true {
				return OpenSearchServerlessPlan{}, fmt.Errorf("service.managed=false cannot be honored by OpenSearch Serverless")
			}
		default:
			return OpenSearchServerlessPlan{}, fmt.Errorf(
				"attribute %s has no OpenSearch Serverless mapping — refusing rather than silently dropping it "+
					"(serverless has no instance type/count, EBS, or shard/replica sizing to map it to)", path)
		}
	}
	if !atRestSeen {
		return OpenSearchServerlessPlan{}, fmt.Errorf("collection requires encryption.atRest=true")
	}
	if p.Region == "" {
		return OpenSearchServerlessPlan{}, fmt.Errorf("collection requires location.region")
	}
	if !regionOK.MatchString(p.Region) {
		return OpenSearchServerlessPlan{}, fmt.Errorf("location.region %q is not a valid AWS region", p.Region)
	}
	// a PRIVATE collection (network.publicExposure=false) is reached over a VPC
	// endpoint — a binding the operator brings (the one-binding rule D26), exactly
	// as the provisioned domain brings subnets/security groups. Without it the
	// network policy would deny all access, so refuse rather than ship an
	// unreachable collection.
	if !p.Public {
		p.VPCEndpointIDs = implStrings(impl, "vpc_endpoint_ids")
		if len(p.VPCEndpointIDs) == 0 {
			return OpenSearchServerlessPlan{}, fmt.Errorf(
				"a PRIVATE collection (network.publicExposure=false) requires implementation." +
					"vpc_endpoint_ids (VPC endpoint access is topology the driver references but does not create)")
		}
	}
	if !osNameOK.MatchString(p.Name) {
		return OpenSearchServerlessPlan{}, fmt.Errorf("derived collection name %q is invalid", p.Name)
	}
	if !aossPolicyOK.MatchString(aossEncPolicyName(p.Name)) || !aossPolicyOK.MatchString(aossNetPolicyName(p.Name)) {
		return OpenSearchServerlessPlan{}, fmt.Errorf("derived security-policy name for %q is invalid", p.Name)
	}
	return p, nil
}

// encryptionPolicyBody builds the CreateSecurityPolicy body for the REQUIRED
// encryption policy. The policy document is a JSON STRING (aoss quirk): a single
// object whose Rules cover collection/<name>, keyed either to an AWS-owned key
// (AWSOwnedKey:true) or a customer key (KmsARN). Without a matching encryption
// policy a collection cannot be created — this is the first owned sub-resource.
func (p OpenSearchServerlessPlan) encryptionPolicyBody() map[string]any {
	rule := map[string]any{
		"Rules": []any{
			map[string]any{"ResourceType": "collection", "Resource": []any{"collection/" + p.Name}},
		},
	}
	if p.CMEK {
		rule["KmsARN"] = p.KmsKeyArn
	} else {
		rule["AWSOwnedKey"] = true
	}
	return map[string]any{
		"name":        aossEncPolicyName(p.Name),
		"type":        "encryption",
		"description": "groundhold " + sanitizeTag(p.Name),
		"policy":      jsonString(rule),
	}
}

// networkPolicyBody builds the CreateSecurityPolicy body for the network policy.
// The document is a JSON STRING that is an ARRAY of rule blocks (aoss quirk):
// AllowFromPublic:true for a public endpoint, or AllowFromPublic:false +
// SourceVPCEs for VPC-only access. Both the collection and its dashboard endpoint
// are covered.
func (p OpenSearchServerlessPlan) networkPolicyBody() map[string]any {
	block := map[string]any{
		"Rules": []any{
			map[string]any{"ResourceType": "collection", "Resource": []any{"collection/" + p.Name}},
			map[string]any{"ResourceType": "dashboard", "Resource": []any{"collection/" + p.Name}},
		},
	}
	if p.Public {
		block["AllowFromPublic"] = true
	} else {
		block["AllowFromPublic"] = false
		vpces := make([]any, len(p.VPCEndpointIDs))
		for i, v := range p.VPCEndpointIDs {
			vpces[i] = v
		}
		block["SourceVPCEs"] = vpces
	}
	return map[string]any{
		"name":        aossNetPolicyName(p.Name),
		"type":        "network",
		"description": "groundhold " + sanitizeTag(p.Name),
		"policy":      jsonString([]any{block}),
	}
}

// createCollectionBody is the CreateCollection request body. type=SEARCH is the
// full-text search collection (the capability.search.index shape). Ownership is
// tags at birth.
func (p OpenSearchServerlessPlan) createCollectionBody(capability, environment string) map[string]any {
	return map[string]any{
		"name":        p.Name,
		"type":        "SEARCH",
		"description": "groundhold " + sanitizeTag(capability),
		"tags": []any{
			map[string]any{"key": "groundhold-capability", "value": sanitizeTag(capability)},
			map[string]any{"key": "groundhold-environment", "value": sanitizeTag(environment)},
		},
	}
}

// classifyOpenSearchServerlessChange (D46): PURE — can a search.index transition be
// honored IN PLACE on a serverless collection? This slice wires create/observe/
// delete but NO in-place update, so every drift is either satisfied-by-construction
// (encryption/availability — refused at create, nothing to patch), a projection
// property, or a create-time property whose reconciliation is a REPLACEMENT
// (consent-gated: search.index is stateful, D47/D48). Never a silent "mutable" that
// would route to an unwired update path and stall.
func classifyOpenSearchServerlessChange(path string) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "the region is the collection's home — a change is a new collection (replacement; stateful, consent-gated)"
	case "network.publicExposure":
		// D821: the exposure is not a property of the collection at all — observe reads it
		// from the network POLICY document (GetSecurityPolicy), and UpdateSecurityPolicy
		// replaces that document without touching the collection. Replacing a stateful
		// search collection to change a policy is a heavy answer to a question AWS answers
		// with one call.
		return "unsupported", "in-place exposure change is not wired for OpenSearch " +
			"Serverless in this slice — the exposure lives in the network policy document, " +
			"which UpdateSecurityPolicy replaces without touching the collection, so this is " +
			"a gap in groundhold rather than a reason to replace the data"
	case "encryption.customerManagedKeys":
		return "immutable", "the encryption policy (AWS-owned vs CMK) is set at create — reconciling a drift is a replacement (stateful, consent-gated)"
	case "encryption.atRest", "encryption.inTransit":
		return "unsupported", "OpenSearch Serverless always encrypts at rest and in transit — nothing to patch"
	case "availability.class":
		return "unsupported", "a serverless collection is regional (multi-AZ) by construction — nothing to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no OpenSearch Serverless in-place mapping for " + path
	}
}
