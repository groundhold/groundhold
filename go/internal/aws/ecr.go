// ECR request building (D110): the semantic core of the AWS capability.registry.image
// driver — the SAME vocabulary GCP Artifact Registry and Azure ACR fulfil. A managed
// container image registry: regional, optionally CMEK-encrypted, with immutable tags
// (imageTagMutability=IMMUTABLE). ECR is the AWS JSON protocol. The honest gap this cloud
// forces: an ECR PRIVATE registry cannot be made public (public pull is the separate ECR
// Public service, a different resource), so network.publicExposure=true is REFUSED.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var ecrRepoNameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{1,255}$`)

// ECRPlan is the attribute-derived shape a create assembles.
type ECRPlan struct {
	RepoName      string
	ImmutableTags bool
	ScanOnPush    bool
	CMEK          bool
	KmsKey        string
}

func ecrRepoName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(ecrBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-" + slug + "-" + hex.EncodeToString(sum[:])[:8]
}

var ecrBad = regexp.MustCompile(`[^a-z0-9-]+`)

// BuildECR maps capability.registry.image attributes + impl to an ECR plan. Every error
// is a preflight refusal, never a silent drop. (Region + account come from createScope.)
func BuildECR(environment, capability string,
	attrs, impl map[string]any, generation int) (ECRPlan, error) {
	p := ECRPlan{RepoName: ecrRepoName(environment, capability, generation)}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// region is resolved by createScope; the attribute is accepted here
		case "network.publicExposure":
			if raw == true {
				return ECRPlan{}, fmt.Errorf(
					"network.publicExposure=true cannot be honored — an ECR private registry is never " +
						"public; public pull is the separate ECR Public service (a different resource)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.CMEK = true
				p.KmsKey, _ = impl["kms_key"].(string)
				if p.KmsKey == "" {
					return ECRPlan{}, fmt.Errorf("encryption.customerManagedKeys requires implementation.kms_key")
				}
			}
		case "immutable.tags":
			p.ImmutableTags, _ = raw.(bool)
		case "security.scanOnPush":
			p.ScanOnPush, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return ECRPlan{}, fmt.Errorf("service.managed=false cannot be honored by ECR")
			}
		default:
			return ECRPlan{}, fmt.Errorf(
				"attribute %s has no ECR mapping — refusing rather than silently dropping it", path)
		}
	}
	if !ecrRepoNameOK.MatchString(p.RepoName) {
		return ECRPlan{}, fmt.Errorf("derived repository name %q is invalid", p.RepoName)
	}
	return p, nil
}

func (p ECRPlan) createBody(capability, environment string) string {
	body := map[string]any{
		"repositoryName": p.RepoName,
		"tags": []any{
			map[string]any{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
			map[string]any{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
		},
	}
	if p.ImmutableTags {
		body["imageTagMutability"] = "IMMUTABLE"
	} else {
		body["imageTagMutability"] = "MUTABLE"
	}
	if p.CMEK {
		body["encryptionConfiguration"] = map[string]any{"encryptionType": "KMS", "kmsKey": p.KmsKey}
	}
	if p.ScanOnPush {
		// scan-on-push posture: images are scanned for vulnerabilities at push.
		body["imageScanningConfiguration"] = map[string]any{"scanOnPush": true}
	}
	b, _ := json.Marshal(body)
	return string(b)
}
