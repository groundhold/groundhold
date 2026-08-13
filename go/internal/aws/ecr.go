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

	"groundhold/internal/scalars"
)

var ecrRepoNameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{1,255}$`)

// ECRPlan is the attribute-derived shape a create assembles.
type ECRPlan struct {
	RepoName         string
	ImmutableTags    bool
	ScanOnPush       bool
	CMEK             bool
	KmsKey           string
	RetentionMaxDays int64 // retention.maximum: expire images older than N days (0 = no rule)
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
		case "retention.maximum":
			sc, err := scalars.Parse(raw)
			if err != nil || sc.Kind != scalars.Duration {
				return ECRPlan{}, fmt.Errorf("retention.maximum must be a duration, got %v", raw)
			}
			days := int64(sc.Value.(float64)) / 86400000
			if days < 1 {
				return ECRPlan{}, fmt.Errorf(
					"retention.maximum must be at least 1 day (ECR lifecycle age-out is whole days)")
			}
			p.RetentionMaxDays = days
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

// lifecyclePolicyText renders the ONE closed rule retention.maximum maps to: expire
// images older than RetentionMaxDays since push. Deterministic, never user-authored —
// observe reverse-maps exactly this shape and reports anything richer as unknown.
func (p ECRPlan) lifecyclePolicyText() string {
	pol := map[string]any{"rules": []any{map[string]any{
		"rulePriority": 1,
		"description":  "groundhold-retention-maximum",
		"selection": map[string]any{
			"tagStatus":   "any",
			"countType":   "sinceImagePushed",
			"countUnit":   "days",
			"countNumber": p.RetentionMaxDays,
		},
		"action": map[string]any{"type": "expire"},
	}}}
	b, _ := json.Marshal(pol)
	return string(b)
}

// ecrLifecycleDays reverse-maps a lifecyclePolicyText back to a since-pushed-days
// expiry, or (0, false) if the policy is empty or a shape this driver does not render
// (richer/hand-authored rules) — which observe reports as unknown, never a guess.
func ecrLifecycleDays(policyText string) (int64, bool) {
	if policyText == "" {
		return 0, false
	}
	var pol struct {
		Rules []struct {
			Selection struct {
				CountType   string `json:"countType"`
				CountUnit   string `json:"countUnit"`
				CountNumber int64  `json:"countNumber"`
			} `json:"selection"`
			Action struct {
				Type string `json:"type"`
			} `json:"action"`
		} `json:"rules"`
	}
	if json.Unmarshal([]byte(policyText), &pol) != nil {
		return 0, false
	}
	for _, r := range pol.Rules {
		if r.Action.Type == "expire" && r.Selection.CountType == "sinceImagePushed" &&
			r.Selection.CountUnit == "days" && r.Selection.CountNumber > 0 {
			return r.Selection.CountNumber, true
		}
	}
	return 0, false
}
