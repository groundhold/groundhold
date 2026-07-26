// AWS KMS request building (D102): the semantic core of the AWS
// capability.key.encryption driver — the SAME vocabulary GCP Cloud KMS and Azure
// Key Vault keys fulfil. Unlike Cloud KMS (keyRing + key) and Azure (vault + key),
// an AWS KMS key is a SINGLE resource — no ring. Two honest boundaries this cloud
// forces: AWS KMS is ALWAYS HSM-backed (FIPS 140-2), so protection.level=software
// is refused, not faked; and a KMS key cannot be hard-deleted — the honest delete
// is ScheduleKeyDeletion with a recovery window. The KeyId is server-assigned (a
// UUID) and CreateKey has no idempotency token, so a lost create is honestly
// unknown (reconcile by tags), never a fabricated handle.
package aws

import (
	"fmt"

	"groundhold/internal/scalars"
)

const kmsTarget = "TrentService"

// AWSKMSKeyPlan is the attribute-derived shape a create assembles.
type AWSKMSKeyPlan struct {
	Region       string
	RotationDays int // 0 = no automatic rotation
	Description  string
}

// BuildAWSKMSKey maps capability.key.encryption attributes to a KMS create plan.
// Every error is a preflight refusal, never a silent drop.
func BuildAWSKMSKey(environment, capability string,
	attrs, impl map[string]any, generation int) (AWSKMSKeyPlan, error) {
	p := AWSKMSKeyPlan{Description: "groundhold-managed key for " + sanitizeTag(capability)}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "rotation.period":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Duration {
				return AWSKMSKeyPlan{}, fmt.Errorf("rotation.period is not a duration")
			}
			ms, ok := s.Value.(float64)
			if !ok {
				return AWSKMSKeyPlan{}, fmt.Errorf("rotation.period is not a duration")
			}
			days := int(ms / 86400000)
			if days < 90 || days > 2560 {
				return AWSKMSKeyPlan{}, fmt.Errorf(
					"rotation.period %dd is outside the AWS KMS automatic-rotation range (90-2560 days) "+
						"— refusing rather than clamping", days)
			}
			p.RotationDays = days
		case "protection.level":
			switch raw {
			case "hsm":
				// AWS KMS is always HSM-backed — honored
			case "software":
				return AWSKMSKeyPlan{}, fmt.Errorf(
					"protection.level=software cannot be honored by AWS KMS — every KMS key is " +
						"HSM-backed (FIPS 140-2); refusing rather than silently upgrading to hsm (honest one-cloud gap)")
			default:
				return AWSKMSKeyPlan{}, fmt.Errorf("protection.level %v has no AWS KMS mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return AWSKMSKeyPlan{}, fmt.Errorf("service.managed=false cannot be honored by AWS KMS")
			}
		default:
			return AWSKMSKeyPlan{}, fmt.Errorf(
				"attribute %s has no AWS KMS mapping — refusing rather than silently dropping it "+
					"(the key material is never exported, key size/spec is impl)", path)
		}
	}
	if p.Region == "" {
		return AWSKMSKeyPlan{}, fmt.Errorf("key requires location.region")
	}
	if !regionOK.MatchString(p.Region) {
		return AWSKMSKeyPlan{}, fmt.Errorf("location.region %q is not a valid AWS region", p.Region)
	}
	return p, nil
}

// createJSON is the CreateKey request body (symmetric encryption key, ownership
// tags at birth).
func (p AWSKMSKeyPlan) createJSON(capability, environment string) string {
	return fmt.Sprintf(`{"Description":%q,"KeyUsage":"ENCRYPT_DECRYPT",`+
		`"KeySpec":"SYMMETRIC_DEFAULT","Origin":"AWS_KMS","Tags":[`+
		`{"TagKey":"groundhold-capability","TagValue":%q},`+
		`{"TagKey":"groundhold-environment","TagValue":%q}]}`,
		p.Description, sanitizeTag(capability), sanitizeTag(environment))
}
