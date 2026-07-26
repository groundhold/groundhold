// GCP Cloud KMS request building (D102): the semantic core of the GCP
// capability.key.encryption driver — the SAME vocabulary AWS KMS and Azure Key
// Vault keys fulfil. A Cloud KMS key is a CONSTITUTIVE COMPOSITE (D89): a
// cryptoKey lives in a keyRing, so the driver creates ring + key under one
// binding. Two Cloud KMS quirks shape the driver: keyRings and cryptoKeys are
// PERMANENT (neither can be deleted — only key VERSIONS can be destroyed), and a
// rotationPeriod requires a nextRotationTime (a timestamp, so it is computed in the
// shell from Now(), never in this pure builder). v0 is a symmetric ENCRYPT_DECRYPT
// key — the CMK other capabilities reference.
package gcp

import (
	"fmt"
	"regexp"

	"groundhold/internal/scalars"
)

const cloudKMSBaseURL = "https://cloudkms.googleapis.com/v1"

// kmsLocationOK bounds a Cloud KMS location (a region like europe-west1, a
// multi-region like "us"/"europe", or "global") before path interpolation.
var kmsLocationOK = regexp.MustCompile(`^[a-z][a-z0-9-]{0,29}$`)

// KMSPlan is the attribute-derived shape a create assembles.
type KMSPlan struct {
	Ring            string
	Key             string
	Location        string
	RotationSeconds int64  // 0 = no automatic rotation
	ProtectionLevel string // SOFTWARE | HSM
}

// BuildKMSKey maps capability.key.encryption attributes to a Cloud KMS plan. Every
// error is a preflight refusal, never a silent drop.
func BuildKMSKey(project, environment, capability string,
	attrs, impl map[string]any, generation int) (KMSPlan, error) {
	p := KMSPlan{
		Ring:            "groundhold-" + sanitizeLabel(environment),
		Key:             resourceName(project, environment, capability, generation, 63),
		ProtectionLevel: "SOFTWARE",
	}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Location, _ = raw.(string)
		case "rotation.period":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Duration {
				return KMSPlan{}, fmt.Errorf("rotation.period is not a duration")
			}
			ms, ok := s.Value.(float64)
			if !ok {
				return KMSPlan{}, fmt.Errorf("rotation.period is not a duration")
			}
			secs := int64(ms / 1000)
			if secs < 86400 {
				return KMSPlan{}, fmt.Errorf(
					"rotation.period below 1 day cannot be honored (Cloud KMS minimum rotation is 24h)")
			}
			p.RotationSeconds = secs
		case "protection.level":
			switch raw {
			case "software":
				p.ProtectionLevel = "SOFTWARE"
			case "hsm":
				p.ProtectionLevel = "HSM"
			default:
				return KMSPlan{}, fmt.Errorf("protection.level %v has no Cloud KMS mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return KMSPlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud KMS")
			}
		default:
			return KMSPlan{}, fmt.Errorf(
				"attribute %s has no Cloud KMS mapping — refusing rather than silently dropping it "+
					"(the key material is never exported, versions are lifecycle, size is impl)", path)
		}
	}
	if p.Location == "" {
		return KMSPlan{}, fmt.Errorf("key requires location.region")
	}
	if !kmsLocationOK.MatchString(p.Location) {
		return KMSPlan{}, fmt.Errorf("location.region %q is not a valid Cloud KMS location", p.Location)
	}
	if !projectOK.MatchString(project) {
		return KMSPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// cryptoKeyBody is the cryptoKeys.create request body. nextRotationTime is passed
// from the shell (Now()+rotation) because Cloud KMS requires it whenever a
// rotationPeriod is set — a runtime timestamp, never a sealed-plan value.
func (p KMSPlan) cryptoKeyBody(capability, environment, nextRotationTime string) map[string]any {
	body := map[string]any{
		"purpose": "ENCRYPT_DECRYPT",
		"versionTemplate": map[string]any{
			"protectionLevel": p.ProtectionLevel,
			"algorithm":       "GOOGLE_SYMMETRIC_ENCRYPTION",
		},
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	if p.RotationSeconds > 0 {
		body["rotationPeriod"] = fmt.Sprintf("%ds", p.RotationSeconds)
		body["nextRotationTime"] = nextRotationTime
	}
	return body
}
