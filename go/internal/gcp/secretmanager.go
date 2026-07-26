// GCP Secret Manager request building (D97): the GCP half of the capability.secret
// driver — a managed, encrypted, versioned secret HANDLE whose value is supplied
// out of band (never a declared attribute). The bound resource is the Secret
// (projects/P/secrets/N); versions are data lifecycle, not a second binding.
// Residency is the crown: Secret Manager defaults to AUTOMATIC (global) replication,
// so a residency-honest create MUST pin a userManaged replica in the region (the
// same lesson as Pub/Sub messageStoragePolicy); observe refuses to report a region
// for an automatic-replication secret.
package gcp

import "fmt"

const secretManagerBaseURL = "https://secretmanager.googleapis.com/v1"

// SecretPlan is the attribute-derived shape a create assembles.
type SecretPlan struct {
	Name       string
	Region     string
	Public     bool
	KmsKeyName string // CMEK, from impl; "" = provider-managed
}

// BuildSecretCreate maps capability.secret attributes to a Secret create request.
// Every error is a refusal apply surfaces in preflight.
func BuildSecretCreate(project, environment, capability string,
	attrs, impl map[string]any, generation int) (SecretPlan, error) {
	p := SecretPlan{Name: resourceName(project, environment, capability, generation, 255)}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return SecretPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored (Secret Manager always encrypts)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyName, _ = impl["kms_key_name"].(string)
				if p.KmsKeyName == "" {
					return SecretPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_name")
				}
			}
		case "service.managed":
			if raw != true {
				return SecretPlan{}, fmt.Errorf("service.managed=false cannot be honored by Secret Manager")
			}
		default:
			return SecretPlan{}, fmt.Errorf(
				"attribute %s has no Secret Manager mapping — refusing rather than "+
					"silently dropping it (rotation is the producer's job, the value is "+
					"data, access is IAM — all out of scope by design)", path)
		}
	}
	if p.Region == "" {
		return SecretPlan{}, fmt.Errorf(
			"secret requires location.region (a userManaged replica) — automatic " +
				"replication is global and carries no residency guarantee")
	}
	return p, nil
}

// createBody is the secrets.create request body: labels + a userManaged replica
// pinned to the region (with optional CMEK). The value is NEVER included.
func (p SecretPlan) createBody(capability, environment string) map[string]any {
	replica := map[string]any{"location": p.Region}
	if p.KmsKeyName != "" {
		replica["customerManagedEncryption"] = map[string]any{"kmsKeyName": p.KmsKeyName}
	}
	return map[string]any{
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
		"replication": map[string]any{
			"userManaged": map[string]any{"replicas": []any{replica}},
		},
	}
}

func sortedKeysG(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
