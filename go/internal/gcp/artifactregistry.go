// GCP Artifact Registry request building (D110): the semantic core of the GCP
// capability.registry.image driver — the SAME vocabulary AWS ECR and Azure ACR fulfil.
// A managed container image registry: regional, optionally CMEK-encrypted, optionally
// public (an allUsers reader binding), with immutable tags (dockerConfig.immutableTags,
// the supply-chain guarantee). Format is DOCKER (OCI); other formats are a one-cloud
// feature, deferred. Ownership is labels.
package gcp

import (
	"fmt"
	"regexp"
)

const artifactRegistryBaseURL = "https://artifactregistry.googleapis.com/v1"

// GCP image vulnerability scanning is NOT a per-repository property (the honest
// divergence from AWS ECR's per-repo imageScanningConfiguration): it is the
// project-level Container Scanning API, enabled ONCE per project via Service Usage.
// So security.scanOnPush is OBSERVED from that API's state and ENABLED at create —
// never faked as a repository field. (fala 2)
const serviceUsageBaseURL = "https://serviceusage.googleapis.com/v1"
const containerScanningService = "containerscanning.googleapis.com"

var arRepoIDOK = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// ARRepoPlan is the attribute-derived shape a create assembles.
type ARRepoPlan struct {
	RepoID        string
	Region        string
	Public        bool
	KmsKey        string // "" = provider-managed
	ImmutableTags bool
	// ScanOnPush is a PROJECT posture, not a repo field: true => enable the
	// Container Scanning API for the project (additive, idempotent).
	ScanOnPush bool
}

// BuildARRepo maps capability.registry.image attributes + impl to a plan. Every error
// is a preflight refusal, never a silent drop.
func BuildARRepo(project, environment, capability string,
	attrs, impl map[string]any, generation int) (ARRepoPlan, error) {
	p := ARRepoPlan{RepoID: resourceName(project, environment, capability, generation, 63)}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKey, _ = impl["kms_key"].(string)
				if p.KmsKey == "" {
					return ARRepoPlan{}, fmt.Errorf("encryption.customerManagedKeys requires implementation.kms_key")
				}
			}
		case "immutable.tags":
			p.ImmutableTags, _ = raw.(bool)
		case "security.scanOnPush":
			// PROJECT-level Container Scanning API, not a repo field. Recorded in
			// the plan; honored by enabling the API at create (createARRepo), NOT
			// written into createBody. Observed from the API state, not the repo.
			p.ScanOnPush, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return ARRepoPlan{}, fmt.Errorf("service.managed=false cannot be honored by Artifact Registry")
			}
		default:
			return ARRepoPlan{}, fmt.Errorf(
				"attribute %s has no Artifact Registry mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Region == "" {
		return ARRepoPlan{}, fmt.Errorf("registry requires location.region")
	}
	if !arRepoIDOK.MatchString(p.RepoID) {
		return ARRepoPlan{}, fmt.Errorf("derived repository id %q is invalid", p.RepoID)
	}
	if !projectOK.MatchString(project) {
		return ARRepoPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

func (p ARRepoPlan) createBody(capability, environment string) map[string]any {
	body := map[string]any{
		"format":      "DOCKER",
		"description": "groundhold-managed registry",
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
		"dockerConfig": map[string]any{"immutableTags": p.ImmutableTags},
	}
	if p.KmsKey != "" {
		body["kmsKeyName"] = p.KmsKey
	}
	return body
}

// classifyARChange (D46 / fala 2): PURE — which capability.registry.image transitions
// can Artifact Registry honor in place? The honest divergence from AWS ECR
// (classifyECRChange) is security.scanOnPush. In ECR scan-on-push is a per-repository
// field, so ECR classifies it mutable and patches it with PutImageScanningConfiguration.
// In GCP there is NO per-repository scanning setting: image scanning is the project-level
// Container Scanning API (containerscanning.googleapis.com), enabled once per PROJECT.
// groundhold ENABLES it at create (additive, idempotent, safe), but a per-repository in-place
// update MUST NOT toggle a project-wide API — flipping it would change scanning for EVERY
// repository in the project, a blast radius a repo-scoped patch cannot honestly own. So it
// is classified "unsupported" with a truthful reason: deliberately-not-mutable, which is
// NOT the same as mutable-without-updater. Region and CMEK are create-time (a replacement);
// immutable.tags and public exposure are patchable in principle but not wired in this slice.
func classifyARChange(path string) (string, string) {
	switch path {
	case "security.scanOnPush":
		return "unsupported", "scanOnPush in GCP is the project-level Container Scanning API " +
			"(containerscanning.googleapis.com), not a per-repository property — groundhold enables it " +
			"at create, but a per-repository update will not toggle a project-wide API (it would " +
			"change scanning for every repository in the project)"
	case "immutable.tags", "network.publicExposure":
		return "unsupported", "in-place patch of " + path + " is not wired for Artifact Registry in this slice"
	case "location.region", "encryption.customerManagedKeys":
		return "immutable", "an Artifact Registry repository's region/CMEK is fixed at creation — a change is a replacement"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Artifact Registry in-place mapping for " + path
	}
}
