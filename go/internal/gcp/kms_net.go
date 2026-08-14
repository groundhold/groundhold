// GCP Cloud KMS network shell (D102): the bearer-signed REST half of the
// capability.key.encryption driver. Create is the constitutive-composite sequence
// keyRing (permanent, idempotent) then cryptoKey. Ownership is labels. The DELETE
// is the honest one: Cloud KMS keyRings and cryptoKeys CANNOT be deleted, so delete
// destroys the key MATERIAL (schedules destruction of every enabled version) and
// says so — the tombstone reflects material-destroyed, not resource-removed,
// because the shell is permanent by the provider's design. D29/D87 honesty.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) kmsBase() string {
	if d.KMSBaseURL != "" {
		return d.KMSBaseURL
	}
	return cloudKMSBaseURL
}

var kmsNameOK = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)

func gkmsProviderID(project, location, ring, key string) string {
	return "gkms:" + project + ":" + location + ":" + ring + ":" + key
}

func splitGKMSProviderID(providerID string) (project, location, ring, key string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 5 || parts[0] != "gkms" {
		return "", "", "", "", fmt.Errorf("providerId %q is not gkms:project:location:ring:key", providerID)
	}
	if !projectOK.MatchString(parts[1]) || !kmsLocationOK.MatchString(parts[2]) ||
		!kmsNameOK.MatchString(parts[3]) || !kmsNameOK.MatchString(parts[4]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], parts[4], nil
}

func (d *Driver) cryptoKeyURL(project, location, ring, key string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		d.kmsBase(), project, location, ring, key)
}

type cryptoKeyDoc struct {
	Name            string            `json:"name"`
	Labels          map[string]string `json:"labels"`
	RotationPeriod  string            `json:"rotationPeriod"`
	VersionTemplate struct {
		ProtectionLevel string `json:"protectionLevel"`
	} `json:"versionTemplate"`
}

func (d *Driver) getCryptoKey(project, location, ring, key string) (cryptoKeyDoc, bool, error) {
	const op = "cryptoKey.get"
	st, body, err := d.call("GET", d.cryptoKeyURL(project, location, ring, key), nil)
	if err != nil {
		return cryptoKeyDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return cryptoKeyDoc{}, false, nil
	}
	if st != http.StatusOK {
		return cryptoKeyDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc cryptoKeyDoc
	if json.Unmarshal(body, &doc) != nil {
		return cryptoKeyDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createKMS(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildKMSKey(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gkmsProviderID(d.Project, plan.Location, plan.Ring, plan.Key)

	// ---- 1. keyRing (constitutive, PERMANENT, idempotent) ----
	ringURL := fmt.Sprintf("%s/projects/%s/locations/%s/keyRings?keyRingId=%s",
		d.kmsBase(), d.Project, plan.Location, plan.Ring)
	st, body, err := d.call("POST", ringURL, map[string]any{})
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("keyRing create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated || st == http.StatusConflict:
		// created or already exists — a keyRing is permanent, so a 409 is fine
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("keyRing create HTTP %d (server error) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "keyRing create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("keyRing create HTTP %d: %s", st, mutDetail(body))}
	}

	// ---- 2. cryptoKey ----
	nextRotation := ""
	if plan.RotationSeconds > 0 {
		nextRotation = d.Now().Add(time.Duration(plan.RotationSeconds) * time.Second).UTC().Format(time.RFC3339)
	}
	keyURL := fmt.Sprintf("%s/projects/%s/locations/%s/keyRings/%s/cryptoKeys?cryptoKeyId=%s",
		d.kmsBase(), d.Project, plan.Location, plan.Ring, plan.Key)
	kst, kbody, kerr := d.call("POST", keyURL, plan.cryptoKeyBody(capability, environment, nextRotation))
	switch {
	case kerr != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("cryptoKey create outcome unknown (may have landed): %v", kerr)}
	case kst == http.StatusOK || kst == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case kst == http.StatusConflict:
		doc, found, rerr := d.getCryptoKey(d.Project, plan.Location, plan.Ring, plan.Key)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict, existing key gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a cryptoKey with this name exists and is not ours (labels do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, idempotent
	case kst >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("cryptoKey create HTTP %d (server error — may have landed) — reconcile", kst)}
	default:
		if r := provider.MutationResult(kst, gcpErrCode(kbody), nil, pid, "cryptoKey create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("cryptoKey create HTTP %d: %s", kst, mutDetail(kbody))}
	}
}

func (d *Driver) observeKMS(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, ring, key, err := splitGKMSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getCryptoKey(project, location, ring, key)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"cryptoKey not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	// D1040/D1067: rotation.enabled is emitted for BOTH states — a cryptoKey with no
	// rotationPeriod is a MEASURED false (rotation OFF), not an absence. Emitting only
	// the ON case let a rotation contract be adopted/verified as satisfied over a
	// non-rotating key (the cross-cloud twin of the AWS KMS fix). rotation.period is
	// emitted only when rotating (a disabled key has no period; inventing one would lie).
	obs = append(obs, provider.Observation{Path: "rotation.enabled",
		Value: doc.RotationPeriod != "", Derivation: "measured"})
	if doc.RotationPeriod != "" {
		// the API form "2592000s" is a canonical duration — the verifier compares
		// it to a declared "30d" as durations.
		obs = append(obs, provider.Observation{Path: "rotation.period", Value: doc.RotationPeriod, Derivation: "measured"})
	}
	switch doc.VersionTemplate.ProtectionLevel {
	case "SOFTWARE":
		obs = append(obs, provider.Observation{Path: "protection.level", Value: "software", Derivation: "measured"})
	case "HSM":
		obs = append(obs, provider.Observation{Path: "protection.level", Value: "hsm", Derivation: "measured"})
	}
	return obs, nil, nil
}

// deleteKMS destroys the key MATERIAL — Cloud KMS forbids deleting a keyRing or
// cryptoKey, so every enabled version is scheduled for destruction and the honest
// result says the shell is permanent (never a false "resource removed").
func (d *Driver) deleteKMS(capability, environment, providerID string) provider.CreateResult {
	project, location, ring, key, err := splitGKMSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getCryptoKey(project, location, ring, key)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cryptoKey labels do not match — refusing to destroy a key that is not ours"}
	}
	// list versions and destroy every ENABLED one.
	listURL := d.cryptoKeyURL(project, location, ring, key) + "/cryptoKeyVersions"
	st, body, e := d.call("GET", listURL, nil)
	if e != nil || st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "could not list key versions — reconcile"}
	}
	var vl struct {
		CryptoKeyVersions []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"cryptoKeyVersions"`
	}
	if json.Unmarshal(body, &vl) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "key-version list gave no answer — reconcile: " + readBody("cryptoKeyVersions.list", st).Error()}
	}
	for _, v := range vl.CryptoKeyVersions {
		if v.State != "ENABLED" {
			continue
		}
		dst, dbody, de := d.call("POST", d.kmsBase()+"/"+v.Name+":destroy", map[string]any{})
		if de != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("version destroy outcome unknown: %v", de)}
		}
		if dst >= 500 {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("version destroy HTTP %d (server error) — reconcile", dst)}
		}
		if dst < 200 || dst >= 300 {
			if r := provider.MutationResult(dst, gcpErrCode(dbody), nil, providerID, "version destroy"); r != nil {
				return *r
			}
			return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("version destroy HTTP %d: %s", dst, mutDetail(dbody))}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
		Reason: "key material scheduled for destruction; the cryptoKey and keyRing resources are PERMANENT " +
			"(Cloud KMS forbids their deletion) — the key is unusable, not removed"}
}
