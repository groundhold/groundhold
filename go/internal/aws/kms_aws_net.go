// AWS KMS network shell (D102): the SigV4-signed, JSON-protocol half of the AWS
// capability.key.encryption driver. The KeyId is SERVER-ASSIGNED and CreateKey has
// no idempotency token, so a lost create is honestly unknown WITHOUT a fabricated
// pid (reconcile by tags), and a successful create parses the KeyId from the
// response (DeterministicID=false). Ownership is TAGS (set inline at CreateKey).
// The honest DELETE is ScheduleKeyDeletion: a KMS key cannot be hard-deleted, so it
// enters a recovery window — the result says so rather than claim removal.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

var kmsKeyIDOK = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (d *Driver) kmsBase(region string) string {
	if d.KMSBaseURL != "" {
		return d.KMSBaseURL
	}
	return "https://kms." + region + ".amazonaws.com"
}

func (d *Driver) kmsCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": kmsTarget + "." + action,
	}
	return d.doSigned("POST", d.kmsBase(region)+"/", "kms", region, h, []byte(body))
}

// kmsKeyIsCustomerManaged reports whether a KMS key (ARN or id) is CUSTOMER-managed
// — a real CMK — vs an AWS-managed default (KeyManager=AWS, e.g. the aws/rds key).
// ok=false on any unreadable/parse failure so the caller emits a diagnostic, never
// a fabricated customerManagedKeys=false. This is the second-service trace that
// lets the DB drivers MEASURE encryption.customerManagedKeys instead of punting it.
func (d *Driver) kmsKeyIsCustomerManaged(region, keyID string) (customer bool, err error) {
	const op = "DescribeKey"
	st, resp, cerr := d.kmsCall(region, "DescribeKey", fmt.Sprintf(`{"KeyId":%q}`, keyID))
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, awsErrCodeOf(resp))
	}
	var out struct {
		KeyMetadata struct {
			KeyManager string `json:"KeyManager"`
		} `json:"KeyMetadata"`
	}
	if json.Unmarshal(resp, &out) != nil || out.KeyMetadata.KeyManager == "" {
		return false, readBody(op, st)
	}
	return out.KeyMetadata.KeyManager == "CUSTOMER", nil
}

func awsKMSProviderID(region, keyID string) string { return "akms:" + region + ":" + keyID }

func splitAWSKMSProviderID(providerID string) (region, keyID string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "akms" {
		return "", "", fmt.Errorf("providerId %q is not akms:region:keyid", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !kmsKeyIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId key id %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

func (d *Driver) kmsTags(region, keyID string) (map[string]string, error) {
	const op = "ListResourceTags"
	st, resp, err := d.kmsCall(region, "ListResourceTags", fmt.Sprintf(`{"KeyId":%q}`, keyID))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Tags []struct {
			TagKey   string `json:"TagKey"`
			TagValue string `json:"TagValue"`
		} `json:"Tags"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range r.Tags {
		m[t.TagKey] = t.TagValue
	}
	return m, nil
}

// findKMSKeyByTags (D253) scans for KMS keys carrying OUR ownership tags — the
// create-adoption lookup for a server-assigned KeyId with no idempotency token,
// where a blind CreateKey on a lost ledger would mint a NEW key every time.
// Paginates ListKeys (a key on a later page missed would defeat the guard), reads
// each key's tags and VERIFIES them, and returns the count of owned keys + (when
// exactly one) its id. readable=false on any failure — the caller then falls back
// to a normal create rather than blocking a genuine first deploy.
func (d *Driver) findKMSKeyByTags(region, capability, environment string) (keyID string, count int, readable bool) {
	marker := ""
	var owned []string
	for {
		req := `{"Limit":1000}`
		if marker != "" {
			req = fmt.Sprintf(`{"Limit":1000,"Marker":%q}`, marker)
		}
		st, body, err := d.kmsCall(region, "ListKeys", req)
		if err != nil || st != http.StatusOK {
			return "", 0, false
		}
		var r struct {
			Keys []struct {
				KeyID string `json:"KeyId"`
			} `json:"Keys"`
			Truncated  bool   `json:"Truncated"`
			NextMarker string `json:"NextMarker"`
		}
		if json.Unmarshal(body, &r) != nil {
			return "", 0, false
		}
		for _, k := range r.Keys {
			if k.KeyID == "" {
				continue
			}
			tags, terr := d.kmsTags(region, k.KeyID)
			if terr != nil {
				// a key whose tags we cannot read could be ours — fail closed
				// (fall back to create) rather than miss it and blind-duplicate.
				return "", 0, false
			}
			if groundholdTagsMatch(tags, capability, environment) {
				owned = append(owned, k.KeyID)
			}
		}
		if !r.Truncated || r.NextMarker == "" {
			break
		}
		marker = r.NextMarker
	}
	if len(owned) == 1 {
		return owned[0], 1, true
	}
	return "", len(owned), true
}

func (d *Driver) createAWSKMS(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAWSKMSKey(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// create-adoption (D253): a KMS KeyId is server-assigned and CreateKey has no
	// idempotency token, so a blind create on a lost ledger mints a NEW key every
	// run. Scan for an existing key carrying our ownership tags first; exactly one
	// ours -> BIND it (reality), never create. A FOREIGN-tagged key never matches,
	// so it is never adopted. Ambiguous (>1) -> refuse to guess. A readable-empty or
	// unreadable scan falls through to the normal create.
	if keyID, n, readable := d.findKMSKeyByTags(region, capability, environment); readable && n == 1 {
		return provider.CreateResult{ProviderID: awsKMSProviderID(region, keyID), Status: "succeeded"}
	} else if readable && n > 1 {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("multiple KMS keys carry our ownership tags for %s/%s — cannot pick one to adopt; reconcile manually", capability, environment)}
	}
	st, resp, err := d.kmsCall(region, "CreateKey", plan.createJSON(capability, environment))
	if err != nil {
		// server-assigned id + no idempotency token: no pid to carry, so the
		// honest outcome is unknown, reconcilable by our ownership tags.
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have created an orphan key — reconcile by tags): %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile by tags", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, ecsErr(resp), nil, "", "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, ecsErr(resp))}
	}
	var r struct {
		KeyMetadata struct {
			KeyID string `json:"KeyId"`
		} `json:"KeyMetadata"`
	}
	if json.Unmarshal(resp, &r) != nil || r.KeyMetadata.KeyID == "" {
		return provider.CreateResult{Status: "unknown", Reason: "create returned no KeyId — reconcile by tags"}
	}
	pid := awsKMSProviderID(region, r.KeyMetadata.KeyID)
	if plan.RotationDays > 0 {
		body := fmt.Sprintf(`{"KeyId":%q,"RotationPeriodInDays":%d}`, r.KeyMetadata.KeyID, plan.RotationDays)
		rst, rresp, rerr := d.kmsCall(region, "EnableKeyRotation", body)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "key created; enable-rotation outcome unknown — reconcile"}
		}
		if rst >= 500 {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("key created; enable-rotation HTTP %d (server error) — reconcile", rst)}
		}
		if rst != http.StatusOK {
			if r := provider.MutationResult(rst, ecsErr(rresp), nil, pid, "enable-rotation"); r != nil {
				return *r
			}
			return provider.CreateResult{ProviderID: pid, Status: "failed", Reason: fmt.Sprintf("key created but enable-rotation failed: HTTP %d (%s)", rst, ecsErr(rresp))}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) observeAWSKMS(capability, providerID string) ([]provider.Observation, []string, error) {
	region, keyID, err := splitAWSKMSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	st, resp, e := d.kmsCall(region, "DescribeKey", fmt.Sprintf(`{"KeyId":%q}`, keyID))
	if e != nil {
		return nil, nil, fmt.Errorf("DescribeKey: %v", e)
	}
	if strings.Contains(ecsErr(resp), "NotFound") {
		// F-LC3 (D521): a BOUND resource the API says is GONE. A diagnostic
		// alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"key not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("DescribeKey: HTTP %d", st)
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// every AWS KMS key is HSM-backed (FIPS 140-2).
		{Path: "protection.level", Value: "hsm", Derivation: "measured"},
	}
	var diags []string
	const rotOp = "GetKeyRotationStatus"
	rst, rresp, rerr := d.kmsCall(region, "GetKeyRotationStatus", fmt.Sprintf(`{"KeyId":%q}`, keyID))
	if rerr != nil {
		diags = append(diags, "rotation.period not observed: "+readTransport(rotOp, rerr).Error())
	} else if rst != http.StatusOK {
		diags = append(diags, "rotation.period not observed: "+
			readHTTP(rotOp, rst, awsErrCodeOf(rresp)).Error())
	} else {
		var rr struct {
			KeyRotationEnabled   bool `json:"KeyRotationEnabled"`
			RotationPeriodInDays int  `json:"RotationPeriodInDays"`
		}
		if json.Unmarshal(rresp, &rr) == nil && rr.KeyRotationEnabled {
			days := rr.RotationPeriodInDays
			if days == 0 {
				days = 365 // legacy default when no explicit period
			}
			obs = append(obs, provider.Observation{Path: "rotation.period",
				Value: fmt.Sprintf("%dd", days), Derivation: "measured"})
		}
	}
	return obs, diags, nil
}

func (d *Driver) deleteAWSKMS(capability, environment, providerID string) provider.CreateResult {
	region, keyID, err := splitAWSKMSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	tags, terr := d.kmsTags(region, keyID)
	if terr != nil {
		// distinguish "gone" from "unreadable": a NotFound describe is idempotent.
		st, resp, _ := d.kmsCall(region, "DescribeKey", fmt.Sprintf(`{"KeyId":%q}`, keyID))
		if strings.Contains(ecsErr(resp), "NotFound") {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
		}
		_ = st
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "key tags do not match — refusing to schedule deletion of a key that is not ours"}
	}
	st, resp, e := d.kmsCall(region, "ScheduleKeyDeletion",
		fmt.Sprintf(`{"KeyId":%q,"PendingWindowInDays":7}`, keyID))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(ecsErr(resp), "NotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if strings.Contains(ecsErr(resp), "KMSInvalidState") {
		// already pending deletion — idempotent success.
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
			Reason: "key already scheduled for deletion (recovery window pending)"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
		Reason: "key scheduled for deletion after a 7-day recovery window — an AWS KMS key cannot be " +
			"destroyed immediately (it is disabled, then deleted); never forced"}
}
