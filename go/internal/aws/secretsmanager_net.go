// Secrets Manager network shell (D97): the SigV4-signed, JSON-protocol half of
// the AWS capability.secret driver. The secret name is deterministic (the
// idempotency key), so the handle is knowable BEFORE the create response — a
// lost/garbled outcome (D29) always carries the pid. Ownership is TAGS applied
// at CreateSecret birth; a name is scoped to account+region (no global
// namespace, no D82 squat concern). The VALUE is never written — CreateSecret is
// issued with no SecretString. Create sequence: CreateSecret (+tags [+CMEK]) ->
// ownership re-check -> PutResourcePolicy (only if public).
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/adoptcheck"
	"groundhold/internal/provider"
)

// asmAdoptControls (D1062): a secret's CMEK key and its public-exposure posture are
// set INLINE at CreateSecret (KmsKeyId) / by the resource policy, and a create that
// finds the secret already ours never applied them to it. Both are re-assertable in
// place (updateASM wires UpdateSecret KmsKeyId and PutResourcePolicy), so a live
// secret on the AWS-default key where we declared CMEK, or with a public policy where
// we declared private, is unknown+bound — converge reconciles it through the consented
// update, never a silent adopt that claims a control the secret lacks.
var asmAdoptControls = []adoptcheck.Control{
	{Path: "encryption.customerManagedKeys", Direction: adoptcheck.SecureTrue, UpdateWired: true},
	{Path: "network.publicExposure", Direction: adoptcheck.SecureFalse, UpdateWired: true},
}

const asmTarget = "secretsmanager"

func (d *Driver) asmBase(region string) string {
	if d.SecretsManagerBaseURL != "" {
		return d.SecretsManagerBaseURL
	}
	return "https://secretsmanager." + region + ".amazonaws.com"
}

// asmCall signs and sends a JSON-protocol request (X-Amz-Target =
// secretsmanager.<Action>).
func (d *Driver) asmCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": asmTarget + "." + action,
	}
	return d.doSigned("POST", d.asmBase(region)+"/", "secretsmanager", region, h, []byte(body))
}

func asmProviderID(region, name string) string { return "asm:" + region + ":" + name }

// splitASMProviderID validates every component before it is interpolated into a
// request (D73 boundary). Region+name suffice — SecretId resolves the secret
// within the caller's account+region, so no account rides in the id.
func splitASMProviderID(providerID string) (region, name string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "asm" {
		return "", "", fmt.Errorf("providerId %q is not asm:region:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !asmNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId secret name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type asmDescribe struct {
	ARN         string `json:"ARN"`
	Name        string `json:"Name"`
	KmsKeyId    string `json:"KmsKeyId"`
	DeletedDate any    `json:"DeletedDate"`
	Tags        []struct {
		Key   string `json:"Key"`
		Value string `json:"Value"`
	} `json:"Tags"`
}

// describeASM reads a secret's metadata. found=false + readable=true is an
// authoritative "does not exist" (ResourceNotFoundException); readable=false is a
// transport/HTTP/parse failure (never "no tags", never "not found").
func (d *Driver) describeASM(region, name string) (doc asmDescribe, found bool, err error) {
	const op = "DescribeSecret"
	st, resp, cerr := d.asmCall(region, "DescribeSecret",
		fmt.Sprintf(`{"SecretId":%q}`, name))
	if cerr != nil {
		return asmDescribe{}, false, readTransport(op, cerr)
	}
	if st == http.StatusNotFound || strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return asmDescribe{}, false, nil
	}
	if st != http.StatusOK {
		return asmDescribe{}, false, readHTTP(op, st, ecsErr(resp))
	}
	if json.Unmarshal(resp, &doc) != nil {
		return asmDescribe{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (doc asmDescribe) tagMap() map[string]string {
	m := map[string]string{}
	for _, t := range doc.Tags {
		m[t.Key] = t.Value
	}
	return m
}

// asmRequestToken is a DETERMINISTIC UUID-format idempotency token for CreateSecret,
// derived from the secret name — a retry of the same create reuses it, so AWS treats
// the duplicate as one request instead of erroring or versioning twice (F27).
func asmRequestToken(name string) string {
	h := sha256hex([]byte("groundhold-asm|" + name))
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (d *Driver) createASM(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildSecretsManagerCreate(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := asmProviderID(region, plan.Name)

	// ---- CreateSecret (+ ownership tags at birth). No SecretString: the value
	// is data supplied out of band; groundhold creates a versionless handle.
	body := map[string]any{
		"Name": plan.Name,
		// F27: Secrets Manager REQUIRES a ClientRequestToken when the request carries
		// KMS/tags. Derive it DETERMINISTICALLY from the secret name so a retry after a
		// lost response is idempotent (AWS collapses the duplicate) rather than a random
		// UUID that would make each retry a distinct request.
		"ClientRequestToken": asmRequestToken(plan.Name),
		"Tags": []map[string]string{
			{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
			{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
		},
	}
	if plan.KmsKeyID != "" {
		body["KmsKeyId"] = plan.KmsKeyID
	}
	raw, _ := json.Marshal(body)
	st, resp, err := d.asmCall(region, "CreateSecret", string(raw))
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	}
	adopted := false
	switch {
	case st == http.StatusOK:
		// created — the ownership re-check below is belt-and-suspenders
	case strings.Contains(ecsErr(resp), "ResourceExists"):
		// a secret with this name exists — continue only if OURS
		doc, found, rerr := d.describeASM(region, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing secret gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !groundholdTagsMatch(doc.tagMap(), capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a secret with this name exists and is not ours (tags do not match) — refusing"}
		}
		// ours — fall through to re-assert exposure. The CreateSecret body (KmsKeyId)
		// never applied to this pre-existing secret, so its declared controls must be
		// re-verified before we call the adopt a success (D1062).
		adopted = true
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed): %s", st, ecsErr(resp))}
	default:
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, ecsErr(resp))}
	}

	// ---- public resource policy (rare exposure second gate). The PutResourcePolicy
	// call scopes to the secret by SecretId, so a "*" resource in the policy body
	// is correct (the ARN need not be threaded through the create response). ----
	if plan.Public {
		if r := d.asmPutPolicy(region, plan.Name, "", pid); r != nil {
			return *r
		}
	}
	if adopted {
		obs, _, oerr := d.observeASM(capability, pid)
		if oerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "adopted secret re-observe gave no answer — reconcile: " + oerr.Error()}
		}
		switch v := adoptcheck.Compare(attrs, obs, asmAdoptControls); v.Status {
		case "failed":
			return provider.CreateResult{Status: "failed", Reason: v.Reason}
		case "unknown":
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: v.Reason}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// asmPutPolicy runs one PutResourcePolicy; nil = ok, non-nil = a terminal result
// WITH the pid (the secret exists, so a partial is unknown/failed, never lost).
func (d *Driver) asmPutPolicy(region, name, arn, pid string) *provider.CreateResult {
	body := fmt.Sprintf(`{"SecretId":%q,"ResourcePolicy":%q}`, name, asmPublicPolicy(arn))
	st, resp, err := d.asmCall(region, "PutResourcePolicy", body)
	if err != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "secret created; public policy outcome unknown — reconcile"}
		return &r
	}
	if st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("secret created; public policy HTTP %d (server error) — reconcile", st)}
		return &r
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "public policy"); r != nil {
			return r
		}
		r := provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("secret created but public policy failed: HTTP %d (%s)", st, ecsErr(resp))}
		return &r
	}
	return nil
}

// asmDeletePolicy removes the resource policy (public exposure -> private).
func (d *Driver) asmDeletePolicy(region, name, pid string) *provider.CreateResult {
	st, resp, err := d.asmCall(region, "DeleteResourcePolicy", fmt.Sprintf(`{"SecretId":%q}`, name))
	if err != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "public policy removal outcome unknown — reconcile"}
		return &r
	}
	if st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("public policy removal HTTP %d (server error) — reconcile", st)}
		return &r
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "public policy removal"); r != nil {
			return r
		}
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("public policy removal failed: HTTP %d (%s)", st, ecsErr(resp))}
		return &r
	}
	return nil
}

// getASMPolicy reads the resource policy. readable=false is a transport/parse
// failure; an empty ResourcePolicy is an authoritative "no policy" (private).
func (d *Driver) getASMPolicy(region, name string) (policy string, err error) {
	const op = "GetResourcePolicy"
	st, resp, cerr := d.asmCall(region, "GetResourcePolicy", fmt.Sprintf(`{"SecretId":%q}`, name))
	if cerr != nil {
		return "", readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return "", readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		ResourcePolicy string `json:"ResourcePolicy"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return "", readBody(op, st)
	}
	return r.ResourcePolicy, nil
}

// observeASM reverse-maps a live secret. Residency is honest by construction: a
// Secrets Manager secret lives in the endpoint's region (unlike GCP Secret
// Manager's global default), so the region is reported without a diagnostic.
func (d *Driver) observeASM(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitASMProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	docm, found, rerr := d.describeASM(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"secret not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "measured"},
	}
	// CMEK iff a KmsKeyId is set to a NON-default key. Secrets Manager returns
	// the default key's id (aws/secretsmanager) or a customer key ARN.
	k := docm.KmsKeyId
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
		Value: k != "" && k != asmDefaultKeyAlias &&
			!strings.HasSuffix(k, ":alias/aws/secretsmanager") && k != "aws/secretsmanager",
		Derivation: "measured"})
	var diags []string
	// D756: DeletedDate was DECODED and never read — found by the fixture-coverage
	// sweep, which is the only reason anyone looked. A secret scheduled for deletion
	// still answers DescribeSecret, so every observation above stays true and nothing
	// said that GetSecretValue already refuses it: "you can't perform this operation on
	// the secret because it was marked for deletion". converge reported converged and
	// posture green over a secret the application could no longer read, for the whole
	// recovery window.
	//
	// The marker is NOT resource.absent: the secret exists, and a re-create under the
	// same name is refused by AWS while the window runs. This driver's own reconcile
	// already treats the twin state on a KMS key as TERMINAL-FAILED; observe now at
	// least says it out loud.
	if !isNilLike(docm.DeletedDate) {
		diags = append(diags, fmt.Sprintf("the secret is SCHEDULED FOR DELETION (%v) — it "+
			"still answers DescribeSecret, but GetSecretValue refuses it, so anything "+
			"reading this secret is already broken. Restore it (RestoreSecret) or bind a "+
			"new one; a re-create under the same name is refused while the recovery "+
			"window runs", docm.DeletedDate))
	}
	policy, polErr := d.getASMPolicy(region, name)
	switch {
	case polErr != nil:
		diags = append(diags, "network.publicExposure not observed: "+polErr.Error())
	case strings.TrimSpace(policy) == "":
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	default:
		public, parseable := snsPolicyPublic(policy)
		if !parseable {
			diags = append(diags, "network.publicExposure not observed: resource policy unparseable")
		} else {
			obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: public, Derivation: "measured"})
		}
	}
	return obs, diags, nil
}

// deleteASM: ownership (tags) pre-check, then DeleteSecret with a short recovery
// window (recoverable — the conservative default, mirroring deletionProtection).
// A ResourceNotFound is idempotent success; a foreign/untagged secret is refused.
func (d *Driver) deleteASM(capability, environment, providerID string) provider.CreateResult {
	region, name, err := splitASMProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	docm, found, rerr := d.describeASM(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(docm.tagMap(), capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "secret tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.asmCall(region, "DeleteSecret",
		fmt.Sprintf(`{"SecretId":%q,"RecoveryWindowInDays":7}`, name))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("delete HTTP %d: %s", st, ecsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// classifyASMChange (D46): PURE — can this capability.secret transition be
// honored in place? The secret's region and name are fixed at birth
// (location.region is a replacement); the resource policy (public exposure) and
// the CMEK key (UpdateSecret KmsKeyId) are re-assertable, so they are mutable.
// encryption.atRest is const-true (always encrypted) — a change away is
// unsupported. Platform/projection properties are unsupported.
func classifyASMChange(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "a Secrets Manager secret is regional; its region is fixed at creation — a change is a replacement"
	case "network.publicExposure":
		return "mutable", ""
	case "encryption.customerManagedKeys":
		return "mutable", ""
	case "encryption.atRest":
		return "unsupported", "Secrets Manager always encrypts at rest — there is nothing to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Secrets Manager in-place mapping for " + path
	}
}

// updateASM: ownership (tags) re-check FIRST, then patch ONLY the changed paths.
// The CMEK key and the public verdict are reused from the SAME create builder so
// an update and a create make identical honesty/encryption choices.
func (d *Driver) updateASM(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, name, err := splitASMProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	docm, found, rerr := d.describeASM(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "secret no longer exists — re-observe and re-plan"}
	}
	if !groundholdTagsMatch(docm.tagMap(), capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "secret tags do not match — refusing to patch a resource that is not ours"}
	}
	plan, err := BuildSecretsManagerCreate(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	setKey, setPolicy := false, false
	for _, path := range changes {
		switch path {
		case "encryption.customerManagedKeys":
			setKey = true
		case "network.publicExposure":
			setPolicy = true
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("secretsmanager path %s is not patchable in place", path)}
		}
	}
	if setKey {
		kms := plan.KmsKeyID
		if kms == "" {
			kms = asmDefaultKeyAlias // revert to the AWS-managed key
		}
		st, resp, e := d.asmCall(region, "UpdateSecret",
			fmt.Sprintf(`{"SecretId":%q,"KmsKeyId":%q}`, name, kms))
		if e != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "encryption patch outcome unknown — reconcile"}
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("encryption patch HTTP %d (server error) — reconcile", st)}
		}
		if st < 200 || st >= 300 {
			if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "encryption patch"); r != nil {
				return *r
			}
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("encryption patch failed: HTTP %d (%s)", st, ecsErr(resp))}
		}
	}
	if setPolicy {
		if plan.Public {
			if r := d.asmPutPolicy(region, name, "", providerID); r != nil {
				return *r
			}
		} else {
			if r := d.asmDeletePolicy(region, name, providerID); r != nil {
				return *r
			}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// isNilLike reports whether an `any` decoded from JSON carries no value. DeletedDate
// arrives as a number (epoch seconds) when present and is absent otherwise (D756).
func isNilLike(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case float64:
		return t == 0
	}
	return false
}
