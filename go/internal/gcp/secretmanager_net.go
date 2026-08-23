// GCP Secret Manager network shell (D97): the bearer-signed REST half of the
// capability.secret driver. The secret is created as a versionless container — the
// VALUE is never written by groundhold (it is data, supplied out of band). Ownership
// is labels; residency is read back from the replication policy (an automatic-
// replication secret has no region to report). D29/D87 honesty throughout.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"groundhold/internal/adoptcheck"
	"groundhold/internal/provider"
)

// gsecretAdoptControls (D1062): a secret's CMEK lives in its create-time replication
// policy and its public exposure is an IAM grant — both set inline at create and never
// applied to a secret that already exists. CMEK is immutable (the replication policy
// cannot change), so a live secret on a Google-managed key where we declared CMEK
// FAILS. Public exposure is re-assertable (updateSecret / setSecretPrivate), so a live
// public secret where we declared private is unknown+bound and converge reconciles it.
var gsecretAdoptControls = []adoptcheck.Control{
	{Path: "encryption.customerManagedKeys", Direction: adoptcheck.SecureTrue, ImmutableAtCreate: true},
	{Path: "network.publicExposure", Direction: adoptcheck.SecureFalse, UpdateWired: true},
}

func (d *Driver) secretBase() string {
	if d.SecretBaseURL != "" {
		return d.SecretBaseURL
	}
	return secretManagerBaseURL
}

func gsecretProviderID(project, name string) string { return "gsecret:" + project + ":" + name }

func splitGSecretProviderID(providerID string) (project, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "gsecret" {
		return "", "", fmt.Errorf("providerId %q is not gsecret:project:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	return parts[1], parts[2], nil
}

type secretDoc struct {
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels"`
	Replication struct {
		// D1238: `automatic` was decoded as an EMPTY struct — a shape that says "this
		// variant carries nothing". The API says otherwise: `Automatic` has a
		// `customerManagedEncryption` field, exactly like a user-managed replica. So a
		// secret with automatic replication and a customer key reported no key at all,
		// and the driver's own comment described that as a shape it could not read.
		Automatic *struct {
			CustomerManagedEncryption *struct {
				KmsKeyName string `json:"kmsKeyName"`
			} `json:"customerManagedEncryption"`
		} `json:"automatic"`
		UserManaged *struct {
			Replicas []struct {
				Location                  string `json:"location"`
				CustomerManagedEncryption *struct {
					KmsKeyName string `json:"kmsKeyName"`
				} `json:"customerManagedEncryption"`
			} `json:"replicas"`
		} `json:"userManaged"`
	} `json:"replication"`
}

func (d *Driver) getSecret(project, name string) (secretDoc, bool, error) {
	const op = "secret.get"
	url := fmt.Sprintf("%s/projects/%s/secrets/%s", d.secretBase(), project, name)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return secretDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return secretDoc{}, false, nil
	}
	if st != http.StatusOK {
		return secretDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc secretDoc
	if json.Unmarshal(body, &doc) != nil {
		return secretDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createSecret(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildSecretCreate(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := gsecretProviderID(d.Project, plan.Name)
	url := fmt.Sprintf("%s/projects/%s/secrets?secretId=%s", d.secretBase(), d.Project, plan.Name)
	st, body, err := d.call("POST", url, plan.createBody(capability, environment))
	adopted := false
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// created — fall through
	case st == http.StatusConflict:
		// exists — continue only if OURS (labels match)
		doc, found, rerr := d.getSecret(d.Project, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict, existing secret gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed", Reason: "a secret with this name exists and is not ours (labels do not match)"}
		}
		// ours — fall through to re-assert exposure. The create body (CMEK in the
		// replication policy) never applied to this pre-existing secret, so its declared
		// controls are verified below before the adopt is called a success (D1062).
		adopted = true
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
	// public exposure (rare for a secret): grant allUsers secretAccessor.
	if plan.Public {
		if unknown, e := d.setSecretPublic(plan.Name); e != nil {
			s := "failed"
			if unknown {
				s = "unknown"
			}
			return provider.CreateResult{ProviderID: pid, Status: s, Reason: "secret created but public grant: " + e.Error()}
		}
	}
	if adopted {
		obs, _, oerr := d.observeSecret(capability, pid)
		if oerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "adopted secret re-observe gave no answer — reconcile: " + oerr.Error()}
		}
		switch v := adoptcheck.Compare(attrs, obs, gsecretAdoptControls); v.Status {
		case "failed":
			return provider.CreateResult{Status: "failed", Reason: v.Reason}
		case "unknown":
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: v.Reason}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) observeSecret(capability, providerID string) ([]provider.Observation, []string, error) {
	project, name, err := splitGSecretProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getSecret(project, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"secret not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
	}
	var diags []string
	// residency: only a userManaged single-region replica is an honest region.
	if um := doc.Replication.UserManaged; um != nil && len(um.Replicas) == 1 {
		obs = append(obs, provider.Observation{Path: "location.region", Value: um.Replicas[0].Location, Derivation: "measured"})
	} else {
		diags = append(diags, "location.region not observed: automatic or multi-replica replication carries no single-region residency guarantee")
	}

	// D1238: the customer key is a SEPARATE question from residency, and it used to
	// ride on the residency branch — so an automatic or multi-replica secret had
	// `encryption.customerManagedKeys` omitted with a diagnostic that only mentioned
	// the REGION. The attribute is readable in every replication shape (the API gives
	// `automatic.customerManagedEncryption` as well as a per-replica one, which the
	// doc struct used to model as an empty object), so it is answered here for all of
	// them and the two questions no longer share a branch.
	//
	// D1003's reasoning is kept and widened: a readable "no key" is a MEASURED FALSE,
	// not an absence, so a hard constraint cannot pass vacuously over it.
	switch cmk, keyed, total := secretCMK(doc); {
	case total == 0:
		diags = append(diags, "encryption.customerManagedKeys not observed: the secret "+
			"declares neither automatic nor user-managed replication, so there is no "+
			"replica whose key could be read")
	case cmk:
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	default:
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: false, Derivation: "measured"})
		if keyed > 0 {
			// The weakest-across-the-set rule (D1186's shape): `true` means every copy
			// is under a customer key. A partly-keyed secret is NOT customer-managed,
			// and saying only `false` would hide that some replicas are.
			diags = append(diags, "encryption.customerManagedKeys=false because "+
				strconv.Itoa(keyed)+" of "+strconv.Itoa(total)+" replicas carry a customer "+
				"key — the attribute is true only when EVERY copy is, and the unkeyed ones "+
				"are encrypted with a Google-managed key")
		}
	}
	pub, iamErr := d.readSecretPublic(name)
	if iamErr == nil {
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: pub, Derivation: "measured"})
	} else {
		diags = append(diags, "network.publicExposure not observed: "+iamErr.Error())
	}
	return obs, diags, nil
}

func (d *Driver) deleteSecret(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitGSecretProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getSecret(project, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed", Reason: "secret labels do not match — refusing to delete a resource that is not ours"}
	}
	url := fmt.Sprintf("%s/projects/%s/secrets/%s", d.secretBase(), project, name)
	st, body, e := d.call("DELETE", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// readSecretPublic reports whether allUsers/allAuthenticatedUsers hold any role.
func (d *Driver) readSecretPublic(name string) (public bool, err error) {
	const op = "secrets.getIamPolicy"
	url := fmt.Sprintf("%s/projects/%s/secrets/%s:getIamPolicy", d.secretBase(), d.Project, name)
	st, body, cerr := d.call("GET", url, nil)
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, gcpErrCode(body))
	}
	var pol struct {
		Bindings []struct {
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if json.Unmarshal(body, &pol) != nil {
		return false, readBody(op, st)
	}
	for _, b := range pol.Bindings {
		for _, m := range b.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				return true, nil
			}
		}
	}
	return false, nil
}

// setSecretPublic grants allUsers the secretAccessor role (append-only RMW).
func (d *Driver) setSecretPublic(name string) (unknown bool, err error) {
	getURL := fmt.Sprintf("%s/projects/%s/secrets/%s:getIamPolicy", d.secretBase(), d.Project, name)
	st, body, e := d.call("GET", getURL, nil)
	if e != nil {
		return true, fmt.Errorf("getIamPolicy outcome unknown: %v", e)
	}
	if st != http.StatusOK {
		return st >= 500, fmt.Errorf("getIamPolicy HTTP %d", st)
	}
	var pol map[string]any
	if json.Unmarshal(body, &pol) != nil {
		return false, fmt.Errorf("getIamPolicy unparseable")
	}
	bindings, _ := pol["bindings"].([]any)
	bindings = append(bindings, map[string]any{
		"role": "roles/secretmanager.secretAccessor", "members": []any{"allUsers"}})
	pol["bindings"] = bindings
	setURL := fmt.Sprintf("%s/projects/%s/secrets/%s:setIamPolicy", d.secretBase(), d.Project, name)
	sst, sbody, se := d.call("POST", setURL, map[string]any{"policy": pol})
	if se != nil {
		return true, fmt.Errorf("setIamPolicy outcome unknown: %v", se)
	}
	if sst >= 500 {
		return true, fmt.Errorf("setIamPolicy HTTP %d (server error)", sst)
	}
	if sst < 200 || sst >= 300 {
		return false, fmt.Errorf("setIamPolicy HTTP %d: %s", sst, mutDetail(sbody))
	}
	return false, nil
}

// setSecretPrivate revokes any allUsers/allAuthenticatedUsers member from the secret's
// IAM policy (the revoke twin of setSecretPublic) via the same getIamPolicy ->
// setIamPolicy read-modify-write, preserving the etag as the CAS, then re-reads to
// confirm the secret is no longer public. The member filtering is INLINED here (not the
// shared removeMember helper) to stay self-contained. unknown=true only when the
// MUTATING setIamPolicy response was lost (D29), never "failed".
func (d *Driver) setSecretPrivate(name string) (unknown bool, err error) {
	getURL := fmt.Sprintf("%s/projects/%s/secrets/%s:getIamPolicy", d.secretBase(), d.Project, name)
	st, body, e := d.call("GET", getURL, nil)
	if e != nil {
		return true, fmt.Errorf("getIamPolicy outcome unknown: %v", e)
	}
	if st != http.StatusOK {
		return st >= 500, fmt.Errorf("getIamPolicy HTTP %d", st)
	}
	var pol map[string]any
	if json.Unmarshal(body, &pol) != nil {
		return false, fmt.Errorf("getIamPolicy unparseable")
	}
	raw, _ := pol["bindings"].([]any)
	kept := make([]any, 0, len(raw))
	for _, b := range raw {
		bm, _ := b.(map[string]any)
		members, _ := bm["members"].([]any)
		keptM := make([]any, 0, len(members))
		for _, m := range members {
			if m != "allUsers" && m != "allAuthenticatedUsers" {
				keptM = append(keptM, m)
			}
		}
		if len(keptM) == 0 {
			continue // drop an emptied binding rather than leave a role with no members
		}
		bm["members"] = keptM
		kept = append(kept, bm)
	}
	pol["bindings"] = kept
	setURL := fmt.Sprintf("%s/projects/%s/secrets/%s:setIamPolicy", d.secretBase(), d.Project, name)
	sst, sbody, se := d.call("POST", setURL, map[string]any{"policy": pol})
	if se != nil {
		return true, fmt.Errorf("setIamPolicy outcome unknown — reconcile: %v", se)
	}
	if sst >= 500 {
		return true, fmt.Errorf("setIamPolicy HTTP %d (server error — may have landed) — reconcile", sst)
	}
	if sst < 200 || sst >= 300 {
		return false, fmt.Errorf("setIamPolicy HTTP %d: %s", sst, mutDetail(sbody))
	}
	pub, cerr := d.readSecretPublic(name)
	switch {
	case cerr != nil:
		return true, fmt.Errorf("setIamPolicy returned %d but the policy could not be confirmed (%v) — reconcile", sst, cerr)
	case pub:
		return false, fmt.Errorf("the allUsers/allAuthenticatedUsers binding is still present after the write")
	default:
		return false, nil
	}
}

// updateSecret patches a secret's mutable attributes in place (D131 update slice,
// symmetric with the ASM update). Only network.publicExposure is mutable on a GCP
// secret — a grant or revoke of the allUsers secretAccessor binding (the IAM etag is
// the CAS). encryption.customerManagedKeys and residency are create-time (the
// replication policy is immutable) so ClassifyChange refuses them as a replacement, not
// a patch. Ownership (labels) is re-checked first.
func (d *Driver) updateSecret(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	project, name, err := splitGSecretProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getSecret(project, name)
	if rerr != nil {
		return provider.CreateResult{Status: "unknown", Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "secret labels do not match — refusing to patch a resource that is not ours"}
	}
	for _, path := range changes {
		if path != "network.publicExposure" {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("path %s is not patchable in place on a GCP secret (ClassifyChange should have refused it)", path)}
		}
		desired, _ := attrs[path].(bool)
		var unknown bool
		if desired {
			unknown, err = d.setSecretPublic(name)
		} else {
			unknown, err = d.setSecretPrivate(name)
		}
		if err != nil {
			st := "failed"
			if unknown {
				st = "unknown"
			}
			return provider.CreateResult{ProviderID: providerID, Status: st, Reason: err.Error()}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// secretCMK answers the customer-key question for ANY replication shape: automatic
// (one implicit copy) or user-managed (one per replica).
//
// D1238. Returns (allKeyed, keyed, total). `allKeyed` is true only when every copy has
// a key — the weakest-across-the-set rule this codebase applies to encryption
// elsewhere, because a secret whose replicas are half Google-managed is not a
// customer-managed secret. total=0 means neither shape was present, which is a read
// that cannot answer rather than an answer of no.
func secretCMK(doc secretDoc) (allKeyed bool, keyed, total int) {
	if a := doc.Replication.Automatic; a != nil {
		total = 1
		if a.CustomerManagedEncryption != nil && a.CustomerManagedEncryption.KmsKeyName != "" {
			keyed = 1
		}
	}
	if um := doc.Replication.UserManaged; um != nil {
		for _, r := range um.Replicas {
			total++
			if r.CustomerManagedEncryption != nil && r.CustomerManagedEncryption.KmsKeyName != "" {
				keyed++
			}
		}
	}
	return total > 0 && keyed == total, keyed, total
}
