// D254 — the Azure create-path ownership pre-read.
//
// An ARM PUT is an UNCONDITIONAL UPSERT: PUT to a deterministic resourceId that
// already holds a resource just overwrites it (its tags, properties — even a
// flexible-server administrator password). Every Azure create writes with a PUT,
// so without a check a create (or a re-PUT) would silently OVERWRITE a same-named
// FOREIGN resource — an ownership bypass the delete/reconcile paths already guard
// against but create did not. This is the create-side of "never touch a resource
// that is not ours".
//
// The check derives the ownership it is ASSERTING from the body about to be PUT:
// tag-owned resources carry groundhold-capability/environment in `tags`, so the
// pre-read GETs the live resource and REFUSES if it exists with different (or no)
// ownership tags. Bodies WITHOUT groundhold tags — content-addressed roles
// (azrole/azcustomrole) and tagless children — carry no ownership claim, so they
// skip the check automatically (no signature threading, no per-driver opt-in).
package azure

import (
	"encoding/json"

	"groundhold/internal/provider"
)

// groundholdTagsInBody extracts the ownership tags the PUT body declares. tagged is
// false when the body carries no groundhold-capability tag (content-addressed /
// tagless resources), in which case the pre-read is skipped.
func groundholdTagsInBody(body []byte) (capability, environment string, tagged bool) {
	var b struct {
		Tags map[string]string `json:"tags"`
	}
	if json.Unmarshal(body, &b) != nil {
		return "", "", false
	}
	c := b.Tags["groundhold-capability"]
	e := b.Tags["groundhold-environment"]
	if c == "" {
		return "", "", false
	}
	return c, e, true
}

// armResourceTags GETs an ARM resource and returns its top-level tags. found=false
// with a nil error on a 404 (the resource is absent — a genuine create). A non-nil
// error names any transport/HTTP/parse failure (the caller falls back to the PUT:
// a read that gave no answer almost always means the PUT will not answer either,
// so the mutation fails on its own — and blocking every create on a transient read
// would be worse than the rare miss).
func (d *Driver) armResourceTags(url string) (tags map[string]string, found bool, err error) {
	var doc struct {
		Tags map[string]string `json:"tags"`
	}
	found, err = d.armGetURLInto("ownership-preread.get", url, &doc)
	if err != nil || !found {
		return nil, false, err
	}
	return doc.Tags, true, nil
}

// refuseForeignUpsert returns a terminal failed result iff the PUT would OVERWRITE a
// resource that is not ours: the body claims groundhold ownership, and a resource
// already exists at the url carrying different (or absent) ownership tags. Returns
// nil — proceed with the PUT — when the body is not tag-owned, when the resource is
// absent (create) or gave no answer (fall back), or when the existing resource is OURS
// (an idempotent re-PUT / update). It NEVER adopts or mutates; it only refuses.
func (d *Driver) refuseForeignUpsert(url string, body []byte) *provider.CreateResult {
	wantCap, wantEnv, tagged := groundholdTagsInBody(body)
	if !tagged {
		return nil
	}
	tags, found, rerr := d.armResourceTags(url)
	if rerr != nil || !found {
		return nil
	}
	if tags["groundhold-capability"] != wantCap || tags["groundhold-environment"] != wantEnv {
		return &provider.CreateResult{Status: "failed",
			Reason: "a resource already exists at this name and its ownership tags are not " +
				"ours — refusing to overwrite a resource groundhold does not own (an Azure ARM " +
				"PUT is an unconditional upsert; delete the foreign resource or pick another name)"}
	}
	return nil
}

// refuseForeignOrAdopt is the CREATE-path variant (D256): like refuseForeignUpsert
// it refuses a foreign resource, but when the existing resource is OURS it ADOPTS
// it — returns succeeded WITH the deterministic pid and skips the PUT — so a
// lost-ledger self-adopt binds reality rather than re-PUTting our own body over it
// (which for e.g. a Flexible Server would RESET the administrator password to the
// declared value). Any drift is the next reconcile's job. Returns nil (proceed with
// the create PUT) when the body is not tag-owned, or the resource is absent or
// gave no answer. Update paths must NOT use this (they intend to re-PUT) — they call
// putAndPollForce / doARM directly.
func (d *Driver) refuseForeignOrAdopt(url string, body []byte, pid string) *provider.CreateResult {
	wantCap, wantEnv, tagged := groundholdTagsInBody(body)
	if !tagged {
		return nil
	}
	tags, found, rerr := d.armResourceTags(url)
	if rerr != nil || !found {
		return nil
	}
	if tags["groundhold-capability"] != wantCap || tags["groundhold-environment"] != wantEnv {
		return &provider.CreateResult{Status: "failed",
			Reason: "a resource already exists at this name and its ownership tags are not " +
				"ours — refusing to overwrite a resource groundhold does not own (an Azure ARM " +
				"PUT is an unconditional upsert; delete the foreign resource or pick another name)"}
	}
	// OURS — adopt (bind) without re-PUTting, so our own config/secrets are untouched.
	return &provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}
