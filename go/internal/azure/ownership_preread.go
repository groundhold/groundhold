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
	"fmt"
	"net/http"

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

// refuseForeignByContentOrAdopt is the pre-read for resources that carry NO TAGS, so
// ownership cannot be read from one (D804). A diagnostic setting and a consumption
// budget are both of that kind, and both are written at a name derived from environment
// and capability alone — a name a second groundhold deployment over the same
// subscription computes identically, and an ARM PUT is an unconditional upsert.
//
// What CAN be read is the resource itself, which answers the only question that matters:
// if the fields THIS contract would set already hold the values it would write, the PUT
// changes nothing and binding is safe (the D525 identity-from-content reasoning, applied
// to content actually read). If any of them differs, something else authored it, and the
// create refuses rather than silently replacing it.
//
// Only the fields we would SET are compared. ARM answers with id, name, type and
// systemData that no contract describes, and demanding those match would refuse
// everything.
func (d *Driver) refuseForeignByContentOrAdopt(url string, want map[string]any,
	pid, what string) *provider.CreateResult {
	st, resp, err := d.doARM("GET", url, nil)
	switch {
	case err != nil:
		return &provider.CreateResult{Status: "unknown", Reason: "ownership pre-read of " +
			what + " gave no answer, so a write at this deterministic name cannot be shown " +
			"to be safe — reconcile: " + err.Error()}
	case st == http.StatusNotFound:
		return nil // nothing stands at the name; proceed with the create
	case st != http.StatusOK:
		return &provider.CreateResult{Status: "unknown", Reason: fmt.Sprintf(
			"ownership pre-read of %s answered HTTP %d, so a write at this deterministic "+
				"name cannot be shown to be safe — reconcile", what, st)}
	}
	var existing map[string]any
	if json.Unmarshal(resp, &existing) != nil {
		return &provider.CreateResult{Status: "unknown", Reason: "ownership pre-read of " +
			what + " returned a body this driver cannot parse — refusing to overwrite what " +
			"it cannot read"}
	}
	if subsetMatches(any(want), any(existing)) {
		// already exactly what this contract describes: bind it, mutate nothing.
		return &provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	return &provider.CreateResult{Status: "unknown", Reason: "a " + what + " already exists " +
		"at this name and its settings are NOT what this contract describes — the name is " +
		"derived from environment and capability alone, so another deployment over this " +
		"subscription computes the same one. Refusing to overwrite it; adopt it explicitly " +
		"to take it over"}
}

// subsetMatches reports whether every field `want` sets is present in `got` with an
// equal value, recursing into maps AND into list elements.
//
// Recursing into list ELEMENTS matters and is not fussiness: ARM echoes fields inside a
// list entry that no contract sets — a diagnostic setting's `logs` come back carrying a
// retentionPolicy this driver never wrote. Comparing the list whole would call every
// resource foreign, including our own, which is the failure mode that makes a
// lost-ledger converge unsafe (D252/D253).
func subsetMatches(want, got any) bool {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for k, wv := range w {
			gv, present := g[k]
			if !present || !subsetMatches(wv, gv) {
				return false
			}
		}
		return true
	case []any:
		g, ok := got.([]any)
		if !ok || len(g) != len(w) {
			return false
		}
		for i := range w {
			if !subsetMatches(w[i], g[i]) {
				return false
			}
		}
		return true
	default:
		wj, _ := json.Marshal(want)
		gj, _ := json.Marshal(got)
		return string(wj) == string(gj)
	}
}

// deleteCompanionIfOurs deletes a SIBLING companion resource (a separate top-level
// ARM resource the create provisioned alongside the primary, at a derived name) only
// after confirming it carries OUR ownership tags.
//
// D943: the D940 companion cleanup deleted these by DERIVED NAME with no ownership
// check. For a greenfield parent the name is content-addressed (pv-<type>-<slug>-<sha8>),
// so <name>-nsg is unguessable and safe. But a BROWNFIELD-adopted parent has an
// arbitrary operator-chosen name, and `<vnet>-nsg` / `<app>-env` is an extremely common
// Azure convention — so the cleanup could DELETE a foreign resource groundhold never
// created and never tagged. Read the companion's tags first: absent (404) => nothing to
// do; foreign (tags absent or different) => LEAVE it untouched and return nil so the
// caller records it; ours => delete; a read error => unknown (the parent is gone but
// this sibling's fate is unresolved). This is the Azure equivalent of GCP deleteVPC's
// per-companion markerOurs skip.
func (d *Driver) deleteCompanionIfOurs(url, capability, environment, pid, what string) (res *provider.CreateResult, foreign bool) {
	tags, found, rerr := d.armResourceTags(url)
	if rerr != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("%s ownership read gave no answer — reconcile: %v", what, rerr)}, false
	}
	if !found {
		return nil, false // absent — nothing to delete (idempotent)
	}
	if tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return nil, true // a foreign resource sits at our derived name — never delete it
	}
	return d.deleteAndConfirm(url, pid, what), false
}
