// OpenSearch Serverless network shell: the SigV4-signed, JSON-1.0 half of the
// second AWS capability.search.index backend. A collection is a COMPOSITE the
// driver OWNS end to end — the create orchestrates two required security policies
// then the collection; the delete tears them down in REVERSE. The collection name
// is deterministic, so the providerId (aoss:<region>:<account>:<name>) is knowable
// before any response (D29): a lost/garbled outcome carries the handle. Ownership
// is TAGS on the collection (ListTagsForResource on the ARN) plus a deterministic
// name marker on the two owned policies.
//
// CRITICAL LRO discipline (the F29/D273 lesson): the create/delete polls read the
// OBSERVABLE collection state via BatchGetCollection and conclude on the
// collection's Status (ACTIVE = done; CREATING = keep polling; FAILED = failed).
// They NEVER construct an operation-by-id path. The poll is bounded by PollTimeout;
// a still-in-progress collection at the deadline is unknown-with-pid, never a hang
// and never a fabricated success.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) openSearchServerlessBase(region string) string {
	if d.OpenSearchServerlessBaseURL != "" {
		return d.OpenSearchServerlessBaseURL
	}
	return "https://aoss." + region + ".amazonaws.com"
}

func openSearchServerlessProviderID(region, account, name string) string {
	return "aoss:" + region + ":" + account + ":" + name
}

func splitOpenSearchServerlessProviderID(providerID string) (region, account, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "aoss" {
		return "", "", "", fmt.Errorf("providerId %q is not aoss:region:account:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !osNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId collection name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// aossCall signs and sends a JSON-1.0 request (X-Amz-Target = OpenSearchServerless.<Op>).
func (d *Driver) aossCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.0",
		"X-Amz-Target": openSearchServerlessTarget + "." + action,
	}
	return d.doSigned("POST", d.openSearchServerlessBase(region)+"/", "aoss", region, h, []byte(body))
}

// aossErr pulls a human string out of an aoss JSON error body (__type + message,
// joined so both the code and the message survive).
func aossErr(body []byte) string {
	var e struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	msg := e.Message
	if msg == "" {
		msg = e.Msg
	}
	s := strings.TrimSpace(e.Type + " " + msg)
	if s == "" {
		return "" // D309: never the raw body — this string reaches a persisted receipt
	}
	return boundMsg(s)
}

type aossCollection struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Status             string `json:"status"`
	ARN                string `json:"arn"`
	KmsKeyArn          string `json:"kmsKeyArn"`
	CollectionEndpoint string `json:"collectionEndpoint"`
}

// batchGetCollection reads a collection by name. found=false + readable (nil err)
// is an authoritative "does not exist"; a non-nil error is a transport/HTTP/parse
// failure that NAMES the cause (D296), never a fabricated absence.
func (d *Driver) batchGetCollection(region, name string) (aossCollection, bool, error) {
	const op = "BatchGetCollection"
	st, resp, err := d.aossCall(region, "BatchGetCollection", jsonBody(map[string]any{"names": []any{name}}))
	if err != nil {
		return aossCollection{}, false, readTransport(op, err)
	}
	if st != http.StatusOK {
		return aossCollection{}, false, readHTTP(op, st, aossErr(resp))
	}
	var out struct {
		CollectionDetails []aossCollection `json:"collectionDetails"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return aossCollection{}, false, readBody(op, st)
	}
	if len(out.CollectionDetails) == 0 {
		return aossCollection{}, false, nil // readable, name absent — a real "gone/never-created"
	}
	return out.CollectionDetails[0], true, nil
}

// openSearchServerlessTags reads the collection's ownership tags via its ARN. A
// non-nil error is a transport/HTTP/parse failure naming the cause (never "no tags").
func (d *Driver) openSearchServerlessTags(region, arn string) (map[string]string, error) {
	const op = "ListTagsForResource"
	st, resp, err := d.aossCall(region, "ListTagsForResource", jsonBody(map[string]any{"resourceArn": arn}))
	if err != nil {
		return nil, readTransport(op, err)
	}
	if st != http.StatusOK {
		return nil, readHTTP(op, st, aossErr(resp))
	}
	var out struct {
		Tags []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"tags"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

// ensureSecurityPolicy creates one owned security policy (encryption or network),
// tolerating a ConflictException (the policy already exists at our deterministic
// name — idempotent, ours by the name marker). Any other non-2xx is a typed error
// naming the cause, so a composite create refuses BEFORE CreateCollection rather
// than half-standing a collection with no matching policy.
func (d *Driver) ensureSecurityPolicy(region, kind, body string) error {
	const op = "CreateSecurityPolicy"
	st, resp, err := d.aossCall(region, "CreateSecurityPolicy", body)
	if err != nil {
		return readTransport(op+"("+kind+")", err)
	}
	if st == http.StatusOK || st == http.StatusCreated {
		return nil
	}
	if strings.Contains(aossErr(resp), "ConflictException") {
		return nil // already exists at our name — idempotent
	}
	return readHTTP(op+"("+kind+")", st, aossErr(resp))
}

// deleteSecurityPolicy removes one owned security policy in the composite teardown.
// A ResourceNotFoundException is idempotent success. NOTE: DeleteSecurityPolicy is
// a standard aoss operation used here for the reverse-delete of policies the driver
// owns by name — see the file header's FLAG on targets beyond the create set.
func (d *Driver) deleteSecurityPolicy(region, name, kind string) error {
	const op = "DeleteSecurityPolicy"
	st, resp, err := d.aossCall(region, "DeleteSecurityPolicy",
		jsonBody(map[string]any{"name": name, "type": kind}))
	if err != nil {
		return readTransport(op+"("+kind+")", err)
	}
	if st == http.StatusOK || strings.Contains(aossErr(resp), "ResourceNotFoundException") {
		return nil
	}
	return readHTTP(op+"("+kind+")", st, aossErr(resp))
}

// createOpenSearchServerless orchestrates the composite: ensure encryption policy
// -> ensure network policy -> CreateCollection -> poll BatchGetCollection to
// ACTIVE. Every step refuses BEFORE the next mutation; the deterministic pid rides
// every non-terminal outcome (D29).
func (d *Driver) createOpenSearchServerless(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildOpenSearchServerless(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := openSearchServerlessProviderID(region, account, plan.Name)

	// sub-resource 1: the REQUIRED encryption policy (no collection without it).
	if perr := d.ensureSecurityPolicy(region, "encryption", jsonBody(plan.encryptionPolicyBody())); perr != nil {
		return provider.CreateResult{Status: "failed",
			Reason: "encryption security policy could not be ensured — refusing before CreateCollection: " + perr.Error()}
	}
	// sub-resource 2: the network policy (access; public or VPC).
	if perr := d.ensureSecurityPolicy(region, "network", jsonBody(plan.networkPolicyBody())); perr != nil {
		return provider.CreateResult{Status: "failed",
			Reason: "network security policy could not be ensured — refusing before CreateCollection: " + perr.Error()}
	}

	st, resp, err := d.aossCall(region, "CreateCollection", jsonBody(plan.createCollectionBody(capability, environment)))
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create collection outcome unknown (may have landed): %v", err)}
	}
	switch {
	case st == http.StatusOK || st == http.StatusCreated:
		// creating — poll below
	case strings.Contains(aossErr(resp), "ConflictException"):
		// a collection with this name exists — adopt only if ours (tags off the ARN).
		cur, found, derr := d.batchGetCollection(region, plan.Name)
		if derr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing collection read gave no answer — reconcile: " + derr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict but the existing collection then read as absent — reconcile"}
		}
		tags, terr := d.openSearchServerlessTags(region, cur.ARN)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing collection tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a collection with this name exists and is not ours (tags do not match)"}
		}
		// ours — fall through to poll
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create collection HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, aossErr(resp), nil, pid, "create collection"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create collection HTTP %d (%s)", st, aossErr(resp))}
	}

	// LRO: poll the OBSERVABLE collection state to a terminal Status (D273 — never an
	// operation-by-id path). ACTIVE = succeeded; FAILED = failed WITH the pid; the
	// poll timeout is unknown WITH the pid. Bounded by PollTimeout, never a hang.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		c, found, rerr := d.batchGetCollection(region, plan.Name)
		if rerr == nil && found {
			switch strings.ToUpper(c.Status) {
			case "ACTIVE":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "FAILED":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "collection entered status FAILED during create"}
				// CREATING -> keep polling
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "collection still creating at poll timeout — reconcile via BatchGetCollection"}
		}
		d.progress("OpenSearch Serverless collection provisioning — waiting for ACTIVE")
		time.Sleep(d.PollInterval)
	}
}

// observeOpenSearchServerless reverse-maps a live collection to
// capability.search.index. encryption at rest / in transit and the regional
// (multi-AZ) failure domain are structural guarantees of the serverless model
// (config-intent, like the provisioned domain's EnforceHTTPS); CMK is measured off
// the collection's kmsKeyArn ("auto" = AWS-owned). network.publicExposure lives in
// the network policy document (GetSecurityPolicy) — read honestly, or emit a
// diagnostic rather than fabricate.
func (d *Driver) observeOpenSearchServerless(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, name, err := splitOpenSearchServerlessProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	c, found, rerr := d.batchGetCollection(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"collection not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a serverless collection ALWAYS encrypts at rest and in transit — structural
		// guarantees (config-intent), not read fields.
		{Path: "encryption.atRest", Value: true, Derivation: "platform-invariant"},
		{Path: "encryption.inTransit", Value: true, Derivation: "platform-invariant"},
		// regional (multi-AZ) by construction.
		{Path: "availability.class", Value: "regional", Derivation: "platform-invariant"},
	}
	var diags []string
	// CMK is measured: kmsKeyArn is "auto" for an AWS-owned key, a key ARN for a CMK.
	obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
		Value: c.KmsKeyArn != "" && !strings.EqualFold(c.KmsKeyArn, "auto"), Derivation: "measured"})
	// public exposure is in the owned network policy, not the collection detail — read it.
	public, perr := d.networkPolicyPublic(region, aossNetPolicyName(name))
	if perr != nil {
		diags = append(diags, "network.publicExposure not observed: "+perr.Error()+" — probe/reconcile")
	} else {
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: public, Derivation: "measured"})
	}
	return obs, diags, nil
}

// networkPolicyPublic reads the owned network policy document and reports whether
// ANY rule block allows public access (AllowFromPublic). A non-nil error is a
// read/parse failure naming the cause — never a fabricated exposure. NOTE:
// GetSecurityPolicy is a standard aoss operation used for the honest exposure read;
// see the file header's FLAG on targets beyond the create set.
func (d *Driver) networkPolicyPublic(region, policyName string) (bool, error) {
	const op = "GetSecurityPolicy"
	st, resp, err := d.aossCall(region, "GetSecurityPolicy",
		jsonBody(map[string]any{"name": policyName, "type": "network"}))
	if err != nil {
		return false, readTransport(op, err)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, aossErr(resp))
	}
	// the policy document is a JSON STRING (an array of rule blocks) inside the detail.
	var out struct {
		SecurityPolicyDetail struct {
			Policy json.RawMessage `json:"policy"`
		} `json:"securityPolicyDetail"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return false, readBody(op, st)
	}
	var doc []byte = out.SecurityPolicyDetail.Policy
	// aoss returns the document as a JSON string; unwrap one layer if so.
	var asString string
	if json.Unmarshal(doc, &asString) == nil {
		doc = []byte(asString)
	}
	var blocks []struct {
		AllowFromPublic bool `json:"AllowFromPublic"`
	}
	if json.Unmarshal(doc, &blocks) != nil {
		return false, readBody(op, st)
	}
	for _, b := range blocks {
		if b.AllowFromPublic {
			return true, nil
		}
	}
	return false, nil
}

// deleteOpenSearchServerless tears the composite down in REVERSE: DeleteCollection
// -> poll BatchGetCollection to gone -> delete the owned network policy -> delete
// the owned encryption policy. Ownership is re-checked (collection tags) before any
// mutation. 404/absent at each step is idempotent.
func (d *Driver) deleteOpenSearchServerless(capability, environment, providerID string) provider.CreateResult {
	region, _, name, err := splitOpenSearchServerlessProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	cur, found, rerr := d.batchGetCollection(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if found {
		tags, terr := d.openSearchServerlessTags(region, cur.ARN)
		if terr != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "collection tags do not match — refusing to delete a resource that is not ours"}
		}
		// DeleteCollection takes the ID (the pid holds only the name).
		st, resp, e := d.aossCall(region, "DeleteCollection", jsonBody(map[string]any{"id": cur.ID}))
		if e != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("delete collection outcome unknown: %v", e)}
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("delete collection HTTP %d (server error) — reconcile", st)}
		}
		if st != http.StatusOK && !strings.Contains(aossErr(resp), "ResourceNotFoundException") {
			if r := provider.MutationResult(st, aossErr(resp), nil, providerID, "delete collection"); r != nil {
				return *r
			}
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("delete collection HTTP %d (%s)", st, aossErr(resp))}
		}
		// poll until the collection is READABLY gone (D273 — observable state, never
		// an operation-by-id path). A FAILED, or the poll timeout, is unknown-with-pid.
		deadline := d.Now().Add(d.PollTimeout)
		for {
			c, stillThere, derr := d.batchGetCollection(region, name)
			if derr == nil && !stillThere {
				break
			}
			if derr == nil && stillThere && strings.ToUpper(c.Status) == "FAILED" {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: "collection entered FAILED during delete — reconcile"}
			}
			if d.Now().After(deadline) {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: "collection still deleting at poll timeout — reconcile via BatchGetCollection"}
			}
			d.progress("OpenSearch Serverless collection deleting — waiting for removal")
			time.Sleep(d.PollInterval)
		}
	}
	// reverse teardown of the owned sub-resources: network then encryption. Both are
	// idempotent (ResourceNotFound = already gone); an unreadable delete is unknown.
	if e := d.deleteSecurityPolicy(region, aossNetPolicyName(name), "network"); e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "collection deleted but the owned network policy teardown gave no answer — reconcile: " + e.Error()}
	}
	if e := d.deleteSecurityPolicy(region, aossEncPolicyName(name), "encryption"); e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "collection deleted but the owned encryption policy teardown gave no answer — reconcile: " + e.Error()}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverOpenSearchServerless enumerates collections in the region as
// capability.search.index — so `discover --provider aws` surfaces a console/TF-
// stood serverless collection for adoption. ListCollections -> per-collection
// reverse map.
func (d *Driver) discoverOpenSearchServerless(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("opensearch-serverless: %v", err)
	}
	st, body, err := d.aossCall(region, "ListCollections", "{}")
	if err != nil {
		return nil, nil, fmt.Errorf("opensearch-serverless ListCollections: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("opensearch-serverless ListCollections: HTTP %d: %s", st, aossErr(body))
	}
	var out struct {
		CollectionSummaries []struct {
			Name string `json:"name"`
		} `json:"collectionSummaries"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil, nil, fmt.Errorf("opensearch-serverless ListCollections: HTTP %d but the response did not parse", st)
	}
	var found []provider.Discovered
	var diags []string
	for _, c := range out.CollectionSummaries {
		if c.Name == "" {
			continue
		}
		if !osNameOK.MatchString(c.Name) {
			diags = append(diags, c.Name+": name not representable as aoss:region:account:name — needs adoption by explicit id")
			continue
		}
		pid := openSearchServerlessProviderID(region, account, c.Name)
		obs, odiags, oerr := d.observeOpenSearchServerless("", pid)
		if oerr != nil {
			diags = append(diags, c.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, c.Name+": "+dg)
		}
		found = append(found, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.search.index", Observations: provider.WithoutAbsence(obs)})
	}
	return found, diags, nil
}
