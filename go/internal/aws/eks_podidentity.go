// EKS Pod Identity Association driver (D149): the AWS half of
// capability.identity.podidentity — a binding from a Kubernetes serviceAccount
// (namespace + name) to an IAM role, so pods authenticate to AWS without static
// keys. The cluster and the IAM role are OPERANDS (implementation.clusterName /
// implementation.roleArn, D26); the namespace + serviceAccount are the CAPABILITY
// identity. The association is keyed server-side by a generated associationId, so
// every op RESOLVES the id via ListPodIdentityAssociations filtered by
// namespace+serviceAccount (the MSK describe-to-resolve pattern). Speaks EKS
// REST-JSON at eks.<region>.amazonaws.com (SigV4 "eks") via the shared eksDo
// plumbing. Four-valued throughout (D29/D87); ownership tags gate every mutation.
// D53: never read a secret.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"groundhold/internal/provider"
)

// eksPodIdentityProviderID is the pinned identity:
// eks-podidentity:<region>:<cluster>/<namespace>/<serviceAccount>. The
// server-generated associationId is NOT in the pid (it is resolved for each op).
func eksPodIdentityProviderID(region, cluster, namespace, serviceAccount string) string {
	return "eks-podidentity:" + region + ":" + cluster + "/" + namespace + "/" + serviceAccount
}

func splitEKSPodIdentityProviderID(providerID string) (region, cluster, namespace, serviceAccount string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "eks-podidentity" {
		return "", "", "", "", fmt.Errorf("providerId %q is not eks-podidentity:region:cluster/namespace/serviceAccount", providerID)
	}
	region = parts[1]
	if !regionOK.MatchString(region) {
		return "", "", "", "", fmt.Errorf("providerId region %q is invalid", region)
	}
	rest := strings.SplitN(parts[2], "/", 3)
	if len(rest) != 3 || rest[0] == "" || rest[1] == "" || rest[2] == "" {
		return "", "", "", "", fmt.Errorf("providerId %q is missing cluster/namespace/serviceAccount", providerID)
	}
	return region, rest[0], rest[1], rest[2], nil
}

// EKSPodIdentityPlan is the attribute+operand-derived shape a create assembles.
// The IDENTITY (namespace, serviceAccount) is driven by CAPABILITY attributes; the
// cluster and the IAM role are OPERATOR operands (implementation: block, D26).
type EKSPodIdentityPlan struct {
	ClusterName    string // operand (required)
	Namespace      string // capability (required)
	ServiceAccount string // capability (required)
	RoleArn        string // operand (required)
}

// BuildEKSPodIdentity maps capability.identity.podidentity attributes +
// implementation operands to a plan, or REFUSES. Every error is a preflight
// refusal (never a half-build): an unmapped attribute, or a missing required
// attribute/operand, is refused here, before the first EKS mutation (invariant #4,
// D26). generation is unused (the identity is ns+sa, not a hashed discriminator).
func BuildEKSPodIdentity(environment, capability string,
	attrs, impl map[string]any, generation int) (EKSPodIdentityPlan, error) {
	p := EKSPodIdentityPlan{}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "workload.namespace":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return EKSPodIdentityPlan{}, fmt.Errorf("workload.namespace must be a non-empty string")
			}
			p.Namespace = strings.TrimSpace(v)
		case "workload.serviceAccount":
			v, ok := raw.(string)
			if !ok || strings.TrimSpace(v) == "" {
				return EKSPodIdentityPlan{}, fmt.Errorf("workload.serviceAccount must be a non-empty string")
			}
			p.ServiceAccount = strings.TrimSpace(v)
		case "service.managed":
			if raw != true {
				return EKSPodIdentityPlan{}, fmt.Errorf("service.managed=false cannot be honored by EKS (a pod identity association IS managed by construction)")
			}
		case "location.region":
			// location.region scopes the create (resolved by the dispatch, not here);
			// cost.monthly is a projection — neither is a build input.
		default:
			return EKSPodIdentityPlan{}, fmt.Errorf(
				"attribute %s has no EKS pod identity mapping — refusing rather than silently dropping it "+
					"(the identity.podidentity vocab governs workload.namespace + workload.serviceAccount)", path)
		}
	}
	if p.Namespace == "" {
		return EKSPodIdentityPlan{}, fmt.Errorf("workload.namespace is required")
	}
	if p.ServiceAccount == "" {
		return EKSPodIdentityPlan{}, fmt.Errorf("workload.serviceAccount is required")
	}

	// --- OPERATOR operands (implementation: block, D26) ---
	if p.ClusterName = strings.TrimSpace(implString(impl, "clusterName")); p.ClusterName == "" {
		return EKSPodIdentityPlan{}, fmt.Errorf("implementation.clusterName is required (the EKS cluster the association lives in — a separate capability/operand)")
	}
	// roleArn is a REFERENCE (it names an IAM role), never key material — safe to
	// carry (D53).
	if p.RoleArn = strings.TrimSpace(implString(impl, "roleArn")); p.RoleArn == "" {
		return EKSPodIdentityPlan{}, fmt.Errorf("implementation.roleArn is required (the IAM role the serviceAccount assumes — a separate capability/operand)")
	}
	return p, nil
}

// createBody is the CreatePodIdentityAssociation request body: the namespace +
// serviceAccount, the IAM role, and ownership tags. Cited: EKS
// CreatePodIdentityAssociation.
func (p EKSPodIdentityPlan) createBody(capability, environment string) []byte {
	return []byte(jsonBody(map[string]any{
		"namespace":      p.Namespace,
		"serviceAccount": p.ServiceAccount,
		"roleArn":        p.RoleArn,
		"tags": map[string]any{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}))
}

// eksPodIdentity is the projection of a pod identity association the driver reads.
type eksPodIdentity struct {
	AssociationID  string            `json:"associationId"`
	AssociationArn string            `json:"associationArn"`
	Namespace      string            `json:"namespace"`
	ServiceAccount string            `json:"serviceAccount"`
	RoleArn        string            `json:"roleArn"`
	Tags           map[string]string `json:"tags"`
}

// resolvePodIdentityID resolves the server-generated associationId for our
// namespace+serviceAccount via ListPodIdentityAssociations (the MSK
// describe-to-resolve pattern). found=false with a nil error is an authoritative
// "no such association"; any transport/HTTP/parse failure comes back as a named
// read error (unknown, never a fabricated absence).
func (d *Driver) resolvePodIdentityID(region, cluster, namespace, serviceAccount string) (id string, found bool, err error) {
	const op = "ListPodIdentityAssociations"
	path := "/clusters/" + cluster + "/pod-identity-associations?namespace=" +
		url.QueryEscape(namespace) + "&serviceAccount=" + url.QueryEscape(serviceAccount)
	st, resp, cerr := d.eksGet(region, path)
	if cerr != nil {
		return "", false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return "", false, readHTTP(op, st, eksErr(resp))
	}
	var out struct {
		Associations []eksPodIdentity `json:"associations"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return "", false, readBody(op, st)
	}
	for _, a := range out.Associations {
		if a.Namespace == namespace && a.ServiceAccount == serviceAccount {
			return a.AssociationID, true, nil
		}
	}
	return "", false, nil
}

// describePodIdentity resolves one association by id, mirroring the cluster
// describe: a 404 is found=false with a nil error (gone), a transport/other
// error names itself (unknown — never a fabricated absence).
func (d *Driver) describePodIdentity(region, cluster, id string) (eksPodIdentity, bool, error) {
	const op = "DescribePodIdentityAssociation"
	st, resp, err := d.eksGet(region, "/clusters/"+cluster+"/pod-identity-associations/"+id)
	if err != nil {
		return eksPodIdentity{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return eksPodIdentity{}, false, nil
	}
	if st != http.StatusOK {
		return eksPodIdentity{}, false, readHTTP(op, st, eksErr(resp))
	}
	var out struct {
		Association eksPodIdentity `json:"association"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return eksPodIdentity{}, false, readBody(op, st)
	}
	return out.Association, true, nil
}

// createEKSPodIdentity creates a pod identity association, four-valued throughout.
// Pre-read resolves any existing association for our ns+sa: an ours-already one is
// a repair (succeeded); a foreign one is refused; else CreatePodIdentityAssociation
// (synchronous — no long poll). Transport/5xx/conflict are unknown WITH the pid.
func (d *Driver) createEKSPodIdentity(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildEKSPodIdentity(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := eksPodIdentityProviderID(region, plan.ClusterName, plan.Namespace, plan.ServiceAccount)

	id, found, rerr := d.resolvePodIdentityID(region, plan.ClusterName, plan.Namespace, plan.ServiceAccount)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pod-identity ownership pre-read gave no answer after retry (check " +
				"eks:ListPodIdentityAssociations permission; a transient throttle/5xx is " +
				"retried) — reconcile: " + rerr.Error()}
	}
	if found {
		a, f2, r2 := d.describePodIdentity(region, plan.ClusterName, id)
		if r2 != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "the existing pod-identity association gave no answer after retry (check " +
					"eks:DescribePodIdentityAssociation permission; a transient throttle/5xx is " +
					"retried) — reconcile: " + r2.Error()}
		}
		if f2 {
			if !groundholdTagsMatch(a.Tags, capability, environment) {
				return provider.CreateResult{Status: "failed",
					Reason: "an association for this serviceAccount exists and is not ours (tags do not match) — refusing to adopt it"}
			}
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours already — repair/no-op
		}
		// vanished between list and describe — fall through to create.
	}

	st, body, err := d.eksDo("POST", region, "/clusters/"+plan.ClusterName+"/pod-identity-associations",
		plan.createBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreatePodIdentityAssociation outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreatePodIdentityAssociation says the association now exists — reconcile ownership"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreatePodIdentityAssociation HTTP %d (server error — may have landed): %s", st, eksErr(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreatePodIdentityAssociation HTTP %d: %s", st, eksErr(body))}
	}
}

// observeEKSPodIdentity reverse-maps an association to
// capability.identity.podidentity: resolve the id via List, then Describe. An
// unreadable read is an error (unknown), never a fabricated absence; a not-found is
// "nothing to observe".
func (d *Driver) observeEKSPodIdentity(capability, providerID string) ([]provider.Observation, []string, error) {
	region, cluster, namespace, serviceAccount, err := splitEKSPodIdentityProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	id, found, rerr := d.resolvePodIdentityID(region, cluster, namespace, serviceAccount)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"pod identity association not found — bound resource is gone (will re-create)"}, nil
	}
	a, f2, r2 := d.describePodIdentity(region, cluster, id)
	if r2 != nil {
		return nil, nil, r2
	}
	if !f2 {
		return []provider.Observation{
			// F-LC3 (D802): the bound subject is GONE; an empty return would leave the
			// last good reading standing as the freshest word about it.
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"pod identity association not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "workload.namespace", Value: a.Namespace, Derivation: "measured"},
		{Path: "workload.serviceAccount", Value: a.ServiceAccount, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	return obs, nil, nil
}

// deleteEKSPodIdentity removes the association, ownership-guarded: resolve the id,
// re-check the ownership tags, DeletePodIdentityAssociation. Idempotent on
// already-gone; a transport/5xx is unknown WITH the pid (reconcile); a foreign
// association is refused.
func (d *Driver) deleteEKSPodIdentity(capability, environment, providerID string) provider.CreateResult {
	region, cluster, namespace, serviceAccount, err := splitEKSPodIdentityProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	id, found, rerr := d.resolvePodIdentityID(region, cluster, namespace, serviceAccount)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	a, f2, r2 := d.describePodIdentity(region, cluster, id)
	if r2 != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete association read gave no answer — reconcile: " + r2.Error()}
	}
	if f2 && !groundholdTagsMatch(a.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "association tags do not match — refusing to delete a resource that is not ours"}
	}
	st, body, err := d.eksDo("DELETE", region, "/clusters/"+cluster+"/pod-identity-associations/"+id, nil)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeletePodIdentityAssociation outcome unknown: %v", err)}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case st == http.StatusOK || st == http.StatusAccepted:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("DeletePodIdentityAssociation HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("DeletePodIdentityAssociation HTTP %d: %s", st, eksErr(body))}
	}
}

// classifyEKSPodIdentityChange (D46): PURE. namespace + serviceAccount are the
// association identity (immutable — a different binding is a different resource);
// the rest are platform/projection (unsupported). roleArn is an OPERAND, so a
// roleArn change is a candidate-hash change the compiler handles (not a vocab
// attribute reaching here).
func classifyEKSPodIdentityChange(path string) (string, string) {
	switch path {
	case "workload.namespace", "workload.serviceAccount":
		return "immutable", "the namespace/serviceAccount is the association identity — a different binding is a different resource, not an in-place patch"
	case "service.managed", "location.region":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no EKS pod identity in-place mapping for " + path
	}
}

// discoverEKSPodIdentity enumerates every pod identity association UNDER every
// cluster in the region as capability.identity.podidentity (associations live
// under a cluster, so the region-level discover first lists the clusters, then
// ListPodIdentityAssociations per cluster with no filter). Reuses
// observeEKSPodIdentity for the reverse map.
func (d *Driver) discoverEKSPodIdentity(region string) ([]provider.Discovered, []string, error) {
	st, resp, err := d.eksDo("GET", region, "/clusters", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("eks ListClusters: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("eks ListClusters: HTTP %d", st)
	}
	var cl struct {
		Clusters []string `json:"clusters"`
	}
	if json.Unmarshal(resp, &cl) != nil {
		return nil, nil, readBody("ListClusters", st)
	}
	var found []provider.Discovered
	var diags []string
	for _, cluster := range cl.Clusters {
		const listOp = "ListPodIdentityAssociations"
		st, resp, err := d.eksDo("GET", region, "/clusters/"+cluster+"/pod-identity-associations", nil)
		if err != nil {
			diags = append(diags, cluster+": "+readTransport(listOp, err).Error()+" — skipped")
			continue
		}
		if st != http.StatusOK {
			diags = append(diags, cluster+": "+readHTTP(listOp, st, eksErr(resp)).Error()+" — skipped")
			continue
		}
		var out struct {
			Associations []eksPodIdentity `json:"associations"`
		}
		if json.Unmarshal(resp, &out) != nil {
			diags = append(diags, cluster+": "+readBody(listOp, st).Error()+" — skipped")
			continue
		}
		for _, a := range out.Associations {
			pid := eksPodIdentityProviderID(region, cluster, a.Namespace, a.ServiceAccount)
			obs, od, oerr := d.observeEKSPodIdentity("", pid)
			if oerr != nil {
				diags = append(diags, a.Namespace+"/"+a.ServiceAccount+": "+oerr.Error())
				continue
			}
			diags = append(diags, od...)
			found = append(found, provider.Discovered{
				ProviderID: pid, ResourceType: "capability.identity.podidentity", Observations: provider.WithoutAbsence(obs)})
		}
	}
	return found, diags, nil
}
