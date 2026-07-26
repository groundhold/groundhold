// Redshift Serverless network shell (D122): the SigV4-signed, JSON-protocol half of
// the AWS capability.warehouse.analytics driver. A COMPOSITE under one binding —
// CreateNamespace (data + CMK) then CreateWorkgroup (compute + publiclyAccessible),
// both tagged at birth. The names are deterministic, so the pid is knowable BEFORE
// any response (D29). Workgroup creation is async — the shell polls GetWorkgroup to
// AVAILABLE (still-creating at timeout is unknown-with-pid). Ownership is tags read
// via ListTagsForResource against the live ARN (Get* does not echo tags). Delete is
// reverse (workgroup then namespace); no final snapshot (retirement is data loss).
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

const rssTarget = "RedshiftServerless"

func (d *Driver) rssBase(region string) string {
	if d.RedshiftServerlessBaseURL != "" {
		return d.RedshiftServerlessBaseURL
	}
	return "https://redshift-serverless." + region + ".amazonaws.com"
}

func (d *Driver) rssCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": rssTarget + "." + action,
	}
	return d.doSigned("POST", d.rssBase(region)+"/", "redshift-serverless", region, h, []byte(body))
}

func rssProviderID(region, name string) string { return "rss:" + region + ":" + name }

func splitRSSProviderID(providerID string) (region, name string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "rss" {
		return "", "", fmt.Errorf("providerId %q is not rss:region:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !rssNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type rssWorkgroup struct {
	WorkgroupName      string `json:"workgroupName"`
	WorkgroupArn       string `json:"workgroupArn"`
	NamespaceName      string `json:"namespaceName"`
	Status             string `json:"status"`
	PubliclyAccessible bool   `json:"publiclyAccessible"`
}

type rssNamespace struct {
	NamespaceName string `json:"namespaceName"`
	NamespaceArn  string `json:"namespaceArn"`
	Status        string `json:"status"`
	KmsKeyID      string `json:"kmsKeyId"`
}

// getWorkgroup reads a workgroup. found=false + readable=true is authoritative
// "does not exist"; readable=false is transport/HTTP/parse failure.
func (d *Driver) getWorkgroup(region, name string) (rssWorkgroup, bool, error) {
	const op = "GetWorkgroup"
	st, resp, err := d.rssCall(region, "GetWorkgroup", fmt.Sprintf(`{"workgroupName":%q}`, name))
	if err != nil {
		return rssWorkgroup{}, false, readTransport(op, err)
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return rssWorkgroup{}, false, nil
	}
	if st != http.StatusOK {
		return rssWorkgroup{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Workgroup rssWorkgroup `json:"workgroup"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return rssWorkgroup{}, false, readBody(op, st)
	}
	return r.Workgroup, true, nil
}

func (d *Driver) getNamespace(region, name string) (rssNamespace, bool, error) {
	const op = "GetNamespace"
	st, resp, err := d.rssCall(region, "GetNamespace", fmt.Sprintf(`{"namespaceName":%q}`, name))
	if err != nil {
		return rssNamespace{}, false, readTransport(op, err)
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return rssNamespace{}, false, nil
	}
	if st != http.StatusOK {
		return rssNamespace{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Namespace rssNamespace `json:"namespace"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return rssNamespace{}, false, readBody(op, st)
	}
	return r.Namespace, true, nil
}

// rssTagsFor reads ownership tags via ListTagsForResource against the live ARN
// (Get* does not echo tags). readable=false on any transport/HTTP/parse failure.
func (d *Driver) rssTagsFor(region, arn string) (map[string]string, error) {
	const op = "ListTagsForResource"
	st, resp, err := d.rssCall(region, "ListTagsForResource", fmt.Sprintf(`{"resourceArn":%q}`, arn))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Tags []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"tags"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range r.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

// workgroupOurs reads the workgroup's ARN then its tags; three-valued (a read
// that gave no answer is never "not ours"). An absent workgroup is (false, nil):
// there is nothing to own.
func (d *Driver) workgroupOurs(region, name, capability, environment string) (ours bool, err error) {
	wg, found, rerr := d.getWorkgroup(region, name)
	if rerr != nil || !found {
		return false, rerr
	}
	tags, terr := d.rssTagsFor(region, wg.WorkgroupArn)
	if terr != nil {
		return false, terr
	}
	return groundholdTagsMatch(tags, capability, environment), nil
}

func (d *Driver) createRedshiftServerless(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildRedshiftServerless(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Region != "" && plan.Region != region {
		region = plan.Region
	}
	pid := rssProviderID(region, plan.Name)

	// ---- 1. CreateNamespace (data + CMK, tagged at birth) ----
	nb, _ := json.Marshal(plan.namespaceBody(capability, environment))
	st, resp, err := d.rssCall(region, "CreateNamespace", string(nb))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateNamespace outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// created
	case strings.Contains(ecsErr(resp), "ConflictException"), strings.Contains(ecsErr(resp), "ResourceExists"):
		ns, found, rerr := d.getNamespace(region, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "namespace name conflict, existing namespace gave no answer — reconcile: " + rerr.Error()}
		}
		tags, terr := d.rssTagsFor(region, ns.NamespaceArn)
		if !found || terr != nil || !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a namespace with this name exists and is not ours (tags do not match)"}
		}
		// ours — fall through to ensure the workgroup exists
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateNamespace HTTP %d (server error — may have landed): %s", st, ecsErr(resp))}
	default:
		// D237: throttle/503/live-403 -> unknown WITH the pid (names are
		// deterministic, keep the handle); only a clean 4xx refusal fails.
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "CreateNamespace"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateNamespace HTTP %d: %s", st, ecsErr(resp))}
	}

	// ---- 2. CreateWorkgroup (compute + publiclyAccessible) then poll to AVAILABLE ----
	wb, _ := json.Marshal(plan.workgroupBody(capability, environment))
	st, resp, err = d.rssCall(region, "CreateWorkgroup", string(wb))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateWorkgroup outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// accepted — poll below
	case strings.Contains(ecsErr(resp), "ConflictException"), strings.Contains(ecsErr(resp), "ResourceExists"):
		ours, oerr := d.workgroupOurs(region, plan.Name, capability, environment)
		if oerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "workgroup name conflict, existing workgroup gave no answer — reconcile: " + oerr.Error()}
		}
		if !ours {
			return provider.CreateResult{Status: "failed",
				Reason: "a workgroup with this name exists and is not ours (tags do not match)"}
		}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateWorkgroup HTTP %d (server error — may have landed): %s", st, ecsErr(resp))}
	default:
		// D237: throttle/503/live-403 -> unknown WITH the pid, never failed.
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "CreateWorkgroup"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateWorkgroup HTTP %d: %s", st, ecsErr(resp))}
	}

	deadline := d.Now().Add(d.PollTimeout)
	for {
		wg, found, rerr := d.getWorkgroup(region, plan.Name)
		if rerr == nil && found {
			switch wg.Status {
			case "AVAILABLE":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "FAILED":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "workgroup entered status FAILED"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "workgroup still provisioning at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

func (d *Driver) observeRedshiftServerless(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitRSSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	wg, wgFound, wgOK := d.getWorkgroup(region, name)
	if wgOK != nil {
		return nil, nil, wgOK
	}
	if !wgFound {
		return nil, []string{"workgroup not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "encryption.atRest", Value: true, Derivation: "config-intent"}, // always encrypted
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "network.publicExposure", Value: wg.PubliclyAccessible, Derivation: "measured"},
	}
	// a customer key is present iff the namespace carries a non-default kmsKeyId.
	ns, nsFound, nsOK := d.getNamespace(region, name)
	if nsOK == nil && nsFound && ns.KmsKeyID != "" && !strings.Contains(ns.KmsKeyID, "aws/redshift") {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteRedshiftServerless(capability, environment, providerID string) provider.CreateResult {
	// the region is read from the provider ID, which carries the authoritative location.
	region, name, err := splitRSSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	ours, oerr := d.workgroupOurs(region, name, capability, environment)
	wg, found, wgReadable := d.getWorkgroup(region, name)
	if wgReadable != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + wgReadable.Error()}
	}
	if found && oerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "ownership read gave no answer — reconcile: " + oerr.Error()}
	}
	if found && !ours {
		return provider.CreateResult{Status: "failed",
			Reason: "workgroup tags do not match — refusing to delete a resource that is not ours"}
	}
	_ = wg
	// ---- workgroup first (compute), then namespace (data) ----
	if found {
		if r := d.rssDelete(region, "DeleteWorkgroup", fmt.Sprintf(`{"workgroupName":%q}`, name), providerID, "workgroup"); r != nil {
			return *r
		}
	}
	// no finalSnapshotName: retirement is data loss (the D47 gate authorized it).
	if r := d.rssDelete(region, "DeleteNamespace", fmt.Sprintf(`{"namespaceName":%q}`, name), providerID, "namespace"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// rssDelete issues one delete; nil = ok (or idempotent absence), non-nil = a terminal
// result WITH the pid (D29 honesty).
func (d *Driver) rssDelete(region, action, body, pid, what string) *provider.CreateResult {
	st, resp, err := d.rssCall(region, action, body)
	if err != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("%s delete outcome unknown: %v", what, err)}
	}
	if strings.Contains(ecsErr(resp), "ResourceNotFound") {
		return nil // idempotent absence
	}
	if st >= 500 {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("%s delete HTTP %d (server error) — reconcile", what, st)}
	}
	if st != http.StatusOK {
		// D237: throttle/503/live-403 -> unknown WITH the pid, never failed.
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, what+" delete"); r != nil {
			return r
		}
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s delete HTTP %d: %s", what, st, ecsErr(resp))}
	}
	return nil
}
