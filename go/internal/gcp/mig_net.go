// Managed instance group network shell (D371): auth, HTTP, operation polling and
// the reverse mapping. No semantics here — those are in mig.go.
//
// The long-running-operation handling is NOT reimplemented: `computeInsert` and
// `pollComputeOperation` already carry the D29 discipline for this API family,
// and the scope argument takes "regions/<r>" as readily as "zones/<z>".
//
// A create is TWO mutations when an autoscaler is wanted: the group, then the
// autoscaler. The group goes first, so a failure between them leaves a real fleet
// at its declared floor — under-scaled but running, which is the survivable half.
// The reverse order is impossible (an autoscaler targets a group that must
// already exist), and the outcome is reported honestly rather than rolled back.
//
// `network.publicExposure` is read from the INSTANCE TEMPLATE, which the group
// inherits and cannot override — the same shape as the ASG's launch template, and
// the same handling: refuse before creating when it contradicts the contract, and
// report it unread rather than defaulted when the template cannot be read.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// migProviderID is scope-qualified: a group name is unique per zone (zonal) or
// per region (regional), and the two namespaces are distinct.
func migProviderID(project, scope, name string) string {
	return "mig:" + project + ":" + scope + ":" + name
}

func splitMIGProviderID(providerID string) (project, scope, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "mig" {
		return "", "", "", fmt.Errorf("providerId %q is not mig:project:scope:name", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !gceZoneOK.MatchString(parts[2]) && !pdRegionOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId scope %q is neither a zone nor a region", parts[2])
	}
	if !gcpName.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId group name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// migScopeIsRegional reports whether a providerId scope names a region. A zone
// always carries the trailing letter a region does not.
func migScopeIsRegional(scope string) bool { return !gceZoneOK.MatchString(scope) }

func (d *Driver) migCollectionURL(project, scope string) string {
	if migScopeIsRegional(scope) {
		return fmt.Sprintf("%s/projects/%s/regions/%s/instanceGroupManagers", d.computeBase(), project, scope)
	}
	return fmt.Sprintf("%s/projects/%s/zones/%s/instanceGroupManagers", d.computeBase(), project, scope)
}

func (d *Driver) migAutoscalerURL(project, scope string) string {
	if migScopeIsRegional(scope) {
		return fmt.Sprintf("%s/projects/%s/regions/%s/autoscalers", d.computeBase(), project, scope)
	}
	return fmt.Sprintf("%s/projects/%s/zones/%s/autoscalers", d.computeBase(), project, scope)
}

func migOperationScope(scope string) string {
	if migScopeIsRegional(scope) {
		return "regions/" + scope
	}
	return "zones/" + scope
}

// migDoc is the slice of instanceGroupManagers.get this driver reads.
type migDoc struct {
	Name             string `json:"name"`
	SelfLink         string `json:"selfLink"`
	TargetSize       int    `json:"targetSize"`
	InstanceTemplate string `json:"instanceTemplate"`
	Description      string `json:"description"` // the ownership marker
}

func (d *Driver) getMIG(project, scope, name string) (migDoc, bool, error) {
	st, body, err := d.call("GET", d.migCollectionURL(project, scope)+"/"+name, nil)
	if err != nil {
		return migDoc{}, false, readTransport("instanceGroupManagers.get", err)
	}
	if st == http.StatusNotFound {
		return migDoc{}, false, nil
	}
	if st != http.StatusOK {
		return migDoc{}, false, readHTTP("instanceGroupManagers.get", st, gcpErrCode(body))
	}
	var doc migDoc
	if json.Unmarshal(body, &doc) != nil {
		return migDoc{}, false, readBody("instanceGroupManagers.get", st)
	}
	return doc, true, nil
}

// migAutoscaler reads the autoscaler targeting a group, if any. Returns
// (min, max, found, known): `known=false` means the read did not answer, and the
// caller must report the attributes unread rather than choose values for them.
func (d *Driver) migAutoscaler(project, scope, groupSelfLink string) (min, max int, found bool, err error) {
	st, body, cerr := d.call("GET", d.migAutoscalerURL(project, scope), nil)
	if cerr != nil {
		return 0, 0, false, readTransport("autoscalers.list", cerr)
	}
	if st != http.StatusOK {
		return 0, 0, false, readHTTP("autoscalers.list", st, gcpErrCode(body))
	}
	var page struct {
		Items []struct {
			Target string `json:"target"`
			Policy struct {
				Min int `json:"minNumReplicas"`
				Max int `json:"maxNumReplicas"`
			} `json:"autoscalingPolicy"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &page) != nil {
		return 0, 0, false, readBody("autoscalers.list", st)
	}
	for _, it := range page.Items {
		// selfLink comparison by suffix: the API returns fully-qualified targets
		// while a caller may hold a shorter form of the same resource.
		if it.Target != "" && groupSelfLink != "" &&
			(it.Target == groupSelfLink || strings.HasSuffix(it.Target, groupSelfLink) ||
				strings.HasSuffix(groupSelfLink, it.Target)) {
			return it.Policy.Min, it.Policy.Max, true, nil
		}
	}
	return 0, 0, false, nil
}

// instanceTemplateAssignsPublicIP reads the addressing the template gives every
// machine: an accessConfig on a network interface IS the public address on GCP,
// exactly as it is for a single instance (D359).
func (d *Driver) instanceTemplateAssignsPublicIP(project, template string) (public bool, err error) {
	name := template
	if i := strings.LastIndex(template, "/"); i >= 0 {
		name = template[i+1:]
	}
	if !gcpName.MatchString(name) {
		return false, fmt.Errorf("instanceTemplates.get: %q is not a template name", template)
	}
	st, body, cerr := d.call("GET", fmt.Sprintf("%s/projects/%s/global/instanceTemplates/%s",
		d.computeBase(), project, name), nil)
	if cerr != nil {
		return false, readTransport("instanceTemplates.get", cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP("instanceTemplates.get", st, gcpErrCode(body))
	}
	var doc struct {
		Properties struct {
			NetworkInterfaces []struct {
				AccessConfigs []struct {
					Type string `json:"type"`
				} `json:"accessConfigs"`
			} `json:"networkInterfaces"`
		} `json:"properties"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return false, readBody("instanceTemplates.get", st)
	}
	for _, nic := range doc.Properties.NetworkInterfaces {
		if len(nic.AccessConfigs) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func (d *Driver) createMIG(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {

	plan, err := BuildMIGCreate(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	scope := plan.Zone
	if plan.Regional {
		scope = plan.Region
	}
	pid := migProviderID(d.Project, scope, plan.Name)

	// The group inherits the template's addressing and cannot override it, so the
	// only honest options are to read it or to ignore the contract.
	if plan.PublicDeclared {
		public, terr := d.instanceTemplateAssignsPublicIP(d.Project, plan.InstanceTemplate)
		if terr != nil {
			return provider.CreateResult{Status: "failed",
				Reason: "network.publicExposure could not be verified for instance template " +
					plan.InstanceTemplate + " (" + terr.Error() +
					") — the group cannot set addressing itself"}
		}
		if public != plan.WantPublic {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("network.publicExposure=%v contradicts instance template %s, which "+
					"assigns external addresses = %v — the group inherits the template's addressing "+
					"and cannot override it, so the contract would be reported satisfied by a fleet "+
					"that violates it", plan.WantPublic, plan.InstanceTemplate, public)}
		}
	}

	st, res := d.computeInsert(d.migCollectionURL(d.Project, scope),
		plan.createBody(capability, environment), migOperationScope(scope))
	if st == http.StatusConflict {
		// The deterministic name already exists. It is ours only if the description
		// marker says so — otherwise we would bind a stranger's fleet to this
		// contract, and put our delete over it.
		doc, found, rerr := d.getMIG(d.Project, scope, plan.Name)
		if rerr != nil || !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing group gave no answer — reconcile"}
		}
		if doc.Description != vpcOwnerMarker(capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a group with this name exists and is not ours (description marker does not match) — refusing to bind it"}
		}
	} else if res.Status != "succeeded" {
		if res.ProviderID == "" {
			res.ProviderID = pid
		}
		return res
	}

	if !plan.AutoscalingWanted {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}
	doc, found, rerr := d.getMIG(d.Project, scope, plan.Name)
	if rerr != nil || !found || doc.SelfLink == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "the group was created but its selfLink could not be read, so the " +
				"autoscaler was not attached — the fleet holds its floor and does not scale; reconcile"}
	}
	ast, ares := d.computeInsert(d.migAutoscalerURL(d.Project, scope),
		plan.autoscalerBody(doc.SelfLink), migOperationScope(scope))
	switch {
	case ast == http.StatusConflict:
		// an autoscaler with our deterministic name already targets the group
	case ares.Status == "failed":
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: "the group was created but the autoscaler was refused — " +
				"autoscaling.enabled is not satisfied: " + ares.Reason}
	case ares.Status != "succeeded":
		// The group EXISTS and holds its floor; only the autoscaler is uncertain.
		// Reporting `failed` would invite a retry of the whole create.
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "the group was created but the autoscaler outcome is unknown — " +
				"the fleet holds its floor and does not scale; reconcile"}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// observeMIG is the reverse mapping. The capacity envelope comes from the
// AUTOSCALER when one exists and from targetSize when none does — the same
// asymmetry the create path honors, read back the same way.
func (d *Driver) observeMIG(capability, providerID string) ([]provider.Observation, []string, error) {
	project, scope, name, err := splitMIGProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	// D466 — the project boundary. 39 of 44 GCP deletes already guard it; these
	// families did not, and the label check is not a substitute: our capability +
	// environment labels are IDENTICAL in every project we manage, so a providerId
	// naming another project passes it. sameProject is a no-op when nothing is
	// pinned (observe/discover), a refusal when apply/converge pinned one.
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getMIG(project, scope, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"managed instance group not found — bound resource is gone (will re-create)"}, nil
	}
	region, class := scope, "regional"
	if !migScopeIsRegional(scope) {
		region, class = gceRegionOfZone(scope), "zonal"
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "availability.class", Value: class, Derivation: "measured"},
	}
	var unread []string
	min, max, hasAuto, aerr := d.migAutoscaler(project, scope, doc.SelfLink)
	switch {
	case aerr != nil:
		// A silent false would report a scaling fleet as fixed-size, and the bounds
		// would then be read off targetSize — two wrong answers from one unread call.
		unread = append(unread,
			"autoscaling.enabled and the capacity envelope unread: "+aerr.Error())
	case hasAuto:
		obs = append(obs,
			provider.Observation{Path: "autoscaling.enabled", Value: true, Derivation: "measured"},
			provider.Observation{Path: "replicas.minimum", Value: min, Derivation: "measured"},
			provider.Observation{Path: "replicas.maximum", Value: max, Derivation: "measured"})
	default:
		// No autoscaler: the group has one size, and it is both bounds.
		obs = append(obs,
			provider.Observation{Path: "autoscaling.enabled", Value: false, Derivation: "measured"},
			provider.Observation{Path: "replicas.minimum", Value: doc.TargetSize, Derivation: "measured"},
			provider.Observation{Path: "replicas.maximum", Value: doc.TargetSize, Derivation: "measured"})
	}
	if doc.InstanceTemplate == "" {
		unread = append(unread, "group reports no instance template — network.publicExposure unread")
	} else if public, terr := d.instanceTemplateAssignsPublicIP(project, doc.InstanceTemplate); terr == nil {
		obs = append(obs, provider.Observation{
			Path: "network.publicExposure", Value: public, Derivation: "measured"})
	} else {
		unread = append(unread, "network.publicExposure unread for instance template "+
			doc.InstanceTemplate+": "+terr.Error())
	}
	return obs, unread, nil
}

// deleteMIG retires the group AND the fleet it manages — that is what retiring a
// group MEANS (D363: the machines are cattle by construction). The autoscaler is
// deleted with its target by the API, so there is nothing extra to tear down.
func (d *Driver) deleteMIG(capability, environment, providerID string) provider.CreateResult {
	project, scope, name, err := splitMIGProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// D466 — the project boundary. 39 of 44 GCP deletes already guard it; these
	// families did not, and the label check is not a substitute: our capability +
	// environment labels are IDENTICAL in every project we manage, so a providerId
	// naming another project passes it. sameProject is a no-op when nothing is
	// pinned (observe/discover), a refusal when apply/converge pinned one.
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getMIG(project, scope, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Description != vpcOwnerMarker(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "group description marker does not match — refusing to terminate a fleet that is not ours"}
	}
	st, body, e := d.call("DELETE", d.migCollectionURL(project, scope)+"/"+name, nil)
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case st >= 400:
		r := mutationResult("delete", st, body)
		r.ProviderID = providerID
		return r
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "delete response carried no operation — reconcile"}
	}
	r := d.pollComputeOperation(migOperationScope(scope), op.Name)
	r.ProviderID = providerID
	return r
}

// discoverMIGs enumerates groups in the region, ZONAL AND REGIONAL BOTH. A sweep
// that enumerated zones only would miss every regional group and report the
// account clean — and a fleet that scales itself unwatched is a bill that grows
// on its own.
func (d *Driver) discoverMIGs(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.call("GET", fmt.Sprintf("%s/projects/%s/aggregated/instanceGroupManagers",
		d.computeBase(), d.Project), nil)
	if err != nil {
		return nil, nil, readTransport("instanceGroupManagers.aggregatedList", err)
	}
	if st != http.StatusOK {
		return nil, nil, readHTTP("instanceGroupManagers.aggregatedList", st, gcpErrCode(body))
	}
	var page struct {
		Items map[string]struct {
			Managers []struct {
				Name string `json:"name"`
			} `json:"instanceGroupManagers"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &page) != nil {
		return nil, nil, readBody("instanceGroupManagers.aggregatedList", st)
	}
	var out []provider.Discovered
	var diags []string
	for key, group := range page.Items {
		scope := ""
		switch {
		case strings.HasPrefix(key, "zones/"):
			z := strings.TrimPrefix(key, "zones/")
			if gceRegionOfZone(z) != region {
				continue
			}
			scope = z
		case strings.HasPrefix(key, "regions/"):
			r := strings.TrimPrefix(key, "regions/")
			if r != region {
				continue
			}
			scope = r
		default:
			continue
		}
		for _, m := range group.Managers {
			if m.Name == "" {
				continue
			}
			pid := migProviderID(d.Project, scope, m.Name)
			obs, odiags, oerr := d.observeMIG("", pid)
			if oerr != nil {
				diags = append(diags, m.Name+": "+oerr.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, m.Name+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.compute.autoscaling",
				Observations: provider.WithoutAbsence(obs),
			})
		}
	}
	return out, diags, nil
}
