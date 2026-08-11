// Virtual machine scale set network shell (D372): auth, HTTP and the reverse
// mapping. No semantics here — those are in vmss.go.
//
// The ARM plumbing is NOT reimplemented: `putAndPoll` already carries the D29
// discipline for this API family AND the foreign-upsert refusal (D254) — a PUT at
// a named path would otherwise happily overwrite a fleet somebody else owns.
//
// A create is TWO mutations when scaling is wanted: the scale set, then the
// autoscale setting. The scale set goes first, so a failure between them leaves a
// real fleet at its declared floor — under-scaled but running, which is the
// survivable half. The reverse order is impossible (an autoscale setting targets
// a resource that must already exist), and the outcome is reported honestly
// rather than rolled back. This is the same shape both twins use (D371); the
// ordering argument is a property of the vocabulary, not of a cloud.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"groundhold/internal/provider"
)

const (
	// azureVMSSAPIVersion pins the Compute scale-set API this driver targets.
	azureVMSSAPIVersion = "2024-07-01"
	// azureAutoscaleAPIVersion pins the Insights autoscale-settings API.
	azureAutoscaleAPIVersion = "2022-10-01"
)

func azureVMSSProviderID(sub, rg, name string) string {
	return "azvmss:" + sub + ":" + rg + ":" + name
}

func splitAzureVMSSProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "azvmss" {
		return "", "", "", fmt.Errorf("providerId %q is not azvmss:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || parts[3] == "" {
		return "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) azureVMSSPath(name string) string {
	return "Microsoft.Compute/virtualMachineScaleSets/" + name
}

func (d *Driver) azureAutoscalePath(name string) string {
	return "Microsoft.Insights/autoscalesettings/" + name + "-cpu"
}

// azureVMSSDoc is the slice of virtualMachineScaleSets.get this driver reads.
type azureVMSSDoc struct {
	ID       string            `json:"id"`
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
	Zones    []string          `json:"zones"`
	SKU      struct {
		Capacity int `json:"capacity"`
	} `json:"sku"`
	Properties struct {
		VirtualMachineProfile struct {
			NetworkProfile struct {
				NICs []struct {
					Properties struct {
						IPConfigurations []struct {
							Properties struct {
								PublicIP *struct {
									Name string `json:"name"`
								} `json:"publicIPAddressConfiguration"`
							} `json:"properties"`
						} `json:"ipConfigurations"`
					} `json:"properties"`
				} `json:"networkInterfaceConfigurations"`
			} `json:"networkProfile"`
		} `json:"virtualMachineProfile"`
	} `json:"properties"`
}

func (d *Driver) getAzureVMSS(rg, name string) (azureVMSSDoc, bool, error) {
	url, _ := d.armURL(rg, d.azureVMSSPath(name), azureVMSSAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return azureVMSSDoc{}, false, &armReadError{Op: "virtualMachineScaleSets.get", Cause: "transport", Detail: e.Error()}
	}
	if st == http.StatusNotFound {
		return azureVMSSDoc{}, false, nil
	}
	if st < 200 || st >= 300 {
		return azureVMSSDoc{}, false, &armReadError{Op: "virtualMachineScaleSets.get", Cause: "http", Status: st, Code: azErrCode(resp)}
	}
	var doc azureVMSSDoc
	if json.Unmarshal(resp, &doc) != nil {
		return azureVMSSDoc{}, false, &armReadError{Op: "virtualMachineScaleSets.get", Cause: "body", Status: st}
	}
	return doc, true, nil
}

// azureAutoscaleSetting reads the autoscale setting attached to a fleet. Returns
// (min, max, found, err): an error means the read did not answer, and the caller
// must report the attributes unread rather than choose values for them.
func (d *Driver) azureAutoscaleSetting(rg, name string) (min, max int, found bool, err error) {
	url, _ := d.armURL(rg, d.azureAutoscalePath(name), azureAutoscaleAPIVersion)
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return 0, 0, false, &armReadError{Op: "autoscalesettings.get", Cause: "transport", Detail: e.Error()}
	}
	if st == http.StatusNotFound {
		return 0, 0, false, nil // the API answered: there is no setting
	}
	if st < 200 || st >= 300 {
		return 0, 0, false, &armReadError{Op: "autoscalesettings.get", Cause: "http", Status: st, Code: azErrCode(resp)}
	}
	var doc struct {
		Properties struct {
			Enabled  bool `json:"enabled"`
			Profiles []struct {
				Capacity struct {
					Minimum string `json:"minimum"`
					Maximum string `json:"maximum"`
				} `json:"capacity"`
			} `json:"profiles"`
		} `json:"properties"`
	}
	if json.Unmarshal(resp, &doc) != nil || len(doc.Properties.Profiles) == 0 {
		return 0, 0, false, &armReadError{Op: "autoscalesettings.get", Cause: "body", Status: st}
	}
	if !doc.Properties.Enabled {
		// A DISABLED setting is not a scaling fleet: the resource exists but the
		// control loop does not run, and reporting `true` would claim behaviour the
		// fleet does not have.
		return 0, 0, false, nil
	}
	// ARM types these capacities as STRINGS. A value that is not a number is not a
	// bound we can report, so it is an unread envelope rather than a plausible 0.
	c := doc.Properties.Profiles[0].Capacity
	lo, loErr := strconv.Atoi(c.Minimum)
	hi, hiErr := strconv.Atoi(c.Maximum)
	if loErr != nil || hiErr != nil {
		return 0, 0, false, &armReadError{Op: "autoscalesettings.get", Cause: "body", Status: st}
	}
	return lo, hi, true, nil
}

func (d *Driver) createAzureVMSS(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {

	plan, err := BuildVMSS(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure scale set requires implementation.resource_group (groundhold does not create resource groups)"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := azureVMSSProviderID(d.Subscription, rg, plan.Name)
	tags := d.tags(capability, environment)

	url, _ := d.armURL(rg, d.azureVMSSPath(plan.Name), azureVMSSAPIVersion)
	body, _ := json.Marshal(plan.createBody(tags))
	if r := d.putAndPoll(url, body, pid, "scale set"); r != nil {
		return *r
	}
	if !plan.AutoscalingWanted {
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	}

	doc, found, rerr := d.getAzureVMSS(rg, plan.Name)
	if rerr != nil || !found || doc.ID == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "the scale set was created but its resource id could not be read, so the " +
				"autoscale setting was not attached — the fleet holds its floor and does not scale; reconcile"}
	}
	// An autoscale setting is a SYNCHRONOUS Microsoft.Insights resource: it carries
	// no provisioningState, so `putAndPoll` would wait for a "Succeeded" that never
	// arrives and report every healthy create as unknown at the timeout. The
	// sibling Insights drivers (alert, dashboard, webtest, scheduled query) all use
	// this shape — the foreign-upsert refusal (D254) still runs, but the PUT is the
	// whole operation.
	aurl, _ := d.armURL(rg, d.azureAutoscalePath(plan.Name), azureAutoscaleAPIVersion)
	abody, _ := json.Marshal(plan.autoscaleBody(doc.ID, tags))
	if r := d.refuseForeignUpsert(aurl, abody); r != nil {
		r.ProviderID = pid
		r.Reason = "the scale set was created but the autoscale setting was refused (" +
			r.Reason + ") — autoscaling.enabled is not satisfied"
		return *r
	}
	ast, aresp, aerr := d.doARM("PUT", aurl, abody)
	switch {
	case aerr != nil || ast >= 500:
		// The scale set EXISTS and holds its floor; only the setting is uncertain.
		// Reporting `failed` would invite a retry of the whole create.
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "the scale set was created but the autoscale setting outcome is unknown — " +
				"the fleet holds its floor and does not scale; reconcile"}
	case ast == http.StatusOK || ast == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	default:
		// A throttle or a permission gap never reached a decision, so the outcome is
		// unresolved; only a definitive 4xx means the setting was refused.
		if r := provider.MutationResult(ast, azErrCode(aresp), nil, pid, "create"); r != nil {
			r.Reason = "the scale set was created but the autoscale setting did not resolve (" +
				r.Reason + ") — the fleet holds its floor and does not scale; reconcile"
			return *r
		}
		return provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("the scale set was created but the autoscale setting was refused "+
				"(HTTP %d: %s) — autoscaling.enabled is not satisfied", ast, mutDetailAz(aresp))}
	}
}

// observeAzureVMSS is the reverse mapping. The capacity envelope comes from the
// AUTOSCALE SETTING when one exists and from sku.capacity when none does — the
// same asymmetry the create path honors, read back the same way.
func (d *Driver) observeAzureVMSS(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitAzureVMSSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's", sub)
	}
	doc, found, rerr := d.getAzureVMSS(rg, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D518): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"scale set not found — bound resource is gone (will re-create)"}, nil
	}
	class := "zonal"
	if len(doc.Zones) > 1 {
		class = "regional"
	}
	public := false
	for _, nic := range doc.Properties.VirtualMachineProfile.NetworkProfile.NICs {
		for _, ip := range nic.Properties.IPConfigurations {
			if ip.Properties.PublicIP != nil {
				public = true
			}
		}
	}
	// Present: clear the marker, or a stale "gone" survives a re-create.
	obs := []provider.Observation{
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: doc.Location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "availability.class", Value: class, Derivation: "measured"},
		// The VM profile is inline, so this is a genuine reading of the fleet rather
		// than of a template the fleet references.
		{Path: "network.publicExposure", Value: public, Derivation: "measured"},
	}
	var unread []string
	min, max, hasAuto, aerr := d.azureAutoscaleSetting(rg, name)
	switch {
	case aerr != nil:
		// One unread call would otherwise produce two wrong answers: a scaling fleet
		// reported fixed-size, and its bounds read off sku.capacity.
		unread = append(unread,
			"autoscaling.enabled and the capacity envelope unread: "+aerr.Error())
	case hasAuto:
		obs = append(obs,
			provider.Observation{Path: "autoscaling.enabled", Value: true, Derivation: "measured"},
			provider.Observation{Path: "replicas.minimum", Value: min, Derivation: "measured"},
			provider.Observation{Path: "replicas.maximum", Value: max, Derivation: "measured"})
	default:
		obs = append(obs,
			provider.Observation{Path: "autoscaling.enabled", Value: false, Derivation: "measured"},
			provider.Observation{Path: "replicas.minimum", Value: doc.SKU.Capacity, Derivation: "measured"},
			provider.Observation{Path: "replicas.maximum", Value: doc.SKU.Capacity, Derivation: "measured"})
	}
	return obs, unread, nil
}

// deleteAzureVMSS retires the fleet — that is what retiring a group MEANS (D363:
// the machines are cattle by construction). The autoscale setting is deleted
// first: a setting whose target has gone is an orphan that keeps evaluating, and
// leaving one behind is how a resource group accumulates things nobody can
// explain.
func (d *Driver) deleteAzureVMSS(capability, environment, providerID string) provider.CreateResult {
	sub, rg, name, err := splitAzureVMSSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's", sub)}
	}
	doc, found, rerr := d.getAzureVMSS(rg, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "scale set tags do not match — refusing to terminate a fleet that is not ours"}
	}
	// The autoscale setting goes FIRST, and its outcome must RESOLVE before the
	// fleet is touched. A setting whose target has gone keeps evaluating against a
	// resource that no longer exists, so swallowing an unresolved delete here would
	// report a clean retirement while leaving an orphan behind — exactly the
	// "we did not find out" treated as "we found out no" that D29 exists to
	// prevent. A 404 is resolved: the setting is already gone.
	// D944: the autoscale setting is a SEPARATE top-level resource deleted by derived
	// name (`<name>-cpu`). Without an ownership check, a brownfield-adopted fleet
	// (arbitrary name) would DELETE a FOREIGN autoscale setting at that name (the same
	// class as D943's vnet/containerapps companions; vmss is brownfield-adoptable). Read
	// its tags first: foreign => LEAVE it and proceed (not ours); absent (404) => nothing
	// to do; ours but the delete did not RESOLVE (transient/failed/read-error) => return
	// that outcome and leave the FLEET in place (D29 — the setting must conclude before
	// the fleet, else an orphaned setting keeps evaluating against a gone target). The
	// create tags the setting, so ours is confirmable.
	aurl, _ := d.armURL(rg, d.azureAutoscalePath(name), azureAutoscaleAPIVersion)
	if r, foreign := d.deleteCompanionIfOurs(aurl, capability, environment, providerID, "autoscale setting"); !foreign && r != nil && r.Status != "succeeded" {
		r.Reason = "the autoscale setting's delete did not resolve (" + r.Reason +
			") — the fleet was left in place rather than orphaning it; reconcile"
		return *r
	}

	url, _ := d.armURL(rg, d.azureVMSSPath(name), azureVMSSAPIVersion)
	// D984: route the delete through deleteAndConfirm (D971) — a VMSS DELETE returns
	// 202 Accepted (async); concluding succeeded here tombstoned a billable fleet
	// still live. The helper polls to a confirmed 404, unknown on timeout.
	return *d.deleteAndConfirm(url, providerID, "vm scale set")
}

// discoverAzureVMSS enumerates the scale sets in the subscription. A fleet that
// scales itself and nobody is watching is a bill that grows on its own.
func (d *Driver) discoverAzureVMSS(region string) ([]provider.Discovered, []string, error) {
	url := d.BaseURL + "/subscriptions/" + d.Subscription +
		"/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=" + azureVMSSAPIVersion
	st, resp, e := d.doARM("GET", url, nil)
	if e != nil {
		return nil, nil, fmt.Errorf("virtualMachineScaleSets.list: %s", azReadWhy(0, nil, e))
	}
	if st < 200 || st >= 300 {
		return nil, nil, fmt.Errorf("virtualMachineScaleSets.list: %s", azReadWhy(st, resp, nil))
	}
	var page struct {
		Value []struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"value"`
	}
	if json.Unmarshal(resp, &page) != nil {
		return nil, nil, &armReadError{Op: "virtualMachineScaleSets.list", Cause: "body", Status: st}
	}
	var out []provider.Discovered
	var diags []string
	for _, item := range page.Value {
		if item.Name == "" || (region != "" && item.Location != region) {
			continue
		}
		rg := resourceGroupOfID(item.ID)
		if rg == "" {
			diags = append(diags, item.Name+": resource group not readable from the resource id")
			continue
		}
		pid := azureVMSSProviderID(d.Subscription, rg, item.Name)
		obs, odiags, oerr := d.observeAzureVMSS("", pid)
		if oerr != nil {
			diags = append(diags, item.Name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, item.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.compute.autoscaling",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
