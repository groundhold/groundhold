// Azure VNet network shell (D99): the bearer-signed, ARM-JSON half of the
// network.private driver. Constitutive composite (one binding): the NSG is PUT
// first (when egress is restricted), then the VNet with its inline subnet
// referencing the NSG. ARM PUTs are async — the shell polls provisioningState to
// Succeeded (still-provisioning at timeout is unknown-with-pid, Failed is failed).
// Ownership is ARM tags; delete is reverse (VNet then NSG).
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func vnetProviderID(sub, rg, name string) string {
	return "vnet:" + sub + ":" + rg + ":" + name
}

func splitVNetProviderID(providerID string) (sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "vnet" {
		return "", "", "", fmt.Errorf("providerId %q is not vnet:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId subscription %q is invalid", parts[1])
	}
	if !rgOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId resource group %q is invalid", parts[2])
	}
	if !azNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) nsgID(sub, rg, nsgName string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/networkSecurityGroups/%s",
		sub, rg, nsgName)
}

func (d *Driver) natGatewayID(sub, rg, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/natGateways/%s",
		sub, rg, name)
}

func (d *Driver) publicIPID(sub, rg, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/publicIPAddresses/%s",
		sub, rg, name)
}

func (d *Driver) tags(capability, environment string) map[string]any {
	return map[string]any{
		"groundhold-capability":  sanitizeAzTag(capability),
		"groundhold-environment": sanitizeAzTag(environment),
	}
}

// createVNet: NSG (if egress restricted) -> VNet with inline subnet, one binding.
func (d *Driver) createVNet(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildVNet(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure vnet requires implementation.resource_group (a valid Azure resource group)"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := vnetProviderID(d.Subscription, rg, plan.Name)
	nsgName := plan.Name + "-nsg"

	// ---- 1. constitutive NSG (only when egress is restricted) ----
	var nsgRef map[string]any
	if plan.EgressRestricted {
		nsgURL, e := d.armURL(rg, "Microsoft.Network/networkSecurityGroups/"+nsgName, networkAPIVersion)
		if e != nil {
			return provider.CreateResult{Status: "failed", Reason: e.Error()}
		}
		body, _ := json.Marshal(map[string]any{
			"location": plan.Region,
			"tags":     d.tags(capability, environment),
			"properties": map[string]any{"securityRules": []any{
				denyRule("AllowVnetOutbound", 4000, "Allow", "VirtualNetwork", "VirtualNetwork"),
				denyRule("DenyInternetOutbound", 4096, "Deny", "*", "Internet"),
			}},
		})
		if r := d.putAndPoll(nsgURL, body, pid, "nsg"); r != nil {
			return *r
		}
		nsgRef = map[string]any{"id": d.nsgID(d.Subscription, rg, nsgName)}
	}

	// ---- 1b. NAT road (egress.internet=nat): a public IP + a NAT Gateway, the
	// subnet then references the gateway. Public IP first (the gateway references
	// it), then the gateway (the subnet references it). These precede the VNet the
	// same way the NSG does; a failure carries the vnet pid so the deterministic-
	// named orphans are targetable by retire/reconcile (the NSG precedent, D29). ----
	var natRef map[string]any
	if plan.EgressInternet == "nat" {
		pipName := plan.Name + "-natip"
		pipURL, e := d.armURL(rg, "Microsoft.Network/publicIPAddresses/"+pipName, networkAPIVersion)
		if e != nil {
			return provider.CreateResult{ProviderID: pid, Status: "failed", Reason: e.Error()}
		}
		pipBody, _ := json.Marshal(map[string]any{
			"location":   plan.Region,
			"tags":       d.tags(capability, environment),
			"sku":        map[string]any{"name": "Standard"},
			"properties": map[string]any{"publicIPAllocationMethod": "Static", "publicIPAddressVersion": "IPv4"},
		})
		if r := d.putAndPoll(pipURL, pipBody, pid, "public-ip"); r != nil {
			return *r
		}
		natName := plan.Name + "-nat"
		natURL, e := d.armURL(rg, "Microsoft.Network/natGateways/"+natName, networkAPIVersion)
		if e != nil {
			return provider.CreateResult{ProviderID: pid, Status: "failed", Reason: e.Error()}
		}
		natBody, _ := json.Marshal(map[string]any{
			"location": plan.Region,
			"tags":     d.tags(capability, environment),
			"sku":      map[string]any{"name": "Standard"},
			"properties": map[string]any{
				"publicIpAddresses": []any{map[string]any{"id": d.publicIPID(d.Subscription, rg, pipName)}},
			},
		})
		if r := d.putAndPoll(natURL, natBody, pid, "nat-gateway"); r != nil {
			return *r
		}
		natRef = map[string]any{"id": d.natGatewayID(d.Subscription, rg, natName)}
	}

	// ---- 2. the VNet with its inline subnet ----
	vnetURL, e := d.armURL(rg, "Microsoft.Network/virtualNetworks/"+plan.Name, networkAPIVersion)
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "failed", Reason: e.Error()}
	}
	subnetProps := map[string]any{"addressPrefix": "10.0.0.0/24"}
	if plan.EgressRestricted {
		subnetProps["defaultOutboundAccess"] = false
		subnetProps["networkSecurityGroup"] = nsgRef
	}
	if natRef != nil {
		// the NAT Gateway is the explicit outbound road — disable the implicit
		// default-outbound path so egress rides the gateway, not the platform default.
		subnetProps["defaultOutboundAccess"] = false
		subnetProps["natGateway"] = natRef
	}
	if len(plan.ServiceEndpoints) > 0 {
		eps := make([]any, 0, len(plan.ServiceEndpoints))
		for _, s := range plan.ServiceEndpoints {
			eps = append(eps, map[string]any{"service": s})
		}
		subnetProps["serviceEndpoints"] = eps
	}
	vnetBody, _ := json.Marshal(map[string]any{
		"location": plan.Region,
		"tags":     d.tags(capability, environment),
		"properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}},
			"subnets":      []any{map[string]any{"name": "default", "properties": subnetProps}},
		},
	})
	if r := d.putAndPoll(vnetURL, vnetBody, pid, "vnet"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func denyRule(name string, priority int, access, src, dst string) map[string]any {
	return map[string]any{"name": name, "properties": map[string]any{
		"priority": priority, "direction": "Outbound", "access": access, "protocol": "*",
		"sourcePortRange": "*", "destinationPortRange": "*",
		"sourceAddressPrefix": src, "destinationAddressPrefix": dst,
	}}
}

// putAndPoll PUTs an ARM resource then polls provisioningState. nil = provisioned;
// non-nil = a terminal result WITH the pid (D29/D87 honesty).
// putAndPoll upserts and polls provisioningState against the generic PollTimeout —
// the right ceiling for the ~30 fast-provisioning ARM resources that call it.
func (d *Driver) putAndPoll(url string, body []byte, pid, what string) *provider.CreateResult {
	return d.putAndPollT(url, body, pid, what, d.PollTimeout)
}

// putAndPollT is putAndPoll with an explicit LRO ceiling (D265): a slow control-plane
// operation (an AKS upgrade runs 20-40 min) passes d.aksLROTimeout() so a HEALTHY
// slow op is not reported unknown before its true deadline (the D264 class).
func (d *Driver) putAndPollT(url string, body []byte, pid, what string, timeout time.Duration) *provider.CreateResult {
	// D254: never PUT over a foreign resource (an ARM upsert would overwrite it).
	if r := d.refuseForeignUpsert(url, body); r != nil {
		return r
	}
	st, resp, err := d.doARM("PUT", url, body)
	if err != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("%s PUT outcome unknown (may have landed): %v", what, err)}
	}
	if st >= 500 {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("%s PUT HTTP %d (server error — may have landed) — reconcile", what, st)}
	}
	if st < 200 || st >= 300 {
		// D237: a throttle (429), service-unavailable, or live 403 is unknown (the
		// PUT may have landed / a retry may land it) — keep the pid; only a clean
		// 4xx refusal fails.
		if r := provider.MutationResult(st, azErrCode(resp), nil, pid, what+" PUT"); r != nil {
			return r
		}
		return &provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("%s PUT HTTP %d: %s", what, st, mutDetailAz(resp))}
	}
	// poll provisioningState via GET
	deadline := d.Now().Add(timeout)
	for {
		state, rerr := d.provisioningState(url)
		if rerr == nil {
			switch state {
			case "Succeeded":
				return nil
			case "Failed", "Canceled":
				return &provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: fmt.Sprintf("%s entered provisioningState %s", what, state)}
			}
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("%s still provisioning at poll timeout — reconcile", what)}
		}
		time.Sleep(d.PollInterval)
	}
}

// provisioningState GETs a resource and returns its provisioningState. A garbled
// 200 names itself (never a confident state).
func (d *Driver) provisioningState(url string) (state string, err error) {
	var doc struct {
		Properties struct {
			ProvisioningState string `json:"provisioningState"`
		} `json:"properties"`
	}
	found, rerr := d.armGetURLInto("provisioningState.get", url, &doc)
	if rerr != nil {
		return "", rerr
	}
	if !found {
		return "", &armReadError{Op: "provisioningState.get", Cause: "http", Status: 404}
	}
	return doc.Properties.ProvisioningState, nil
}

type vnetDoc struct {
	Location   string            `json:"location"`
	Tags       map[string]string `json:"tags"`
	Properties struct {
		ProvisioningState string `json:"provisioningState"`
		Subnets           []struct {
			Properties struct {
				NetworkSecurityGroup *struct {
					ID string `json:"id"`
				} `json:"networkSecurityGroup"`
				NatGateway *struct {
					ID string `json:"id"`
				} `json:"natGateway"`
				ServiceEndpoints []struct {
					Service string `json:"service"`
				} `json:"serviceEndpoints"`
			} `json:"properties"`
		} `json:"subnets"`
	} `json:"properties"`
}

// getVNet returns the vnet doc and whether it exists. D295: a read that
// yielded nothing returns an error NAMING the cause (status + the provider's
// own code) instead of a bare "unreadable"; a 404 stays an authoritative
// absence (found=false, no error), so the four-valued semantics are untouched.
func (d *Driver) getVNet(rg, name string) (doc vnetDoc, found bool, err error) {
	found, err = d.armGetInto("virtualNetworks.get", rg,
		"Microsoft.Network/virtualNetworks/"+name, networkAPIVersion, &doc)
	return doc, found, err
}

func (d *Driver) observeVNet(capability, providerID string) ([]provider.Observation, []string, error) {
	sub, rg, name, err := splitVNetProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's %q", sub, d.Subscription)
	}
	doc, found, err := d.getVNet(rg, name)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		return nil, []string{"vnet not found — nothing to observe"}, nil
	}
	var obs []provider.Observation
	if doc.Location != "" {
		obs = append(obs, provider.Observation{Path: "location.region", Value: strings.ToLower(doc.Location), Derivation: "measured"})
	}
	obs = append(obs,
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		// a fresh VNet has no internet gateway — private ingress by construction.
		provider.Observation{Path: "ingress.public", Value: false, Derivation: "config-intent"},
	)
	// egress.restricted: measured from the presence of an NSG on the subnet (the
	// deny-outbound composite). A subnet with no NSG is not egress-restricted.
	restricted := false
	for _, s := range doc.Properties.Subnets {
		if s.Properties.NetworkSecurityGroup != nil && s.Properties.NetworkSecurityGroup.ID != "" {
			restricted = true
		}
	}
	obs = append(obs, provider.Observation{Path: "egress.restricted", Value: restricted, Derivation: "measured"})

	diags := []string{"flowLogs.enabled not observed: Azure flow logs live on a subscription-level Network Watcher, out of the capability's scope"}

	// egress.internet: the road is read from the subnet's NAT Gateway reference. A
	// subnet carrying a natGateway => "nat"; otherwise "none". "direct" (per-instance
	// public IPs) is not a VNet-layer property, so it is never emitted here — a diag
	// records that the direct road is not audited (symmetric with GCP/AWS).
	road := "none"
	for _, s := range doc.Properties.Subnets {
		if s.Properties.NatGateway != nil && s.Properties.NatGateway.ID != "" {
			road = "nat"
		}
	}
	obs = append(obs, provider.Observation{Path: "egress.internet", Value: road, Derivation: "measured"})
	if road == "none" {
		diags = append(diags, "egress.internet=none reflects no NAT Gateway on the subnet; "+
			"the direct road (per-instance public IPs) is not audited at the VNet layer")
	}

	// serviceAccess.private: the driver KNOWS the required canonical service-endpoint
	// set; observe gathers the subnet serviceEndpoints and emits true iff the observed
	// set is a SUPERSET of the required set (symmetric with the AWS endpoint-superset
	// check). A partial set is a MEASURED false with a diag naming the gap. Observe
	// cannot know an impl-declared bespoke set, so it audits against the canonical one.
	observed := map[string]bool{}
	for _, s := range doc.Properties.Subnets {
		for _, ep := range s.Properties.ServiceEndpoints {
			if ep.Service != "" {
				observed[ep.Service] = true
			}
		}
	}
	missing := missingServiceEndpoints(defaultVNetServiceEndpoints, observed)
	obs = append(obs, provider.Observation{Path: "serviceAccess.private", Value: len(missing) == 0, Derivation: "measured"})
	if len(missing) > 0 {
		diags = append(diags, "serviceAccess.private=false: missing subnet service endpoints for "+strings.Join(missing, ", "))
	}
	return obs, diags, nil
}

func (d *Driver) deleteVNet(capability, environment, providerID string) provider.CreateResult {
	sub, rg, name, err := splitVNetProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_ = sub
	doc, found, rerr := d.getVNet(rg, name)
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
			Reason: "vnet tags do not match — refusing to delete a resource that is not ours"}
	}
	// delete the VNet first (frees the subnet's references to the NSG + NAT Gateway),
	// then the constitutive children in reverse dependency order: NSG, then the NAT
	// Gateway (releasing its public IP), then the public IP itself. Each child is
	// best-effort — the workload (network) is retired, so a child that will not
	// delete is left standing rather than blocking, but surfaced. Children absent
	// (a vnet with no NSG / no NAT road) DELETE to 404 => idempotent success, so no
	// false "inconclusive".
	vnetURL, _ := d.armURL(rg, "Microsoft.Network/virtualNetworks/"+name, networkAPIVersion)
	if r := d.deleteAndConfirm(vnetURL, providerID, "vnet"); r != nil {
		return *r
	}
	children := []struct{ path, what string }{
		{"Microsoft.Network/networkSecurityGroups/" + name + "-nsg", "NSG"},
		{"Microsoft.Network/natGateways/" + name + "-nat", "NAT Gateway"},
		{"Microsoft.Network/publicIPAddresses/" + name + "-natip", "public IP"},
	}
	inconclusive := ""
	for _, c := range children {
		url, _ := d.armURL(rg, c.path, networkAPIVersion)
		if r := d.deleteAndConfirm(url, providerID, c.what); r != nil && r.Status != "succeeded" {
			inconclusive = c.what
		}
	}
	if inconclusive != "" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
			Reason: "vnet retired; " + inconclusive + " cleanup inconclusive — reconcile"}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

func (d *Driver) deleteAndConfirm(url, pid, what string) *provider.CreateResult {
	st, _, err := d.doARM("DELETE", url, nil)
	if err != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("%s delete outcome unknown: %v", what, err)}
	}
	if st == http.StatusNotFound {
		return &provider.CreateResult{ProviderID: pid, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("%s delete HTTP %d (server error) — reconcile", what, st)}
	}
	if st < 200 || st >= 300 {
		// D237: throttle (429) / live 403 -> unknown (keep the handle), never a
		// terminal failed (5xx handled above).
		if r := provider.MutationResult(st, "", nil, pid, what+" delete"); r != nil {
			return r
		}
		return &provider.CreateResult{ProviderID: pid, Status: "failed", Reason: fmt.Sprintf("%s delete HTTP %d", what, st)}
	}
	return &provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}
