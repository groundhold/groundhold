// Azure load balancer network shell (read-only slice): the bearer-signed, ARM-JSON
// half of the capability.network.loadbalancer driver. This slice is READ-ONLY —
// Observe (an ARM GET reverse-mapped) and the discovery sweep are real; Create /
// Update / Delete refuse-closed HONESTLY, because provisioning a load balancer
// (frontend IP + backend pool + probes/listeners, and for HTTPS a TLS certificate)
// is a later slice. The driver never created these resources, so it never claims it
// can mutate them.
//
// Two ARM types, ONE capability. The providerId kind prefix discriminates the layer
// so a single Observe dispatch routes to the right GET + reverse map:
//   - loadbalancer:<sub>:<rg>:<name>  → Microsoft.Network/loadBalancers   (L4)
//   - appgateway:<sub>:<rg>:<name>    → Microsoft.Network/applicationGateways (L7)
//
// Both types live on Microsoft.Network, so they share networkAPIVersion (2023-11-01)
// — the same pinned version the VNet driver uses.
package azure

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// agwSelfID is the Application Gateway's own ARM resource id — the App Gateway's
// internal sub-resources (listener -> frontend/port/cert/pool/settings) reference
// one another by FULL resource id, which embeds the gateway's own id.
func agwSelfID(sub, rg, name string) string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Network/applicationGateways/%s",
		sub, rg, name)
}

// providerId kind prefixes — the layer discriminator (the Service Bus precedent:
// one service token, kind-tagged providerIds).
func lbProviderID(sub, rg, name string) string  { return "loadbalancer:" + sub + ":" + rg + ":" + name }
func agwProviderID(sub, rg, name string) string { return "appgateway:" + sub + ":" + rg + ":" + name }

func splitLBProviderID(providerID string) (kind, sub, rg, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || (parts[0] != "loadbalancer" && parts[0] != "appgateway") {
		return "", "", "", "", fmt.Errorf("providerId %q is not loadbalancer|appgateway:sub:rg:name", providerID)
	}
	if !subOK.MatchString(parts[1]) || !rgOK.MatchString(parts[2]) || !azNameOK.MatchString(parts[3]) {
		return "", "", "", "", fmt.Errorf("providerId %q has an invalid component", providerID)
	}
	return parts[0], parts[1], parts[2], parts[3], nil
}

// observeLoadBalancer routes on the providerId kind to the L4 or L7 GET, then the
// matching pure reverse map. A subscription mismatch is refused before any read.
func (d *Driver) observeLoadBalancer(capability, providerID string) ([]provider.Observation, []string, error) {
	kind, sub, rg, name, err := splitLBProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if sub != d.Subscription && d.Subscription != "" {
		return nil, nil, fmt.Errorf("providerId subscription %q is not the driver's %q", sub, d.Subscription)
	}
	switch kind {
	case "loadbalancer":
		return d.observeL4LoadBalancer(rg, name)
	case "appgateway":
		return d.observeAppGateway(rg, name)
	default:
		return nil, nil, fmt.Errorf("providerId kind %q is not a load balancer type", kind)
	}
}

// observeL4LoadBalancer GETs a Microsoft.Network/loadBalancers resource and reverse-
// maps it. Exposure is measured from the frontend; inTransit is false by construction.
func (d *Driver) observeL4LoadBalancer(rg, name string) ([]provider.Observation, []string, error) {
	url, err := d.armURL(rg, "Microsoft.Network/loadBalancers/"+name, networkAPIVersion)
	if err != nil {
		return nil, nil, err
	}
	st, resp, err := d.doARM("GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("loadBalancers.get: %v", err)
	}
	if st == http.StatusNotFound {
		return []provider.Observation{
			// F-LC3 (D802): a BOUND resource the API authoritatively 404s is GONE. An
			// empty return leaves the last good observations standing as the freshest
			// word, so posture reads managed-ok and audit stays satisfied about a
			// resource that does not exist (D513/D518, fixed here last).
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"load balancer not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("loadBalancers.get: HTTP %d", st)
	}
	var doc lbDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, armBody("loadBalancers.get", st)
	}
	return reverseMapLoadBalancer(doc),
		[]string{"encryption.inTransit observed false: an L4 load balancer forwards packets and does not terminate TLS — HTTPS termination lives on an L7 Application Gateway"},
		nil
}

// observeAppGateway GETs a Microsoft.Network/applicationGateways resource and
// reverse-maps it — inTransit is MEASURED from an HTTPS listener.
func (d *Driver) observeAppGateway(rg, name string) ([]provider.Observation, []string, error) {
	url, err := d.armURL(rg, "Microsoft.Network/applicationGateways/"+name, networkAPIVersion)
	if err != nil {
		return nil, nil, err
	}
	st, resp, err := d.doARM("GET", url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("applicationGateways.get: %v", err)
	}
	if st == http.StatusNotFound {
		return []provider.Observation{
			// F-LC3 (D802): a BOUND resource the API authoritatively 404s is GONE. An
			// empty return leaves the last good observations standing as the freshest
			// word, so posture reads managed-ok and audit stays satisfied about a
			// resource that does not exist (D513/D518, fixed here last).
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"application gateway not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("applicationGateways.get: HTTP %d", st)
	}
	var doc agwDoc
	if json.Unmarshal(resp, &doc) != nil {
		return nil, nil, &armReadError{Op: "applicationGateways.get", Cause: "body", Status: st}
	}
	return reverseMapAppGateway(doc), nil, nil
}

// discoverLoadBalancers sweeps BOTH the L4 loadBalancers and the L7
// applicationGateways as capability.network.loadbalancer, reusing discoverRegional
// and each type's kind-tagged providerId. An error in one sub-sweep is a diagnostic,
// never a failure that hides the other's resources (four-valued discipline).
func (d *Driver) discoverLoadBalancers(region string) ([]provider.Discovered, []string, error) {
	kinds := []struct {
		path, label string
		pid         func(sub, rg, name string) string
	}{
		{"Microsoft.Network/loadBalancers", "loadBalancers", lbProviderID},
		{"Microsoft.Network/applicationGateways", "applicationGateways", agwProviderID},
	}
	labels := make([]string, len(kinds))
	byLabel := map[string]int{}
	for i, k := range kinds {
		labels[i], byLabel[k.label] = k.label, i
	}
	// D642: one of the two ARM kinds failing is a diagnostic — the other's load
	// balancers are still real. BOTH failing means the sweep read nothing, and this
	// loop used to hand that back as "no load balancers" with a nil error, which
	// List then counted as a successful service sweep.
	return provider.SweepAll(labels, func(label string) ([]provider.Discovered, []string, error) {
		k := kinds[byLabel[label]]
		return d.discoverRegional(k.path, networkAPIVersion, region,
			"capability.network.loadbalancer", k.label, k.pid, d.observeLoadBalancer)
	}, d.trunc)
}

// createLoadBalancer provisions the HONEST composite — an L7 Application Gateway
// (Microsoft.Network/applicationGateways) whose single ARM PUT internally carries
// frontend IP config, frontend port, http listener, backend address pool, backend
// http settings and request routing rule. This is the Azure advantage: one PUT
// with a rich body fulfils BOTH governed attributes (a public frontend for
// publicExposure, an Https listener + SSL cert REFERENCE for inTransit) — no
// multi-resource ordering. Ownership is an ARM tag; the providerId is emitted
// BEFORE the PUT so a partial/ambiguous outcome is `unknown` WITH the id.
func (d *Driver) createLoadBalancer(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAppGateway(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rg, _ := impl["resource_group"].(string)
	if !rgOK.MatchString(rg) {
		return provider.CreateResult{Status: "failed",
			Reason: "azure application gateway requires implementation.resource_group"}
	}
	if !subOK.MatchString(d.Subscription) {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("azure subscription %q is not a valid GUID", d.Subscription)}
	}
	pid := agwProviderID(d.Subscription, rg, plan.Name)

	url, e := d.armURL(rg, "Microsoft.Network/applicationGateways/"+plan.Name, networkAPIVersion)
	if e != nil {
		return provider.CreateResult{Status: "failed", Reason: e.Error()}
	}
	body := d.appGatewayBody(plan, rg, capability, environment)
	// putAndPoll is four-valued: nil = Succeeded; a returned result is failed
	// (4xx), or unknown WITH the pid (transport error / 5xx / poll timeout) — an
	// ambiguous create is NEVER a silent success (D29/D87).
	if r := d.putAndPoll(url, body, pid, "application gateway"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// appGatewayBody assembles the full applicationGateways ARM body from
// attributes+operands. The listener is Https (with an SSL cert whose value is a
// Key Vault secret REFERENCE — never cert bytes) iff inTransit; the frontend is
// public (an existing public IP) iff publicExposure. Sub-resources reference one
// another by full resource id embedding the gateway's own id.
func (d *Driver) appGatewayBody(plan AppGatewayPlan, rg, capability, environment string) []byte {
	self := agwSelfID(d.Subscription, rg, plan.Name)
	const (
		feName      = "appGwFrontendIp"
		fePortName  = "appGwFrontendPort"
		certName    = "appGwSslCert"
		poolName    = "appGwBackendPool"
		settingName = "appGwBackendHttpSettings"
		listenName  = "appGwHttpListener"
		ruleName    = "appGwRoutingRule"
		ipCfgName   = "appGatewayIpConfig"
	)

	// frontend IP config: a public IP (public) or a private IP in the subnet.
	feProps := map[string]any{}
	if plan.Public {
		feProps["publicIPAddress"] = map[string]any{"id": plan.PublicIP}
	} else {
		feProps["subnet"] = map[string]any{"id": plan.SubnetID}
		feProps["privateIPAllocationMethod"] = "Dynamic"
	}

	// backend address pool targets (fqdn / ipAddress).
	var backendAddrs []any
	for _, f := range plan.BackendFQDNs {
		backendAddrs = append(backendAddrs, map[string]any{"fqdn": f})
	}
	for _, ip := range plan.BackendIPs {
		backendAddrs = append(backendAddrs, map[string]any{"ipAddress": ip})
	}

	// the http listener — Https + SSL cert iff inTransit, else Http.
	protocol := "Http"
	listenerProps := map[string]any{
		"frontendIPConfiguration": map[string]any{"id": self + "/frontendIPConfigurations/" + feName},
		"frontendPort":            map[string]any{"id": self + "/frontendPorts/" + fePortName},
	}
	props := map[string]any{
		"sku": map[string]any{"name": plan.SKU, "tier": plan.SKU, "capacity": 2},
		"gatewayIPConfigurations": []any{map[string]any{
			"name": ipCfgName, "properties": map[string]any{"subnet": map[string]any{"id": plan.SubnetID}}}},
		"frontendIPConfigurations": []any{map[string]any{"name": feName, "properties": feProps}},
		"frontendPorts": []any{map[string]any{
			"name": fePortName, "properties": map[string]any{"port": plan.Port}}},
		"backendAddressPools": []any{map[string]any{
			"name": poolName, "properties": map[string]any{"backendAddresses": backendAddrs}}},
		"backendHttpSettingsCollection": []any{map[string]any{
			"name": settingName, "properties": map[string]any{
				"port": 80, "protocol": "Http", "cookieBasedAffinity": "Disabled", "requestTimeout": 20}}},
	}
	if plan.InTransit {
		protocol = "Https"
		// the SSL certificate is a Key Vault secret REFERENCE — never cert bytes.
		props["sslCertificates"] = []any{map[string]any{
			"name": certName, "properties": map[string]any{"keyVaultSecretId": plan.CertRef}}}
		listenerProps["sslCertificate"] = map[string]any{"id": self + "/sslCertificates/" + certName}
	}
	listenerProps["protocol"] = protocol
	props["httpListeners"] = []any{map[string]any{"name": listenName, "properties": listenerProps}}
	props["requestRoutingRules"] = []any{map[string]any{
		"name": ruleName, "properties": map[string]any{
			"ruleType": "Basic", "priority": 100,
			"httpListener":        map[string]any{"id": self + "/httpListeners/" + listenName},
			"backendAddressPool":  map[string]any{"id": self + "/backendAddressPools/" + poolName},
			"backendHttpSettings": map[string]any{"id": self + "/backendHttpSettingsCollection/" + settingName},
		}}}

	body, _ := json.Marshal(map[string]any{
		"location":   plan.Region,
		"tags":       d.tags(capability, environment),
		"properties": props,
	})
	return body
}

// deleteLoadBalancer is ownership-guarded: a pre-read confirms the gateway carries
// groundhold's tags before ARM DELETE. A foreign gateway is REFUSED; an unreadable
// pre-read is unknown; a 404 is idempotent success. The read-only L4 loadBalancers
// path is not provisioned by this driver, so a loadbalancer-kind providerId here is
// refused (it never created that resource).
func (d *Driver) deleteLoadBalancer(capability, environment, providerID string) provider.CreateResult {
	kind, sub, rg, name, err := splitLBProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if sub != d.Subscription && d.Subscription != "" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("providerId subscription %q is not the driver's %q", sub, d.Subscription)}
	}
	if kind != "appgateway" {
		return provider.CreateResult{ProviderID: providerID, Status: "failed",
			Reason: "azure loadbalancer provisions the L7 Application Gateway; the L4 loadBalancers path is " +
				"observe-only — this driver never created a loadBalancers resource, so it refuses to delete it"}
	}
	url, e := d.armURL(rg, "Microsoft.Network/applicationGateways/"+name, networkAPIVersion)
	if e != nil {
		return provider.CreateResult{Status: "failed", Reason: e.Error()}
	}
	st, resp, gerr := d.doARM("GET", url, nil)
	if gerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + azReadWhy(st, resp, gerr)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st != http.StatusOK {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read HTTP %d — reconcile", st)}
	}
	var doc agwDoc
	if json.Unmarshal(resp, &doc) != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read answered HTTP 200 with an unparseable body — reconcile"}
	}
	if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) ||
		doc.Tags["groundhold-environment"] != sanitizeAzTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "application gateway tags do not match — refusing to delete a resource that is not ours"}
	}
	if r := d.deleteAndConfirm(url, providerID, "application gateway"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// classifyLoadBalancerChange (D46): the semantic change class per capability
// attribute path + the operand pseudo-paths the task pins. sku and subnet are
// fixed at gateway creation -> a change is a REPLACEMENT (immutable); the backend
// pool is mutable in place; the frontend exposure and region are immutable.
func classifyLoadBalancerChange(path string) (string, string) {
	switch path {
	case "sku", "subnetId", "subnet_id", "location.region":
		return "immutable", "an Application Gateway's sku, subnet and region are fixed at creation — a change is a replacement"
	case "backendFqdns", "backendIps", "backend", "backendAddressPool":
		return "mutable", "the backend address pool is patchable in place"
	case "network.publicExposure":
		return "immutable", "the frontend IP configuration (public vs private) is fixed at creation — a change is a replacement"
	case "encryption.inTransit":
		return "caveated", "toggling TLS termination adds/removes the Https listener and its SSL certificate REFERENCE — an in-place re-PUT that requires the cert operand"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Application Gateway in-place mapping for " + path
	}
}
