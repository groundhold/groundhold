package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"groundhold/internal/provider"
)

// List enumerates existing gcp resources in the region as vocabulary
// capabilities — the gcp half of the D52 brownfield path (discover ->
// adopt). Strictly read-only. Each service is swept independently: a
// service that errors becomes a diagnostic, never a hard failure that
// hides another's resources.
func (d *Driver) List(region string) ([]provider.Discovered, []string, error) {
	var out []provider.Discovered
	var diags []string
	reg := d.serviceDiscoverers()
	for _, tok := range d.DiscoverableServices() { // sorted, deterministic
		found, ds, err := reg[tok](region)
		if err != nil {
			diags = append(diags, err.Error())
			continue
		}
		out = append(out, found...)
		diags = append(diags, ds...)
	}
	return out, diags, nil
}

// serviceDiscoverers maps each SERVICE token (the D76 dispatch key) to its
// read-only sweep. List iterates it; TestGCPDriverCertification asserts via
// provider.CertifyDiscoverability that every certified service is either a key
// here or a declared non-listable exemption — so no Observe ships undiscoverable
// (spec/drivers.md §2). Each sweep reuses its service's Observe reverse map.
func (d *Driver) serviceDiscoverers() map[string]func(string) ([]provider.Discovered, []string, error) {
	return map[string]func(string) ([]provider.Discovered, []string, error){
		// original discovery breadth
		"cloudsql": d.discoverCloudSQL, "gcs": d.discoverGCS, "firestore": d.discoverFirestore,
		"pubsub-topic": d.discoverPubSubTopics, "pubsub-queue": d.discoverPubSubQueues,
		"memorystore": d.discoverMemorystore, "cloudrun": d.discoverCloudRun, "vpc": d.discoverVPC,
		"serviceaccount": d.discoverServiceAccounts, "customrole": d.discoverCustomRoles,
		"iambinding": d.discoverIAMBindings, "secretmanager": d.discoverSecrets,
		"monitoring": d.discoverAlertPolicies, "uptime": d.discoverUptimeChecks,
		"gce": d.discoverGCEInstances, "artifactregistry": d.discoverArtifactRegistries, "loadbalancer": d.discoverLoadBalancers,
		// discoverability backfill
		"backupvault": d.discoverBackupVault, "bigquery": d.discoverBigQuery,
		"certmanager": d.discoverCertManager, "cloudarmor": d.discoverCloudArmor,
		"clouddns": d.discoverCloudDNS, "cloudfunctions": d.discoverCloudFunctions,
		"cloudfunctions-fn": d.discoverCloudFunctionFn, // capability.function.serverless

		"cloudkms": d.discoverCloudKMS, "cloudrunjobs": d.discoverCloudRunJobs,
		"cloudscheduler": d.discoverCloudScheduler, "dashboard": d.discoverDashboards,
		"filestore": d.discoverFilestore, "logmetric": d.discoverLogMetrics,
		"managedkafka": d.discoverManagedKafka, "vpngateway": d.discoverVPNGateways,
		// posture parity (D76): budget / log retention / audit / threat-detection / AI
		"billingbudget": d.discoverBillingBudget, "logbucket": d.discoverLogBuckets,
		"auditlogs": d.discoverAuditLogs, "scc": d.discoverSCC, "vertexai": d.discoverVertexAI,
		// cluster family (D76 parity)
		"gke": d.discoverGKE, "gke-addon": d.discoverGKEAddon,
		"gke-workloadidentity": d.discoverGKEWorkloadIdentity,
		"backupplan":           d.discoverBackupPlansGCP,
	}
}

// DiscoverableServices reports the tokens serviceDiscoverers covers (sorted), so
// the discoverability gate proves coverage rather than trusting it.
func (d *Driver) DiscoverableServices() []string {
	reg := d.serviceDiscoverers()
	out := make([]string, 0, len(reg))
	for tok := range reg {
		out = append(out, tok)
	}
	sort.Strings(out)
	return out
}

// NonListableServices names the certified services that are NOT standalone
// listable resources, with a categorical reason — the only sanctioned exemption
// from the discoverability gate.
func (d *Driver) NonListableServices() map[string]string {
	return map[string]string{
		"assetfeed":      "provisioned-feed", // the Cloud Asset feed groundhold PROVISIONS, not a resource it lists
		"clouddnsrecord": "sub-resource",     // an rrset, enumerated only under its parent managed zone
	}
}

// discoverGCS enumerates Cloud Storage buckets as capability.storage.object,
// reusing the same reverse map observe uses. Buckets are global with a
// location; region, when given, filters on that location.
func (d *Driver) discoverGCS(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.gcsBase()+"/b?project="+d.Project, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("buckets.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("buckets.list: HTTP %d", status)
	}
	var resp struct {
		Items []struct {
			Name     string `json:"name"`
			Location string `json:"location"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("buckets.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, b := range resp.Items {
		if b.Name == "" {
			continue
		}
		if region != "" && !strings.EqualFold(b.Location, region) {
			continue // another location — not this sweep
		}
		pid := gcsProviderID(d.Project, b.Name)
		obs, odiags, err := d.observeGCS("", pid)
		if err != nil {
			diags = append(diags, b.Name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, b.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.storage.object",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// leafName returns the final path segment of a GCP resource name
// ("projects/p/topics/alerts" -> "alerts").
func leafName(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// discoverPubSubTopics enumerates Pub/Sub topics as
// capability.messaging.topic. Topics are global, so region does not filter.
func (d *Driver) discoverPubSubTopics(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.pubsubBase()+"/projects/"+d.Project+"/topics", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("topics.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("topics.list: HTTP %d", status)
	}
	var resp struct {
		Topics []struct {
			Name string `json:"name"`
		} `json:"topics"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("topics.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, t := range resp.Topics {
		name := leafName(t.Name)
		if name == "" {
			continue
		}
		pid := pubsubProviderID(d.Project, name)
		obs, odiags, err := d.observePubSub("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.messaging.topic",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverPubSubQueues enumerates Pub/Sub subscriptions as
// capability.messaging.queue. Subscriptions are global, so region does not
// filter.
func (d *Driver) discoverPubSubQueues(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.pubsubBase()+"/projects/"+d.Project+"/subscriptions", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("subscriptions.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("subscriptions.list: HTTP %d", status)
	}
	var resp struct {
		Subscriptions []struct {
			Name string `json:"name"`
		} `json:"subscriptions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("subscriptions.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, s := range resp.Subscriptions {
		name := leafName(s.Name)
		if name == "" {
			continue
		}
		pid := pubsubProviderID(d.Project, name)
		obs, odiags, err := d.observePubSubQueue("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.messaging.queue",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverMemorystore enumerates Redis instances as capability.cache.keyvalue.
// The list spans all locations (locations/-); region, when given, filters on
// the instance's own location, parsed from its resource name.
func (d *Driver) discoverMemorystore(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.memorystoreBase()+"/projects/"+d.Project+"/locations/-/instances", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("instances.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("instances.list: HTTP %d", status)
	}
	var resp struct {
		Instances []struct {
			Name string `json:"name"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("instances.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, inst := range resp.Instances {
		loc, name := redisLocationName(inst.Name)
		if name == "" || loc == "" {
			continue
		}
		if region != "" && loc != region {
			continue // another location — not this sweep
		}
		pid := gredisProviderID(d.Project, loc, name)
		obs, odiags, err := d.observeMemorystore("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.cache.keyvalue",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// redisLocationName pulls location and instance name out of a Memorystore
// resource name (projects/p/locations/<loc>/instances/<name>).
func redisLocationName(resourceName string) (loc, name string) {
	parts := strings.Split(resourceName, "/")
	for i := 0; i+1 < len(parts); i++ {
		switch parts[i] {
		case "locations":
			loc = parts[i+1]
		case "instances":
			name = parts[i+1]
		}
	}
	return loc, name
}

// discoverFirestore enumerates Firestore databases as
// capability.database.nosql. Databases are project-global with a location;
// region, when given, filters on that location (a multi-region database's
// locationId, e.g. "eur3", simply will not match a single-region filter).
func (d *Driver) discoverFirestore(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.firestoreBase()+"/projects/"+d.Project+"/databases", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("databases.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("databases.list: HTTP %d", status)
	}
	var resp struct {
		Databases []struct {
			Name       string `json:"name"`
			LocationID string `json:"locationId"`
		} `json:"databases"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("databases.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, db := range resp.Databases {
		id := leafName(db.Name)
		if id == "" {
			continue
		}
		if region != "" && db.LocationID != region {
			continue
		}
		pid := firestoreProviderID(d.Project, id)
		obs, odiags, err := d.observeFirestore("", pid)
		if err != nil {
			diags = append(diags, id+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, id+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.database.nosql",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// runLocationName pulls location and service name out of a Cloud Run v2
// resource name (projects/p/locations/<loc>/services/<name>).
func runLocationName(resourceName string) (loc, name string, ok bool) {
	li := strings.Index(resourceName, "/locations/")
	si := strings.Index(resourceName, "/services/")
	if li < 0 || si < 0 || si < li {
		return "", "", false
	}
	loc = resourceName[li+len("/locations/") : si]
	name = resourceName[si+len("/services/"):]
	if loc == "" || name == "" {
		return "", "", false
	}
	return loc, name, true
}

// discoverCloudRun enumerates Cloud Run services as
// capability.workload.container, reusing observeCloudRun's reverse map. The
// aggregated list (locations/-) spans every region; region, when given,
// filters on the service's own location parsed from its resource name.
func (d *Driver) discoverCloudRun(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.runBase()+"/projects/"+d.Project+"/locations/-/services", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("services.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("services.list: HTTP %d", status)
	}
	var resp struct {
		Services []struct {
			Name string `json:"name"`
		} `json:"services"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("services.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, s := range resp.Services {
		loc, name, ok := runLocationName(s.Name)
		if !ok {
			continue
		}
		if region != "" && loc != region {
			continue // another location — not this sweep
		}
		pid := runProviderID(d.Project, loc, name)
		obs, odiags, err := d.observeCloudRun("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.workload.container",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverVPC enumerates VPC networks as capability.network.private. A network
// is global but a private-network binding is per (network, region) — the
// observe reverse map needs the regional scope to find the subnet — so one
// Discovered is emitted per network and each distinct subnet region. region,
// when given, filters on that subnet region. A network with no subnetworks in
// scope is not surfaced (nothing regional to bind to).
func (d *Driver) discoverVPC(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/global/networks", d.computeBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("networks.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("networks.list: HTTP %d", status)
	}
	var resp struct {
		Items []struct {
			Name        string   `json:"name"`
			Subnetworks []string `json:"subnetworks"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("networks.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, n := range resp.Items {
		if n.Name == "" {
			continue
		}
		seen := map[string]bool{}
		for _, link := range n.Subnetworks {
			r, _, ok := regionNameFromSubnetLink(link)
			if !ok || seen[r] {
				continue
			}
			seen[r] = true
			if region != "" && r != region {
				continue // another region — not this sweep
			}
			pid := vpcProviderID(d.Project, r, n.Name)
			obs, odiags, err := d.observeVPC("", pid)
			if err != nil {
				diags = append(diags, n.Name+": "+err.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, n.Name+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.network.private",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}

// discoverServiceAccounts enumerates service accounts as
// capability.identity.serviceaccount, reusing observeGServiceAccount. Service
// accounts are project-global (no region); region does not filter. Only
// accounts in the pinned project's own namespace are surfaced — a default or
// imported account under a foreign domain would not reconstruct to a readable
// providerId, so it is skipped rather than misreported.
func (d *Driver) discoverServiceAccounts(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/serviceAccounts", d.iamBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("serviceAccounts.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("serviceAccounts.list: HTTP %d", status)
	}
	var resp struct {
		Accounts []struct {
			Email string `json:"email"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("serviceAccounts.list", status)
	}
	suffix := "@" + d.Project + ".iam.gserviceaccount.com"
	var out []provider.Discovered
	var diags []string
	for _, a := range resp.Accounts {
		if !strings.HasSuffix(a.Email, suffix) {
			continue // foreign / default-domain account — not addressable by our providerId
		}
		accountID := strings.TrimSuffix(a.Email, suffix)
		if accountID == "" {
			continue
		}
		pid := gsaProviderID(d.Project, accountID)
		obs, odiags, err := d.observeGServiceAccount("", pid)
		if err != nil {
			diags = append(diags, accountID+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, accountID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.identity.serviceaccount",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverCustomRoles enumerates project-level IAM custom roles as
// capability.authorization.role, reusing observeCustomRole (which re-reads the
// full role for its permission set — the list view omits it). Custom roles are
// project-global; region does not filter.
func (d *Driver) discoverCustomRoles(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/roles", d.iamBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("roles.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("roles.list: HTTP %d", status)
	}
	var resp struct {
		Roles []struct {
			Name string `json:"name"`
		} `json:"roles"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("roles.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, r := range resp.Roles {
		roleID := leafName(r.Name)
		if roleID == "" {
			continue
		}
		pid := gcRoleProviderID(d.Project, roleID)
		obs, odiags, err := d.observeCustomRole("", pid)
		if err != nil {
			diags = append(diags, roleID+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, roleID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.authorization.role",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverIAMBindings enumerates the project IAM policy's {role, member} pairs
// as capability.authorization.grant, reusing observeIAMBinding. Grants are
// project-scoped; region does not filter. A member whose form does not parse
// (allUsers, deleted:, a domain) becomes a per-item diagnostic, never a
// fabricated grant.
func (d *Driver) discoverIAMBindings(region string) ([]provider.Discovered, []string, error) {
	pol, perr := d.crmGetProjectPolicy(d.Project)
	if perr != nil {
		return nil, nil, perr
	}
	var out []provider.Discovered
	var diags []string
	for _, b := range pol.Bindings {
		for _, m := range b.Members {
			pid := iamBindingProviderID(d.Project, b.Role, m)
			obs, odiags, err := d.observeIAMBinding("", pid)
			if err != nil {
				diags = append(diags, b.Role+"/"+m+": "+err.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, b.Role+"/"+m+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.authorization.grant",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}

// discoverSecrets enumerates Secret Manager secrets as capability.secret,
// reusing observeSecret. D53 ABSOLUTE: this is existence + metadata ONLY —
// observeSecret reads secrets.get (labels/replication) and the IAM policy, and
// NEVER accessSecretVersion; a secret's VALUE is never read. Secrets are
// project-global; region does not filter (residency, when single-region, is
// reported by the observe map itself).
func (d *Driver) discoverSecrets(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/secrets", d.secretBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("secrets.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("secrets.list: HTTP %d", status)
	}
	var resp struct {
		Secrets []struct {
			Name string `json:"name"`
		} `json:"secrets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("secrets.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, s := range resp.Secrets {
		name := leafName(s.Name)
		if name == "" {
			continue
		}
		pid := gsecretProviderID(d.Project, name)
		obs, odiags, err := d.observeSecret("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.secret",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverAlertPolicies enumerates Cloud Monitoring alert policies as
// capability.monitoring.alert, reusing observeAlertPolicy. Alert policies are
// project-global; region does not filter.
func (d *Driver) discoverAlertPolicies(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/alertPolicies", d.monitoringBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("alertPolicies.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("alertPolicies.list: HTTP %d", status)
	}
	var resp struct {
		AlertPolicies []struct {
			Name string `json:"name"`
		} `json:"alertPolicies"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("alertPolicies.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, p := range resp.AlertPolicies {
		id := leafName(p.Name)
		if id == "" {
			continue
		}
		pid := galertProviderID(d.Project, id)
		obs, odiags, err := d.observeAlertPolicy("", pid)
		if err != nil {
			diags = append(diags, id+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, id+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.monitoring.alert",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverUptimeChecks enumerates Cloud Monitoring uptime check configs as
// capability.monitoring.uptime, reusing observeUptimeCheck. Uptime configs are
// project-global; region does not filter.
func (d *Driver) discoverUptimeChecks(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/uptimeCheckConfigs", d.uptimeBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("uptimeCheckConfigs.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("uptimeCheckConfigs.list: HTTP %d", status)
	}
	var resp struct {
		UptimeCheckConfigs []struct {
			Name string `json:"name"`
		} `json:"uptimeCheckConfigs"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("uptimeCheckConfigs.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, c := range resp.UptimeCheckConfigs {
		id := leafName(c.Name)
		if id == "" {
			continue
		}
		pid := guptimeProviderID(d.Project, id)
		obs, odiags, err := d.observeUptimeCheck("", pid)
		if err != nil {
			diags = append(diags, id+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, id+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.monitoring.uptime",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// arLocations lists the Artifact Registry locations available to the project.
// repositories.list requires a concrete location (no `-` wildcard), so a
// full-estate sweep enumerates locations first.
func (d *Driver) arLocations() ([]string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/locations", d.arBase(), d.Project), nil)
	if err != nil {
		return nil, fmt.Errorf("locations.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("locations.list: HTTP %d", status)
	}
	var resp struct {
		Locations []struct {
			LocationID string `json:"locationId"`
		} `json:"locations"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, readBody("locations.list", status)
	}
	var out []string
	for _, l := range resp.Locations {
		if l.LocationID != "" {
			out = append(out, l.LocationID)
		}
	}
	return out, nil
}

// discoverArtifactRegistries enumerates Artifact Registry repositories as
// capability.registry.image, reusing observeARRepo. A given region is swept
// directly; an empty region enumerates the project's locations first (AR's
// list has no cross-location wildcard). A per-location list failure is a
// diagnostic — it never hides the repositories another location did return.
func (d *Driver) discoverArtifactRegistries(region string) ([]provider.Discovered, []string, error) {
	var locations []string
	var diags []string
	if region != "" {
		locations = []string{region}
	} else {
		locs, err := d.arLocations()
		if err != nil {
			return nil, nil, err
		}
		locations = locs
	}
	var out []provider.Discovered
	for _, loc := range locations {
		status, body, err := d.call("GET", fmt.Sprintf(
			"%s/projects/%s/locations/%s/repositories", d.arBase(), d.Project, loc), nil)
		if err != nil {
			diags = append(diags, "repositories.list "+loc+": "+err.Error())
			continue
		}
		if status != http.StatusOK {
			diags = append(diags, fmt.Sprintf("repositories.list %s: HTTP %d", loc, status))
			continue
		}
		var resp struct {
			Repositories []struct {
				Name string `json:"name"`
			} `json:"repositories"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			diags = append(diags, loc+": "+readBody("repositories.list", status).Error())
			continue
		}
		for _, r := range resp.Repositories {
			repoID := leafName(r.Name)
			if repoID == "" {
				continue
			}
			pid := garProviderID(d.Project, loc, repoID)
			obs, odiags, err := d.observeARRepo("", pid)
			if err != nil {
				diags = append(diags, repoID+": "+err.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, repoID+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.registry.image",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}
