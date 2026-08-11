// EKS substrate driver (slice 1, D147): the READ-ONLY half of
// capability.cluster.kubernetes for AWS — the managed cluster itself, distinct
// from the in-cluster governance the k8s driver handles. Slice 1 OBSERVES an
// adopted cluster (residency, version, API-server exposure, secrets encryption)
// so groundhold can witness + audit + adopt an EKS cluster stood up by eksctl/TF;
// provisioning the composite (cluster + node groups + IAM + OIDC) is slice 2, so
// the mutating methods refuse-closed honestly ("not wired yet") via the driver's
// default. EKS speaks REST-JSON at eks.<region>.amazonaws.com; SigV4 service "eks".
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

// eksNameOK bounds a cluster name (AWS: alphanumeric + hyphen/underscore, <=100).
var eksNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)

// eksProviderID is the pinned identity: eks:<region>:<clusterName>.
func eksProviderID(region, name string) string { return "eks:" + region + ":" + name }

// eksIAMPropagationWindow bounds the retry of a role-visibility 400 right
// after the role's same-plan create (D281). IAM is eventually consistent —
// AWS documents that a freshly created role can take seconds to become
// assumable by a service — so the dependent create retries briefly; a role
// that never appears fails with AWS's own message, never an endless loop.
const eksIAMPropagationWindow = 90 * time.Second

// eksRoleNotYetVisible recognizes the CreateCluster/CreateNodegroup 400 class
// for a not-yet-propagated role. Deliberately narrow: only the role-assumption
// wording retries; every other 400 stays a terminal refusal.
func eksRoleNotYetVisible(body []byte) bool {
	msg := strings.ToLower(eksErr(body))
	return strings.Contains(msg, "could not be assumed") ||
		(strings.Contains(msg, "role") && strings.Contains(msg, "does not exist"))
}

func splitEKSProviderID(providerID string) (region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "eks" {
		return "", "", fmt.Errorf("providerId %q is not eks:region:name", providerID)
	}
	region, name = parts[1], parts[2]
	if !regionOK.MatchString(region) {
		return "", "", fmt.Errorf("providerId region %q is invalid", region)
	}
	if !eksNameOK.MatchString(name) {
		return "", "", fmt.Errorf("providerId cluster name %q is invalid", name)
	}
	return region, name, nil
}

func (d *Driver) eksBase(region string) string {
	if d.EKSBaseURL != "" {
		return d.EKSBaseURL
	}
	return "https://eks." + region + ".amazonaws.com"
}

func (d *Driver) eksDo(method, region, path string, body []byte) (int, []byte, error) {
	return d.doSigned(method, d.eksBase(region)+path, "eks", region,
		map[string]string{"Content-Type": "application/json"}, body)
}

// eksReadAttempts bounds the transient-retry budget for a single-shot EKS read.
const eksReadAttempts = 4

// eksGet issues a signed EKS GET and RETRIES a bounded number of times on a TRANSIENT
// failure (transport error, 429 throttle, or 5xx) — the read layer's answer to D260.
// The whole EKS adopt/reconcile path is a chain of single-shot ownership reads
// (DescribeCluster, DescribeAddon, DescribePodIdentity, ListNodegroups); WITHOUT retry
// each one turns a momentary throttle into a fatal "unknown" that aborts the entire
// converge (Acme: an all-ACTIVE adopted cluster "DIED" because one sibling read
// hiccuped). A DEFINITIVE status returns at once: 2xx, 404 (a real absence), 403 or any
// other 4xx (a real permission/validation gap is NOT something to spin on). Only the
// transient class is retried, d.PollInterval apart (0 in tests). This never converts a
// genuine failure into a success — it only rides out the noise a live multi-resource
// adopt is guaranteed to hit.
func (d *Driver) eksGet(region, path string) (int, []byte, error) {
	var st int
	var body []byte
	var err error
	for attempt := 0; attempt < eksReadAttempts; attempt++ {
		st, body, err = d.eksDo("GET", region, path, nil)
		if err == nil && st != http.StatusTooManyRequests && st < 500 {
			return st, body, err // definitive (2xx / 4xx incl. 403 / 404)
		}
		if attempt < eksReadAttempts-1 {
			time.Sleep(d.PollInterval) // transient: transport error / 429 / 5xx
		}
	}
	return st, body, err
}

// eksCluster is the projection of DescribeCluster this driver governs — the
// machine-authoritative half. Instance types, AMIs, addon versions are noise.
// Status (CREATING/ACTIVE/FAILED/DELETING) drives the create poll; Tags drive the
// ownership gate for every mutation (slice 2).
type eksCluster struct {
	Status             string `json:"status"`
	Version            string `json:"version"`
	ResourcesVpcConfig struct {
		EndpointPublicAccess  bool `json:"endpointPublicAccess"`
		EndpointPrivateAccess bool `json:"endpointPrivateAccess"`
	} `json:"resourcesVpcConfig"`
	EncryptionConfig []struct {
		Resources []string `json:"resources"`
	} `json:"encryptionConfig"`
	Tags map[string]string `json:"tags"`
}

// describeEKSCluster resolves the cluster our name identifies. Returns
// (cluster, found, readable): a 404 is found=false (a vanished cluster, not an
// error); a transport error or any other non-200 is readable=false (unknown —
// never a fabricated absence).
// describeEKSCluster reads the resource. D296: a failed read names its cause; an
// authoritative absence stays found=false with NO error.
func (d *Driver) describeEKSCluster(region, name string) (eksCluster, bool, error) {
	const op = "DescribeCluster"
	st, resp, err := d.eksGet(region, "/clusters/"+name)
	if err != nil {
		return eksCluster{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return eksCluster{}, false, nil
	}
	if st != http.StatusOK {
		return eksCluster{}, false, readHTTP(op, st, eksErr(resp))
	}
	var out struct {
		Cluster eksCluster `json:"cluster"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return eksCluster{}, false, readBody(op, st)
	}
	return out.Cluster, true, nil
}

// observeEKS reverse-maps a cluster to capability.cluster.kubernetes. It emits
// only what one DescribeCluster proves; availability.class is a node-group
// attribute observed in slice 2 (a diagnostic names the honest omission).
func (d *Driver) observeEKS(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitEKSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	c, found, rerr := d.describeEKSCluster(region, name)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"cluster not found — bound resource is gone (will re-create)"}, nil
	}

	var exposure string
	switch pub, priv := c.ResourcesVpcConfig.EndpointPublicAccess, c.ResourcesVpcConfig.EndpointPrivateAccess; {
	case pub && priv:
		exposure = "mixed"
	case pub:
		exposure = "public"
	default:
		exposure = "private"
	}

	secretsEnc := false
	for _, ec := range c.EncryptionConfig {
		for _, r := range ec.Resources {
			if r == "secrets" {
				secretsEnc = true
			}
		}
	}

	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "cluster.version", Value: c.Version, Derivation: "measured"},
		{Path: "network.apiExposure", Value: exposure, Derivation: "measured"},
		{Path: "encryption.secrets", Value: secretsEnc, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	// availability.class is a NODE-GROUP attribute: it is the AZ spread of the
	// managed node group's subnets, not a control-plane field. Derive it ONLY when
	// resolvable cheaply (list node groups -> describe the first -> map its subnets
	// to AZs via EC2). If it cannot be resolved, emit NOTHING and keep an honest
	// diagnostic — never fabricate a class from the control plane alone.
	if class, ok := d.eksAvailabilityClass(region, name); ok {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: class, Derivation: "measured"})
	} else {
		diags = append(diags, "availability.class not derivable (no readable node group / subnet AZs) — omitted rather than fabricated")
	}
	return obs, diags, nil
}

// eksNodegroup is the node-group projection the driver reads: Status drives the
// create/delete polls; Subnets feed the availability.class AZ derivation.
type eksNodegroup struct {
	Status  string   `json:"status"`
	Subnets []string `json:"subnets"`
	Version string   `json:"version"` // Kubernetes version; follows the cluster (D248)
}

// describeNodegroup resolves one node group. (found, readable) mirror the cluster
// describe: a 404 is found=false+readable (gone), a transport/other error is
// readable=false (unknown, never a fabricated absence).
func (d *Driver) describeNodegroup(region, cluster, ng string) (eksNodegroup, bool, error) {
	const op = "DescribeNodegroup"
	st, resp, err := d.eksGet(region, "/clusters/"+cluster+"/node-groups/"+ng)
	if err != nil {
		return eksNodegroup{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return eksNodegroup{}, false, nil
	}
	if st != http.StatusOK {
		return eksNodegroup{}, false, readHTTP(op, st, eksErr(resp))
	}
	var out struct {
		Nodegroup eksNodegroup `json:"nodegroup"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return eksNodegroup{}, false, readBody(op, st)
	}
	return out.Nodegroup, true, nil
}

// listNodegroups lists a cluster's node-group names. readable=false on any
// transport/HTTP/parse failure (never a fabricated empty set).
func (d *Driver) listNodegroups(region, cluster string) ([]string, error) {
	const op = "ListNodegroups"
	st, resp, cerr := d.eksGet(region, "/clusters/"+cluster+"/node-groups")
	if cerr != nil {
		return nil, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return nil, readHTTP(op, st, eksErr(resp))
	}
	var out struct {
		Nodegroups []string `json:"nodegroups"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	return out.Nodegroups, nil
}

// eksAvailabilityClass derives availability.class from the FIRST node group's
// subnet AZ spread: >1 distinct AZ -> "regional", ==1 -> "zonal". Returns ok=false
// (the caller omits the observation) whenever anything is unreadable — an honest
// omission, never a fabricated class.
func (d *Driver) eksAvailabilityClass(region, cluster string) (string, bool) {
	names, lerr := d.listNodegroups(region, cluster)
	if lerr != nil || len(names) == 0 {
		return "", false
	}
	ng, found, rerr := d.describeNodegroup(region, cluster, names[0])
	if rerr != nil || !found || len(ng.Subnets) == 0 {
		return "", false
	}
	azs, ok := d.subnetAZs(region, ng.Subnets)
	if !ok || len(azs) == 0 {
		return "", false
	}
	if len(azs) > 1 {
		return "regional", true
	}
	return "zonal", true
}

// subnetAZs maps subnet ids to their availability zones via EC2 DescribeSubnets
// (reusing the package's ec2PostBase Query plumbing). readable=false on any
// failure — an unreadable AZ set must not become a false "single-AZ" claim.
func (d *Driver) subnetAZs(region string, subnetIds []string) (map[string]bool, bool) {
	form := map[string]string{"Action": "DescribeSubnets", "Version": ec2Version}
	for i, s := range subnetIds {
		form[fmt.Sprintf("SubnetId.%d", i+1)] = s
	}
	st, resp, err := d.ec2PostBase(region, encodeForm(form))
	if err != nil || st != http.StatusOK {
		return nil, false
	}
	azs := map[string]bool{}
	for _, az := range allBetween(string(resp), "<availabilityZone>", "</availabilityZone>") {
		if strings.TrimSpace(az) != "" {
			azs[az] = true
		}
	}
	if len(azs) == 0 {
		return nil, false
	}
	return azs, true
}

// eksErr pulls a human string out of an EKS JSON error body (the message lives in
// "message"). Falls back to the raw body when it cannot be parsed.
func eksErr(body []byte) string {
	var e struct {
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	msg := e.Message
	if msg == "" {
		msg = e.Msg
	}
	if strings.TrimSpace(msg) == "" {
		return mutDetail(body)
	}
	return msg
}

// createEKS provisions the composite (D26): the CLUSTER + ONE managed NODE GROUP.
// Four-valued throughout — once the cluster lands, ANY later ambiguity (poll,
// node-group create, node-group poll) is unknown WITH the providerId, never a
// silent half-provisioned cluster and never a bare "failed" that hides the
// standing cluster.
func (d *Driver) createEKS(region, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildEKS(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := eksProviderID(region, plan.Name)

	// ownership pre-read: refuse to touch a foreign cluster already at our
	// (deterministic) name. Not-found continues to a fresh create; ours-already
	// repairs (ensures the node group exists), refusing to re-create the cluster.
	c, found, rerr := d.describeEKSCluster(region, plan.Name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: rerr.Error() + " — a persistent DescribeCluster failure " +
				"(check the acting identity's eks:DescribeCluster permission; a transient throttle/5xx is retried) — reconcile"}
	}
	if found {
		if !groundholdTagsMatch(c.Tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("a cluster with this name exists and is not ours (tags do not match) — "+
					"refusing to adopt it; to take over a foreign cluster run `groundhold discover "+
					"--provider aws --region %s %s` then `adopt` (which claims it through the "+
					"gated adoption flow), never a bare converge", region, perr.AtNow)}
		}
		return d.ensureEKSNodeGroup(region, pid, plan, capability, environment)
	}

	// D261: an explicit adopt name (implementation.clusterName) that resolves to NO
	// cluster must NEVER create one — that is exactly the duplicate a brownfield adopt
	// hit (the real cluster has a custom name; a deterministic-name miss stood up a
	// SECOND cluster). Refuse instead of creating at an adoption name.
	if plan.AdoptByName {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("implementation.clusterName=%q names a cluster to adopt, but no such cluster "+
				"exists in %s — refusing to create one at an adoption name (check the name/region, or run "+
				"`groundhold discover --provider aws --region %[2]s %[3]s` then `adopt` first)",
				plan.Name, region, perr.AtNow)}
	}

	// CreateCluster (POST /clusters). The pid is knowable before the response
	// (deterministic name), so transport/5xx/conflict ambiguity carries it.
	// D281: a role created in THIS plan (D277 $ref wiring) may not be visible
	// to EKS yet — IAM is eventually consistent and AWS documents retrying the
	// dependent create. A 400 naming the role-assumption failure retries within
	// a bounded window; a role that never appears fails with AWS's own message.
	deadline := d.Now().Add(eksIAMPropagationWindow)
	var st int
	var body []byte
	for {
		st, body, err = d.eksDo("POST", region, "/clusters", plan.createClusterBody(capability, environment))
		if err == nil && st == http.StatusBadRequest && eksRoleNotYetVisible(body) &&
			d.Now().Before(deadline) {
			d.progress("cluster role not yet visible to EKS (IAM propagation) — retrying") // D257
			time.Sleep(d.PollInterval)
			continue
		}
		break
	}
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateCluster outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// creating — fall through to poll
	case st == http.StatusConflict:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreateCluster says the name now exists — reconcile ownership"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateCluster HTTP %d (server error — may have landed): %s", st, eksErr(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateCluster HTTP %d: %s", st, eksErr(body))}
	}

	// poll the cluster to ACTIVE, then attach the node group.
	if res := d.waitEKSClusterActive(region, pid, plan.Name); res != nil {
		return *res
	}
	return d.ensureEKSNodeGroup(region, pid, plan, capability, environment)
}

// waitEKSClusterActive polls DescribeCluster until ACTIVE. CREATING keeps polling;
// FAILED is a failed create WITH the pid (the cluster object exists — mirror ECS's
// rollout-failed); the poll timeout is unknown WITH the pid (may still be coming
// up). Returns nil once ACTIVE.
func (d *Driver) waitEKSClusterActive(region, pid, name string) *provider.CreateResult {
	deadline := d.Now().Add(d.eksLROTimeout())
	for {
		c, found, rerr := d.describeEKSCluster(region, name)
		if rerr == nil && found {
			switch c.Status {
			case "ACTIVE":
				return nil
			case "FAILED", "DELETING":
				return &provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "cluster entered " + c.Status + " during create"}
			}
			// CREATING / PENDING / UPDATING -> keep polling
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "cluster still creating at poll timeout — reconcile via DescribeCluster"}
		}
		d.progress("cluster provisioning — waiting for ACTIVE") // D257
		time.Sleep(d.PollInterval)
	}
}

// ensureEKSNodeGroup makes the cluster ACTIVE (idempotent for the ours-already
// repair path) and then creates + polls the ONE managed node group. PARTIAL
// FAILURE is the crux (D29/D87): the cluster is ACTIVE but the node group create
// or poll fails -> unknown WITH the pid (the cluster exists — reconcile the
// half-provisioned cluster), NEVER a bare "failed" that implies nothing was
// created and NEVER a silent success.
func (d *Driver) ensureEKSNodeGroup(region, pid string, plan EKSPlan, capability, environment string) provider.CreateResult {
	if res := d.waitEKSClusterActive(region, pid, plan.Name); res != nil {
		return *res
	}
	// D258: an ADOPTED cluster already carries its node group(s) — under whatever
	// name they were created with, which for a cluster groundhold did NOT freshly
	// create here need NOT equal the deterministic plan.NodeGroupName. LIST the
	// cluster's real node groups and, if any exist, treat the composite as
	// provisioned once ANY is ACTIVE (the per-node-group version upgrade is the
	// reconcile's job — rollEKSNodegroups lists them too). Without this, a self-adopt
	// polled a deterministic name the real node group did not carry and hung until
	// the poll timeout (Acme). Only a cluster with ZERO node groups gets a fresh one.
	if ngs, lerr := d.listNodegroups(region, plan.Name); lerr == nil && len(ngs) > 0 {
		return d.bindExistingNodegroups(region, pid, plan.Name, ngs)
	}
	// D281: the node role may be a same-plan create — retry the IAM-propagation
	// 400 within the bounded window, exactly as CreateCluster does.
	deadline := d.Now().Add(eksIAMPropagationWindow)
	var st int
	var body []byte
	var err error
	for {
		st, body, err = d.eksDo("POST", region, "/clusters/"+plan.Name+"/node-groups",
			plan.createNodegroupBody(capability, environment))
		if err == nil && st == http.StatusBadRequest && eksRoleNotYetVisible(body) &&
			d.Now().Before(deadline) {
			d.progress("node role not yet visible to EKS (IAM propagation) — retrying") // D257
			time.Sleep(d.PollInterval)
			continue
		}
		break
	}
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("cluster ACTIVE but CreateNodegroup outcome unknown — reconcile: %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// creating — fall through to poll
	case st == http.StatusConflict:
		// already exists (a prior partial / race) — poll it to ACTIVE.
	default:
		// transport/5xx/4xx are ALL unknown WITH the pid here: the cluster is
		// already ACTIVE, so this is a partial composite, never a plain "failed".
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("cluster ACTIVE but CreateNodegroup failed (HTTP %d: %s) — "+
				"the cluster exists with no node group; reconcile the half-provisioned cluster", st, eksErr(body))}
	}
	return d.pollNodegroupActive(region, pid, plan)
}

// pollNodegroupActive polls DescribeNodegroup until ACTIVE (succeeded WITH the
// pid). A CREATE_FAILED / DEGRADED / DELETING node group, or the poll timeout, is
// unknown WITH the pid — the cluster is ACTIVE (a partial composite), so this is
// never a bare "failed".
func (d *Driver) pollNodegroupActive(region, pid string, plan EKSPlan) provider.CreateResult {
	deadline := d.Now().Add(d.eksLROTimeout())
	for {
		ng, found, rerr := d.describeNodegroup(region, plan.Name, plan.NodeGroupName)
		if rerr == nil && found {
			switch ng.Status {
			case "ACTIVE":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "CREATE_FAILED", "DEGRADED", "DELETING":
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "cluster is ACTIVE but the managed node group entered " + ng.Status +
						" — reconcile the half-provisioned cluster (the cluster exists)"}
			}
			// CREATING -> keep polling
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "cluster ACTIVE but the node group is still creating at poll timeout — reconcile via DescribeNodegroup"}
		}
		d.progress("node group provisioning — waiting for ACTIVE") // D257
		time.Sleep(d.PollInterval)
	}
}

// bindExistingNodegroups (D259) concludes the ADOPT path in a SINGLE PASS — never a
// timeout poll. An adopted cluster's node groups ALREADY EXIST (ListNodegroups just
// returned them) and the cluster is ACTIVE and ours, so the composite EXISTS: the
// create succeeds. The single describe pass only ever DOWNGRADES that: a node group
// positively in a terminal-bad state (CREATE_FAILED / DEGRADED), with none ACTIVE,
// is unknown WITH the pid (reconcile the standing cluster). An INCONCLUSIVE describe
// (404, unreadable, or a transient non-terminal status) must NOT block or loop — the
// node group's live health is an observe/verify concern, not a bind concern, and a
// running adopted cluster must not be held hostage to a describe that never reports
// ACTIVE. This replaces D258's pollAnyNodegroupActive, whose "keep watching" branch
// spun to the 20-minute timeout whenever describe never said ACTIVE for a genuinely
// running node group (Acme, twice: cluster + node group ACTIVE, yet it hung).
func (d *Driver) bindExistingNodegroups(region, pid, cluster string, ngNames []string) provider.CreateResult {
	badState := ""
	for _, ng := range ngNames {
		doc, found, rerr := d.describeNodegroup(region, cluster, ng)
		if rerr != nil || !found {
			continue // inconclusive describe never blocks adoption of a standing cluster
		}
		if doc.Status == "ACTIVE" {
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		}
		if doc.Status == "CREATE_FAILED" || doc.Status == "DEGRADED" {
			badState = ng + " is " + doc.Status
		}
	}
	if badState != "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "adopted cluster's node group " + badState +
				" — reconcile the cluster (the cluster exists)"}
	}
	// Cluster ACTIVE + ours + >=1 node group listed, none positively ACTIVE and none
	// positively bad (describe inconclusive): the composite EXISTS. Bind it rather than
	// hang; observe/verify report the node group's real state and version.
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// deleteEKS tears the composite down in REVERSE order, ownership-guarded: pre-read
// the ownership tags (refuse a foreign cluster), DeleteNodegroup -> poll gone ->
// DeleteCluster -> poll gone. Idempotent on already-gone (404); a node group still
// deleting is not-yet-gone (keep polling); a transport/5xx or a poll timeout is
// unknown WITH the pid (reconcile), never a claimed success.
func (d *Driver) deleteEKS(capability, environment, providerID string) provider.CreateResult {
	region, name, err := splitEKSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	c, found, rerr := d.describeEKSCluster(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	// ownership guard: refuse a foreign cluster at our name.
	if !groundholdTagsMatch(c.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster tags do not match — refusing to delete a resource that is not ours"}
	}
	// (1) DeleteNodegroup (the node-group name is recoverable from the cluster name).
	if res := d.deleteEKSNodegroup(region, providerID, name, name+"-ng"); res != nil {
		return *res
	}
	// (2) DeleteCluster.
	return d.deleteEKSCluster(region, providerID, name)
}

// deleteEKSNodegroup removes the node group and polls until it is READABLY gone
// (404). Returns nil once gone; a non-nil unknown/failed aborts the teardown.
func (d *Driver) deleteEKSNodegroup(region, pid, cluster, ng string) *provider.CreateResult {
	_, found, rerr := d.describeNodegroup(region, cluster, ng)
	if rerr != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "pre-delete node group read gave no answer — reconcile: " + rerr.Error()}
	}
	if found {
		st, body, err := d.eksDo("DELETE", region, "/clusters/"+cluster+"/node-groups/"+ng, nil)
		switch {
		case err != nil:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("DeleteNodegroup outcome unknown: %v", err)}
		case st == http.StatusNotFound:
			return nil // idempotent — already gone
		case st == http.StatusOK || st == http.StatusAccepted:
			// deleting — fall through to poll
		case st >= 500:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("DeleteNodegroup HTTP %d (server error) — reconcile", st)}
		default:
			return &provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("DeleteNodegroup HTTP %d: %s", st, eksErr(body))}
		}
	}
	// poll until the node group is readably gone (a still-DELETING node group is
	// not-yet-gone — keep polling; the timeout is unknown WITH the pid).
	deadline := d.Now().Add(d.eksLROTimeout())
	for {
		_, stillThere, r := d.describeNodegroup(region, cluster, ng)
		if r == nil && !stillThere {
			return nil
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "node group still deleting at poll timeout — reconcile before the cluster delete"}
		}
		time.Sleep(d.PollInterval)
	}
}

// deleteEKSCluster removes the cluster and polls until it is READABLY gone.
func (d *Driver) deleteEKSCluster(region, pid, name string) provider.CreateResult {
	st, body, err := d.eksDo("DELETE", region, "/clusters/"+name, nil)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("DeleteCluster outcome unknown: %v", err)}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // idempotent — already gone
	case st == http.StatusOK || st == http.StatusAccepted:
		// deleting — fall through to poll
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("DeleteCluster HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("DeleteCluster HTTP %d: %s", st, eksErr(body))}
	}
	deadline := d.Now().Add(d.eksLROTimeout())
	for {
		_, stillThere, r := d.describeEKSCluster(region, name)
		if r == nil && !stillThere {
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "cluster still deleting at poll timeout — reconcile via DescribeCluster"}
		}
		time.Sleep(d.PollInterval)
	}
}

// classifyEKSChange (D46): PURE — can a capability.cluster.kubernetes transition be
// honored in place? In-place EKS cluster updates (version bump, endpoint exposure,
// secrets encryption) are slice 3 — NOT yet automatable — and groundhold will not
// REPLACE a stateful cluster. So the governed attributes are "unsupported" with an
// honest reason, never a silent claim of mutability and never a replacement.
func classifyEKSChange(path string) (string, string) {
	switch path {
	case "cluster.version":
		return "mutable", "in-place via UpdateClusterVersion (a long-running control-plane upgrade)"
	case "network.apiExposure":
		return "mutable", "in-place via UpdateClusterConfig (endpoint public/private access)"
	case "encryption.secrets":
		// EKS can only ENABLE secrets encryption (AssociateEncryptionConfig, one-way);
		// disabling is impossible. A change here is refused, never a cluster replace.
		return "unsupported", "secrets encryption cannot be changed in place safely (enable is one-way, disable is impossible) — groundhold will not replace a stateful cluster"
	case "availability.class":
		return "unsupported", "availability.class is a node-group property (subnet AZ spread), not an in-place cluster patch"
	case "location.region", "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no EKS cluster in-place mapping for " + path
	}
}

// discoverEKS enumerates the region's clusters as capability.cluster.kubernetes —
// so `discover --provider aws` surfaces an eksctl/TF-stood cluster for adoption.
// Reuses observeEKS (two-step: ListClusters names -> per-cluster reverse map).
func (d *Driver) discoverEKS(region string) ([]provider.Discovered, []string, error) {
	st, resp, err := d.eksDo("GET", region, "/clusters", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("eks ListClusters: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("eks ListClusters: HTTP %d", st)
	}
	var out struct {
		Clusters []string `json:"clusters"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, nil, readBody("ListClusters", st)
	}
	var found []provider.Discovered
	var diags []string
	for _, name := range out.Clusters {
		pid := eksProviderID(region, name)
		obs, od, oerr := d.observeEKS("", pid)
		if oerr != nil {
			diags = append(diags, name+": "+oerr.Error())
			continue
		}
		diags = append(diags, od...)
		found = append(found, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.cluster.kubernetes", Observations: provider.WithoutAbsence(obs)})
	}
	return found, diags, nil
}

// eksEndpointFlags maps the network.apiExposure enum to the endpoint-access pair.
func eksEndpointFlags(exposure string) (pub, priv, ok bool) {
	switch exposure {
	case "public":
		return true, false, true
	case "private":
		return false, true, true
	case "mixed":
		return true, true, true
	}
	return false, false, false
}

// updateEKS patches a bound cluster in place (D147 slice 3): cluster.version via
// UpdateClusterVersion, network.apiExposure via UpdateClusterConfig. EKS permits
// ONE update at a time, so the changed paths are applied SEQUENTIALLY, each polled
// to Successful. Ownership tags gate the patch; four-valued throughout (an
// ambiguous outcome is unknown WITH the providerId, never a silent success).
func (d *Driver) updateEKS(capability, environment, providerID string,
	attrs map[string]any, changes []string) provider.CreateResult {
	region, name, err := splitEKSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// ownership re-check before mutating (refuse a foreign cluster at our name).
	c, found, rerr := d.describeEKSCluster(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "cluster no longer exists — cannot update"}
	}
	if !groundholdTagsMatch(c.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster tags do not match — refusing to patch a resource that is not ours"}
	}

	versionBumped := ""
	for _, path := range changes {
		switch path {
		case "cluster.version":
			ver, _ := attrs["cluster.version"].(string)
			if ver == "" {
				return provider.CreateResult{Status: "failed", Reason: "cluster.version must be a non-empty string"}
			}
			body, _ := json.Marshal(map[string]any{"version": ver})
			if res := d.applyEKSUpdate(region, providerID, name, "/clusters/"+name+"/updates", body); res != nil {
				return *res
			}
			versionBumped = ver
		case "network.apiExposure":
			exp, _ := attrs["network.apiExposure"].(string)
			pub, priv, ok := eksEndpointFlags(exp)
			if !ok {
				return provider.CreateResult{Status: "failed", Reason: "network.apiExposure must be public|private|mixed"}
			}
			body, _ := json.Marshal(map[string]any{
				"resourcesVpcConfig": map[string]any{"endpointPublicAccess": pub, "endpointPrivateAccess": priv}})
			if res := d.applyEKSUpdate(region, providerID, name, "/clusters/"+name+"/update-config", body); res != nil {
				return *res
			}
		default:
			// ClassifyChange gates this (unsupported), so a reviewed plan never
			// reaches here — but refuse honestly rather than silently no-op.
			return provider.CreateResult{Status: "failed",
				Reason: "no in-place EKS mapping for " + path}
		}
	}
	// D248: the managed node group follows the cluster. Once the control plane is
	// upgraded (above, polled to Successful), roll every node group to the same
	// version — AWS's UpdateNodegroupVersion does a rolling replace that respects
	// PodDisruptionBudgets. Ordering is guaranteed: the control-plane update
	// completed before this runs, so a node group is never asked to outrun it.
	if versionBumped != "" {
		if res := d.rollEKSNodegroups(region, providerID, name, versionBumped); res != nil {
			return *res
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// rollEKSNodegroups upgrades every managed node group of a cluster to ver after a
// control-plane bump (D248). Idempotent per node group: a group already at ver is
// skipped (no update issued), so a re-run after a partial roll converges without a
// spurious replacement. Ownership is already proven (the cluster is ours — its
// node groups are ours). Polled to completion; any ambiguity is unknown WITH the
// pid (a half-upgraded cluster — reconcile), never a claimed success.
func (d *Driver) rollEKSNodegroups(region, pid, name, ver string) *provider.CreateResult {
	ngs, lerr := d.listNodegroups(region, name)
	if lerr != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "control plane upgraded but the node-group list gave no answer — reconcile the node-group versions: " + lerr.Error()}
	}
	for _, ng := range ngs {
		// idempotent: skip a node group already at the target version.
		if cur, found, rerr := d.describeNodegroup(region, name, ng); rerr == nil && found && cur.Version == ver {
			continue
		}
		body, _ := json.Marshal(map[string]any{"version": ver})
		st, resp, err := d.eksDo("POST", region, "/clusters/"+name+"/node-groups/"+ng+"/update-version", body)
		switch {
		case err != nil:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("control plane at %s but node group %s upgrade outcome unknown (may have landed): %v", ver, ng, err)}
		case st == http.StatusOK:
			// accepted — poll the returned update below
		case st >= 500:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("node group %s upgrade HTTP %d (server error — may have landed): %s", ng, st, eksErr(resp))}
		default:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("control plane at %s but node group %s upgrade failed (HTTP %d: %s) — the cluster is half-upgraded; reconcile the node-group versions", ver, ng, st, eksErr(resp))}
		}
		// The update was accepted (200). Poll the NODE GROUP itself to its target
		// version — its observable Status+Version is the end state, and (unlike the
		// DescribeUpdate-by-id path this used to get wrong) uses a real, known endpoint.
		if res := d.waitEKSNodegroupUpdate(region, pid, name, ng, ver); res != nil {
			return res
		}
	}
	return nil
}

// waitEKSNodegroupUpdate polls a node-group update to Successful (nil). Failed/
// Cancelled is a half-upgraded cluster (unknown WITH the pid — the control plane
// already moved), as is a poll timeout — never a bare failed.
// waitEKSNodegroupUpdate polls the NODE GROUP to its target version (D273 — the real
// F29 root cause). It watches the node group's own observable end state
// (describeNodegroup: Status ACTIVE at the target Version) instead of a DescribeUpdate-
// by-id call. The prior code polled "/clusters/<n>/node-groups/<ng>/updates/<id>" — a
// path that DOES NOT EXIST in the EKS API (the real DescribeUpdate is
// /clusters/<n>/updates/<id>?nodegroupName=<ng>), so every GET missed and the poll NEVER
// saw "Successful", spinning to the LRO timeout even after AWS finished the roll (Acme:
// node group ACTIVE at target + VersionUpdate Successful, yet the driver slept forever —
// the transport fixes D260/D264/D271 only masked/moved this). The unit test did not catch
// it because the fake MIRRORED the driver's wrong path. Watching the node group's own
// Version+Status is correct AND robust (a real, everywhere-used endpoint via eksGet).
func (d *Driver) waitEKSNodegroupUpdate(region, pid, name, ng, ver string) *provider.CreateResult {
	deadline := d.Now().Add(d.eksLROTimeout())
	for {
		if ngd, found, rerr := d.describeNodegroup(region, name, ng); rerr == nil && found {
			switch ngd.Status {
			case "ACTIVE":
				if ngd.Version == ver {
					return nil // rolled to the target version — done
				}
				// ACTIVE but not yet at ver: the roll has not transitioned it yet — keep polling.
			case "DEGRADED", "UPDATE_FAILED", "CREATE_FAILED", "DELETING":
				return &provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "node group " + ng + " entered " + ngd.Status + " during the version roll — reconcile the half-upgraded cluster"}
			}
			// CREATING / UPDATING -> keep polling
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "node group " + ng + " not at version " + ver + " at poll timeout — reconcile via DescribeNodegroup"}
		}
		d.progress("node group " + ng + " upgrading — draining + rolling nodes") // D257
		time.Sleep(d.PollInterval)
	}
}

// applyEKSUpdate POSTs one cluster update and polls it to Successful. Returns nil
// on success, or a four-valued result on ambiguity/failure.
// eksUpdateInProgress reports whether a 409 body is the TRANSIENT post-update lock EKS
// returns for a few minutes AFTER a version-update settles (eventual consistency), as
// opposed to a real terminal conflict — matched on the message EKS uses.
func eksUpdateInProgress(resp []byte) bool {
	m := strings.ToLower(eksErr(resp))
	return strings.Contains(m, "update") &&
		(strings.Contains(m, "in progress") || strings.Contains(m, "undergoing") || strings.Contains(m, "already"))
}

func (d *Driver) applyEKSUpdate(region, pid, name, path string, body []byte) *provider.CreateResult {
	// D270: EKS returns 409 "cluster currently has an update in progress" for a few
	// minutes AFTER a version-update completes — a transient post-update settling lock,
	// not a real conflict. Retry it (bounded by the LRO ceiling) instead of failing the
	// converge (Acme F29-adjacent: this 409 DIED the run; a ~4-min cooldown cleared it).
	deadline := d.Now().Add(d.eksLROTimeout())
	var st int
	var resp []byte
	var err error
	for {
		st, resp, err = d.eksDo("POST", region, path, body)
		if err != nil || st != http.StatusConflict || !eksUpdateInProgress(resp) {
			break
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "cluster still reports an update in progress at the retry deadline — reconcile"}
		}
		d.progress("waiting for the previous EKS update to settle (409 in progress)")
		time.Sleep(d.PollInterval)
	}
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("update outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// accepted — poll the returned update below
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("update HTTP %d (server error — may have landed): %s", st, eksErr(resp))}
	default:
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("update HTTP %d: %s", st, eksErr(resp))}
	}
	var out struct {
		Update struct {
			ID string `json:"id"`
		} `json:"update"`
	}
	if json.Unmarshal(resp, &out) != nil || out.Update.ID == "" {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "update response carried no update id — reconcile via DescribeCluster"}
	}
	return d.waitEKSUpdate(region, pid, name, out.Update.ID)
}

// waitEKSUpdate polls DescribeUpdate until the update is Successful. Failed/Cancelled
// is a clean failed WITH the pid; a timeout is unknown WITH the pid.
func (d *Driver) waitEKSUpdate(region, pid, name, updateID string) *provider.CreateResult {
	deadline := d.Now().Add(d.eksLROTimeout())
	for {
		st, resp, err := d.eksDo("GET", region, "/clusters/"+name+"/updates/"+updateID, nil)
		if err == nil && st == http.StatusOK {
			var out struct {
				Update struct {
					Status string `json:"status"`
				} `json:"update"`
			}
			if json.Unmarshal(resp, &out) == nil {
				switch out.Update.Status {
				case "Successful":
					return nil
				case "Failed", "Cancelled":
					return &provider.CreateResult{ProviderID: pid, Status: "failed",
						Reason: "cluster update " + out.Update.Status}
				}
				// InProgress -> keep polling
			}
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "cluster update still in progress at poll timeout — reconcile via DescribeUpdate"}
		}
		d.progress("control plane upgrading — waiting on cluster update") // D257
		time.Sleep(d.PollInterval)
	}
}
