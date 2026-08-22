// Update path (D46): ClassifyChange is PURE provider knowledge —
// mutability on Cloud SQL is transition-dependent. BuildUpdateRequest is
// a pure function (golden-tested): PATCH bodies carry ONLY the changed
// semantic paths, nested objects are merged from the CURRENT instance so
// siblings survive, and settings.settingsVersion rides along so a
// concurrent change surfaces as a conflict instead of a lost update.
package gcp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"groundhold/internal/provider"
	"groundhold/internal/scalars"
)

// ClassifyChange: can this transition be honored in place?
func (d *Driver) ClassifyChange(service, path string, current, desired any,
	impl map[string]any) (string, string) {
	switch service {
	case "cloudsql":
		return classifyCloudSQLChange(path, desired, impl)
	case "firestore":
		return classifyFirestoreChange(path)
	case "gcs":
		return classifyGCSChange(path)
	case "clouddnsrecord":
		return classifyCloudDNSRecordChange(path)
	case "pubsub-topic":
		return classifyPubSubChange(path)
	case "pubsub-queue":
		return classifyPubSubQueueChange(path)
	case "secretmanager":
		return classifySecretChange(path)
	case "assetfeed":
		return classifyAssetFeedChange(path)
	case "loadbalancer":
		return classifyLoadBalancerChange(path)
	case "billingbudget":
		return classifyBillingBudgetChange(path)
	case "logbucket":
		return classifyLogBucketChange(path)
	case "auditlogs":
		return classifyAuditLogsChange(path)
	case "scc":
		return classifySCCChange(path)
	case "vertexai":
		return classifyVertexChange(path)
	case "gce":
		return classifyGCEInstanceChange(path)
	case "pd":
		return classifyPDChange(path)
	case "computeimage":
		return classifyComputeImageChange(path)
	case "mig":
		return classifyMIGChange(path)
	case "artifactregistry":
		return classifyARChange(path)
	case "gke":
		return classifyGKEChange(path)
	case "gke-addon":
		return classifyGKEAddonChange(path)
	case "gke-workloadidentity":
		return classifyGKEWorkloadIdentityChange(path)
	case "backupplan":
		return classifyBackupPlanGCPChange(path, desired)
	default:
		// D215: no explicit ClassifyChange => no in-place update path, so a drift is
		// honestly a REPLACEMENT (consent-gated when stateful), never a freeze.
		return "immutable", fmt.Sprintf(
			"gcp service %q has no in-place update path — reconciling a drift is a replacement", service)
	}
}

// classifyGCSChange: which GCS bucket transitions can be honored in place? Symmetric
// with classifyS3Change (D77) — versioning is a clean buckets.patch; region and
// durability class are create-time-only (a replacement); Object Lock-style retention
// is irreversible. The IAM/exposure and CMEK paths are patchable but their in-place
// application is not wired in this slice — an honest "unsupported", never a silent claim.
func classifyGCSChange(path string) (string, string) {
	switch path {
	case "versioning.enabled":
		return "mutable", ""
	case "location.region", "durability.class",
		"replication.enabled", "replication.destinationRegion":
		// D826: this was true when it was written and stopped being true. Cloud Storage
		// now publishes buckets.relocate ("Initiates a long-running Relocate Bucket
		// operation on the specified bucket"), whose request carries destinationLocation,
		// destinationCustomPlacementConfig and destinationKmsKeyName — so the location,
		// the durability class that follows from it, and the dual-region pair all change
		// on a live bucket, under its own name, with its objects. Google says it plainly:
		// "You can relocate a bucket after it's created." Asking for consent to replace a
		// bucket buys a person the loss of every object in it, for nothing.
		return "unsupported", "in-place relocation is not wired for GCS in this slice — " +
			"Cloud Storage does support it (buckets.relocate takes destinationLocation and " +
			"destinationCustomPlacementConfig, and the durability class follows the " +
			"location), so this is a gap in groundhold rather than a reason to replace the " +
			"bucket and its objects"
	case "retention.minimum", "retention.locked", "retention.maximum",
		"network.publicExposure", "encryption.customerManagedKeys":
		return "unsupported", "in-place patch of " + path + " is not wired for GCS in this slice"
	case "encryption.atRest", "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no GCS in-place mapping for " + path
	}
}

// classifyCloudDNSRecordChange: which Cloud DNS record transitions can be honored in
// place? REPOINTING a record (dns.target) is a clean managedZones.changes patch —
// atomic delete-of-current + add-of-new (you cannot just add: the name+type already
// exists). The record's KIND (dns.type) is create-time identity — a different type is
// a different rrset, so it is a REPLACEMENT, never an in-place edit. dns.proxied is a
// Cloudflare edge concept Cloud DNS has no equivalent for; service.managed/cost.monthly
// are platform/projection props with nothing to patch.
func classifyCloudDNSRecordChange(path string) (string, string) {
	switch path {
	case "dns.target":
		return "mutable", ""
	case "dns.type":
		return "immutable", "a record's KIND (dns.type) is create-time identity on Cloud DNS — a change is a replacement (a different rrset)"
	case "service.managed", "dns.proxied":
		return "unsupported", "platform/projection/edge property — nothing to patch on a Cloud DNS record"
	default:
		return "unsupported", "no Cloud DNS record in-place mapping for " + path
	}
}

// classifyPubSubChange: which Pub/Sub topic transitions can be honored in place?
// Symmetric with classifySNSChange (D94) — network.publicExposure is a clean IAM
// grant/revoke. encryption.customerManagedKeys and residency (messageStoragePolicy)
// are patchable in principle but not wired in THIS slice — an honest "unsupported",
// never a silent claim; the platform properties have nothing to patch.
func classifyPubSubChange(path string) (string, string) {
	switch path {
	case "network.publicExposure":
		return "mutable", ""
	case "encryption.customerManagedKeys", "location.region":
		return "unsupported", "in-place patch of " + path + " is not wired for Pub/Sub in this slice"
	case "encryption.atRest", "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Pub/Sub in-place mapping for " + path
	}
}

// classifyPubSubQueueChange: which Pub/Sub subscription transitions can be honored in
// place? Symmetric with classifySQSChange (D95) — retention.minimum is a clean
// subscriptions.patch. Exposure (IAM), CMEK and residency are patchable in principle
// but not wired in THIS slice — an honest "unsupported", never a silent claim; the
// create-time delivery/ordering type is a replacement; platform props have nothing to patch.
func classifyPubSubQueueChange(path string) (string, string) {
	switch path {
	case "retention.minimum":
		return "mutable", ""
	case "reliability.deadLetter":
		// deadLetterPolicy is set/cleared in place via subscriptions.patch (updateMask
		// deadLetterPolicy) — symmetric with the SQS RedrivePolicy.
		return "mutable", ""
	case "ordering.enabled":
		return "immutable", "message ordering is create-time only on a Pub/Sub subscription " +
			"— a change is a replacement"
	case "delivery.guarantee":
		// D834: this shared a case with ordering.enabled and inherited its verdict. The two
		// differ: `gcloud pubsub subscriptions update` — a command that builds an explicit
		// update mask, so its flag set is a statement about what is updatable — carries
		// --enable-exactly-once-delivery, and carries no ordering flag at all. Replacing a
		// subscription to turn on exactly-once loses the undelivered backlog for a change
		// Google makes on the live subscription.
		return "unsupported", "in-place delivery-guarantee change is not wired for Pub/Sub " +
			"in this slice — Google does support it on a live subscription " +
			"(subscriptions.patch with enableExactlyOnceDelivery in the update mask), so " +
			"this is a gap in groundhold rather than a reason to replace the subscription " +
			"and drop its backlog"
	case "network.publicExposure", "encryption.customerManagedKeys", "location.region":
		return "unsupported", "in-place patch of " + path + " is not wired for Pub/Sub subscriptions in this slice"
	case "encryption.atRest", "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Pub/Sub subscription in-place mapping for " + path
	}
}

// classifySecretChange: which GCP secret transitions can be honored in place?
// Symmetric with classifyASMChange (D97) on network.publicExposure — a clean IAM
// grant/revoke. The interesting honest divergence is encryption.customerManagedKeys:
// ASM lets you patch a secret's KmsKeyId, but a GCP secret's CMEK lives in its
// create-time REPLICATION policy, which is immutable — so it is a REPLACEMENT here,
// not a patch. ClassifyChange being per-provider tells the truth for each cloud.
func classifySecretChange(path string) (string, string) {
	switch path {
	case "network.publicExposure":
		return "mutable", ""
	case "encryption.customerManagedKeys", "location.region":
		return "immutable", "a GCP secret's CMEK/residency lives in its create-time replication policy, which is immutable — a change is a replacement"
	case "encryption.atRest", "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no GCP secret in-place mapping for " + path
	}
}

// classifyAssetFeedChange: which Cloud Asset change-feed transitions can be
// honored in place? feed.target (the Pub/Sub topic) IS patchable via UpdateFeed
// with an updateMask, but the in-place patch is not wired in THIS slice — an
// honest "unsupported", never a silent claim. service.managed is a platform
// property with nothing to patch.
func classifyAssetFeedChange(path string) (string, string) {
	switch path {
	case "feed.target":
		return "unsupported", "in-place patch of feed.target is not wired for Cloud Asset feeds in this slice"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Cloud Asset feed in-place mapping for " + path
	}
}

func classifyCloudSQLChange(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "region is create-time only on Cloud SQL"
	case "engine.protocol":
		return "immutable", "engine/version changes are a migration, " +
			"not a patch"
	case "availability.class":
		if desired == "multi-regional" {
			return "unsupported", "no Cloud SQL equivalent"
		}
		return "caveated", "availabilityType changes can restart the instance"
	case "network.publicExposure":
		if desired == false {
			network, _ := impl["network"].(map[string]any)
			if link, _ := network["privateNetwork"].(string); link == "" {
				return "unsupported", "removing public exposure requires " +
					"implementation.network.privateNetwork (private IP " +
					"cannot be attached without a prepared link)"
			}
		}
		return "caveated", "a private IP, once attached, cannot be removed"
	case "recovery.rpo":
		return "mutable", ""
	case "encryption.atRest", "service.managed":
		return "unsupported", "platform property, not patchable"
	}
	return "unsupported", "no Cloud SQL mapping for " + path
}

// BuildUpdateRequest: PATCH with only the changed paths; nested objects
// merged from current; settingsVersion pinned against concurrent edits.
func BuildUpdateRequest(project, name string, changes []string,
	attrs, impl, current map[string]any) (Request, error) {
	curSettings, _ := current["settings"].(map[string]any)
	sv, _ := curSettings["settingsVersion"].(string)
	if sv == "" {
		return Request{}, fmt.Errorf(
			"current instance has no settings.settingsVersion — refusing " +
				"a blind patch")
	}
	settings := map[string]any{"settingsVersion": sv}
	body := map[string]any{"settings": settings}

	for _, path := range changes {
		desired := attrs[path]
		switch path {
		case "availability.class":
			switch desired {
			case "zonal":
				settings["availabilityType"] = "ZONAL"
			case "regional":
				settings["availabilityType"] = "REGIONAL"
			default:
				return Request{}, fmt.Errorf(
					"availability.class %v cannot be honored", desired)
			}
		case "recovery.rpo":
			sc, err := scalars.Parse(desired)
			if err != nil || sc.Kind != scalars.Duration {
				return Request{}, fmt.Errorf("recovery.rpo is not a duration")
			}
			if sc.Value.(float64) > 7*24*3600*1000 {
				return Request{}, fmt.Errorf(
					"recovery.rpo beyond PITR bounds")
			}
			// merge from current so sibling backup fields survive
			merged := map[string]any{}
			if cur, ok := curSettings["backupConfiguration"].(map[string]any); ok {
				for k, v := range cur {
					merged[k] = v
				}
			}
			merged["enabled"] = true
			// engine-specific PITR mechanism, mutually exclusive at the API
			// (D950): MySQL uses binaryLogEnabled, Postgres/SQL Server use
			// pointInTimeRecoveryEnabled. A patch with the wrong spelling 400s.
			dv, _ := current["databaseVersion"].(string)
			if strings.HasPrefix(dv, "MYSQL_") {
				merged["binaryLogEnabled"] = true
			} else {
				merged["pointInTimeRecoveryEnabled"] = true
			}
			settings["backupConfiguration"] = merged
		case "network.publicExposure":
			merged := map[string]any{}
			if cur, ok := curSettings["ipConfiguration"].(map[string]any); ok {
				for k, v := range cur {
					merged[k] = v
				}
			}
			exposed, _ := desired.(bool)
			if exposed {
				merged["ipv4Enabled"] = true
			} else {
				network, _ := impl["network"].(map[string]any)
				link, _ := network["privateNetwork"].(string)
				if link == "" {
					return Request{}, fmt.Errorf(
						"network.publicExposure=false requires " +
							"implementation.network.privateNetwork")
				}
				merged["ipv4Enabled"] = false
				merged["privateNetwork"] = link
				merged["authorizedNetworks"] = []any{}
			}
			settings["ipConfiguration"] = merged
		default:
			return Request{}, fmt.Errorf(
				"path %s is not patchable on Cloud SQL", path)
		}
	}

	return Request{
		Method: "PATCH",
		URL: fmt.Sprintf("%s/projects/%s/instances/%s",
			baseURL, project, name),
		Body: body,
	}, nil
}

// Update: GET first (ownership labels + settingsVersion), PATCH only the
// changed paths, poll. A version conflict is a provider-side concurrent
// change — failed with a re-observe hint, never a blind retry.
func (d *Driver) Update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string,
	key string) provider.CreateResult {
	defer d.forgetSecrets()
	d.rememberSecrets(impl)
	cr := d.update(service, capability, environment, providerID, attrs, impl, changes, key)
	cr.Reason = d.scrub(cr.Reason)
	return cr
}

func (d *Driver) update(service, capability, environment, providerID string,
	attrs, impl map[string]any, changes []string,
	key string) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if service == "backupplan" {
		return d.updateBackupPlanGCP(capability, environment, providerID, attrs, impl, changes)
	}
	if service == "gke" {
		return d.updateGKE(capability, environment, providerID, attrs, impl, changes)
	}
	if service == "gke-addon" {
		return d.updateGKEAddon(capability, environment, providerID, attrs, impl, changes)
	}
	if service == "billingbudget" {
		return d.updateBillingBudget(capability, environment, providerID, attrs, impl, changes)
	}
	if service == "logbucket" {
		return d.updateLogBucket(capability, environment, providerID, attrs, impl, changes)
	}
	if service == "auditlogs" {
		return d.updateAuditLogs(capability, environment, providerID, attrs, impl, changes)
	}
	if service == "scc" {
		return d.updateSCC(capability, environment, providerID, attrs, impl, changes)
	}
	if service == "gcs" {
		return d.updateGCS(capability, environment, providerID, attrs, changes)
	}
	if service == "firestore" {
		return d.updateFirestore(capability, environment, providerID, attrs, changes)
	}
	if service == "clouddnsrecord" {
		return d.updateCloudDNSRecord(capability, environment, providerID, attrs, changes)
	}
	if service == "pubsub-topic" {
		return d.updatePubSub(capability, environment, providerID, attrs, changes)
	}
	if service == "pubsub-queue" {
		return d.updatePubSubQueue(capability, environment, providerID, attrs, impl, changes)
	}
	if service == "secretmanager" {
		return d.updateSecret(capability, environment, providerID, attrs, changes)
	}
	if service == "loadbalancer" {
		return d.updateLoadBalancer(capability, environment, providerID)
	}
	if service == "cloudrun" || service == "vpc" ||
		service == "cloudfunctions" || service == "cloudfunctions-fn" ||
		service == "bigquery" || service == "cloudscheduler" || service == "vpngateway" || service == "backupvault" ||
		service == "assetfeed" {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s in-place update is not wired yet", service)}
	}
	project, region, name, err := splitProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_ = region

	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/instances/%s", d.BaseURL, project, name), nil)
	if err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("pre-update read failed: %v", err)}
	}
	if status != 200 {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("pre-update read: HTTP %d", status)}
	}
	current := map[string]any{}
	if err := json.Unmarshal(body, &current); err != nil {
		return provider.CreateResult{Status: "failed",
			Reason: "pre-update read unparseable"}
	}
	if !ownedBy(current, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "instance labels do not match — refusing to patch " +
				"a resource that is not ours"}
	}

	req, err := BuildUpdateRequest(project, name, changes, attrs, impl, current)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	req.URL = fmt.Sprintf("%s/projects/%s/instances/%s",
		d.BaseURL, project, name)

	status, respBody, err := d.call(req.Method, req.URL, req.Body)
	if err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("patch outcome unknown: %v", err)}
	}
	if status == 409 || status == 412 {
		return provider.CreateResult{Status: "failed",
			Reason: "concurrent settings change (settingsVersion conflict) " +
				"— re-observe and re-seal"}
	}
	if status >= 400 {
		return mutationResult("patch", status, respBody)
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(respBody, &op) != nil || op.Name == "" {
		return provider.CreateResult{Status: "unknown",
			Reason: "patch response carried no operation — reconcile"}
	}
	res := d.pollOperation(op.Name, name, region)
	if res.Status == "succeeded" {
		res.ProviderID = providerID // identity survives an update
	}
	return res
}

// Delete (D47): GET first — ownership labels AND deletion protection.
// Protection is never auto-disabled; lifting it is an explicit prior
// step, that is the point of protection.
func (d *Driver) Delete(service, capability, environment, providerID string,
	key string) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if service == "backupplan" {
		return d.deleteBackupPlanGCP(capability, environment, providerID)
	}
	if service == "gke" {
		return d.deleteGKE(capability, environment, providerID)
	}
	if service == "gke-addon" {
		return d.deleteGKEAddon(capability, environment, providerID)
	}
	if service == "gke-workloadidentity" {
		return d.deleteGKEWorkloadIdentity(capability, environment, providerID)
	}
	if service == "billingbudget" {
		return d.deleteBillingBudget(capability, environment, providerID)
	}
	if service == "logbucket" {
		return d.deleteLogBucket(capability, environment, providerID)
	}
	if service == "auditlogs" {
		return d.deleteAuditLogs(capability, environment, providerID)
	}
	if service == "scc" {
		return d.deleteSCC(capability, environment, providerID)
	}
	if service == "vertexai" {
		return d.deleteVertexAI(capability, environment, providerID)
	}
	if service == "cloudrun" {
		return d.deleteCloudRun(capability, environment, providerID)
	}
	if service == "gcs" {
		return d.deleteGCS(capability, environment, providerID)
	}
	if service == "secretmanager" {
		return d.deleteSecret(capability, environment, providerID)
	}
	if service == "cloudkms" {
		return d.deleteKMS(capability, environment, providerID)
	}
	if service == "clouddns" {
		return d.deleteCloudDNS(capability, environment, providerID)
	}
	if service == "clouddnsrecord" {
		return d.deleteCloudDNSRecord(capability, environment, providerID)
	}
	if service == "iambinding" {
		return d.deleteIAMBinding(capability, environment, providerID)
	}
	if service == "customrole" {
		return d.deleteCustomRole(capability, environment, providerID)
	}
	if service == "monitoring" {
		return d.deleteAlertPolicy(capability, environment, providerID)
	}
	if service == "dashboard" {
		return d.deleteDashboard(capability, environment, providerID)
	}
	if service == "uptime" {
		return d.deleteUptimeCheck(capability, environment, providerID)
	}
	if service == "logmetric" {
		return d.deleteLogMetric(capability, environment, providerID)
	}
	if service == "gce" {
		return d.deleteGCEInstance(capability, environment, providerID)
	}
	if service == "pd" {
		return d.deletePD(capability, environment, providerID)
	}
	if service == "mig" {
		return d.deleteMIG(capability, environment, providerID)
	}
	if !provider.CanAuthor("gcp", service) {
		// Deleting an image groundhold never created would destroy something a
		// pipeline owns, on the strength of a record we only ever read.
		return provider.CreateResult{Status: "failed", Reason: errWitnessOnlyGCP(service).Error()}
	}
	if service == "artifactregistry" {
		return d.deleteARRepo(capability, environment, providerID)
	}
	if service == "firestore" {
		return d.deleteFirestore(capability, environment, providerID)
	}
	if service == "managedkafka" {
		return d.deleteManagedKafka(capability, environment, providerID)
	}
	if service == "cloudarmor" {
		return d.deleteArmor(capability, environment, providerID)
	}
	if service == "certmanager" {
		return d.deleteCertManager(capability, environment, providerID)
	}
	if service == "cloudrunjobs" {
		return d.deleteCloudRunJob(capability, environment, providerID)
	}
	if service == "serviceaccount" {
		return d.deleteGServiceAccount(capability, environment, providerID)
	}
	if service == "bigquery" {
		return d.deleteBigQuery(capability, environment, providerID)
	}
	if service == "cloudscheduler" {
		return d.deleteCloudScheduler(capability, environment, providerID)
	}
	if service == "vpngateway" {
		return d.deleteCloudVPN(capability, environment, providerID)
	}
	if service == "backupvault" {
		return d.deleteBackupDR(capability, environment, providerID)
	}
	if service == "assetfeed" {
		return d.deleteAssetFeed(capability, environment, providerID)
	}
	if service == "loadbalancer" {
		return d.deleteLoadBalancer(capability, environment, providerID)
	}
	if service == "vpc" {
		return d.deleteVPC(capability, environment, providerID)
	}
	if service == "cloudfunctions" {
		return d.deleteCloudFunction(capability, environment, providerID)
	}
	if service == "cloudfunctions-fn" {
		return d.deleteCloudFunctionFn(capability, environment, providerID)
	}
	if service == "pubsub-queue" {
		return d.deletePubSubQueue(capability, environment, providerID)
	}
	if service == "pubsub-topic" {
		return d.deletePubSub(capability, environment, providerID)
	}
	if service == "memorystore" {
		return d.deleteMemorystore(capability, environment, providerID)
	}
	if service == "filestore" {
		return d.deleteFilestore(capability, environment, providerID)
	}
	project, region, name, err := splitProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/instances/%s", d.BaseURL, project, name), nil)
	if err != nil {
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read failed: %v", err)}
	}
	if status == 404 {
		// already gone — deleting is idempotent on absence
		return provider.CreateResult{ProviderID: providerID,
			Status: "succeeded"}
	}
	if status != 200 {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("pre-delete read: HTTP %d", status)}
	}
	current := map[string]any{}
	if err := json.Unmarshal(body, &current); err != nil {
		return provider.CreateResult{Status: "failed",
			Reason: "pre-delete read unparseable"}
	}
	if !ownedBy(current, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "instance labels do not match — refusing to delete " +
				"a resource that is not ours"}
	}
	settings, _ := current["settings"].(map[string]any)
	if dp, has := settings["deletionProtectionEnabled"]; has {
		prot, ok := dp.(bool)
		if !ok {
			// present but not a bool (e.g. the API returns "true" as a string):
			// refuse rather than collapse to false in the dangerous direction —
			// the create side already refuses a non-bool for this exact reason.
			return provider.CreateResult{Status: "failed",
				Reason: "deletionProtectionEnabled is present but not a boolean — " +
					"refusing to delete on an ambiguous protection flag"}
		}
		if prot {
			return provider.CreateResult{Status: "failed",
				Reason: "deletion protection is enabled — lift it explicitly " +
					"first; it is never auto-disabled"}
		}
	}

	status, respBody, err := d.call("DELETE", fmt.Sprintf(
		"%s/projects/%s/instances/%s", d.BaseURL, project, name), nil)
	if err != nil {
		// a lost delete response (D29) — the delete may have landed; keep the
		// pinned handle so reconcile/resume can conclude it, never drop it.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if status >= 400 {
		res := mutationResult("delete", status, respBody)
		if res.Status == "unknown" {
			res.ProviderID = providerID
		}
		return res
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(respBody, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollOperation(op.Name, name, region)
	if res.Status == "succeeded" {
		res.ProviderID = providerID
	}
	return res
}

func ownedBy(inst map[string]any, capability, environment string) bool {
	settings, _ := inst["settings"].(map[string]any)
	labels, _ := settings["userLabels"].(map[string]any)
	capLabel, _ := labels["groundhold-capability"].(string)
	envLabel, _ := labels["groundhold-environment"].(string)
	// sanitized on write (cloudsql.go), so compare sanitized — the identical
	// transform on write and read is the ownership invariant (AUTHORING.md).
	return capLabel == sanitizeLabel(capability) && envLabel == sanitizeLabel(environment)
}

// gcpName bounds every providerId component to the GCP identifier
// charset (lowercase alnum + hyphen). This is a SECURITY boundary, not
// cosmetics: the components are interpolated into sqladmin REST paths,
// and providerIds can enter through adopt/hints/forged-ledger routes —
// a component containing '/', '.', '?', '#' or '%' could rewrite the
// path or redirect the call (confused deputy). Reject before use.
var gcpName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,79}$`)

// bucketNameOK bounds a GCS bucket name (D77): lowercase alnum, '.', '_', '-',
// start/end alnum, 3-63 chars — accepts real bucket names while keeping '/',
// ':', '%' and leading dots out of the REST path (D73 boundary).
var bucketNameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)

func splitProviderID(providerID string) (string, string, string, error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf(
			"providerId %q is not project:region:name", providerID)
	}
	for i, p := range parts {
		if !gcpName.MatchString(p) {
			return "", "", "", fmt.Errorf(
				"providerId component %d (%q) is not a valid GCP "+
					"identifier — refusing to interpolate it into an API "+
					"path", i, p)
		}
	}
	return parts[0], parts[1], parts[2], nil
}
