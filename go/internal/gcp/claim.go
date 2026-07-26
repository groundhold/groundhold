package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// gcp opts into the takeover claim (D140/D14x): once the driver is a Claimer, the
// compiler emits a one-time `claim` for every adopted-but-unclaimed gcp capability
// (compiler.go). Claim STAMPS groundhold's ownership marker on the adopted resource so
// a later drift pre-read recognises it as ours — closing the orphan gap (Q5) where
// a converged no-op falsely certified takeover, the operator ran `terraform state
// rm`, and a subsequent drift found no marker and refused "not ours".
var _ provider.Claimer = (*Driver)(nil)

// Claim dispatches per service (D76, fail-closed). Cloud SQL is the proven path: a
// read-modify-write label merge that ADDS groundhold's labels without clobbering the
// operator's. A service groundhold cannot yet claim refuses HONESTLY (failed), which
// stops the converge before the takeover signal — so an unclaimable resource stays
// externally owned rather than orphaned (a failed claim is safer than a silent one).
func (d *Driver) Claim(service, capability, environment, providerID string) provider.CreateResult {
	if err := d.requireService(service); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	switch service {
	case "cloudsql":
		return d.claimCloudSQL(capability, environment, providerID)
	case "gcs":
		return d.claimGCS(capability, environment, providerID)
	case "pubsub-topic":
		return d.claimPubSubTopic(capability, environment, providerID)
	case "pubsub-queue":
		return d.claimPubSubQueue(capability, environment, providerID)
	case "secretmanager":
		return d.claimSecretManager(capability, environment, providerID)
	case "bigquery":
		return d.claimBigQuery(capability, environment, providerID)
	case "clouddns":
		return d.claimCloudDNS(capability, environment, providerID)
	case "artifactregistry":
		return d.claimArtifactRegistry(capability, environment, providerID)
	case "cloudkms":
		return d.claimKMS(capability, environment, providerID)
	case "monitoring":
		return d.claimAlertPolicy(capability, environment, providerID)
	case "uptime":
		return d.claimUptime(capability, environment, providerID)
	case "memorystore":
		return d.claimMemorystore(capability, environment, providerID)
	case "filestore":
		return d.claimFilestore(capability, environment, providerID)
	case "managedkafka":
		return d.claimManagedKafka(capability, environment, providerID)
	case "certmanager":
		return d.claimCertManager(capability, environment, providerID)
	case "cloudfunctions":
		return d.claimCloudFunction(capability, environment, providerID)
	case "backupvault":
		return d.claimBackupVault(capability, environment, providerID)
	case "backupplan":
		return d.claimBackupPlanGCP(capability, environment, providerID)
	case "cloudrun":
		return d.claimCloudRun(capability, environment, providerID)
	case "cloudrunjobs":
		return d.claimCloudRunJob(capability, environment, providerID)
	default:
		// Ownership-by-DESCRIPTION/NAME services (dashboard, cloudarmor,
		// vpngateway, cloudscheduler, logmetric, iambinding, customrole,
		// serviceaccount, firestore, vpc, assetfeed, loadbalancer) carry no
		// groundhold LABELS to merge — a label claim would be a no-op lie. They
		// refuse HONESTLY: the resource stays externally owned until a
		// marker-appropriate claim is wired.
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("gcp cannot yet claim ownership of a %q resource — "+
				"it stays externally owned; adoption is not takeover for this service "+
				"until claim is wired", service)}
	}
}

// claimCloudSQL stamps groundhold's ownership labels on an adopted instance. It READS
// the current userLabels + settingsVersion and patches back the UNION, so the
// operator's existing labels survive (a full-map patch would clobber them). Four-
// valued: an ambiguous outcome is unknown WITH the providerId (never a silent
// success), a vanished instance or a settings conflict is a clean failure.
func (d *Driver) claimCloudSQL(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	url := fmt.Sprintf("%s/projects/%s/instances/%s", d.BaseURL, project, name)

	status, body, err := d.call("GET", url, nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-claim read failed: %v", err)}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{Status: "failed",
			Reason: "instance no longer exists — cannot claim"}
	}
	if status != http.StatusOK {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("pre-claim read: HTTP %d", status)}
	}
	current := map[string]any{}
	if json.Unmarshal(body, &current) != nil {
		return provider.CreateResult{Status: "failed", Reason: "pre-claim read unparseable"}
	}

	// merge groundhold's labels into the existing set (additive; never a clobber).
	settings, _ := current["settings"].(map[string]any)
	labels := map[string]any{}
	if settings != nil {
		if ul, ok := settings["userLabels"].(map[string]any); ok {
			for k, v := range ul {
				labels[k] = v
			}
		}
	}
	labels["groundhold-capability"] = sanitizeLabel(capability)
	labels["groundhold-environment"] = sanitizeLabel(environment)

	patchSettings := map[string]any{"userLabels": labels}
	if settings != nil {
		if sv, ok := settings["settingsVersion"]; ok {
			patchSettings["settingsVersion"] = sv // optimistic concurrency
		}
	}
	st, respBody, err := d.call("PATCH", url, map[string]any{"settings": patchSettings})
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim outcome unknown: %v", err)}
	}
	if st == 409 || st == 412 {
		return provider.CreateResult{Status: "failed",
			Reason: "concurrent settings change (settingsVersion conflict) — re-observe and re-claim"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("claim HTTP %d", st)}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(respBody, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "claim response carried no operation — reconcile"}
	}
	res := d.pollOperation(op.Name, name, region)
	if res.Status == "succeeded" {
		res.ProviderID = providerID // identity survives a claim
	}
	return res
}

// ─── label-merge claim (D145 breadth) ──────────────────────────────────────
//
// Every label-bearing GCP service claims takeover with the SAME shape as Cloud
// SQL: a READ-MODIFY-WRITE label merge. GET the resource, merge groundhold's
// `groundhold-capability`/`groundhold-environment` into the EXISTING label map, and
// PATCH back the UNION. GCP labels are a full-map field, so the read-modify-
// write is mandatory — patching only groundhold's two keys would clobber the
// operator's TF-applied labels (metadata data-loss). Four-valued on the wire:
// a transport error or a 5xx is `unknown` WITH the providerId, a vanished
// resource (404) or a 4xx is a clean `failed`, and success (immediate 2xx, or
// a DONE operation for the LRO patches) carries the providerId — identity
// survives a claim. The claim deliberately does NOT gate on prior ownership:
// the whole point is to stamp a resource that currently carries the operator's
// labels, not ours.

func failedClaim(err error) provider.CreateResult {
	return provider.CreateResult{Status: "failed", Reason: err.Error()}
}

// claimFetchLabels GETs the resource and returns the existing top-level label
// map at `field` (typically "labels", "userLabels" for the monitoring family)
// with groundhold's ownership keys merged in — additive, never a clobber. On any
// pre-claim read problem it returns a terminal four-valued result instead.
func (d *Driver) claimFetchLabels(providerID, getURL, field, capability, environment string) (map[string]any, *provider.CreateResult) {
	status, body, err := d.call("GET", getURL, nil)
	if err != nil {
		r := provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-claim read failed: %v", err)}
		return nil, &r
	}
	if status == http.StatusNotFound {
		r := provider.CreateResult{Status: "failed",
			Reason: "resource no longer exists — cannot claim"}
		return nil, &r
	}
	if status != http.StatusOK {
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("pre-claim read: HTTP %d", status)}
		return nil, &r
	}
	current := map[string]any{}
	if json.Unmarshal(body, &current) != nil {
		r := provider.CreateResult{Status: "failed", Reason: "pre-claim read unparseable"}
		return nil, &r
	}
	return mergeGroundholdLabels(current[field], capability, environment), nil
}

// mergeGroundholdLabels copies an existing label map (if any) and stamps groundhold's
// ownership keys over it — the additive union that survives the operator's labels.
func mergeGroundholdLabels(existing any, capability, environment string) map[string]any {
	labels := map[string]any{}
	if ex, ok := existing.(map[string]any); ok {
		for k, v := range ex {
			labels[k] = v
		}
	}
	labels["groundhold-capability"] = sanitizeLabel(capability)
	labels["groundhold-environment"] = sanitizeLabel(environment)
	return labels
}

// finishLabelClaim maps a label PATCH outcome onto the four-valued contract. For
// immediate-patch services poll is nil (a 2xx is the confirmation); for LRO-patch
// services poll drives the returned operation to DONE like Cloud SQL.
func (d *Driver) finishLabelClaim(providerID string, status int, respBody []byte,
	callErr error, poll func(opName string) provider.CreateResult) provider.CreateResult {
	if callErr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim outcome unknown: %v", callErr)}
	}
	if status == 409 || status == 412 {
		return provider.CreateResult{Status: "failed",
			Reason: "concurrent change (precondition/version conflict) — re-observe and re-claim"}
	}
	if status >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("claim HTTP %d (server error) — reconcile", status)}
	}
	if status >= 400 {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("claim HTTP %d", status)}
	}
	if poll == nil {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(respBody, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "claim response carried no operation — reconcile"}
	}
	res := poll(op.Name)
	if res.Status == "succeeded" {
		res.ProviderID = providerID // identity survives a claim
	}
	return res
}

// ─── immediate-patch services (2xx confirms) ───────────────────────────────

// claimGCS: buckets.patch of `labels`, guarded by ifMetagenerationMatch so a
// concurrent change surfaces as a 412 conflict instead of a lost update. GCS
// uses the service-prefixed providerId (gcs:project:name).
func (d *Driver) claimGCS(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitGcsProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.bucketURL(name)
	status, body, err := d.call("GET", url, nil)
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-claim read failed: %v", err)}
	}
	if status == http.StatusNotFound {
		return provider.CreateResult{Status: "failed", Reason: "bucket no longer exists — cannot claim"}
	}
	if status != http.StatusOK {
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("pre-claim read: HTTP %d", status)}
	}
	doc := map[string]any{}
	if json.Unmarshal(body, &doc) != nil {
		return provider.CreateResult{Status: "failed", Reason: "pre-claim read unparseable"}
	}
	labels := mergeGroundholdLabels(doc["labels"], capability, environment)
	patchURL := url
	if mg, _ := doc["metageneration"].(string); mg != "" {
		patchURL = url + "?ifMetagenerationMatch=" + mg
	}
	st, resp, err := d.call("PATCH", patchURL, map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// claimPubSubTopic: topics.patch takes a WRAPPED body ({topic:{name,labels},
// updateMask:"labels"}), unlike the query-mask services. Synchronous (2xx).
func (d *Driver) claimPubSubTopic(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitPubSubProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.topicURL(project, name)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	body := map[string]any{
		"topic":      map[string]any{"name": "projects/" + project + "/topics/" + name, "labels": labels},
		"updateMask": "labels",
	}
	st, resp, err := d.call("PATCH", url, body)
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// claimPubSubQueue: subscriptions.patch, same wrapped-body shape as topics.
func (d *Driver) claimPubSubQueue(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitPubSubProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.subscriptionURL(project, name)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	body := map[string]any{
		"subscription": map[string]any{"name": "projects/" + project + "/subscriptions/" + name, "labels": labels},
		"updateMask":   "labels",
	}
	st, resp, err := d.call("PATCH", url, body)
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// claimSecretManager: secrets.patch?updateMask=labels, body {labels}. Synchronous.
func (d *Driver) claimSecretManager(capability, environment, providerID string) provider.CreateResult {
	project, name, err := splitGSecretProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := fmt.Sprintf("%s/projects/%s/secrets/%s", d.secretBase(), project, name)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// claimBigQuery: datasets.patch merges the sent `labels` server-side (HTTP PATCH
// semantics, no updateMask). Synchronous.
func (d *Driver) claimBigQuery(capability, environment, providerID string) provider.CreateResult {
	project, datasetID, err := splitBQProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.bqDatasetURL(project, datasetID)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url, map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// claimCloudDNS: managedZones.patch, body {labels}. Handled as immediate (the
// driver already treats DNS managedZones mutations synchronously — no create-LRO
// poll exists), so a 2xx is the confirmation.
func (d *Driver) claimCloudDNS(capability, environment, providerID string) provider.CreateResult {
	project, zone, err := splitGDNSProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := fmt.Sprintf("%s/projects/%s/managedZones/%s", d.dnsBase(), project, zone)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url, map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// claimArtifactRegistry: repositories.patch?updateMask=labels returns the
// Repository synchronously (unlike the create, which is an LRO).
func (d *Driver) claimArtifactRegistry(capability, environment, providerID string) provider.CreateResult {
	project, region, repoID, err := splitGARProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := fmt.Sprintf("%s/projects/%s/locations/%s/repositories/%s", d.arBase(), project, region, repoID)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// claimAlertPolicy: the monitoring family marks ownership with `userLabels`
// (not `labels`). alertPolicies.patch?updateMask=userLabels, synchronous.
func (d *Driver) claimAlertPolicy(capability, environment, providerID string) provider.CreateResult {
	project, policyID, err := splitGAlertProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := fmt.Sprintf("%s/projects/%s/alertPolicies/%s", d.monitoringBase(), project, policyID)
	labels, term := d.claimFetchLabels(providerID, url, "userLabels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=userLabels", map[string]any{"userLabels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// claimUptime: uptimeCheckConfigs.patch?updateMask=userLabels, synchronous.
func (d *Driver) claimUptime(capability, environment, providerID string) provider.CreateResult {
	project, id, err := splitGUptimeProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := fmt.Sprintf("%s/projects/%s/uptimeCheckConfigs/%s", d.uptimeBase(), project, id)
	labels, term := d.claimFetchLabels(providerID, url, "userLabels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=userLabels", map[string]any{"userLabels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// claimKMS: cryptoKeys.patch?updateMask=labels returns the CryptoKey
// synchronously (KMS key mutations are not LRO).
func (d *Driver) claimKMS(capability, environment, providerID string) provider.CreateResult {
	project, location, ring, key, err := splitGKMSProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.cryptoKeyURL(project, location, ring, key)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, nil)
}

// ─── LRO-patch services (poll the returned operation to DONE) ───────────────

// claimMemorystore: redis instances.patch?updateMask=labels is an LRO.
func (d *Driver) claimMemorystore(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitGRedisProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.redisInstanceURL(project, region, name)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, d.pollRedisOperation)
}

// claimFilestore: file instances.patch?updateMask=labels is an LRO.
func (d *Driver) claimFilestore(capability, environment, providerID string) provider.CreateResult {
	project, location, name, err := splitFilestoreProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.filestoreInstanceURL(project, location, name)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, d.pollFilestoreOperation)
}

// claimManagedKafka: clusters.patch?updateMask=labels is an LRO.
func (d *Driver) claimManagedKafka(capability, environment, providerID string) provider.CreateResult {
	project, location, cluster, err := splitManagedKafkaProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.managedKafkaURL(project, location, cluster)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, d.pollManagedKafkaOperation)
}

// claimCertManager: certificates.patch?updateMask=labels is an LRO.
func (d *Driver) claimCertManager(capability, environment, providerID string) provider.CreateResult {
	project, location, certID, err := splitCertManagerProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.certManagerURL(project, location, certID)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, d.pollCertManagerOperation)
}

// claimCloudFunction: functions.patch?updateMask=labels (gen2) is an LRO.
func (d *Driver) claimCloudFunction(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitFunctionProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.functionURL(project, region, name)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, d.pollFunctionOperation)
}

// claimBackupVault: backupVaults.patch?updateMask=labels is an LRO.
func (d *Driver) claimBackupVault(capability, environment, providerID string) provider.CreateResult {
	project, location, vaultID, err := splitBackupDRProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.backupDRVaultURL(project, location, vaultID)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, d.pollBackupDROperation)
}

// claimBackupPlanGCP: backupPlans.patch?updateMask=labels is an LRO (D76 fala 4).
// The exact sibling of claimBackupVault — the same backupdr label RMW.
func (d *Driver) claimBackupPlanGCP(capability, environment, providerID string) provider.CreateResult {
	project, location, planID, err := splitGbpProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.gbpPlanURL(project, location, planID)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, d.pollBackupDROperation)
}

// claimCloudRun: services.patch?updateMask=labels (Admin v2) is an LRO.
func (d *Driver) claimCloudRun(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitRunProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.runServiceURL(project, region, name)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, d.pollRunOperation)
}

// claimCloudRunJob: jobs.patch?updateMask=labels (Admin v2) is an LRO; it shares
// the Cloud Run operation poller.
func (d *Driver) claimCloudRunJob(capability, environment, providerID string) provider.CreateResult {
	project, region, name, err := splitCloudRunJobProviderID(providerID)
	if err != nil {
		return failedClaim(err)
	}
	if err := d.sameProject(project); err != nil {
		return failedClaim(err)
	}
	url := d.cloudRunJobURL(project, region, name)
	labels, term := d.claimFetchLabels(providerID, url, "labels", capability, environment)
	if term != nil {
		return *term
	}
	st, resp, err := d.call("PATCH", url+"?updateMask=labels", map[string]any{"labels": labels})
	return d.finishLabelClaim(providerID, st, resp, err, d.pollRunOperation)
}
