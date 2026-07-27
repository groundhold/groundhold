// Multi-service receipt reconciliation (D76 generalization). `resume` concludes a
// PENDING receipt read-only via Reconcile(capability, environment, receipt). Cloud
// SQL keeps its bespoke path (driver.go, reconcileCloudSQL — pinned by tests); every
// OTHER GCP service is concluded HERE by a uniform algorithm parameterized per service
// with a small adapter (a resource probe + optional deterministic-id rebuild + optional
// google-LRO base). The verdict ladder mirrors Cloud SQL and the AWS reconciler:
//
//	succeeded  ONLY when the resource is found, terminal-ready AND ours;
//	failed     on a foreign-owned resource (create) or a still-present resource (delete)
//	           or a terminal-error operation;
//	unknown    on anything unreadable/still-provisioning/ambiguous — a create whose
//	           resource is absent is unknown (it may have failed OR not yet be visible;
//	           never guessed), exactly as Cloud SQL concludes it.
//
// STRICTLY READ-ONLY: a reconciler that mutates is a bug. NEVER fabricate a conclusion.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// genProbe is the read-only existence/ownership/readiness signal, uniform across
// services. `reason` explains an !readable outcome (a transient read, a malformed or
// cross-project pid) so the pending receipt carries an honest hint.
type genProbe struct {
	readable bool // could the API be read at all (false => transient/unknown)
	found    bool // resource present (meaningful only when readable)
	ours     bool // ownership marker matches (meaningful only when found)
	ready    bool // terminal-good state (meaningful only when found & ours)
	reason   string
}

func probeUnreadable(reason string) genProbe { return genProbe{reason: reason} }

// reconcileAdapter is the per-service plug into the generic reconciler.
type reconcileAdapter struct {
	// probe reads the resource named by pid and reports existence/ownership/readiness.
	probe func(d *Driver, capability, environment, pid string) genProbe
	// createPID rebuilds the DETERMINISTIC providerId for a create whose receipt did
	// not persist one (a receipt written before the id was captured). ok=false when the
	// id depends on user attrs (region/location) or is server-assigned — then a create
	// with no persisted id stays unknown, never guessed.
	createPID func(d *Driver, environment, capability string, gen int) (string, bool)
	// lroBase returns the base URL of a google-style long-running operation poll
	// (GET base+"/"+op; {"done":bool,"error":{"message":...}}). nil => no LRO-first
	// (conclude by the authoritative resource read only — correct, just less able to
	// distinguish a genuinely-failed create from a not-yet-visible one).
	lroBase func(d *Driver) string
	// serverAssignedHint, when set, is the reason a create with no persisted providerId
	// cannot be concluded (the id is assigned by the API and was lost with the response).
	serverAssignedHint string
}

// Reconcile dispatches on the receipt's target service (D76). Cloud SQL keeps its
// pinned bespoke path; every other service is concluded by the generic reconciler.
// An unwired service fails CLOSED to unknown — never a fabricated verdict.
func (d *Driver) Reconcile(capability, environment string,
	receipt map[string]any) provider.ReconcileResult {
	rtgt, _ := receipt["target"].(string)
	svc := serviceFromTarget(rtgt)
	if svc == "cloudsql" {
		return d.reconcileCloudSQL(capability, environment, receipt)
	}
	ad, ok := reconcileAdapters[svc]
	if !ok {
		return provider.ReconcileResult{Status: "unknown",
			Reason: fmt.Sprintf("reconcile for service %q is not wired — reconcile manually", svc)}
	}
	return d.reconcileGeneric(capability, environment, svc, receipt, ad)
}

// reconcileGeneric runs the uniform verdict ladder for a non-Cloud-SQL service.
func (d *Driver) reconcileGeneric(capability, environment, svc string,
	receipt map[string]any, ad reconcileAdapter) provider.ReconcileResult {
	op, _ := receipt["operation"].(string)
	pinned, _ := receipt["targetProviderId"].(string)

	// LRO-first (google style): when the real operation name survived, the operation is
	// the freshest authority. A DONE+error op is a definitive failure; a still-running op
	// is unknown; a 404 op has expired past its retention window (the resource NAME
	// outlives it) so we fall through to the resource read; a transient read is unknown.
	if pop, _ := receipt["providerOperation"].(string); pop != "" && ad.lroBase != nil {
		switch kind, reason := d.googleLROReconcile(ad.lroBase(d), pop); kind {
		case lroFailed:
			return provider.ReconcileResult{Status: "failed", Reason: reason}
		case lroRunning, lroTransient:
			return provider.ReconcileResult{Status: "unknown", Reason: reason}
		case lroDone, lroGone:
			// fall through to the resource read
		}
	}

	switch op {
	case "delete":
		if pinned == "" {
			return provider.ReconcileResult{Status: "unknown",
				Reason: "delete receipt carries no targetProviderId — reconcile manually"}
		}
		pr := ad.probe(d, capability, environment, pinned)
		switch {
		case !pr.readable:
			return provider.ReconcileResult{Status: "unknown",
				Reason: reasonOr(pr.reason, "the delete target gave no answer — cannot conclude; retry resume")}
		case !pr.found:
			// tied to the pinned target: an absent resource IS the delete succeeding.
			return provider.ReconcileResult{Status: "succeeded", ProviderID: pinned}
		default:
			return provider.ReconcileResult{Status: "failed",
				Reason: fmt.Sprintf("%s still exists — the delete never completed", pinned)}
		}
	case "update":
		if pinned == "" {
			return provider.ReconcileResult{Status: "unknown",
				Reason: "update receipt carries no targetProviderId — reconcile manually"}
		}
		pr := ad.probe(d, capability, environment, pinned)
		switch {
		case !pr.readable:
			return provider.ReconcileResult{Status: "unknown",
				Reason: reasonOr(pr.reason, "the update target gave no answer — cannot conclude; retry resume")}
		case !pr.found:
			return provider.ReconcileResult{Status: "unknown",
				Reason: fmt.Sprintf("%s not found — the update's target vanished; re-observe "+
					"before concluding anything", pinned)}
		case !pr.ours:
			return provider.ReconcileResult{Status: "failed",
				Reason: fmt.Sprintf("%s exists and is not ours (ownership marker mismatch)", pinned)}
		default:
			// D72: conclude by MEASURING the pinned desired values against the live
			// reverse mapping — ownership already validated at the pinned pid, and
			// Observe's own sameProject guard neutralizes a forged project component.
			return d.reconcileUpdateByValues(capability, pinned, receipt)
		}
	default: // create
		pid := pinned
		if pid == "" {
			if ad.createPID != nil {
				gen := receiptGenerationGCP(receipt)
				if rebuilt, ok := ad.createPID(d, environment, capability, gen); ok {
					pid = rebuilt
				}
			}
		}
		if pid == "" {
			hint := ad.serverAssignedHint
			if hint == "" {
				hint = "the create receipt persisted no providerId and the id is not " +
					"recomputable from the receipt (region/location is a user attribute) — " +
					"re-observe the capability, then retry"
			}
			return provider.ReconcileResult{Status: "unknown", Reason: hint}
		}
		return concludeGenericCreate(pid, ad.probe(d, capability, environment, pid))
	}
}

// concludeGenericCreate maps a create probe to a verdict. succeeded ONLY when the
// resource is found, ours AND terminal-ready; a foreign-owned resource is failed; an
// absent, still-provisioning or unreadable resource is unknown (never guessed).
func concludeGenericCreate(pid string, pr genProbe) provider.ReconcileResult {
	switch {
	case !pr.readable:
		return provider.ReconcileResult{Status: "unknown",
			Reason: reasonOr(pr.reason, "the resource read gave no answer — cannot conclude the pending create; retry resume")}
	case !pr.found:
		return provider.ReconcileResult{Status: "unknown",
			Reason: fmt.Sprintf("%s not found — the create may have failed or is not yet "+
				"visible; retry resume or check the operation log", pid)}
	case !pr.ours:
		return provider.ReconcileResult{Status: "failed",
			Reason: fmt.Sprintf("%s exists and is not ours (ownership marker mismatch) — "+
				"adopt is an explicit action, not a reconcile", pid)}
	case !pr.ready:
		return provider.ReconcileResult{Status: "unknown",
			Reason: fmt.Sprintf("%s exists and is ours but is not yet in a terminal-ready "+
				"state — still provisioning; retry resume once it settles", pid)}
	default:
		return provider.ReconcileResult{Status: "succeeded", ProviderID: pid}
	}
}

func reasonOr(reason, fallback string) string {
	if reason != "" {
		return reason
	}
	return fallback
}

// receiptGenerationGCP reads the receipt's generation tolerantly (ledger events
// round-trip through JSON; a whole float can reach us unnormalized). Missing => 1.
func receiptGenerationGCP(receipt map[string]any) int {
	switch g := receipt["generation"].(type) {
	case int:
		if g >= 1 {
			return g
		}
	case float64:
		if g >= 1 {
			return int(g)
		}
	}
	return 1
}

type lroKind int

const (
	lroDone lroKind = iota // DONE with no error — fall through to resource read
	lroGone                // operation expired (404) — name outlives it, fall through
	lroRunning
	lroFailed
	lroTransient
)

// googleLROReconcile polls a google-style long-running operation
// (GET base+"/"+op; {"done":bool,"error":{"message":...}}). A DONE op with ANY non-nil
// error is a failure; a 404 means the op expired (fall through to the name read); a
// transport error or non-2xx is transient (unknown — do NOT guess a verdict).
func (d *Driver) googleLROReconcile(base, opName string) (lroKind, string) {
	status, body, err := d.call("GET", base+"/"+opName, nil)
	switch {
	case err == nil && status == http.StatusOK:
		var op struct {
			Done  bool `json:"done"`
			Error *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &op) == nil && op.Done {
			if op.Error != nil {
				msg := op.Error.Message
				if msg == "" {
					msg = "unspecified"
				}
				return lroFailed, fmt.Sprintf("operation %s concluded with error: %s", opName, msg)
			}
			return lroDone, ""
		}
		return lroRunning, fmt.Sprintf("operation %s still running", opName)
	case err == nil && status == http.StatusNotFound:
		return lroGone, ""
	default:
		return lroTransient, fmt.Sprintf("operation %s read failed (HTTP %d) — retry reconcile", opName, status)
	}
}

// ownsLabels is the common label ownership predicate.
func ownsLabels(labels map[string]string, capability, environment string) bool {
	return labels["groundhold-capability"] == sanitizeLabel(capability) &&
		labels["groundhold-environment"] == sanitizeLabel(environment)
}

// reconcileAdapters wires EVERY non-Cloud-SQL GCP service into the generic reconciler.
// Ownership is labels for most; a description/displayName marker for the label-less
// services; a deterministic name/member (found-implies-ours) for the content-addressed
// ones. The five server-assigned-id services conclude a create only from a persisted id.
var reconcileAdapters = map[string]reconcileAdapter{

	// ---- label ownership, async (google LRO) ----
	"memorystore": {
		lroBase: func(d *Driver) string { return d.memorystoreBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, region, name, err := splitGRedisProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getRedis(project, region, name)
			if rerr != nil {
				return probeUnreadable("cache instance read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours:  found && ownsLabels(doc.Labels, cap, env),
				ready: doc.State == "" || doc.State == "READY"}
		},
	},
	"artifactregistry": {
		lroBase: func(d *Driver) string { return d.arBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, region, repoID, err := splitGARProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getARRepo(project, region, repoID)
			if rerr != nil {
				return probeUnreadable("repository read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.Labels, cap, env), ready: true}
		},
	},
	"filestore": {
		lroBase: func(d *Driver) string { return d.filestoreBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, name, err := splitFilestoreProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getFilestore(project, location, name)
			if rerr != nil {
				return probeUnreadable("filestore instance read gave no answer: " + rerr.Error())
			}
			// terminal-good is State=="READY"; CREATING/REPAIRING/ERROR are not ready
			// (still-provisioning or failed) → unknown, never a fabricated succeeded.
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.Labels, cap, env), ready: doc.State == "READY"}
		},
	},
	"managedkafka": {
		lroBase: func(d *Driver) string { return d.managedKafkaBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, cluster, err := splitManagedKafkaProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getManagedKafka(project, location, cluster)
			if rerr != nil {
				return probeUnreadable("kafka cluster read gave no answer: " + rerr.Error())
			}
			// terminal-good is State=="ACTIVE"; CREATING is not ready → unknown.
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.Labels, cap, env), ready: doc.State == "ACTIVE"}
		},
	},
	"certmanager": {
		lroBase: func(d *Driver) string { return d.certManagerBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, certID, err := splitCertManagerProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getCertManager(project, location, certID)
			if rerr != nil {
				return probeUnreadable("certificate read gave no answer: " + rerr.Error())
			}
			// terminal-good is managed.state=="ACTIVE"; PROVISIONING/FAILED are not
			// ready → unknown, never a fabricated succeeded for an unissued cert.
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.Labels, cap, env), ready: doc.Managed.State == "ACTIVE"}
		},
	},
	"cloudrunjobs": {
		lroBase: func(d *Driver) string { return d.runBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, region, name, err := splitCloudRunJobProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getCloudRunJob(project, region, name)
			if rerr != nil {
				return probeUnreadable("job read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.Labels, cap, env), ready: true}
		},
	},
	"backupvault": {
		lroBase: func(d *Driver) string { return d.backupDRBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, vaultID, err := splitBackupDRProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.backupDRGet(project, location, vaultID)
			if rerr != nil {
				return probeUnreadable("backup vault read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && doc.ours(cap, env), ready: true}
		},
	},
	"backupplan": {
		lroBase: func(d *Driver) string { return d.backupDRBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, planID, err := splitGbpProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.gbpGet(project, location, planID)
			if rerr != nil {
				return probeUnreadable("backup plan read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && doc.ours(cap, env), ready: true}
		},
	},

	// ---- label ownership, sync ----
	"secretmanager": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return gsecretProviderID(d.Project, resourceName(d.Project, env, cap, gen, 255)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, name, err := splitGSecretProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getSecret(project, name)
			if rerr != nil {
				return probeUnreadable("secret read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.Labels, cap, env), ready: true}
		},
	},
	"clouddns": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return gdnsProviderID(d.Project, resourceName(d.Project, env, cap, gen, 63)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, zone, err := splitGDNSProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getDNSZone(project, zone)
			if rerr != nil {
				return probeUnreadable("managed zone read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.Labels, cap, env), ready: true}
		},
	},
	"cloudkms": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, ring, key, err := splitGKMSProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getCryptoKey(project, location, ring, key)
			if rerr != nil {
				return probeUnreadable("crypto key read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.Labels, cap, env), ready: true}
		},
	},
	"bigquery": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return bqProviderID(d.Project, BQDatasetID(d.Project, env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, datasetID, err := splitBQProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.bqGetDataset(project, datasetID)
			if rerr != nil {
				return probeUnreadable("dataset read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && doc.ours(cap, env), ready: true}
		},
	},

	// ---- label ownership, sync/async, 404-collapsing gets (found == readable) ----
	"cloudrun": {
		lroBase: func(d *Driver) string { return d.runBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, region, name, err := splitRunProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			ours, _, found, rerr := d.runGetService(project, region, name, cap, env)
			if rerr != nil {
				return probeUnreadable("service read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			return genProbe{readable: true, found: true, ours: ours, ready: true}
		},
	},
	"cloudfunctions": {
		lroBase: func(d *Driver) string { return d.cfBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, region, name, err := splitFunctionProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, rerr := d.getFunction(project, region, name)
			if rerr != nil {
				return probeUnreadable("function read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: true,
				ours: ownsLabels(doc.Labels, cap, env), ready: true}
		},
	},
	"cloudfunctions-fn": {
		lroBase: func(d *Driver) string { return d.cfBase() },
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, region, name, err := splitFnServerlessProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, rerr := d.getFnServerless(project, region, name)
			if rerr != nil {
				return probeUnreadable("function read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: true,
				ours: ownsLabels(doc.Labels, cap, env), ready: true}
		},
	},
	"gcs": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return gcsProviderID(d.Project, BucketName(d.Project, env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, name, err := splitGcsProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			ours, _, found, rerr := d.gcsGetBucket(name, cap, env)
			if rerr != nil {
				return probeUnreadable("bucket read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			return genProbe{readable: true, found: true, ours: ours, ready: true}
		},
	},
	"pubsub-topic": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return pubsubProviderID(d.Project, TopicName(d.Project, env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, name, err := splitPubSubProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			ours, _, found, rerr := d.pubsubGetTopic(name, cap, env)
			if rerr != nil {
				return probeUnreadable("topic read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			return genProbe{readable: true, found: true, ours: ours, ready: true}
		},
	},
	"pubsub-queue": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return pubsubProviderID(d.Project, QueueName(d.Project, env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, name, err := splitPubSubProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			ours, _, found, rerr := d.pubsubGetSubscription(name, cap, env)
			if rerr != nil {
				return probeUnreadable("subscription read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			return genProbe{readable: true, found: true, ours: ours, ready: true}
		},
	},
	// A DNS record is a SUB-RESOURCE: it has no identity or labels of its own, so
	// ownership is its parent managed zone's. That is the same handle the create and
	// delete paths use — a record inside a zone we own is ours, and a record inside
	// somebody else's zone is not something this contract may claim.
	"clouddnsrecord": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, zone, recordType, name, err := splitGDNSRecProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			owned, oerr := d.recordZoneOwnedByUs(project, zone, cap, env)
			if oerr != nil {
				return probeUnreadable("managed zone read gave no answer: " + oerr.Error())
			}
			_, found, rerr := d.getRecordSet(project, zone, name, recordType)
			if rerr != nil {
				return probeUnreadable("record set read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found, ours: found && owned, ready: true}
		},
	},

	// ---- compute family (D374). Each providerId carries a SCOPE the receipt does
	// not: an instance's zone, a disk's zone-or-region, a group's zone-or-region.
	// So createPID is deliberately absent — a create whose receipt never persisted
	// an id cannot have one rebuilt, and guessing a scope would probe the wrong
	// resource and report a create landed that did not.
	"gce": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, zone, name, err := splitGCEProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getGCEInstance(project, zone, name)
			if rerr != nil {
				return probeUnreadable("instance read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			return genProbe{readable: true, found: true,
				ours: ownsLabels(doc.Labels, cap, env),
				// A machine still provisioning is not a concluded create: RUNNING is
				// the terminal-good state the create path itself waits for.
				ready: doc.Status == "" || doc.Status == "RUNNING"}
		},
	},
	"pd": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, scope, name, err := splitPDProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getPD(project, scope, name)
			if rerr != nil {
				return probeUnreadable("disk read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			return genProbe{readable: true, found: true,
				ours: ownsLabels(doc.Labels, cap, env),
				// READY is terminal-good; a disk still CREATING has not concluded, and
				// on a stateful capability calling that done invites a second disk.
				ready: doc.Status == "" || doc.Status == "READY"}
		},
	},
	"mig": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, scope, name, err := splitMIGProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getMIG(project, scope, name)
			if rerr != nil {
				return probeUnreadable("instance group read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			// A managed instance group carries no labels, so ownership is the
			// description marker — the same handle the create and delete paths use.
			return genProbe{readable: true, found: true,
				ours: markerOurs(doc.Description, cap, env), ready: true}
		},
	},
	"vpc": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, _, name, err := splitVPCProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getNetwork(project, name)
			if rerr != nil {
				return probeUnreadable("network read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			return genProbe{readable: true, found: true,
				ours: markerOurs(doc.Description, cap, env), ready: true}
		},
	},

	// ---- description/displayName marker ownership ----
	"serviceaccount": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return gsaProviderID(d.Project, GServiceAccountID(d.Project, env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, accountID, err := splitGSAProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getGSA(project, accountID)
			if rerr != nil {
				return probeUnreadable("service account read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && markerOurs(doc.Description, cap, env), ready: true}
		},
	},
	"cloudscheduler": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, jobID, err := splitSchedProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.schedGetJob(project, location, jobID)
			if rerr != nil {
				return probeUnreadable("scheduler job read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && markerOurs(doc.Description, cap, env), ready: true}
		},
	},
	"vpngateway": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, region, name, err := splitCloudVPNProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.cloudVPNGet(project, region, name)
			if rerr != nil {
				return probeUnreadable("vpn gateway read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && markerOurs(doc.Description, cap, env), ready: true}
		},
	},
	"cloudarmor": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return armorProviderID(d.Project, ArmorPolicyName(d.Project, env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, name, err := splitArmorProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			desc, found, rerr := d.computeGet(d.armorURL(project, name))
			if rerr != nil {
				return probeUnreadable("security policy read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			return genProbe{readable: true, found: true,
				ours: markerOurs(desc, cap, env), ready: true}
		},
	},
	"loadbalancer": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, scope, name, err := splitLBProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			desc, found, rerr := d.computeGet(d.lbForwardingRuleURL(project, scope, name))
			if rerr != nil {
				return probeUnreadable("forwarding rule read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			return genProbe{readable: true, found: true,
				ours: markerOurs(desc, cap, env), ready: true}
		},
	},
	"logbucket": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, bucket, err := splitLogBucketProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getLogBucket(project, location, bucket)
			if rerr != nil {
				return probeUnreadable("log bucket read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && doc.Description == logBucketDescription(cap, env), ready: true}
		},
	},
	"auditlogs": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return auditLogsProviderID(d.Project, AuditSinkName(d.Project, env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, sinkName, err := splitAuditLogsProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getAuditSink(project, sinkName)
			if rerr != nil {
				return probeUnreadable("audit sink read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && doc.Description == auditSinkDescription(cap, env), ready: true}
		},
	},
	"logmetric": {
		serverAssignedHint: "the log metric name is author-provided (not derivable from the " +
			"receipt) and no id was persisted — re-observe the capability, then retry",
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, name, err := splitGLogMetricProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getLogMetric(project, name)
			if rerr != nil {
				return probeUnreadable("log metric read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && doc.Description == logMetricDescription(cap, env), ready: true}
		},
	},

	// ---- content-addressed ownership (deterministic name/member => found implies ours) ----
	"customrole": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return gcRoleProviderID(d.Project, gcRoleID(env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, roleID, err := splitGCRoleProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getCustomRole(project, roleID)
			if rerr != nil {
				return probeUnreadable("custom role read gave no answer: " + rerr.Error())
			}
			// a soft-deleted role is absent for our purposes.
			present := found && !doc.Deleted
			return genProbe{readable: true, found: present, ours: present, ready: true}
		},
	},
	"firestore": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return firestoreProviderID(d.Project, FirestoreDatabaseID(d.Project, env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, dbID, err := splitFirestoreProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			_, found, rerr := d.getFirestore(project, dbID)
			if rerr != nil {
				return probeUnreadable("firestore database read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found, ours: found, ready: true}
		},
	},
	"assetfeed": {
		createPID: func(d *Driver, env, cap string, gen int) (string, bool) {
			return assetFeedProviderID(d.Project, AssetFeedID(d.Project, env, cap, gen)), true
		},
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, feedID, err := splitAssetFeedProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			_, found, rerr := d.getAssetFeed(project, feedID)
			if rerr != nil {
				return probeUnreadable("asset feed read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found, ours: found, ready: true}
		},
	},
	"iambinding": {
		serverAssignedHint: "the IAM binding identity (role/member) comes from capability " +
			"attributes not carried in the receipt, and no id was persisted — re-observe, then retry",
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, role, member, err := splitIAMBindingProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			pol, perr := d.crmGetProjectPolicy(project)
			if perr != nil {
				return probeUnreadable("project IAM policy read gave no answer: " + perr.Error())
			}
			present := memberInRole(pol, role, member)
			return genProbe{readable: true, found: present, ours: present, ready: true}
		},
	},
	"gke-workloadidentity": {
		serverAssignedHint: "the workload-identity binding (namespace/service-account) comes " +
			"from capability attributes not carried in the receipt, and no id was persisted — " +
			"re-observe, then retry",
		probe: func(d *Driver, cap, env, pid string) genProbe {
			poolProject, gsaEmail, namespace, serviceAccount, err := splitGKEWIProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			pol, perr := d.saGetIamPolicy(gsaEmail)
			if perr != nil {
				return probeUnreadable("service account IAM policy read gave no answer: " + perr.Error())
			}
			present := memberInRole(pol, wiRole, wiMember(poolProject, namespace, serviceAccount))
			return genProbe{readable: true, found: present, ours: present, ready: true}
		},
	},

	// ---- structural / stateful ----
	"gke": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, cluster, err := splitGKEProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getGKE(project, location, cluster)
			if rerr != nil {
				return probeUnreadable("cluster read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours:  found && ownsLabels(doc.ResourceLabels, cap, env),
				ready: found && gkeHealthy(doc)}
		},
	},
	"gke-addon": {
		serverAssignedHint: "the addon identity (cluster/addon) comes from capability " +
			"attributes/operands not carried in the receipt, and no id was persisted — " +
			"re-observe, then retry",
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, cluster, addon, err := splitGKEAddonProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getGKEAddonCluster(project, location, cluster)
			if rerr != nil {
				return probeUnreadable("host cluster read gave no answer: " + rerr.Error())
			}
			if !found {
				return genProbe{readable: true, found: false}
			}
			enabled, present := gkeAddonRegistry[addon].readEnabled(doc.AddonsConfig)
			// the addon is "created" when it is present AND enabled on the cluster.
			return genProbe{readable: true, found: present && enabled,
				ours: present && enabled, ready: true}
		},
	},
	"scc": {
		probe: func(d *Driver, cap, env, pid string) genProbe {
			scopeType, scopeID, err := splitSCCProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			// SCC is a shared per-parent singleton groundhold CONFIGURES (no owner label);
			// the representative event-threat-detection module answers existence + tier.
			doc, found, rerr := d.getSCCService(scopeType, scopeID, "event-threat-detection")
			if rerr != nil {
				return probeUnreadable("security center service read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found, ours: found,
				ready: doc.EffectiveEnablementState == "ENABLED"}
		},
	},

	// ---- server-assigned id: a create concludes ONLY from a persisted id ----
	"monitoring": {
		serverAssignedHint: serverAssignedCreateHint("alert policy"),
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, policyID, err := splitGAlertProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getAlertPolicy(project, policyID)
			if rerr != nil {
				return probeUnreadable("alert policy read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.UserLabels, cap, env), ready: true}
		},
	},
	"uptime": {
		serverAssignedHint: serverAssignedCreateHint("uptime check"),
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, id, err := splitGUptimeProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getUptimeCheck(project, id)
			if rerr != nil {
				return probeUnreadable("uptime check read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && ownsLabels(doc.UserLabels, cap, env), ready: true}
		},
	},
	"dashboard": {
		serverAssignedHint: serverAssignedCreateHint("dashboard"),
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, id, err := splitGDashProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.getDashboard(project, id)
			if rerr != nil {
				return probeUnreadable("dashboard read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && doc.DisplayName == dashDisplayName(cap, env), ready: true}
		},
	},
	"vertexai": {
		// lroBase is intentionally nil: a func returning "" would enter
		// googleLROReconcile with an empty base (GET "/{op}") and stick at unknown
		// before ever reading the endpoint. nil skips LRO-first straight to the probe.
		serverAssignedHint: serverAssignedCreateHint("vertex ai endpoint"),
		probe: func(d *Driver, cap, env, pid string) genProbe {
			project, location, id, err := splitVertexProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			if err := d.sameProject(project); err != nil {
				return probeUnreadable(err.Error())
			}
			e, found, rerr := d.getVertexEndpoint(project, location, id)
			if rerr != nil {
				return probeUnreadable("endpoint read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && e.ownedBy(cap, env), ready: true}
		},
	},
	"billingbudget": {
		serverAssignedHint: serverAssignedCreateHint("billing budget"),
		probe: func(d *Driver, cap, env, pid string) genProbe {
			// billingbudget identity is billingAccountID:budgetID — no project component.
			billingAccountID, budgetID, err := splitBillingBudgetProviderID(pid)
			if err != nil {
				return probeUnreadable(err.Error())
			}
			doc, found, rerr := d.billingBudgetGet(billingAccountID, budgetID)
			if rerr != nil {
				return probeUnreadable("billing budget read gave no answer: " + rerr.Error())
			}
			return genProbe{readable: true, found: found,
				ours: found && billingBudgetOurs(doc.DisplayName, env, cap), ready: true}
		},
	},
}

// serverAssignedCreateHint is the honest refusal shared by the server-assigned-id
// services when a create receipt persisted no providerId (the id is assigned by the
// API and was lost with the response) — reconcile by displayName manually.
func serverAssignedCreateHint(what string) string {
	return "the " + what + " id is server-assigned and no providerId was persisted with " +
		"the pending create — reconcile by its groundhold displayName/marker manually, " +
		"then retry"
}
