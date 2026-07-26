// GCP Cloud Audit Logs export request building (D76 parity): the PURE forward map
// of the GCP capability.audit.trail driver — the SAME vocabulary AWS CloudTrail
// fulfils, but GCP is a different animal and this file maps it HONESTLY rather than
// pretending a symmetry that does not exist.
//
// The model (the vocab note: "GCP Cloud Audit Logs (a log sink)"): GCP control-plane
// audit logs are ALWAYS on and project-global — there is no "trail" object to create.
// What an operator GOVERNS is the durable EXPORT of those logs: a Cloud Logging log
// SINK (logging.googleapis.com/v2 projects/{p}/sinks) whose filter selects the audit
// logs and whose destination is a durable ujście (a GCS bucket, a BigQuery dataset,
// a Pub/Sub topic — each a SEPARATE capability the operator owns, D26). The sink is
// the resource this driver stands up; the destination is an operand.
//
// HONEST vocab mapping — several CloudTrail attributes have NO GCP analog on the sink:
//   - location.region: a log sink is a GLOBAL project resource; the audit logs are
//     global. Residency lives in the DESTINATION (bucket/dataset), a separate
//     capability. We accept location.region as a declared residency assertion about
//     that operand (validated), but it does NOT enter the sink body and is NOT
//     observable from the sink — observe OMITS it with a diagnostic (never fabricated).
//   - scope.multiRegion: GCP audit logs are project-global by construction, so a
//     project-level audit sink captures every region. We honor true and REFUSE false
//     (a single-region audit scope is not expressible on GCP) — observe reports true.
//   - integrity.logValidation: GCP has NO CloudTrail log-file-validation equivalent.
//     We REFUSE true (never claim a tamper-evidence guarantee GCP does not provide)
//     and observe OMITS it with an unsupported diagnostic. This is the load-bearing
//     honesty of the whole driver: it is NEVER faked true.
//   - encryption.customerManagedKeys: CMEK lives on the DESTINATION bucket/dataset,
//     not the sink. true requires the operand implementation.kmsKeyName (a reference
//     to a separate capability.key.encryption); it does not enter the sink body and is
//     OMITTED on observe (the destination capability governs it).
//   - delivery.assured: the sink is ENABLED (disabled=false) and forwarding — the true
//     GCP analog of StartLogging/IsLogging. Measured from the live disabled flag,
//     mutable in place via sinks.patch(updateMask=disabled).
//   - service.managed: a managed export vs a self-operated pipeline.
//
// This file is PURE: it validates the shape and REFUSES before any mutation (an
// unmapped attribute, a missing/invalid operand, or an unsupportable guarantee is a
// preflight refusal, never a silent drop); auditlogs_net.go drives the plan over the
// wire. No live GCP validation in this env — code + golden httptest certified.
package gcp

import (
	"fmt"
	"regexp"
)

// auditSinkNameOK bounds a sink id before it is interpolated into a providerId or a
// REST path (D73 boundary): a leading letter, then letters/digits/underscore/hyphen/
// period, <=100 chars. resourceName GENERATES the lowercase alnum+hyphen subset; the
// parser accepts the fuller safe set so a hand-adopted sink is not rejected.
var auditSinkNameOK = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,99}$`)

// auditSinkDestOK bounds the destination operand — one of the four durable ujścia the
// Logging sink API accepts, each a reference to a SEPARATE capability the operator
// owns (never key material, never stood up here). The destination rides in the request
// BODY, but a malformed destination is a malformed contract: refuse it in preflight
// rather than let the API reject it after the lease.
var auditSinkDestOK = regexp.MustCompile(
	`^(storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{1,220}|` +
		`bigquery\.googleapis\.com/projects/[^/ ]+/datasets/[A-Za-z0-9_]+|` +
		`pubsub\.googleapis\.com/projects/[^/ ]+/topics/[A-Za-z0-9._~%+-]{3,255}|` +
		`logging\.googleapis\.com/projects/[^/ ]+/locations/[^/ ]+/buckets/[^/ ]+)$`)

// auditKmsKeyOK bounds the CMEK operand: a Cloud KMS cryptoKey resource name (a
// REFERENCE that NAMES a key on the destination, never key material — D53).
var auditKmsKeyOK = regexp.MustCompile(
	`^projects/[^/ ]+/locations/[^/ ]+/keyRings/[^/ ]+/cryptoKeys/[^/ ]+$`)

// auditSinkFilter selects the Cloud Audit Logs across every audit type (activity,
// data_access, system_event, policy) project-wide — the substring match captures all
// four logName suffixes. This is what makes the sink an AUDIT-log sink specifically
// (the "GCP Cloud Audit Logs" of the vocab note), not a generic log export.
const auditSinkFilter = `logName:"cloudaudit.googleapis.com"`

// AuditSinkName is the deterministic sink id — BOTH the idempotency handle (sinks are
// content-addressed by (project, sinkName), no create idempotency key) AND the recovery
// handle: the providerId is knowable BEFORE the create response (D29). g>=2 (D48
// replacements) coexist via the generation salt.
func AuditSinkName(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 100)
}

// auditSinkDescription is the ownership marker (sinks carry no labels, like log
// metrics): a deterministic description a create 409 / delete / update re-checks so a
// foreign sink at our name is refused, never silently adopted.
func auditSinkDescription(capability, environment string) string {
	return "groundhold-managed " + capability + " (" + environment + ")"
}

// AuditSinkPlan is the attribute+operand-derived shape a create assembles. The sink
// SHAPE (whether it is delivering) is driven by capability attributes; the destination,
// the sink name and the CMEK reference are OPERATOR operands (implementation: block, D26).
type AuditSinkPlan struct {
	Project     string
	Name        string
	Destination string // operand, required — the durable ujście
	Description string
	Disabled    bool   // delivery.assured=false -> disabled=true
	Region      string // location.region: declared residency of the destination (NOT on the sink)
	CMK         bool   // encryption.customerManagedKeys — a destination property, declared here
	KmsKeyName  string // operand, required IFF CMK (a reference to capability.key.encryption)
}

// BuildAuditSink maps capability.audit.trail attributes + implementation operands to a
// plan, or REFUSES. Every error is a preflight refusal (never a half-build): an unmapped
// attribute, an unsupportable guarantee (integrity.logValidation on GCP), a
// single-region audit scope, or a missing/invalid operand is refused here, before the
// first sink mutation (invariant #4, D26). delivery.assured defaults to true — a
// configured-but-disabled sink is a silent audit-export gap, so the sink delivers by
// default unless the contract explicitly asks otherwise.
func BuildAuditSink(project, environment, capability string,
	attrs, impl map[string]any, generation int) (AuditSinkPlan, error) {
	if generation < 1 {
		generation = 1
	}
	if !projectOK.MatchString(project) {
		return AuditSinkPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	p := AuditSinkPlan{
		Project:     project,
		Description: auditSinkDescription(capability, environment),
		Disabled:    false, // a sink that does not deliver is a dead export
	}

	// --- CAPABILITY attributes drive the SHAPE (refuse any unmapped attribute) ---
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
			// residency of the DESTINATION operand; validated below. GCP audit logs are
			// global — the sink itself has no region, so this is a declared assertion,
			// not a sink field.
		case "scope.multiRegion":
			b, ok := raw.(bool)
			if !ok {
				return AuditSinkPlan{}, fmt.Errorf("scope.multiRegion must be a bool")
			}
			if !b {
				return AuditSinkPlan{}, fmt.Errorf(
					"scope.multiRegion=false cannot be honored — GCP Cloud Audit Logs are " +
						"project-global; a single-region audit scope is not expressible, and " +
						"groundhold refuses to pretend a project audit sink is region-scoped")
			}
		case "integrity.logValidation":
			b, ok := raw.(bool)
			if !ok {
				return AuditSinkPlan{}, fmt.Errorf("integrity.logValidation must be a bool")
			}
			if b {
				return AuditSinkPlan{}, fmt.Errorf(
					"integrity.logValidation=true has NO GCP equivalent — GCP has no CloudTrail " +
						"log-file-validation (signed-digest tamper evidence); groundhold refuses to " +
						"claim a guarantee GCP does not provide (set it false or omit it)")
			}
		case "encryption.customerManagedKeys":
			b, ok := raw.(bool)
			if !ok {
				return AuditSinkPlan{}, fmt.Errorf("encryption.customerManagedKeys must be a bool")
			}
			p.CMK = b
		case "delivery.assured":
			b, ok := raw.(bool)
			if !ok {
				return AuditSinkPlan{}, fmt.Errorf("delivery.assured must be a bool")
			}
			p.Disabled = !b
		case "service.managed":
			if raw != true {
				return AuditSinkPlan{}, fmt.Errorf(
					"service.managed=false cannot be honored — groundhold manages the log sink it stands up")
			}
		default:
			return AuditSinkPlan{}, fmt.Errorf(
				"attribute %s has no GCP audit-log-sink mapping — refusing rather than silently "+
					"dropping it (the audit.trail vocab governs scope.multiRegion, "+
					"integrity.logValidation, encryption.customerManagedKeys, delivery.assured and "+
					"location.region)", path)
		}
	}

	// location.region, when declared, must be a valid region string (the destination's
	// residency assertion). It is not enforced through the sink API — the destination
	// bucket/dataset (a separate capability) owns residency — so we validate the shape
	// and carry it, never silently drop it.
	if p.Region != "" && !gcpName.MatchString(p.Region) {
		return AuditSinkPlan{}, fmt.Errorf(
			"location.region %q is not a valid region (it declares the residency of the "+
				"destination operand, a separate capability the operator owns)", p.Region)
	}

	// --- OPERATOR operands supply the placement (implementation: block, D26) ---
	// the destination is REQUIRED — a sink with no ujście exports to the void and is not
	// the durable audit record the contract asked for.
	p.Destination, _ = impl["destination"].(string)
	if p.Destination == "" {
		return AuditSinkPlan{}, fmt.Errorf(
			"implementation.destination is required (the durable ujście the sink exports audit " +
				"logs to: storage.googleapis.com/<bucket>, bigquery.googleapis.com/projects/../datasets/.., " +
				"pubsub.googleapis.com/projects/../topics/.. or a logging bucket — a separate capability the operator owns)")
	}
	if !auditSinkDestOK.MatchString(p.Destination) {
		return AuditSinkPlan{}, fmt.Errorf(
			"implementation.destination %q is not a recognized Cloud Logging sink destination", p.Destination)
	}

	// the CMEK is REQUIRED iff customer-managed encryption is asked for. The key name is
	// a REFERENCE (names a key on the destination), never key material (D53). Given but
	// not asked -> ambiguous. It lives on the DESTINATION, not the sink, so it is not
	// sent to the sink API — it is validated and carried as a declared assertion.
	p.KmsKeyName, _ = impl["kms_key_name"].(string)
	if p.CMK {
		if p.KmsKeyName == "" {
			return AuditSinkPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys=true requires implementation.kms_key_name (a Cloud KMS " +
					"cryptoKey on the destination, a separate capability.key.encryption) — refusing to " +
					"claim CMEK with no key")
		}
		if !auditKmsKeyOK.MatchString(p.KmsKeyName) {
			return AuditSinkPlan{}, fmt.Errorf(
				"implementation.kms_key_name %q is not a valid Cloud KMS cryptoKey resource name", p.KmsKeyName)
		}
	} else if p.KmsKeyName != "" {
		return AuditSinkPlan{}, fmt.Errorf(
			"implementation.kms_key_name was given but encryption.customerManagedKeys is not true — " +
				"a customer key only attaches to CMEK encryption; refusing an ambiguous shape")
	}

	// an optional sink-name operand (else the deterministic name), recoverable at observe
	// so a partial create repairs to the SAME sink.
	if given, _ := impl["sinkName"].(string); given != "" {
		if !auditSinkNameOK.MatchString(given) {
			return AuditSinkPlan{}, fmt.Errorf(
				"implementation.sinkName %q is invalid (letter-led, alnum/._- , <=100)", given)
		}
		p.Name = given
	} else {
		p.Name = AuditSinkName(project, environment, capability, generation)
	}
	if !auditSinkNameOK.MatchString(p.Name) {
		return AuditSinkPlan{}, fmt.Errorf("derived sink name %q is invalid", p.Name)
	}
	return p, nil
}

// createBody is the LogSink create/replace request body. The destination + audit
// filter make it an audit-log export; the description carries the ownership marker;
// disabled encodes delivery.assured. The CMEK/residency assertions do NOT appear — they
// are properties of the destination operand, not the sink.
func (p AuditSinkPlan) createBody() map[string]any {
	return map[string]any{
		"name":        p.Name,
		"destination": p.Destination,
		"filter":      auditSinkFilter,
		"description": p.Description,
		"disabled":    p.Disabled,
	}
}

// classifyAuditLogsChange (D46): PURE — can a capability.audit.trail transition be
// honored in place on a GCP log sink? delivery.assured is a single sinks.patch
// (updateMask=disabled). Everything else is either structural (scope), a property of
// the destination operand (residency, CMEK — a destination replacement), or has no GCP
// analog at all (integrity) — each an HONEST unsupported/immutable, never a silent claim.
func classifyAuditLogsChange(path string) (string, string) {
	switch path {
	case "delivery.assured":
		return "mutable", "in-place via sinks.patch (disabled)"
	case "location.region", "encryption.customerManagedKeys":
		return "immutable", "residency/CMEK live on the destination operand (a separate capability); a change is a replacement of the destination, not an in-place sink patch"
	case "scope.multiRegion":
		return "unsupported", "GCP audit logs are project-global — scope is structural, nothing to patch"
	case "integrity.logValidation":
		return "unsupported", "GCP has no CloudTrail log-file-validation equivalent — nothing to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no GCP audit-log-sink in-place mapping for " + path
	}
}
