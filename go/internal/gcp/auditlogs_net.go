// GCP Cloud Audit Logs export network shell (D76 parity): the bearer-signed half of
// the GCP capability.audit.trail driver. The resource is a Cloud Logging log SINK
// (logging.googleapis.com/v2 projects/{p}/sinks) selecting the audit logs and exporting
// them to a durable ujście. A sink is content-addressed by (project, sinkName) — the
// name is deterministic, so the providerId is knowable BEFORE the create response (a
// lost create is unknown, reconcile by the same id).
//
// Ownership honesty: a Cloud Logging sink carries NO labels (like a log metric), so
// ownership is asserted by the deterministic DESCRIPTION marker — the create 409 path,
// the update pre-check and the delete pre-read all verify the existing sink's
// description matches ours before touching it; a sink at our name with a foreign
// description is refused, never silently adopted.
//
// This driver ships ENTIRELY in its own files (auditlogs*.go) — the Driver struct is
// not edited — so the test base-URL override is a package-level var (the AWS CloudTrail
// pattern), not a Driver field. The httptest tests in this package do not run in
// parallel, so a package-level override is safe. Empty = the real Logging API.
//
// Endpoints (logging.googleapis.com/v2):
//
//	CreateSink  POST   projects/{p}/sinks?uniqueWriterIdentity=true   body LogSink
//	GetSink     GET    projects/{p}/sinks/{sink}
//	UpdateSink  PATCH  projects/{p}/sinks/{sink}?updateMask=disabled
//	DeleteSink  DELETE projects/{p}/sinks/{sink}
//	ListSinks   GET    projects/{p}/sinks
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// auditLogsBaseURLOverride redirects the Logging sink endpoint to a test server. It
// lives here rather than on the Driver struct because this driver ships entirely in its
// own files (the Driver struct is not edited). Empty = real logging.googleapis.com/v2.
var auditLogsBaseURLOverride string

func (d *Driver) auditLogsBase() string {
	if auditLogsBaseURLOverride != "" {
		return auditLogsBaseURLOverride
	}
	return loggingBaseURL // https://logging.googleapis.com/v2, defined in logmetric.go
}

func auditLogsProviderID(project, sinkName string) string {
	return "auditlogs:" + project + ":" + sinkName
}

func splitAuditLogsProviderID(providerID string) (project, sinkName string, err error) {
	parts := strings.SplitN(providerID, ":", 3)
	if len(parts) != 3 || parts[0] != "auditlogs" {
		return "", "", fmt.Errorf("providerId %q is not auditlogs:project:sinkName", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !auditSinkNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId sink name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// auditSinkDoc is the projection of a LogSink the driver reverse-maps.
type auditSinkDoc struct {
	Name           string `json:"name"`
	Destination    string `json:"destination"`
	Filter         string `json:"filter"`
	Description    string `json:"description"`
	Disabled       bool   `json:"disabled"`
	WriterIdentity string `json:"writerIdentity"`
}

// getAuditSink reads one sink. (found, readable): a 404 is found=false + readable=true
// (authoritatively absent); a transport/HTTP/parse failure is readable=false (unknown
// — never a fabricated absence).
func (d *Driver) getAuditSink(project, sinkName string) (auditSinkDoc, bool, error) {
	const op = "auditSink.get"
	url := fmt.Sprintf("%s/projects/%s/sinks/%s", d.auditLogsBase(), project, sinkName)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return auditSinkDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return auditSinkDoc{}, false, nil
	}
	if st != http.StatusOK {
		return auditSinkDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc auditSinkDoc
	if json.Unmarshal(body, &doc) != nil {
		return auditSinkDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

// createAuditLogs provisions the audit-log export sink. Four-valued and honest per
// D29: the pid is knowable before the response (deterministic name), so a lost/5xx
// create carries it. A name conflict re-reads ownership: ours (description marker
// matches) is an idempotent success; foreign is refused.
func (d *Driver) createAuditLogs(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAuditSink(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := auditLogsProviderID(d.Project, plan.Name)
	// uniqueWriterIdentity=true so the sink gets its own writer SA (the operator grants
	// it write access on the destination — a separate capability, D26).
	url := fmt.Sprintf("%s/projects/%s/sinks?uniqueWriterIdentity=true", d.auditLogsBase(), d.Project)
	st, body, e := d.call("POST", url, plan.createBody())
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict:
		doc, found, rerr := d.getAuditSink(d.Project, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing sink gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Description != plan.Description {
			return provider.CreateResult{Status: "failed",
				Reason: "a log sink with this name exists and is not ours (description marker does not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // idempotent
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
}

// observeAuditLogs reverse-maps a live sink to capability.audit.trail — HONESTLY. Only
// what the sink genuinely reports is measured: delivery.assured (from disabled),
// service.managed, and scope.multiRegion (a project sink is project-global by
// construction). location.region, integrity.logValidation and
// encryption.customerManagedKeys are OMITTED with diagnostics — they are either a
// property of the destination operand (residency/CMEK, a separate capability) or have
// no GCP equivalent at all (integrity). They are NEVER fabricated.
func (d *Driver) observeAuditLogs(capability, providerID string) ([]provider.Observation, []string, error) {
	project, sinkName, err := splitAuditLogsProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getAuditSink(project, sinkName)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"log sink not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		// a project-level sink captures audit logs across every region (GCP audit logs
		// are project-global) — measured structurally, not fabricated.
		{Path: "scope.multiRegion", Value: true, Derivation: "measured"},
		// D738: `!disabled` is the sink's own configuration flag, not a measurement that
		// anything is delivered. This driver creates the sink with
		// `uniqueWriterIdentity=true` and says so in its own create comment — "the
		// operator grants it write access on the destination, a separate capability" —
		// and NOTHING ever checks that the grant happened. Until it does, the sink
		// exists, reports `disabled: false`, and writes zero entries to the destination
		// forever, which is the shape D725 fixed for CloudTrail one cloud over.
		//
		// GCP publishes no delivery status for a sink, so there is no reading to
		// upgrade to. What can be corrected is the CLAIM: this is config-intent, and
		// after D722 a hard constraint asking for provider-api evidence gets `unknown`
		// and blocks, instead of `satisfied` on an audit trail that may deliver nothing.
		{Path: "delivery.assured", Value: !doc.Disabled, Derivation: "config-intent"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	diags := []string{
		"delivery.assured is config-intent: it reads the sink's own `disabled` flag. The " +
			"sink's writer identity must hold write access on the destination for anything " +
			"to arrive, and that grant is a separate capability this driver does not verify",
		"location.region omitted — a log sink is global; residency lives in the destination operand (a separate capability), not derivable from the sink",
		"integrity.logValidation omitted — GCP has no CloudTrail log-file-validation equivalent (unsupported, never fabricated)",
		"encryption.customerManagedKeys omitted — CMEK is a property of the destination operand (a separate capability), not the sink",
	}
	return obs, diags, nil
}

// updateAuditLogs patches a bound sink in place (D46): the ONLY in-place-mutable
// capability attribute is delivery.assured (sinks.patch, updateMask=disabled). Ownership
// (description marker) gates the patch; the desired shape is re-derived
// (refuse-before-mutate) from the hash-pinned candidate; four-valued throughout.
func (d *Driver) updateAuditLogs(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	project, sinkName, err := splitAuditLogsProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// refuse-before-mutate: re-derive + validate the full desired shape (e.g. an
	// integrity.logValidation=true or a missing destination refuses here).
	plan, err := BuildAuditSink(project, environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if plan.Name != sinkName {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("candidate sink name %q does not match the bound sink %q — refusing", plan.Name, sinkName)}
	}
	// only delivery.assured is patchable; anything else is gated by ClassifyChange
	// (unsupported/immutable) and must never silently no-op here.
	for _, path := range changes {
		if path != "delivery.assured" {
			return provider.CreateResult{Status: "failed",
				Reason: "no in-place GCP audit-log-sink mapping for " + path}
		}
	}
	// ownership re-check before mutating (refuse a foreign sink at our name).
	doc, found, rerr := d.getAuditSink(project, sinkName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer — reconcile before patching: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "sink no longer exists — cannot update"}
	}
	if doc.Description != auditSinkDescription(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "sink description marker does not match — refusing to patch a resource that is not ours"}
	}
	url := fmt.Sprintf("%s/projects/%s/sinks/%s?updateMask=disabled", d.auditLogsBase(), project, sinkName)
	st, body, e := d.call("PATCH", url, map[string]any{"disabled": plan.Disabled})
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch outcome unknown (may have landed): %v", e)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("patch HTTP %d: %s", st, mutDetail(body))}
	}
}

// deleteAuditLogs removes a bound sink (DeleteSink), ownership-marker-gated. The sink
// CONFIG is deleted; the audit log OBJECTS already delivered to the destination (a
// separate capability.storage.object / warehouse / topic) are untouched — deleting the
// sink ENDS the export, it does not erase the past record. Pre-read for idempotence and
// ownership; a transport/5xx is unknown WITH the pid (reconcile).
func (d *Driver) deleteAuditLogs(capability, environment, providerID string) provider.CreateResult {
	project, sinkName, err := splitAuditLogsProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getAuditSink(project, sinkName)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Description != auditSinkDescription(capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "sink description marker does not match — refusing to delete a resource that is not ours"}
	}
	url := fmt.Sprintf("%s/projects/%s/sinks/%s", d.auditLogsBase(), project, sinkName)
	st, body, e := d.call("DELETE", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// discoverAuditLogs enumerates the project's audit-log export sinks as
// capability.audit.trail (ListSinks), each reverse-mapped by observeAuditLogs. Only
// sinks whose filter selects Cloud Audit Logs are surfaced — a generic log-export sink
// is not an audit trail, so filtering on the audit filter avoids misreporting it. Sinks
// are project-global; region does not filter.
func (d *Driver) discoverAuditLogs(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/sinks", d.auditLogsBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("sinks.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("sinks.list: HTTP %d", status)
	}
	var resp struct {
		Sinks []auditSinkDoc `json:"sinks"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("sinks.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, s := range resp.Sinks {
		name := leafName(s.Name)
		if name == "" {
			continue
		}
		if !strings.Contains(s.Filter, "cloudaudit.googleapis.com") {
			continue // a generic log-export sink — not an audit trail
		}
		if !auditSinkNameOK.MatchString(name) {
			diags = append(diags, name+": name not representable as a providerId")
			continue
		}
		pid := auditLogsProviderID(d.Project, name)
		obs, odiags, oerr := d.observeAuditLogs("", pid)
		if oerr != nil {
			diags = append(diags, name+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.audit.trail",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
