// RDS network shell (D86): the SigV4-signed half of the AWS database.relational
// driver. CreateDBInstance is ASYNC — no operation to poll; the shell polls
// DescribeDBInstances until DBInstanceStatus is "available" (a create that is
// still creating at the poll timeout is UNKNOWN, never a false succeeded).
// Ownership is TAGS; deletion protection defaults on and is never auto-disabled.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/caplens"
	"groundhold/internal/provider"
)

func (d *Driver) rdsBase(region string) string {
	if d.RDSBaseURL != "" {
		return d.RDSBaseURL
	}
	return "https://rds." + region + ".amazonaws.com"
}

func rdsProviderID(region, id string) string {
	return "rds:" + region + ":" + id
}

func splitRDSProviderID(providerID string) (region, id string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "rds" {
		return "", "", fmt.Errorf("providerId %q is not rds:region:id", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !dbIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId db id %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// rdsPost signs (region-scoped) and sends a Query-protocol POST.
func (d *Driver) rdsPost(region, body string) (int, []byte, error) {
	return d.doSigned("POST", d.rdsBase(region)+"/", "rds", region,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(body))
}

type dbInstance struct {
	Identifier            string `xml:"DBInstanceIdentifier"`
	Status                string `xml:"DBInstanceStatus"`
	Engine                string `xml:"Engine"`
	EngineVersion         string `xml:"EngineVersion"`
	InstanceClass         string `xml:"DBInstanceClass"`
	InstanceArn           string `xml:"DBInstanceArn"`
	PubliclyAccessible    bool   `xml:"PubliclyAccessible"`
	StorageEncrypted      bool   `xml:"StorageEncrypted"`
	MultiAZ               bool   `xml:"MultiAZ"`
	BackupRetentionPeriod int    `xml:"BackupRetentionPeriod"`
	DeletionProtection    bool   `xml:"DeletionProtection"`
	KmsKeyId              string `xml:"KmsKeyId"`
	// Endpoint is the reachable address (the probe dials it); a private instance
	// still reports one, so exposure is decided by PubliclyAccessible + a handshake.
	Endpoint struct {
		Address string `xml:"Address"`
		Port    int    `xml:"Port"`
	} `xml:"Endpoint"`
	ParameterGroups []struct {
		Name string `xml:"DBParameterGroupName"`
	} `xml:"DBParameterGroups>DBParameterGroup"`
	TagList []struct {
		Key   string `xml:"Key"`
		Value string `xml:"Value"`
	} `xml:"TagList>Tag"`
}

// describeDB returns the instance, whether it was found, and why the read failed
// (nil err + found=false is an authoritative "does not exist").
func (d *Driver) describeDB(region, id string) (inst dbInstance, found bool, err error) {
	const op = "DescribeDBInstances"
	st, body, err := d.rdsPost(region, rdsSimpleBody("DescribeDBInstances",
		map[string]string{"DBInstanceIdentifier": id}))
	if err != nil {
		return dbInstance{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound || rdsErrCode(body) == "DBInstanceNotFound" {
		return dbInstance{}, false, nil
	}
	if st != http.StatusOK {
		return dbInstance{}, false, readHTTP(op, st, rdsErrCode(body))
	}
	var resp struct {
		Instances []dbInstance `xml:"DescribeDBInstancesResult>DBInstances>DBInstance"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		// a garbled 200 is NOT a well-formed "not found" — refusing to decide on
		// an unparseable ownership/existence read (never a false succeeded).
		return dbInstance{}, false, readBody(op, st)
	}
	if len(resp.Instances) == 0 {
		return dbInstance{}, false, nil
	}
	return resp.Instances[0], true, nil
}

func (i dbInstance) tags() map[string]string {
	m := map[string]string{}
	for _, t := range i.TagList {
		m[t.Key] = t.Value
	}
	return m
}

// rdsErrCode pulls <Error><Code> from a Query-protocol error body.
func rdsErrCode(body []byte) string {
	var e struct {
		Code string `xml:"Error>Code"`
	}
	_ = xml.Unmarshal(body, &e)
	return e.Code
}

// createRDS: CreateDBInstance, then poll to "available". A same-name existing
// instance continues only if ours (tags); otherwise refuses.
func (d *Driver) createRDS(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	id, body, err := BuildRDSCreate(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := rdsProviderID(region, id)

	st, resp, err := d.rdsPost(region, body)
	if err != nil {
		// the id is deterministic — carry the pid so reconcile keeps the handle
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", err)}
	}
	switch {
	case st == http.StatusOK:
		// created (status "creating") — fall through to poll
	case rdsErrCode(resp) == "DBInstanceAlreadyExists":
		// AWS has confirmed the instance EXISTS — the deterministic pid is a valid
		// handle, so carry it even when the follow-up describe is inconclusive.
		inst, found, rerr := d.describeDB(region, id)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing instance gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "create said exists but describe found nothing — reconcile"}
		}
		tags := inst.tags()
		if tags["groundhold-capability"] != sanitizeTag(capability) ||
			tags["groundhold-environment"] != sanitizeTag(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "an instance with this name exists but is not ours (tags do not match)"}
		}
		// ours — continue to poll
	case st >= 500:
		// "may have landed" — the id is deterministic, so carry the pid so a
		// reconcile keeps the handle (as the transport-error branch above does).
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create: HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		// D237: throttle/503/live-403 -> unknown (id is deterministic, carry pid);
		// only a clean 4xx refusal fails.
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create: HTTP %d (%s): %s", st, rdsErrCode(resp), mutDetail(resp))}
	}

	// ---- poll to available ----
	deadline := d.Now().Add(d.PollTimeout)
	for {
		inst, found, rerr := d.describeDB(region, id)
		if rerr == nil && found {
			switch inst.Status {
			case "available":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "failed", "incompatible-parameters", "incompatible-restore":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "instance entered status " + inst.Status}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "instance still creating at poll timeout — reconcile via DescribeDBInstances"}
		}
		time.Sleep(d.PollInterval)
	}
}

// observeRDS reverse-maps a live instance.
func (d *Driver) observeRDS(capability, providerID string) ([]provider.Observation, []string, error) {
	region, id, err := splitRDSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	inst, found, rerr := d.describeDB(region, id)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"instance not found — nothing to observe"}, nil
	}
	var obs []provider.Observation
	obs = append(obs,
		provider.Observation{Path: "location.region", Value: region, Derivation: "measured"},
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		provider.Observation{Path: "encryption.atRest", Value: inst.StorageEncrypted, Derivation: "measured"},
		provider.Observation{Path: "network.publicExposure", Value: inst.PubliclyAccessible, Derivation: "measured"},
	)
	if inst.Engine != "" {
		obs = append(obs, provider.Observation{Path: "engine.protocol",
			Value: caplens.EngineProtocol(inst.Engine, inst.EngineVersion), Derivation: "measured"})
	}
	class := caplens.AvailabilityClass(inst.MultiAZ)
	obs = append(obs, provider.Observation{Path: "availability.class", Value: class, Derivation: "measured"})
	var diags []string
	// encryption.inTransit: TLS is enforced iff the attached DB parameter group
	// sets rds.force_ssl=1. Read it (DescribeDBParameters) so a group WITHOUT
	// force_ssl is caught as inTransit=false — the create trusts the operand,
	// observe verifies the reality (the loop closes on the measured value).
	if len(inst.ParameterGroups) > 0 {
		group := inst.ParameterGroups[0].Name
		if force, perr := d.dbForceSSL(region, group); perr == nil {
			obs = append(obs, provider.Observation{Path: "encryption.inTransit",
				Value: force, Derivation: "measured"})
		} else {
			diags = append(diags, "encryption.inTransit not observed on "+group+": "+
				perr.Error()+" — probe/reconcile")
		}
	}
	// recovery.rpo: automated backups (retention>0) enable point-in-time
	// recovery, whose documented granularity floor is ~5 minutes. Emit it as
	// config-intent (the PITR floor, not a measured RPO) so a contract requiring
	// an RPO can converge instead of hanging on a write-only attribute.
	if inst.BackupRetentionPeriod > 0 {
		obs = append(obs, provider.Observation{Path: "recovery.rpo", Value: "5m", Derivation: "config-intent"})
	}
	// encryption.customerManagedKeys: an encrypted instance always reports a
	// KmsKeyId ARN, whether it is a customer key or the account-default aws/rds
	// key. Trace it to KMS (DescribeKey -> KeyManager) so a real CMK is measured
	// rather than punted; an unreadable trace stays a diagnostic, never a false.
	if inst.KmsKeyId != "" {
		if customer, kerr := d.kmsKeyIsCustomerManaged(region, inst.KmsKeyId); kerr == nil {
			obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
				Value: customer, Derivation: "measured"})
		} else {
			diags = append(diags, "encryption.customerManagedKeys not observed on the "+
				"instance's KMS key: "+kerr.Error()+" — probe/reconcile")
		}
	}
	return obs, diags, nil
}

// dbForceSSL reads rds.force_ssl from a DB parameter group (DescribeDBParameters).
// It returns (forced, ok): ok=false means the group was unreadable (observe emits
// a diag, not a false negative); ok=true with forced=false means the parameter is
// absent or 0. This verifies the db_parameter_group operand actually enforces TLS
// rather than trusting its name.
func (d *Driver) dbForceSSL(region, group string) (forced bool, err error) {
	// DescribeDBParameters PAGINATES — rds.force_ssl can sit past the first page, so
	// follow the Marker until found or exhausted (a single-page scan false-negatived
	// TLS and drifted a bound instance at reconcile).
	marker := ""
	for {
		params := map[string]string{"DBParameterGroupName": group, "MaxRecords": "100"}
		if marker != "" {
			params["Marker"] = marker
		}
		const op = "DescribeDBParameters"
		st, body, cerr := d.rdsPost(region, rdsSimpleBody("DescribeDBParameters", params))
		if cerr != nil {
			return false, readTransport(op, cerr)
		}
		if st != http.StatusOK {
			return false, readHTTP(op, st, rdsErrCode(body))
		}
		var resp struct {
			Params []struct {
				Name  string `xml:"ParameterName"`
				Value string `xml:"ParameterValue"`
			} `xml:"DescribeDBParametersResult>Parameters>Parameter"`
			Marker string `xml:"DescribeDBParametersResult>Marker"`
		}
		if xml.Unmarshal(body, &resp) != nil {
			return false, readBody(op, st)
		}
		for _, p := range resp.Params {
			if p.Name == "rds.force_ssl" {
				return p.Value == "1", nil
			}
		}
		if resp.Marker == "" {
			return false, nil
		}
		marker = resp.Marker
	}
}

// classifyRDSChange (D46): PURE — can this capability.database.relational
// transition be honored in place via ModifyDBInstance? PubliclyAccessible,
// BackupRetentionPeriod (recovery.rpo) and MultiAZ (availability.class) are
// online modifications, so they are mutable (MultiAZ conversion carries a brief
// failover — caveated). engine.protocol is a migration and encryption is fixed
// at creation, so both are immutable/unsupported — never a silent "mutable".
func classifyRDSChange(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "network.publicExposure":
		return "mutable", ""
	case "recovery.rpo":
		return "mutable", ""
	case "availability.class":
		if desired == "multi-regional" {
			return "unsupported", "multi-regional has no single-instance RDS mapping"
		}
		return "caveated", "a Multi-AZ conversion triggers a brief failover; the modification is asynchronous"
	case "engine.protocol":
		return "immutable", "an engine/version change is a database migration, not a patch — a replacement"
	case "location.region":
		return "immutable", "an RDS instance's region is fixed at creation — a change is a replacement"
	case "encryption.atRest", "encryption.customerManagedKeys":
		return "unsupported", "storage encryption (and its KMS key) is fixed at RDS instance creation — not patchable in place"
	case "encryption.inTransit":
		return "unsupported", "enforcing TLS needs a DB parameter group (a separate binding) — not patchable in place"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no RDS in-place mapping for " + path
	}
}

// updateRDS: ownership (tags) re-check FIRST, then ModifyDBInstance with ONLY
// the changed paths (ApplyImmediately so the change starts now rather than at
// the next maintenance window). RDS modifications are ASYNCHRONOUS — an accepted
// 200 leaves the instance in "modifying"; the accepted request is success (a
// later observe/converge confirms the landed state), mirroring deleteRDS. err/
// 5xx are unknown WITH the pid (may have landed — D29); a 4xx/3xx is failed.
func (d *Driver) updateRDS(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, id, err := splitRDSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	inst, found, rerr := d.describeDB(region, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "instance no longer exists — re-observe and re-plan"}
	}
	tags := inst.tags()
	if tags["groundhold-capability"] != sanitizeTag(capability) ||
		tags["groundhold-environment"] != sanitizeTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "instance tags do not match — refusing to patch a resource that is not ours"}
	}
	p := map[string]string{
		"DBInstanceIdentifier": id,
		"ApplyImmediately":     "true",
	}
	for _, path := range changes {
		switch path {
		case "network.publicExposure":
			p["PubliclyAccessible"] = boolStr(attrs[path] == true)
		case "recovery.rpo":
			// any finite RPO requires automated backups — the same 7-day window
			// the create builder uses.
			p["BackupRetentionPeriod"] = "7"
		case "availability.class":
			switch attrs[path] {
			case "regional":
				p["MultiAZ"] = "true"
			case "zonal":
				p["MultiAZ"] = "false"
			default:
				return provider.CreateResult{Status: "failed",
					Reason: fmt.Sprintf("availability.class %v has no in-place RDS mapping", attrs[path])}
			}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("rds path %s is not patchable in place", path)}
		}
	}
	st, resp, err := d.rdsPost(region, rdsSimpleBody("ModifyDBInstance", p))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch outcome unknown — reconcile: %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("patch HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("patch failed: HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	// the modification is accepted (async — the instance enters "modifying"); a
	// later observe/converge confirms the landed state.
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// deleteRDS: ownership (tags) + deletion-protection pre-check, then
// DeleteDBInstance (SkipFinalSnapshot). Protection is never auto-disabled.
func (d *Driver) deleteRDS(capability, environment, providerID string) provider.CreateResult {
	region, id, err := splitRDSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	inst, found, rerr := d.describeDB(region, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags := inst.tags()
	if tags["groundhold-capability"] != sanitizeTag(capability) ||
		tags["groundhold-environment"] != sanitizeTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "instance tags do not match — refusing to delete a resource that is not ours"}
	}
	if inst.DeletionProtection {
		return provider.CreateResult{Status: "failed",
			Reason: "deletion protection is enabled — lift it explicitly first; it is never auto-disabled"}
	}
	st, resp, err := d.rdsPost(region, rdsSimpleBody("DeleteDBInstance",
		map[string]string{"DBInstanceIdentifier": id, "SkipFinalSnapshot": "true"}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if rdsErrCode(resp) == "DBInstanceNotFound" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete: HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 { // 4xx or a 3xx — not a confirmed accepted delete
		// D237: throttle/503/live-403 -> unknown (keep the handle), never failed.
		if r := provider.MutationResult(st, rdsErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("delete: HTTP %d (%s)", st, rdsErrCode(resp))}
	}
	// deletion is async too; treat the accepted delete as success (the instance
	// enters "deleting"). A reconcile/observe confirms final absence.
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
