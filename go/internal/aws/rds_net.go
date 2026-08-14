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

	"groundhold/internal/adoptcheck"
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
	// PendingModifiedValues carries the fields an accepted-but-not-yet-applied
	// ModifyDBInstance is still going to change (D953). AWS populates it immediately on
	// the async accept and empties it once the change lands, so a non-empty inner body
	// is the honest "not applied yet" signal — field-agnostic (no per-field/version
	// comparison) and race-safe (populated before the instance even enters "modifying").
	PendingModifiedValues struct {
		Inner string `xml:",innerxml"`
	} `xml:"PendingModifiedValues"`
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

// modifyPending reports whether an accepted ModifyDBInstance is still applying — the
// PendingModifiedValues element carries children until the change lands (D953).
func (i dbInstance) modifyPending() bool {
	return strings.TrimSpace(i.PendingModifiedValues.Inner) != ""
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

// rdsAdoptControls are the controls RDS sets INLINE in CreateDBInstance, so on a
// 409-adopt they never applied to the pre-existing instance (D1062). Storage
// encryption, its customer key, and TLS enforcement are fixed at create (a change is
// a replacement or a separate parameter-group binding — classifyRDSChange returns
// "unsupported"), so their absence FAILS the adopt; public exposure is an online
// ModifyDBInstance (mutable+wired), so its absence is unknown+bound and converge
// patches it. deletion.protection is not here yet — observeRDS does not emit it (a
// follow-up: emit it measured, then add it as a control).
var rdsAdoptControls = []adoptcheck.Control{
	{Path: "encryption.atRest", Direction: adoptcheck.SecureTrue, ImmutableAtCreate: true},
	{Path: "encryption.customerManagedKeys", Direction: adoptcheck.SecureTrue, ImmutableAtCreate: true},
	{Path: "encryption.inTransit", Direction: adoptcheck.SecureTrue, ImmutableAtCreate: true},
	{Path: "network.publicExposure", Direction: adoptcheck.SecureFalse, UpdateWired: true},
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
	adopted := false

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
		// ours — continue to poll, then re-check declared controls (D1062)
		adopted = true
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
				// D1062: an ADOPTED instance (409, ours) never received the CreateDBInstance
				// body's inline controls — encryption at rest, its KMS key, TLS enforcement,
				// public exposure. Re-check them against this driver's OWN measured observations
				// (cmek is KMS-traced, so SSE-KMS with the account default key is NOT a customer
				// key) before reporting succeeded: an immutable control the instance lacks fails,
				// a mutable one a wired update can patch is unknown+bound (converge reconciles).
				if adopted {
					obs, _, oerr := d.observeRDS(capability, pid)
					if oerr != nil {
						return provider.CreateResult{ProviderID: pid, Status: "unknown",
							Reason: "adopted instance re-observe gave no answer — reconcile: " + oerr.Error()}
					}
					switch v := adoptcheck.Compare(attrs, obs, rdsAdoptControls); v.Status {
					case "failed":
						return provider.CreateResult{Status: "failed", Reason: v.Reason}
					case "unknown":
						return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: v.Reason}
					}
				}
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
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"instance not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
	}
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
	// encryption.inTransit: TLS is enforced iff the attached DB parameter group sets
	// the engine's enforcement parameter (rds.force_ssl for Postgres/SQL Server,
	// require_secure_transport for MySQL/MariaDB — D952). Read it (DescribeDBParameters)
	// so a group WITHOUT it is caught as inTransit=false — the create trusts the operand,
	// observe verifies the reality (the loop closes on the measured value).
	if len(inst.ParameterGroups) > 0 {
		group := inst.ParameterGroups[0].Name
		if force, perr := d.dbTLSEnforced(region, group, inst.Engine); perr == nil {
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
	} else {
		// D1040/D1003: no KmsKeyId at all = at-rest encryption disabled = definitively
		// not a customer key, read from the main describe → a MEASURED false, not an
		// absence. Omitting it let a `customerManagedKeys: true` candidate be adopted
		// over an unencrypted instance.
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: false, Derivation: "measured"})
	}
	return obs, diags, nil
}

// dbTLSEnforced reads the engine's TLS-enforcement parameter from a DB parameter group
// (DescribeDBParameters). It returns (forced, err): a read error means the group was
// unreadable (observe emits a diag, not a false negative); no error with forced=false
// means the parameter is absent or not set to an enforcing value. The parameter NAME is
// engine-specific (D952) — a MySQL/MariaDB group enforcing TLS via require_secure_transport
// is no longer misread as inTransit=false the way a hardcoded rds.force_ssl scan did. This
// verifies the db_parameter_group operand actually enforces TLS rather than trusting its name.
func (d *Driver) dbTLSEnforced(region, group, engine string) (forced bool, err error) {
	param, ok := rdsTLSParam(engine)
	if !ok {
		return false, fmt.Errorf("no known TLS-enforcement parameter for RDS engine %q — "+
			"refusing to read the wrong parameter and assert a false negative", engine)
	}
	// DescribeDBParameters PAGINATES — the parameter can sit past the first page, so
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
			if p.Name == param {
				// enforcing values differ in spelling across engines (1 / ON / true) —
				// accept them all, and treat anything else as NOT enforcing.
				switch strings.ToLower(strings.TrimSpace(p.Value)) {
				case "1", "on", "true":
					return true, nil
				}
				return false, nil
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
	// D953: ModifyDBInstance is ASYNC — the 2xx only ACCEPTS the change (the instance
	// enters "modifying"); it is not applied yet and can still fail async. Reporting
	// succeeded on accept mis-stated a security-closing change like
	// network.publicExposure=false as done while the instance was still publicly
	// reachable. Poll to the APPLIED state (available with no PendingModifiedValues),
	// matching the sibling async updaters (EKS/GKE/AKS/Lambda/CloudSQL); a change still
	// applying at the timeout is unknown (reconcile), never a false succeeded.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		cur, found, rerr := d.describeDB(region, id)
		if rerr == nil && found {
			switch cur.Status {
			case "available":
				if !cur.modifyPending() {
					return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
				}
			case "failed", "incompatible-parameters", "incompatible-restore":
				return provider.CreateResult{ProviderID: providerID, Status: "failed",
					Reason: "instance entered status " + cur.Status + " during the modification"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "modification still applying at poll timeout — reconcile via DescribeDBInstances"}
		}
		time.Sleep(d.PollInterval)
	}
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
	// ---- poll to absence (D968) ----
	// The delete is async: a 2xx means the instance entered "deleting", not that
	// it is GONE. Reporting "succeeded" here writes a tombstone and drops the
	// binding (apply.go), and the succeeded receipt clears the pending intent — so
	// if the async deletion then FAILS (a dependency/replica error returns it to
	// "available"), a billable stateful DB is orphaned from a ledger that says it
	// is gone, with nothing scheduled to reconcile. Poll to a confirmed 404 exactly
	// as createRDS polls to "available"; unknown on timeout keeps the handle for a
	// reconcile — never a terminal success the world has not reached.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.describeDB(region, id); rerr == nil && !found {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // confirmed gone
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "instance still deleting at poll timeout — reconcile via DescribeDBInstances"}
		}
		time.Sleep(d.PollInterval)
	}
}
