// Aurora network shell (D152): the SigV4-signed half of the Serverless v2 driver.
// Aurora is a COMPOSITE (D26) on the RDS Query API — CreateDBCluster then one
// (zonal) or two (regional) CreateDBInstance calls, then a poll of
// DescribeDBClusters until Status=="available". Four-valued throughout: once the
// CLUSTER lands, ANY later ambiguity (an instance create that fails, a 5xx, a
// poll timeout) is unknown WITH the providerId — a half-provisioned cluster to
// reconcile — NEVER a silent half-provision and NEVER a bare "failed" that hides
// the standing cluster. Ownership is TAGS on the cluster; deletion protection
// defaults on and is never auto-disabled.
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

func auroraProviderID(region, id string) string {
	return "aurora:" + region + ":" + id
}

func splitAuroraProviderID(providerID string) (region, id string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "aurora" {
		return "", "", fmt.Errorf("providerId %q is not aurora:region:id", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !dbIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId cluster id %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

type dbCluster struct {
	Identifier              string   `xml:"DBClusterIdentifier"`
	Status                  string   `xml:"Status"`
	Engine                  string   `xml:"Engine"`
	EngineVersion           string   `xml:"EngineVersion"`
	ClusterArn              string   `xml:"DBClusterArn"`
	Endpoint                string   `xml:"Endpoint"`
	ReaderEndpoint          string   `xml:"ReaderEndpoint"`
	Port                    int      `xml:"Port"`
	StorageEncrypted        bool     `xml:"StorageEncrypted"`
	KmsKeyId                string   `xml:"KmsKeyId"`
	DBClusterParameterGroup string   `xml:"DBClusterParameterGroup"`
	BackupRetentionPeriod   int      `xml:"BackupRetentionPeriod"`
	DeletionProtection      bool     `xml:"DeletionProtection"`
	AvailabilityZones       []string `xml:"AvailabilityZones>AvailabilityZone"`
	// PendingModifiedValues: an accepted-but-unapplied ModifyDBCluster leaves its
	// pending changes here until they land (D953) — the field-agnostic applied signal.
	PendingModifiedValues struct {
		Inner string `xml:",innerxml"`
	} `xml:"PendingModifiedValues"`
	Members []struct {
		InstanceID      string `xml:"DBInstanceIdentifier"`
		IsClusterWriter bool   `xml:"IsClusterWriter"`
	} `xml:"DBClusterMembers>DBClusterMember"`
	ServerlessV2 struct {
		MinCapacity float64 `xml:"MinCapacity"`
		MaxCapacity float64 `xml:"MaxCapacity"`
	} `xml:"ServerlessV2ScalingConfiguration"`
	TagList []struct {
		Key   string `xml:"Key"`
		Value string `xml:"Value"`
	} `xml:"TagList>Tag"`
}

// modifyPending reports whether an accepted ModifyDBCluster is still applying (D953).
func (c dbCluster) modifyPending() bool {
	return strings.TrimSpace(c.PendingModifiedValues.Inner) != ""
}

func (c dbCluster) tags() map[string]string {
	m := map[string]string{}
	for _, t := range c.TagList {
		m[t.Key] = t.Value
	}
	return m
}

// writerID returns the writer member's instance id (the flagged writer, else the
// first member), or "" when there are no members.
func (c dbCluster) writerID() string {
	for _, m := range c.Members {
		if m.IsClusterWriter {
			return m.InstanceID
		}
	}
	if len(c.Members) > 0 {
		return c.Members[0].InstanceID
	}
	return ""
}

// describeCluster returns the cluster, whether it was found, and readability. A
// garbled 200 is NOT a well-formed "not found" (never a false succeeded).
func (d *Driver) describeCluster(region, id string) (cl dbCluster, found bool, err error) {
	const op = "DescribeDBClusters"
	st, body, err := d.rdsPost(region, rdsSimpleBody("DescribeDBClusters",
		map[string]string{"DBClusterIdentifier": id}))
	if err != nil {
		return dbCluster{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound || rdsErrCode(body) == "DBClusterNotFoundFault" {
		return dbCluster{}, false, nil
	}
	if st != http.StatusOK {
		return dbCluster{}, false, readHTTP(op, st, rdsErrCode(body))
	}
	var resp struct {
		Clusters []dbCluster `xml:"DescribeDBClustersResult>DBClusters>DBCluster"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return dbCluster{}, false, readBody(op, st)
	}
	if len(resp.Clusters) == 0 {
		return dbCluster{}, false, nil
	}
	return resp.Clusters[0], true, nil
}

// clusterParamOn reads ONE parameter from a DB cluster parameter group and
// reports whether it is set to an ENFORCING value. It returns (forced, ok):
// ok=false means the group was unreadable (observe emits a diag, not a false
// negative); ok=true with forced=false means the parameter is absent or off.
// This is the observe-side check that verifies a group actually enforces TLS
// rather than trusting its name.
//
// D288: the parameter is passed IN rather than hardcoded, because the two
// Aurora engines enforce TLS through different parameters (rds.force_ssl for
// PostgreSQL, require_secure_transport for MySQL). Hardcoding one meant a
// MySQL cluster created WITH enforcement observed as inTransit=false forever —
// the F17 class (created it, cannot read it back) that froze a pilot's plans.
// Enforcing values differ in spelling too (1 / ON / true), so all are accepted.
func (d *Driver) clusterParamOn(region, group, param string) (forced bool, err error) {
	// DescribeDBClusterParameters PAGINATES (a cluster parameter group has many
	// dozens of parameters). rds.force_ssl can sit past the first page, so follow the
	// Marker until it is found or the list is exhausted — a single-page scan
	// false-negatived TLS as not-enforced, which drifted a bound cluster at reconcile.
	marker := ""
	for {
		params := map[string]string{"DBClusterParameterGroupName": group, "MaxRecords": "100"}
		if marker != "" {
			params["Marker"] = marker
		}
		const op = "DescribeDBClusterParameters"
		st, body, cerr := d.rdsPost(region, rdsSimpleBody("DescribeDBClusterParameters", params))
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
			} `xml:"DescribeDBClusterParametersResult>Parameters>Parameter"`
			Marker string `xml:"DescribeDBClusterParametersResult>Marker"`
		}
		if xml.Unmarshal(body, &resp) != nil {
			return false, readBody(op, st)
		}
		for _, p := range resp.Params {
			if p.Name == param {
				// enforcing values differ in spelling across engines and API
				// versions (1 / ON / true) — accept them all, and treat anything
				// else as NOT enforcing.
				switch strings.ToLower(strings.TrimSpace(p.Value)) {
				case "1", "on", "true":
					return true, nil
				}
				return false, nil
			}
		}
		if resp.Marker == "" {
			return false, nil // exhausted, absent => TLS not enforced
		}
		marker = resp.Marker
	}
}

// createAurora provisions the composite: CreateDBCluster, then the member
// instance(s), then poll to "available". Four-valued throughout.
func (d *Driver) createAurora(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAurora(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := auroraProviderID(region, plan.ClusterID)

	// ownership pre-read: refuse a foreign cluster already at our (deterministic)
	// name. not-found continues to a fresh create; ours-already repairs (ensures
	// the member instances exist), refusing to re-create the cluster.
	cl, found, rerr := d.describeCluster(region, plan.ClusterID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "pre-create ownership read gave no answer — reconcile before provisioning: " + rerr.Error()}
	}
	if found {
		if !groundholdTagsMatch(cl.tags(), capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a cluster with this name exists and is not ours (tags do not match) — refusing to adopt it"}
		}
		return d.ensureAuroraInstances(region, pid, plan)
	}

	// D288: a derived TLS parameter group stands BEFORE the cluster that
	// attaches it. Ordered first among the sub-resources for the same reason:
	// nothing else has landed, so a failure here is a clean per-action refusal.
	if plan.DeriveParamGroup != "" {
		if r := d.ensureClusterParamGroup(region, plan, capability, environment); r != nil {
			return *r
		}
	}

	// D278: a derived subnet group stands BEFORE the cluster that places into it.
	// Nothing else has landed yet, so an ensure failure is a clean per-action
	// refusal; the group itself is free, idempotent-by-name wiring — a leftover
	// from a lost response self-heals on the next attempt's already-exists path.
	if plan.DeriveSubnetGroup != "" {
		if r := d.ensureDBSubnetGroup(region, plan.DeriveSubnetGroup, plan.SubnetIDs,
			capability, environment); r != nil {
			return *r
		}
	}

	st, body, err := d.rdsPost(region, plan.createClusterBody())
	switch {
	case err != nil:
		// the id is deterministic — carry the pid so reconcile keeps the handle.
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateDBCluster outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// created — fall through to the member instances
	case rdsErrCode(body) == "DBClusterAlreadyExistsFault":
		// AWS confirms the cluster EXISTS — the deterministic pid is a valid handle.
		cl, found, rerr := d.describeCluster(region, plan.ClusterID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing cluster gave no answer — reconcile: " + rerr.Error()}
		}
		if !found {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "create said exists but describe found nothing — reconcile"}
		}
		if !groundholdTagsMatch(cl.tags(), capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a cluster with this name exists but is not ours (tags do not match)"}
		}
		// ours — continue to the member instances
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateDBCluster HTTP %d (server error — may have landed): %s", st, mutDetail(body))}
	default:
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateDBCluster HTTP %d (%s): %s", st, rdsErrCode(body), mutDetail(body))}
	}

	return d.ensureAuroraInstances(region, pid, plan)
}

// ensureAuroraInstances creates the writer (and, when regional, the reader) then
// polls the cluster to "available". PARTIAL FAILURE is the crux (D29/D87): the
// cluster is created but a member instance create fails -> unknown WITH the pid,
// never a bare "failed" that implies nothing was created and never a silent
// success of a half-provisioned cluster.
func (d *Driver) ensureAuroraInstances(region, pid string, plan AuroraPlan) provider.CreateResult {
	if res := d.ensureAuroraInstance(region, pid, plan, plan.WriterID); res != nil {
		return *res
	}
	if plan.Regional {
		if res := d.ensureAuroraInstance(region, pid, plan, plan.ReaderID); res != nil {
			return *res
		}
	}

	// ---- poll the cluster to available ----
	deadline := d.Now().Add(d.PollTimeout)
	for {
		cl, found, rerr := d.describeCluster(region, plan.ClusterID)
		if rerr == nil && found && cl.Status == "available" {
			return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "cluster still creating at poll timeout — reconcile via DescribeDBClusters"}
		}
		time.Sleep(d.PollInterval)
	}
}

// ensureAuroraInstance creates one member instance. Returns nil on success (or an
// idempotent already-exists); any failure is unknown WITH the pid — the cluster is
// standing, so this is a partial composite, never a plain "failed".
func (d *Driver) ensureAuroraInstance(region, pid string, plan AuroraPlan, instanceID string) *provider.CreateResult {
	// idempotent: a prior partial may have already landed this instance.
	if _, found, rerr := d.describeDB(region, instanceID); rerr == nil && found {
		return nil
	}
	st, body, err := d.rdsPost(region, plan.instanceBody(instanceID))
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("cluster created but CreateDBInstance(%s) outcome unknown — "+
				"reconcile the half-provisioned cluster: %v", instanceID, err)}
	case st == http.StatusOK:
		return nil
	case rdsErrCode(body) == "DBInstanceAlreadyExists":
		return nil
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("cluster created but CreateDBInstance(%s) HTTP %d (server error) — "+
				"reconcile the half-provisioned cluster", instanceID, st)}
	default:
		// a 4xx here is a PARTIAL provision: the cluster exists, the instance failed.
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("cluster created but CreateDBInstance(%s) failed (HTTP %d: %s) — "+
				"the cluster exists with no usable instance; reconcile the half-provisioned cluster",
				instanceID, st, rdsErrCode(body))}
	}
}

// observeAurora reverse-maps a live cluster to capability.database.relational.
// The cluster carries engine/version, encryption, availability (member count)
// and backup retention; public exposure is a MEMBER property, read from the
// writer instance (a diagnostic when it is unreadable, never a false value).
func (d *Driver) observeAurora(capability, providerID string) ([]provider.Observation, []string, error) {
	region, id, err := splitAuroraProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	cl, found, rerr := d.describeCluster(region, id)
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
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: cl.StorageEncrypted, Derivation: "measured"},
	}
	if cl.Engine != "" {
		eng := strings.TrimPrefix(cl.Engine, "aurora-")
		obs = append(obs, provider.Observation{Path: "engine.protocol",
			Value: caplens.EngineProtocol(eng, cl.EngineVersion), Derivation: "measured"})
	}
	// availability.class: a reader member (>1 member) is regional HA; one is zonal.
	obs = append(obs, provider.Observation{Path: "availability.class",
		Value: caplens.AvailabilityClass(len(cl.Members) > 1), Derivation: "measured"})
	var diags []string
	// encryption.inTransit: TLS is enforced iff the attached cluster parameter
	// group sets rds.force_ssl=1. Read it (DescribeDBClusterParameters) so a group
	// WITHOUT force_ssl is caught as inTransit=false — the create trusts the
	// operand, observe verifies the reality (the loop closes on the measured value,
	// not on the create-time intent).
	if cl.DBClusterParameterGroup != "" {
		// D288: read the parameter THIS engine enforces TLS with. An engine whose
		// parameter this driver cannot name yields a DIAGNOSTIC, never a value —
		// absence of evidence, not evidence of absence (a false inTransit=false
		// would drift a correctly-configured cluster forever).
		param, _, known := auroraTLSParam(cl.Engine)
		switch {
		case !known:
			diags = append(diags, "encryption.inTransit not observed: engine "+
				cl.Engine+" has no known TLS parameter in this driver — probe/reconcile")
		default:
			if force, perr := d.clusterParamOn(region, cl.DBClusterParameterGroup, param); perr == nil {
				obs = append(obs, provider.Observation{Path: "encryption.inTransit",
					Value: force, Derivation: "measured"})
			} else {
				diags = append(diags, "encryption.inTransit not observed on "+
					cl.DBClusterParameterGroup+": "+perr.Error()+" — probe/reconcile")
			}
		}
	}
	// recovery.rpo: automated backups (retention>0) enable PITR, whose documented
	// granularity floor is ~5 minutes — config-intent, not a measured RPO.
	if cl.BackupRetentionPeriod > 0 {
		obs = append(obs, provider.Observation{Path: "recovery.rpo", Value: "5m", Derivation: "config-intent"})
	}

	// network.publicExposure lives on the member instances, not the cluster.
	if writer := cl.writerID(); writer != "" {
		inst, ifound, ierr := d.describeDB(region, writer)
		switch {
		case ierr != nil:
			diags = append(diags, "network.publicExposure not observed on the writer "+
				"instance: "+ierr.Error()+" — probe/reconcile")
		case !ifound:
			diags = append(diags, "network.publicExposure not observed: the writer "+
				"instance is not present — probe/reconcile")
		default:
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: inst.PubliclyAccessible, Derivation: "measured"})
		}
	}
	// encryption.customerManagedKeys: an encrypted cluster reports a KmsKeyId
	// whether it is a customer key or the account-default aws/rds key. Trace it to
	// KMS (DescribeKey -> KeyManager) so a real CMK is measured rather than punted;
	// an unreadable trace stays a diagnostic, never a fabricated false.
	if cl.KmsKeyId != "" {
		if customer, kerr := d.kmsKeyIsCustomerManaged(region, cl.KmsKeyId); kerr == nil {
			obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
				Value: customer, Derivation: "measured"})
		} else {
			diags = append(diags, "encryption.customerManagedKeys not observed on the "+
				"cluster's KMS key: "+kerr.Error()+" — probe/reconcile")
		}
	}
	return obs, diags, nil
}

// updateAurora patches a cluster IN PLACE for the mutable paths (D152/D46):
// engine.protocol (a minor EngineVersion bump) and recovery.rpo (backup window)
// via ModifyDBCluster; network.publicExposure is a per-MEMBER modification via
// ModifyDBInstance. availability.class (adding regional HA) attaches a reader —
// an added resource, not an in-place patch — so it is refused here honestly.
// Ownership (tags) is re-checked before any patch; four-valued per D29/D87.
func (d *Driver) updateAurora(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, id, err := splitAuroraProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	cl, found, rerr := d.describeCluster(region, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster no longer exists — re-observe and re-plan"}
	}
	if !groundholdTagsMatch(cl.tags(), capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster tags do not match — refusing to patch a resource that is not ours"}
	}

	// cluster-level patch (ModifyDBCluster) and member-level patch (ModifyDBInstance)
	// are separate calls; collect each set of changed params, then issue only what changed.
	clusterParams := map[string]string{"DBClusterIdentifier": id, "ApplyImmediately": "true"}
	clusterChanged := false
	memberPublic := ""
	for _, path := range changes {
		switch path {
		case "engine.protocol":
			// re-derive the target EngineVersion from the desired protocol (account and
			// generation do not affect the version, only the cluster name we don't touch).
			plan, perr := BuildAurora("", environment, capability, attrs, impl, 1)
			if perr != nil {
				return provider.CreateResult{Status: "failed", Reason: perr.Error()}
			}
			if plan.EngineVersion == "" {
				return provider.CreateResult{Status: "failed",
					Reason: "engine.protocol change carries no target version — reconcile"}
			}
			clusterParams["EngineVersion"] = plan.EngineVersion
			// a minor bump applies online; a major bump needs the explicit allow flag.
			clusterParams["AllowMajorVersionUpgrade"] = "true"
			clusterChanged = true
		case "recovery.rpo":
			// any finite RPO requires automated backups — the same 7-day window create uses.
			clusterParams["BackupRetentionPeriod"] = "7"
			clusterChanged = true
		case "network.publicExposure":
			memberPublic = boolStr(attrs[path] == true)
		case "availability.class":
			return provider.CreateResult{Status: "failed",
				Reason: "availability.class change attaches a reader instance — an added resource, " +
					"not an in-place cluster patch; run a replace/observe cycle"}
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("aurora path %s is not patchable in place", path)}
		}
	}

	if clusterChanged {
		st, resp, cerr := d.rdsPost(region, rdsSimpleBody("ModifyDBCluster", clusterParams))
		if r := auroraPatchOutcome("modify cluster", providerID, st, resp, cerr); r != nil {
			return *r
		}
	}
	if memberPublic != "" {
		// public exposure lives on the member instances — patch every member.
		for _, m := range cl.Members {
			st, resp, cerr := d.rdsPost(region, rdsSimpleBody("ModifyDBInstance",
				map[string]string{"DBInstanceIdentifier": m.InstanceID,
					"ApplyImmediately": "true", "PubliclyAccessible": memberPublic}))
			if r := auroraPatchOutcome("modify member "+m.InstanceID, providerID, st, resp, cerr); r != nil {
				return *r
			}
		}
	}
	// D953: ModifyDBCluster / ModifyDBInstance are ASYNC — the 2xx only ACCEPTS the
	// change (the cluster/members enter "modifying"); it is not applied yet and can fail
	// async. Poll to the APPLIED state (available with no PendingModifiedValues) rather
	// than report succeeded on accept — the sibling async updaters all do, and a
	// premature succeeded on a member's PubliclyAccessible=false mis-stated a
	// security-closing change as done. Still applying at the timeout is unknown.
	deadline := d.Now().Add(d.PollTimeout)
	if clusterChanged {
		for {
			cur, found, rerr := d.describeCluster(region, id)
			if rerr == nil && found && cur.Status == "available" && !cur.modifyPending() {
				break
			}
			if d.Now().After(deadline) {
				return provider.CreateResult{ProviderID: providerID, Status: "unknown",
					Reason: "cluster modification still applying at poll timeout — reconcile via DescribeDBClusters"}
			}
			time.Sleep(d.PollInterval)
		}
	}
	if memberPublic != "" {
		for _, m := range cl.Members {
			for {
				cur, found, rerr := d.describeDB(region, m.InstanceID)
				if rerr == nil && found && cur.Status == "available" && !cur.modifyPending() {
					break
				}
				if d.Now().After(deadline) {
					return provider.CreateResult{ProviderID: providerID, Status: "unknown",
						Reason: "member " + m.InstanceID + " modification still applying at poll timeout — reconcile"}
				}
				time.Sleep(d.PollInterval)
			}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// auroraPatchOutcome folds one RDS-family patch call into the four-valued shape:
// nil means "keep going" (2xx accepted), non-nil is the terminal result. Ambiguous
// (transport / 5xx) is unknown WITH the providerId; a 4xx is failed.
func auroraPatchOutcome(what, providerID string, st int, resp []byte, err error) *provider.CreateResult {
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s outcome unknown (may have landed) — reconcile: %v", what, err)}
	case st >= 500:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s HTTP %d (server error) — reconcile", what, st)}
	case st < 200 || st >= 300:
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s failed: HTTP %d (%s)", what, st, rdsErrCode(resp))}
	default:
		return nil
	}
}

// deleteAurora tears the composite down in REVERSE order — the member instances
// first, then DeleteDBCluster — ownership (tags) + deletion-protection re-checked
// first. Four-valued; protection is never auto-disabled.
func (d *Driver) deleteAurora(capability, environment, providerID string) provider.CreateResult {
	region, id, err := splitAuroraProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	cl, found, rerr := d.describeCluster(region, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(cl.tags(), capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster tags do not match — refusing to delete a resource that is not ours"}
	}
	if cl.DeletionProtection {
		return provider.CreateResult{Status: "failed",
			Reason: "deletion protection is enabled — lift it explicitly first; it is never auto-disabled"}
	}

	// member instances FIRST (reverse of create) — a cluster with instances refuses
	// to delete.
	for _, m := range cl.Members {
		st, body, err := d.rdsPost(region, rdsSimpleBody("DeleteDBInstance",
			map[string]string{"DBInstanceIdentifier": m.InstanceID, "SkipFinalSnapshot": "true"}))
		if err != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("delete member %s outcome unknown — reconcile: %v", m.InstanceID, err)}
		}
		if rdsErrCode(body) == "DBInstanceNotFound" {
			continue // idempotent
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("delete member %s: HTTP %d (server error) — reconcile", m.InstanceID, st)}
		}
		if st < 200 || st >= 300 {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("delete member %s: HTTP %d (%s)", m.InstanceID, st, rdsErrCode(body))}
		}
	}

	st, body, err := d.rdsPost(region, rdsSimpleBody("DeleteDBCluster",
		map[string]string{"DBClusterIdentifier": id, "SkipFinalSnapshot": "true"}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete cluster outcome unknown: %v", err)}
	}
	if rdsErrCode(body) == "DBClusterNotFoundFault" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete cluster: HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("delete cluster: HTTP %d (%s)", st, rdsErrCode(body))}
	}
	// ---- poll the cluster to absence (D968 class, D972) ----
	// The delete is async: the cluster enters "deleting", not gone. Reporting
	// succeeded on the accepted delete tombstones a data-bearing cluster still live,
	// and the derived subnet/param group cleanup below cannot succeed while the
	// cluster still uses them. Poll to a confirmed DBClusterNotFound as createAurora
	// polls to available; unknown on timeout keeps the handle.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.describeCluster(region, id); rerr == nil && !found {
			break // confirmed gone — proceed to derived-resource cleanup
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "cluster still deleting at poll timeout — reconcile via DescribeDBClusters"}
		}
		time.Sleep(d.PollInterval)
	}
	// D278: cleanup of the driver-DERIVED subnet group — part of this
	// capability's composite footprint, so its outcome is reported honestly.
	// Only the deterministic derived name is ever touched (an operator-provided
	// group is never ours to delete); not-found means no derived group was
	// used; in-use means a successor generation still places into it — left
	// standing by design. An unresolved outcome is unknown, never swallowed.
	if r := d.deleteDerivedDBSubnetGroup(region,
		derivedSubnetGroupName(environment, capability), providerID); r != nil {
		return *r
	}
	// D288: the derived TLS parameter group is part of the same owned footprint.
	// Same honesty: gone/not-found concludes, in-use is left standing (a
	// successor generation attaches it), an unresolved outcome is unknown.
	if r := d.deleteDerivedParamGroup(region,
		derivedParamGroupName(environment, capability), providerID); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// deleteDerivedParamGroup removes the driver-derived TLS parameter group
// (D288). nil = concluded (deleted, never-existed, or honestly left standing
// while in use); non-nil = the cleanup outcome is unresolved — unknown.
func (d *Driver) deleteDerivedParamGroup(region, name, providerID string) *provider.CreateResult {
	st, body, err := d.rdsPost(region, rdsSimpleBody("DeleteDBClusterParameterGroup",
		map[string]string{"DBClusterParameterGroupName": name}))
	if err != nil {
		r := provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("cluster deleted; derived parameter group %s cleanup outcome unknown — reconcile: %v", name, err)}
		return &r
	}
	code := rdsErrCode(body)
	switch {
	case st == http.StatusOK,
		st == http.StatusNotFound,
		code == "DBParameterGroupNotFound",
		code == "InvalidDBParameterGroupState": // still attached to a surviving cluster
		return nil
	default:
		r := provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("cluster deleted; derived parameter group %s cleanup HTTP %d (%s) — reconcile", name, st, code)}
		return &r
	}
}

// ensureClusterParamGroup creates (or verifies) the driver-owned cluster
// parameter group that ENFORCES TLS (D288), then sets the one parameter on it.
// Already-exists resolves by CONTENT, and the content test here is the
// SECURITY property itself: the group is reused only when it actually enforces
// TLS. The driver never edits a group it does not own — an operator group
// arrives through the operand path and is attached verbatim.
func (d *Driver) ensureClusterParamGroup(region string, plan AuroraPlan,
	capability, environment string) *provider.CreateResult {
	name := plan.DeriveParamGroup
	st, body, err := d.rdsPost(region, encodeForm(map[string]string{
		"Action":                      "CreateDBClusterParameterGroup",
		"Version":                     rdsVersion,
		"DBClusterParameterGroupName": name,
		"DBParameterGroupFamily":      plan.ParamFamily,
		"Description":                 "groundhold-derived TLS enforcement (D288)",
		"Tags.member.1.Key":           "groundhold-capability",
		"Tags.member.1.Value":         sanitizeTag(capability),
		"Tags.member.2.Key":           "groundhold-environment",
		"Tags.member.2.Value":         sanitizeTag(environment),
	}))
	switch {
	case err != nil:
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateDBClusterParameterGroup %s outcome unknown — retry (the cluster was not attempted): %v", name, err)}
		return &r
	case st == http.StatusOK:
		// created empty — the parameter is set below
	case rdsErrCode(body) == "DBParameterGroupAlreadyExists":
		forced, perr := d.clusterParamEnforcesTLS(region, name, plan.TLSParamName)
		if perr != nil {
			r := provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("parameter group %s exists but its parameters gave no answer — retry: %v", name, perr)}
			return &r
		}
		if forced {
			return nil // ours by content: it already enforces TLS
		}
		// exists but does NOT enforce: fall through and set the parameter.
	default:
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateDBClusterParameterGroup %s: HTTP %d (%s) — the cluster was not attempted", name, st, rdsErrCode(body))}
		return &r
	}

	// ApplyMethod immediate: both TLS parameters are dynamic, and the group is
	// attached at cluster CREATE, so the cluster is born enforcing.
	st, body, err = d.rdsPost(region, encodeForm(map[string]string{
		"Action":                             "ModifyDBClusterParameterGroup",
		"Version":                            rdsVersion,
		"DBClusterParameterGroupName":        name,
		"Parameters.member.1.ParameterName":  plan.TLSParamName,
		"Parameters.member.1.ParameterValue": plan.TLSParamValue,
		"Parameters.member.1.ApplyMethod":    "immediate",
	}))
	if err != nil || st != http.StatusOK {
		code := ""
		if body != nil {
			code = rdsErrCode(body)
		}
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("parameter group %s created but setting %s failed (HTTP %d %s) — "+
				"refusing to create a cluster whose contract claims TLS while the group enforces nothing",
				name, plan.TLSParamName, st, code)}
		return &r
	}
	return nil
}

// clusterParamEnforcesTLS reports whether a group sets the named parameter to
// an enforcing value. Shared by the ensure content-check and observe.
func (d *Driver) clusterParamEnforcesTLS(region, group, param string) (forced bool, err error) {
	return d.clusterParamOn(region, group, param)
}

// ensureDBSubnetGroup creates (or verifies) the driver-owned DB subnet group a
// derived placement uses (D278). Already-exists resolves by CONTENT: the group
// is reused only when its subnet set equals the requested one — the derived
// name encodes capability+environment, and matching content is the same
// intent; anything else is foreign or drifted and refuses. Tagged at birth so
// the ownership is visible to tooling either way.
func (d *Driver) ensureDBSubnetGroup(region, name string, subnetIDs []string,
	capability, environment string) *provider.CreateResult {
	params := map[string]string{
		"Action":                   "CreateDBSubnetGroup",
		"Version":                  rdsVersion,
		"DBSubnetGroupName":        name,
		"DBSubnetGroupDescription": "groundhold-derived placement group (D278)",
		"Tags.member.1.Key":        "groundhold-capability",
		"Tags.member.1.Value":      sanitizeTag(capability),
		"Tags.member.2.Key":        "groundhold-environment",
		"Tags.member.2.Value":      sanitizeTag(environment),
	}
	for i, id := range subnetIDs {
		params[fmt.Sprintf("SubnetIds.member.%d", i+1)] = id
	}
	st, body, err := d.rdsPost(region, encodeForm(params))
	if err != nil {
		// the cluster was NOT attempted; the group is free idempotent wiring, so
		// a possibly-landed group self-heals via already-exists on the retry.
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateDBSubnetGroup %s outcome unknown — retry (the cluster was not attempted): %v", name, err)}
		return &r
	}
	switch {
	case st == http.StatusOK:
		return nil
	case rdsErrCode(body) == "DBSubnetGroupAlreadyExists":
		got, found, gerr := d.describeDBSubnetGroupSubnets(region, name)
		if gerr != nil || !found {
			r := provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("subnet group %s exists but gave no answer — retry: %v", name, gerr)}
			return &r
		}
		if !sameStringSet(got, subnetIDs) {
			r := provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("subnet group %s exists with DIFFERENT subnets (%v vs requested %v) — foreign or drifted, refusing to reuse it", name, got, subnetIDs)}
			return &r
		}
		return nil // ours by content — reuse
	default:
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateDBSubnetGroup %s: HTTP %d (%s) — the cluster was not attempted", name, st, rdsErrCode(body))}
		return &r
	}
}

// describeDBSubnetGroupSubnets returns the subnet ids of a DB subnet group.
func (d *Driver) describeDBSubnetGroupSubnets(region, name string) (ids []string, found bool, err error) {
	const op = "DescribeDBSubnetGroups"
	st, body, cerr := d.rdsPost(region, rdsSimpleBody("DescribeDBSubnetGroups",
		map[string]string{"DBSubnetGroupName": name}))
	if cerr != nil {
		return nil, false, readTransport(op, cerr)
	}
	if rdsErrCode(body) == "DBSubnetGroupNotFoundFault" {
		return nil, false, nil
	}
	if st != http.StatusOK {
		return nil, false, readHTTP(op, st, rdsErrCode(body))
	}
	var out struct {
		IDs []string `xml:"DescribeDBSubnetGroupsResult>DBSubnetGroups>DBSubnetGroup>Subnets>Subnet>SubnetIdentifier"`
	}
	if xml.Unmarshal(body, &out) != nil {
		return nil, false, readBody(op, st)
	}
	return out.IDs, true, nil
}

// deleteDerivedDBSubnetGroup removes the driver-derived subnet group (D278).
// nil = concluded (deleted, never-existed, or honestly left standing in use);
// non-nil = the cleanup mutation's outcome is unresolved — unknown, reconcile.
func (d *Driver) deleteDerivedDBSubnetGroup(region, name, providerID string) *provider.CreateResult {
	st, body, err := d.rdsPost(region, rdsSimpleBody("DeleteDBSubnetGroup",
		map[string]string{"DBSubnetGroupName": name}))
	if err != nil {
		r := provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("cluster deleted; derived subnet group %s cleanup outcome unknown — reconcile: %v", name, err)}
		return &r
	}
	code := rdsErrCode(body)
	switch {
	case st == http.StatusOK,
		st == http.StatusNotFound,                // gone — the same reading describeCluster uses
		code == "DBSubnetGroupNotFoundFault",     // no derived group was used
		code == "InvalidDBSubnetGroupStateFault": // in use — a successor generation still places into it
		return nil
	case st >= 500:
		r := provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("cluster deleted; derived subnet group %s cleanup HTTP %d (server error) — reconcile", name, st)}
		return &r
	default:
		r := provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("cluster deleted; derived subnet group %s cleanup HTTP %d (%s) — reconcile", name, st, code)}
		return &r
	}
}

// sameStringSet compares two string slices as sets.
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
		if m[s] < 0 {
			return false
		}
	}
	return true
}

// classifyAuroraChange (D46): PURE — can this capability.database.relational
// transition be honored in place? A minor engine bump and the backup window
// (recovery.rpo) apply online via ModifyDBCluster; public exposure is a per-member
// online modification. Adding regional HA adds a reader instance (a resource, not
// an in-place patch) — caveated. Storage encryption and the region are fixed at
// cluster creation — immutable.
func classifyAuroraChange(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "engine.protocol":
		return "mutable", "a minor version bump applies online via ModifyDBCluster; a major version is a longer, caveated operation"
	case "network.publicExposure":
		return "mutable", ""
	case "recovery.rpo":
		return "mutable", ""
	case "availability.class":
		if desired == "multi-regional" {
			return "unsupported", "multi-regional has no single-cluster Aurora mapping (a global database is a second binding)"
		}
		return "caveated", "adding regional HA attaches a reader instance — an added resource, not an in-place cluster patch"
	case "location.region":
		return "immutable", "an Aurora cluster's region is fixed at creation — a change is a replacement"
	case "encryption.atRest", "encryption.customerManagedKeys":
		return "immutable", "storage encryption (and its KMS key) is fixed at Aurora cluster creation — not patchable in place"
	case "encryption.inTransit":
		return "unsupported", "enforcing TLS needs a cluster parameter group (a separate binding) — not patchable in place"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no Aurora in-place mapping for " + path
	}
}

// discoverAurora enumerates Aurora clusters in the region as
// capability.database.relational — DescribeDBClusters is region-scoped, and only
// Aurora engines (aurora-*) are surfaced (a plain RDS cluster is not one of ours).
func (d *Driver) discoverAurora(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.rdsPost(region, rdsSimpleBody("DescribeDBClusters", nil))
	if err != nil {
		return nil, nil, fmt.Errorf("aurora DescribeDBClusters: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("aurora DescribeDBClusters: HTTP %d: %s", st, awsErrCode(body))
	}
	var r struct {
		Clusters []struct {
			Identifier string `xml:"DBClusterIdentifier"`
			Engine     string `xml:"Engine"`
		} `xml:"DescribeDBClustersResult>DBClusters>DBCluster"`
	}
	if err := xml.Unmarshal(body, &r); err != nil {
		return nil, nil, fmt.Errorf("aurora DescribeDBClusters: %w", err)
	}
	var out []provider.Discovered
	var diags []string
	for _, cl := range r.Clusters {
		if cl.Identifier == "" || !strings.HasPrefix(cl.Engine, "aurora-") {
			continue
		}
		pid := auroraProviderID(region, cl.Identifier)
		obs, odiags, err := d.observeAurora("", pid)
		if err != nil {
			diags = append(diags, cl.Identifier+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, cl.Identifier+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.database.relational",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
