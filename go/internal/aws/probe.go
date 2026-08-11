// Outcome probes for RDS and Aurora (D59/D65) — the AWS twin of internal/gcp's
// Cloud SQL Prober. Honesty rules mirror the observe mapper exactly: a
// measurement is emitted ONLY when the OUTCOME was actually exercised — a TCP
// handshake that happened, a restore that ran to "available". Anything short of
// that is a probe FAILURE with the reason named, never a fabricated value.
//
// Two probes, both fulfilling capability.database.relational:
//   - NON-INTRUSIVE, always: network.publicExposure by an ACTUAL handshake.
//     A public address that answers is exposure proven; not-publicly-accessible
//     (or no address) is no path to reach; an address that will not answer
//     cannot conclude either way, so it is a failure, not a false.
//   - INTRUSIVE, under double consent: recovery.rto by restoring the latest
//     snapshot into a DETERMINISTICALLY-named scratch resource, timing it to
//     "available", and deleting it. Cleanup is sacred: a scratch that could not
//     be deleted is surfaced LOUDLY (it costs money), never silently leaked.
package aws

import (
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

var _ provider.Prober = (*Driver)(nil)

// Probe implements provider.Prober. Dispatch is on the SERVICE token (fail-closed
// on anything but rds/aurora), mirroring the rest of the AWS driver.
func (d *Driver) Probe(service, capability, providerID string,
	allowIntrusive bool) (provider.ProbeOutcome, error) {
	switch service {
	case "rds":
		return d.probeRDS(capability, providerID, allowIntrusive)
	case "aurora":
		return d.probeAurora(capability, providerID, allowIntrusive)
	default:
		return provider.ProbeOutcome{}, fmt.Errorf(
			"aws driver: probes for service %q are not wired yet", service)
	}
}

// ---- port + ARN helpers ----------------------------------------------------

// enginePort maps an RDS/Aurora engine name to its wire port. Both the plain
// (postgres/mysql/mariadb) and Aurora (aurora-postgresql/aurora-mysql) names are
// covered; 0 means "no known port" (the caller then fails rather than guessing).
func enginePort(engine string) int {
	switch {
	case strings.Contains(engine, "postgres"):
		return 5432
	case strings.Contains(engine, "mysql"), strings.Contains(engine, "mariadb"):
		return 3306
	}
	return 0
}

// arnAccount pulls the account id from an RDS ARN
// (arn:aws:rds:<region>:<account>:db:<id>). "" when the ARN is malformed.
func arnAccount(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 || parts[0] != "arn" {
		return ""
	}
	return parts[4]
}

// ---- exposure (non-intrusive) ----------------------------------------------

// probeExposure decides network.publicExposure from a reachable endpoint:
//   - not publicly accessible (or no address): no public endpoint to reach — the
//     MEASURED outcome is false;
//   - publicly accessible and the handshake succeeds: exposure PROVEN — true;
//   - publicly accessible but the handshake fails: the path may exist, the packet
//     died — cannot conclude, so a retryable FAILURE, never a fabricated value.
func (d *Driver) probeExposure(address string, port int,
	publiclyAccessible bool, engine string, out *provider.ProbeOutcome) {
	// D775. This branch folded two different states into one measured `false`, and
	// stamped `tcp-connect` on a value obtained without connecting to anything.
	//
	// The provider saying the resource has NO public endpoint is a real answer, and it
	// stays a measurement — but the method now says how it was come by, because a probe
	// exists precisely to distinguish an OUTCOME from a config read, and a method field
	// that names a handshake nobody attempted is the same lie one layer down as a
	// verdict printing "observed" over a declaration (D766).
	//
	// An EMPTY ADDRESS on a resource the provider calls publicly accessible is not that
	// answer at all: the endpoint may exist and simply not be readable yet (an instance
	// still coming up). Reporting it as "measured: not exposed" is a proven negative
	// invented out of missing data — absent is not no (D306/D513).
	if publiclyAccessible && address == "" {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "network.publicExposure", Method: "tcp-connect",
			Reason: "the provider reports this resource as publicly accessible but " +
				"returned no endpoint address — there is nothing to dial yet, and an " +
				"unknown address is not a proven absence of exposure",
			Retryable: true})
		return
	}
	if !publiclyAccessible {
		out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
			Path: "network.publicExposure", Value: false,
			Method: "provider-config",
			Evidence: "the provider reports no public endpoint for this resource; " +
				"nothing was dialled"})
		return
	}
	if port == 0 {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "network.publicExposure", Method: "tcp-connect",
			Reason:    fmt.Sprintf("unknown engine %q — no port to dial", engine),
			Retryable: false})
		return
	}
	dial := d.Dial
	if dial == nil {
		dial = net.DialTimeout
	}
	hostPort := net.JoinHostPort(address, fmt.Sprintf("%d", port))
	conn, err := dial("tcp", hostPort, 5*time.Second)
	if err == nil {
		_ = conn.Close()
		out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
			Path: "network.publicExposure", Value: true,
			Method:   "tcp-connect",
			Evidence: fmt.Sprintf("TCP handshake to %s succeeded", hostPort)})
		return
	}
	out.Failures = append(out.Failures, provider.ProbeFailure{
		Path: "network.publicExposure", Method: "tcp-connect",
		Reason: fmt.Sprintf("public endpoint %s allocated but handshake failed "+
			"(%v) — filtered or down; the path may still exist, cannot conclude",
			hostPort, err),
		Retryable: true})
}

// ---- RDS -------------------------------------------------------------------

func (d *Driver) probeRDS(capability, providerID string,
	allowIntrusive bool) (provider.ProbeOutcome, error) {
	region, id, err := splitRDSProviderID(providerID)
	if err != nil {
		return provider.ProbeOutcome{}, err
	}
	inst, found, rerr := d.describeDB(region, id)
	if rerr != nil {
		return provider.ProbeOutcome{}, fmt.Errorf("cannot probe %s: %w", id, rerr)
	}
	if !found {
		return provider.ProbeOutcome{}, fmt.Errorf(
			"instance %s not found — nothing to probe", id)
	}

	var out provider.ProbeOutcome
	port := inst.Endpoint.Port
	if port == 0 {
		port = enginePort(inst.Engine)
	}
	d.probeExposure(inst.Endpoint.Address, port, inst.PubliclyAccessible,
		inst.Engine, &out)

	if allowIntrusive {
		// GATE before spending: the intrusive path CREATES/restores/deletes a
		// BILLED scratch instance. A forged binding must not redirect that spend
		// off a foreign account, and a resource that is not ours must not be
		// touched. Both refusals happen BEFORE any scratch is created.
		if err := d.gateIntrusive(arnAccount(inst.InstanceArn),
			inst.tags(), capability); err != nil {
			return provider.ProbeOutcome{}, err
		}
		d.probeRTORDS(region, inst, &out)
	}
	return out, nil
}

// gateIntrusive enforces the two spend gates shared by both RTO probes:
//
//	(a) sameAccount — the resource's own account must equal the acting identity's
//	    (a forged/stale binding must not redirect a billed restore off-account);
//	(b) ownership — the resource must carry groundhold-capability == this
//	    capability (the Prober interface gives no environment, so match capability
//	    only, exactly as the GCP twin matches the label).
func (d *Driver) gateIntrusive(resourceAccount string,
	tags map[string]string, capability string) error {
	acct, err := d.resolveAccount()
	if err != nil {
		return fmt.Errorf("cannot resolve the acting account to gate an "+
			"intrusive probe: %v", err)
	}
	if resourceAccount == "" || resourceAccount != acct {
		return fmt.Errorf("resource account %q does not match the acting "+
			"account %q — refusing an intrusive probe that would bill a "+
			"foreign or unknown account", resourceAccount, acct)
	}
	if tags["groundhold-capability"] != sanitizeTag(capability) {
		return fmt.Errorf("resource capability tag does not match — refusing " +
			"an intrusive probe on a resource that is not ours")
	}
	return nil
}

// probeRTORDS (INTRUSIVE): restore the latest completed snapshot into a scratch
// instance (same class + engine — a toy-class RTO would be a lie), time it to
// "available", then delete it. The scratch name derives deterministically from
// (source id, snapshot id) so a re-probe of the same snapshot is idempotent.
func (d *Driver) probeRTORDS(region string, src dbInstance,
	out *provider.ProbeOutcome) {
	fail := func(reason string, retryable bool) {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "recovery.rto", Method: "restore-test",
			Reason: reason, Retryable: retryable})
	}

	snap, ok := d.latestDBSnapshot(region, src.Identifier)
	if !ok {
		fail("no snapshot to restore — RTO is unmeasurable until a completed "+
			"snapshot exists", false)
		return
	}
	scratch := scratchName(src.Identifier, snap)
	started := d.Now()

	st, resp, err := d.rdsPost(region, rdsSimpleBody(
		"RestoreDBInstanceFromDBSnapshot", map[string]string{
			"DBInstanceIdentifier": scratch,
			"DBSnapshotIdentifier": snap,
			"DBInstanceClass":      src.InstanceClass,
			"Engine":               src.Engine,
			"DeletionProtection":   "false",
		}))
	if err != nil || st < 200 || st >= 300 {
		fail(fmt.Sprintf("restore-from-snapshot failed (HTTP %d, %v, %s)",
			st, err, rdsErrCode(resp)), true)
		// a 5xx may have landed the scratch — attempt cleanup regardless.
		d.deleteScratchInstance(region, scratch, out)
		return
	}

	// the scratch now exists — cleanup is SACRED from here, on every path.
	availErr := d.pollInstanceAvailable(region, scratch)
	elapsed := d.Now().Sub(started)
	d.deleteScratchInstance(region, scratch, out)
	if availErr != nil {
		fail(availErr.Error(), true)
		return
	}
	emitRTO(snap, scratch, elapsed, out)
}

// latestDBSnapshot returns the id of the most recent COMPLETED (available)
// manual/automated snapshot for the source instance, and whether one exists.
func (d *Driver) latestDBSnapshot(region, instanceID string) (string, bool) {
	st, body, err := d.rdsPost(region, rdsSimpleBody("DescribeDBSnapshots",
		map[string]string{"DBInstanceIdentifier": instanceID}))
	if err != nil || st != http.StatusOK {
		return "", false
	}
	var resp struct {
		Snapshots []struct {
			ID      string `xml:"DBSnapshotIdentifier"`
			Status  string `xml:"Status"`
			Created string `xml:"SnapshotCreateTime"`
		} `xml:"DescribeDBSnapshotsResult>DBSnapshots>DBSnapshot"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return "", false
	}
	best, bestT := "", time.Time{}
	for _, s := range resp.Snapshots {
		if s.Status != "available" || s.ID == "" {
			continue
		}
		t, _ := time.Parse(time.RFC3339, s.Created)
		if best == "" || t.After(bestT) {
			best, bestT = s.ID, t
		}
	}
	return best, best != ""
}

// ---- Aurora ----------------------------------------------------------------

func (d *Driver) probeAurora(capability, providerID string,
	allowIntrusive bool) (provider.ProbeOutcome, error) {
	region, id, err := splitAuroraProviderID(providerID)
	if err != nil {
		return provider.ProbeOutcome{}, err
	}
	cl, found, rerr := d.describeCluster(region, id)
	if rerr != nil {
		return provider.ProbeOutcome{}, fmt.Errorf("cannot probe %s: %w", id, rerr)
	}
	if !found {
		return provider.ProbeOutcome{}, fmt.Errorf(
			"cluster %s not found — nothing to probe", id)
	}

	var out provider.ProbeOutcome
	d.probeAuroraExposure(region, cl, &out)

	if allowIntrusive {
		if err := d.gateIntrusive(arnAccount(cl.ClusterArn),
			cl.tags(), capability); err != nil {
			return provider.ProbeOutcome{}, err
		}
		d.probeRTOAurora(region, cl, &out)
	}
	return out, nil
}

// probeAuroraExposure dials the CLUSTER endpoint (the front door apps use) but
// gates on the WRITER member's PubliclyAccessible flag — public exposure is a
// per-member property on Aurora, not a cluster one. No member, or an unreadable
// one, cannot conclude honestly.
func (d *Driver) probeAuroraExposure(region string, cl dbCluster,
	out *provider.ProbeOutcome) {
	writer := cl.writerID()
	if writer == "" {
		out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
			// D990: this concludes not-exposed from the CONFIG (no member instance, so no
			// endpoint) — nothing dialed. Naming a tcp-connect a handshake nobody attempted
			// is the D775 lie left behind in this branch; the value is honest, the method
			// must say provider-config like every other config-derived path.
			Path: "network.publicExposure", Value: false,
			Method:   "provider-config",
			Evidence: "cluster has no instance — no public endpoint to reach"})
		return
	}
	inst, found, rerr := d.describeDB(region, writer)
	if rerr != nil || !found {
		why := "it is not present"
		if rerr != nil {
			why = rerr.Error()
		}
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "network.publicExposure", Method: "tcp-connect",
			Reason: fmt.Sprintf("cannot determine the exposure of writer instance %s: %s",
				writer, why),
			Retryable: true})
		return
	}
	address := cl.Endpoint
	if address == "" {
		address = inst.Endpoint.Address
	}
	port := cl.Port
	if port == 0 {
		port = inst.Endpoint.Port
	}
	if port == 0 {
		port = enginePort(cl.Engine)
	}
	d.probeExposure(address, port, inst.PubliclyAccessible, cl.Engine, out)
}

// probeRTOAurora (INTRUSIVE): restore the latest cluster snapshot into a scratch
// cluster, add one member (a cluster with no instance never becomes usable),
// time the cluster to "available", then tear both down. Deterministic scratch
// naming; cleanup is sacred on every path.
func (d *Driver) probeRTOAurora(region string, src dbCluster,
	out *provider.ProbeOutcome) {
	fail := func(reason string, retryable bool) {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "recovery.rto", Method: "restore-test",
			Reason: reason, Retryable: retryable})
	}

	snap, ok := d.latestClusterSnapshot(region, src.Identifier)
	if !ok {
		fail("no cluster snapshot to restore — RTO is unmeasurable until a "+
			"completed snapshot exists", false)
		return
	}
	scratchCluster := scratchName(src.Identifier, snap)
	scratchInstance := auroraInstanceID(scratchCluster, "1")
	started := d.Now()

	st, resp, err := d.rdsPost(region, rdsSimpleBody(
		"RestoreDBClusterFromSnapshot", map[string]string{
			"DBClusterIdentifier": scratchCluster,
			"SnapshotIdentifier":  snap,
			"Engine":              src.Engine,
			"DeletionProtection":  "false",
		}))
	if err != nil || st < 200 || st >= 300 {
		fail(fmt.Sprintf("restore-cluster-from-snapshot failed (HTTP %d, %v, %s)",
			st, err, rdsErrCode(resp)), true)
		d.deleteScratchAurora(region, scratchCluster, scratchInstance, out)
		return
	}

	// the scratch cluster now exists — cleanup is SACRED from here, on every path.
	// The member is provisioned as db.serverless. A provisioned (non-Serverless-v2)
	// source will REJECT this member class, so the create fails → the probe reports a
	// failure and tears the cluster down. That is the honest outcome: an RTO probe of a
	// provisioned Aurora cluster yields a named failure, never a misleading value
	// measured on a mismatched member. (A follow-up may copy the source member's class.)
	st, resp, err = d.rdsPost(region, rdsSimpleBody("CreateDBInstance",
		map[string]string{
			"DBInstanceIdentifier": scratchInstance,
			"DBClusterIdentifier":  scratchCluster,
			"DBInstanceClass":      "db.serverless",
			"Engine":               src.Engine,
		}))
	if err != nil || st < 200 || st >= 300 {
		fail(fmt.Sprintf("cluster restored but member create failed "+
			"(HTTP %d, %v, %s)", st, err, rdsErrCode(resp)), true)
		d.deleteScratchAurora(region, scratchCluster, scratchInstance, out)
		return
	}

	// Measure to the MEMBER reaching "available" — the usable endpoint. An Aurora
	// cluster reports "available" as soon as the volume restore finishes, while its
	// instance is still `creating`; timing to the cluster would exclude the member's
	// compute-provisioning (often the majority of a real recovery) and understate the
	// RTO — optimism is fabrication. The member cannot be available before the cluster
	// is, so this subsumes cluster readiness.
	availErr := d.pollInstanceAvailable(region, scratchInstance)
	elapsed := d.Now().Sub(started)
	d.deleteScratchAurora(region, scratchCluster, scratchInstance, out)
	if availErr != nil {
		fail(availErr.Error(), true)
		return
	}
	emitRTO(snap, scratchCluster, elapsed, out)
}

// latestClusterSnapshot returns the id of the most recent COMPLETED cluster
// snapshot for the source cluster, and whether one exists.
func (d *Driver) latestClusterSnapshot(region, clusterID string) (string, bool) {
	st, body, err := d.rdsPost(region, rdsSimpleBody("DescribeDBClusterSnapshots",
		map[string]string{"DBClusterIdentifier": clusterID}))
	if err != nil || st != http.StatusOK {
		return "", false
	}
	var resp struct {
		Snapshots []struct {
			ID      string `xml:"DBClusterSnapshotIdentifier"`
			Status  string `xml:"Status"`
			Created string `xml:"SnapshotCreateTime"`
		} `xml:"DescribeDBClusterSnapshotsResult>DBClusterSnapshots>DBClusterSnapshot"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return "", false
	}
	best, bestT := "", time.Time{}
	for _, s := range resp.Snapshots {
		if s.Status != "available" || s.ID == "" {
			continue
		}
		t, _ := time.Parse(time.RFC3339, s.Created)
		if best == "" || t.After(bestT) {
			best, bestT = s.ID, t
		}
	}
	return best, best != ""
}

// ---- shared polling, cleanup, naming, measurement --------------------------

// scratchName derives a deterministic, RDS-valid (letter-start) scratch id from
// (source, snapshot) — a re-probe of the same snapshot reuses the same name, so
// it is idempotent rather than leaking a second scratch.
func scratchName(source, snapshot string) string {
	return "groundhold-probe-rto-" + sha256hex([]byte(source + "|" + snapshot))[:10]
}

// pollInstanceAvailable polls DescribeDBInstances until the scratch is
// "available" (nil), enters a terminal-failure status, or the poll times out.
func (d *Driver) pollInstanceAvailable(region, id string) error {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		inst, found, rerr := d.describeDB(region, id)
		if rerr == nil && found {
			switch inst.Status {
			case "available":
				return nil
			case "failed", "incompatible-parameters", "incompatible-restore":
				return fmt.Errorf("scratch instance entered status %q — RTO "+
					"could not be measured", inst.Status)
			}
		}
		if d.Now().After(deadline) {
			return fmt.Errorf("scratch instance still restoring at poll " +
				"timeout — RTO could not be measured")
		}
		time.Sleep(d.PollInterval)
	}
}

// waitInstanceGone polls until the member instance no longer exists (or the
// deadline). An Aurora cluster refuses deletion while it still has a member, so the
// cluster teardown must wait for the async member delete to actually complete first.
func (d *Driver) waitInstanceGone(region, id string) {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.describeDB(region, id); rerr == nil && !found {
			return // gone
		}
		if d.Now().After(deadline) {
			return // give up; the cluster-delete retry loop surfaces any real leak
		}
		time.Sleep(d.PollInterval)
	}
}

// deleteScratchInstance is best-effort cleanup; a scratch that could not be
// deleted is surfaced LOUDLY — it costs money — never silently leaked.
func (d *Driver) deleteScratchInstance(region, id string,
	out *provider.ProbeOutcome) {
	st, body, err := d.rdsPost(region, rdsSimpleBody("DeleteDBInstance",
		map[string]string{
			"DBInstanceIdentifier":   id,
			"SkipFinalSnapshot":      "true",
			"DeleteAutomatedBackups": "true",
		}))
	if rdsErrCode(body) == "DBInstanceNotFound" {
		return // already gone — nothing leaked
	}
	if err != nil || st < 200 || st >= 300 {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "recovery.rto", Method: "restore-test",
			Reason: fmt.Sprintf("scratch instance %s NOT deleted (HTTP %d, %v, "+
				"%s) — delete it manually, it costs money", id, st, err,
				rdsErrCode(body)),
			Retryable: true})
	}
}

// deleteScratchAurora tears the scratch composite down in REVERSE order — the
// member instance first, then the cluster. Deletes are ASYNC and a cluster refuses
// deletion while it still has a member, so it WAITS for the member to be gone and
// RETRIES the cluster delete while it transiently refuses. A resource that still
// will not delete at the deadline is surfaced LOUDLY — it costs money.
func (d *Driver) deleteScratchAurora(region, clusterID, instanceID string,
	out *provider.ProbeOutcome) {
	d.deleteScratchInstance(region, instanceID, out)
	d.waitInstanceGone(region, instanceID)

	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, body, err := d.rdsPost(region, rdsSimpleBody("DeleteDBCluster",
			map[string]string{
				"DBClusterIdentifier": clusterID,
				"SkipFinalSnapshot":   "true",
			}))
		if rdsErrCode(body) == "DBClusterNotFoundFault" {
			return // already gone
		}
		if err == nil && st >= 200 && st < 300 {
			return // delete accepted
		}
		// the member's async teardown may still be finishing — retry until it clears.
		if rdsErrCode(body) == "InvalidDBClusterStateFault" && !d.Now().After(deadline) {
			time.Sleep(d.PollInterval)
			continue
		}
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "recovery.rto", Method: "restore-test",
			Reason: fmt.Sprintf("scratch cluster %s NOT deleted (HTTP %d, %v, "+
				"%s) — delete it manually, it costs money", clusterID, st, err,
				rdsErrCode(body)),
			Retryable: true})
		return
	}
}

// emitRTO records the measured recovery.rto. Minutes ROUND UP (optimism is
// fabrication), floor 1, and the measurement is flagged intrusive.
func emitRTO(snapshot, scratch string, elapsed time.Duration,
	out *provider.ProbeOutcome) {
	minutes := int(elapsed.Minutes())
	if elapsed > time.Duration(minutes)*time.Minute {
		minutes++ // measured RTO rounds UP — never down
	}
	if minutes < 1 {
		minutes = 1
	}
	out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
		Path: "recovery.rto", Value: fmt.Sprintf("%dm", minutes),
		Method: "restore-test",
		Evidence: fmt.Sprintf("snapshot %s restored into scratch %s in %s",
			snapshot, scratch, elapsed.Round(time.Second)),
		Intrusive: true})
}
