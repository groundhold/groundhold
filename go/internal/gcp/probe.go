// Outcome probes for Cloud SQL (D59/D65). Honesty rules mirror the
// observe mapper: a measurement is emitted only when the OUTCOME was
// actually exercised — a handshake that happened, a restore that ran.
// Anything short of that is a probe FAILURE with the reason named,
// never a fabricated value.
package gcp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

// engine ports for the handshake probe
func portOf(databaseVersion string) string {
	switch {
	case strings.HasPrefix(databaseVersion, "POSTGRES_"):
		return "5432"
	case strings.HasPrefix(databaseVersion, "MYSQL_"):
		return "3306"
	case strings.HasPrefix(databaseVersion, "SQLSERVER_"):
		return "1433"
	}
	return ""
}

// Probe implements provider.Prober (D59):
//   - non-intrusive, always: network.publicExposure by ACTUAL
//     handshake — a public address that answers is exposure proven;
//     no public address allocated is no path to reach;
//   - intrusive, under double consent: recovery.rto by restoring the
//     latest backup into a scratch instance and timing it to RUNNABLE.
func (d *Driver) Probe(service, capability, providerID string,
	allowIntrusive bool) (provider.ProbeOutcome, error) {
	if service != "cloudsql" {
		return provider.ProbeOutcome{}, fmt.Errorf(
			"gcp driver: probes for service %q are not wired yet", service)
	}
	project, region, name, err := splitProviderID(providerID)
	if err != nil {
		return provider.ProbeOutcome{}, err
	}
	// a forged/stale binding must not redirect a probe (and its billed intrusive
	// restore) into another project or off a foreign identity (adversarial review).
	if err := d.sameProject(project); err != nil {
		return provider.ProbeOutcome{}, err
	}

	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/instances/%s", d.BaseURL, project, name), nil)
	if err != nil {
		return provider.ProbeOutcome{}, err
	}
	if status != http.StatusOK {
		return provider.ProbeOutcome{}, fmt.Errorf(
			"instances.get: HTTP %d", status)
	}
	var inst struct {
		DatabaseVersion string `json:"databaseVersion"`
		IPAddresses     []struct {
			Type      string `json:"type"`
			IPAddress string `json:"ipAddress"`
		} `json:"ipAddresses"`
		Settings struct {
			Tier       string            `json:"tier"`
			Edition    string            `json:"edition"`
			UserLabels map[string]string `json:"userLabels"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(body, &inst); err != nil {
		return provider.ProbeOutcome{}, err
	}

	var out provider.ProbeOutcome
	d.probeExposure(inst.DatabaseVersion, publicIP(instAddrs(
		inst.IPAddresses)), &out)
	if allowIntrusive {
		// the intrusive path CREATES/restores/deletes a billed scratch instance
		// — gate it on ownership before spending. The Prober interface carries
		// only the capability (no environment), so match that: an instance with
		// no groundhold-capability label, or a different one, is not ours to probe.
		if inst.Settings.UserLabels["groundhold-capability"] != sanitizeLabel(capability) {
			return provider.ProbeOutcome{}, fmt.Errorf(
				"instance capability label does not match — refusing an intrusive " +
					"probe on a resource that is not ours")
		}
		d.probeRTO(region, name, inst.Settings.Tier, inst.Settings.Edition,
			inst.DatabaseVersion, &out)
	}
	return out, nil
}

type addr struct{ typ, ip string }

func instAddrs(raw []struct {
	Type      string `json:"type"`
	IPAddress string `json:"ipAddress"`
}) []addr {
	out := make([]addr, 0, len(raw))
	for _, a := range raw {
		out = append(out, addr{a.Type, a.IPAddress})
	}
	return out
}

func publicIP(addrs []addr) string {
	for _, a := range addrs {
		if a.typ == "PRIMARY" && a.ip != "" {
			return a.ip
		}
	}
	return ""
}

// probeExposure: dial the public address if one exists. A successful
// handshake PROVES exposure; a filtered/failed handshake on an
// allocated address cannot conclude either way (the path exists, the
// packet died — today); no allocated address means no endpoint to
// reach, which IS the measured outcome.
func (d *Driver) probeExposure(dbVersion, pubIP string,
	out *provider.ProbeOutcome) {
	if pubIP == "" {
		// D775: the value is right — for Cloud SQL the allocated address list IS the
		// answer, so there is no unknown-versus-absent fold here. What was wrong is the
		// METHOD: `tcp-connect` names a handshake nobody attempted.
		out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
			Path: "network.publicExposure", Value: false,
			Method:   "provider-config",
			Evidence: "no public address allocated; no endpoint to reach, nothing dialled",
		})
		return
	}
	port := portOf(dbVersion)
	if port == "" {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "network.publicExposure", Method: "tcp-connect",
			Reason: fmt.Sprintf("unknown engine %q — no port to dial",
				dbVersion),
			Retryable: false})
		return
	}
	dial := d.Dial
	if dial == nil {
		dial = net.DialTimeout
	}
	conn, err := dial("tcp", net.JoinHostPort(pubIP, port), 5*time.Second)
	if err == nil {
		_ = conn.Close()
		out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
			Path: "network.publicExposure", Value: true,
			Method: "tcp-connect",
			Evidence: fmt.Sprintf("TCP handshake to %s:%s succeeded",
				pubIP, port)})
		return
	}
	out.Failures = append(out.Failures, provider.ProbeFailure{
		Path: "network.publicExposure", Method: "tcp-connect",
		Reason: fmt.Sprintf("public address %s allocated but handshake "+
			"failed (%v) — filtered or down; the path may still exist, "+
			"cannot conclude", pubIP, err),
		Retryable: true})
}

// probeRTO (INTRUSIVE): restore the latest successful backup into a
// scratch instance, time it to DONE, delete the scratch. The scratch
// name derives deterministically from (source, backup id) so a
// re-probe of the same backup is idempotent.
func (d *Driver) probeRTO(region, name, tier, edition, dbVersion string,
	out *provider.ProbeOutcome) {
	fail := func(reason string, retryable bool) {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "recovery.rto", Method: "restore-test",
			Reason: reason, Retryable: retryable})
	}
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/instances/%s/backupRuns?maxResults=1",
		d.BaseURL, d.Project, name), nil)
	if err != nil || status != http.StatusOK {
		fail(fmt.Sprintf("backupRuns.list failed (HTTP %d, %v)",
			status, err), true)
		return
	}
	var runs struct {
		Items []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"items"`
	}
	if json.Unmarshal(body, &runs) != nil || len(runs.Items) == 0 ||
		runs.Items[0].Status != "SUCCESSFUL" {
		fail("no successful backup to restore — RTO is unmeasurable "+
			"until one exists", false)
		return
	}
	backupID := runs.Items[0].ID

	sum := sha256.Sum256([]byte(name + "|" + backupID))
	scratch := "groundhold-probe-rto-" + hex.EncodeToString(sum[:])[:10]
	started := d.Now()

	// scratch instance: same engine and tier as the source (an RTO
	// measured on a toy tier would be a lie), no protection — it is
	// deliberately disposable
	scratchSettings := map[string]any{
		"tier":                      tier,
		"deletionProtectionEnabled": false,
		"userLabels": map[string]any{
			"groundhold-probe": "rto-scratch",
		},
	}
	// edition-specific tiers (e.g. db-perf-optimized-N-2 is ENTERPRISE_PLUS-only)
	// are rejected under a different default edition — copy the source's edition
	// so the scratch matches, or the RTO probe fails for exactly the instances
	// whose RTO matters most (D79 edition drift).
	if edition != "" {
		scratchSettings["edition"] = edition
	}
	insertBody := map[string]any{
		"name": scratch, "region": region,
		"databaseVersion": dbVersion,
		"settings":        scratchSettings,
	}
	if !d.probeStep("POST", fmt.Sprintf("%s/projects/%s/instances",
		d.BaseURL, d.Project), insertBody, scratch, region, fail,
		"scratch create") {
		return
	}
	if !d.probeStep("POST", fmt.Sprintf(
		"%s/projects/%s/instances/%s/restoreBackup",
		d.BaseURL, d.Project, scratch), map[string]any{
		"restoreBackupContext": map[string]any{
			"backupRunId": backupID, "instanceId": name,
		}}, scratch, region, fail, "restore") {
		d.deleteScratch(scratch, region, out)
		return
	}
	elapsed := d.Now().Sub(started)
	d.deleteScratch(scratch, region, out)

	minutes := int(elapsed.Minutes())
	if elapsed > time.Duration(minutes)*time.Minute {
		minutes++ // measured RTO rounds UP — optimism is fabrication
	}
	if minutes < 1 {
		minutes = 1
	}
	out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
		Path: "recovery.rto", Value: fmt.Sprintf("%dm", minutes),
		Method: "restore-test",
		Evidence: fmt.Sprintf("backup %s restored into scratch %s in %s",
			backupID, scratch, elapsed.Round(time.Second)),
		Intrusive: true})
}

// probeStep issues one mutating call and polls its operation to DONE.
func (d *Driver) probeStep(method, url string, body map[string]any,
	scratch, region string, fail func(string, bool), what string) bool {
	status, respBody, err := d.call(method, url, body)
	if err != nil || status < 200 || status >= 300 {
		fail(fmt.Sprintf("%s failed (HTTP %d, %v)", what, status, err),
			true)
		return false
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(respBody, &op) != nil || op.Name == "" {
		fail(what+" returned no operation to poll", true)
		return false
	}
	cr := d.pollOperation(op.Name, scratch, region)
	if cr.Status != "succeeded" {
		fail(fmt.Sprintf("%s operation %s: %s (%s)", what, op.Name,
			cr.Status, cr.Reason), true)
		return false
	}
	return true
}

// deleteScratch is best-effort cleanup; a leftover scratch is
// surfaced loudly, never silently leaked.
func (d *Driver) deleteScratch(scratch, region string,
	out *provider.ProbeOutcome) {
	status, _, err := d.call("DELETE", fmt.Sprintf(
		"%s/projects/%s/instances/%s", d.BaseURL, d.Project, scratch), nil)
	if err != nil || status < 200 || status >= 300 {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "recovery.rto", Method: "restore-test",
			Reason: fmt.Sprintf("scratch instance %s NOT deleted "+
				"(HTTP %d, %v) — delete it manually, it costs money",
				scratch, status, err),
			Retryable: true})
	}
}
