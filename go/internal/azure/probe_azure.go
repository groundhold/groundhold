// Outcome probes for the Azure driver (D59/D65 parity with the GCP prober). The
// honesty rules mirror the observe mapper: a measurement is emitted ONLY when the
// OUTCOME was actually exercised — a TCP handshake that happened, a restore that ran
// to Ready. Anything short of that is a probe FAILURE with the reason named, never a
// fabricated value.
//
// Two probes, exactly as GCP:
//   - non-intrusive, always: network.publicExposure by an ACTUAL TCP handshake to
//     the server's public endpoint (port 5432);
//   - intrusive, under double consent: recovery.rto by a point-in-time restore into
//     a deterministic scratch flexible server, timed to Ready, then deleted.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"groundhold/internal/provider"
)

var _ provider.Prober = (*Driver)(nil)

const flexPostgresPort = "5432" // PostgreSQL wire protocol

// probeFlexDoc captures the fields the prober reads: the public endpoint, its
// exposure switch, the ownership tags, the region and the SKU (a scratch restored
// on a toy SKU would be an RTO lie), plus the readiness state.
type probeFlexDoc struct {
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
	SKU      struct {
		Name string `json:"name"`
		Tier string `json:"tier"`
	} `json:"sku"`
	Properties struct {
		State                    string `json:"state"`
		FullyQualifiedDomainName string `json:"fullyQualifiedDomainName"`
		Network                  struct {
			PublicNetworkAccess string `json:"publicNetworkAccess"`
		} `json:"network"`
	} `json:"properties"`
}

// getProbeFlex reads the resource. D297: a failed read names its cause.
func (d *Driver) getProbeFlex(rg, name string) (probeFlexDoc, bool, error) {
	var doc probeFlexDoc
	url, uerr := d.armURL(rg, d.flexPath(name), pgAPIVersion)
	if uerr != nil {
		return doc, false, &armReadError{Op: "flexibleServers.get", Cause: "scope", Detail: uerr.Error()}
	}
	found, err := d.armGetURLInto("flexibleServers.get", url, &doc)
	return doc, found, err
}

// Probe implements provider.Prober for the Azure driver. Dispatch is on the service
// token, fail-closed on anything not wired.
func (d *Driver) Probe(service, capability, providerID string,
	allowIntrusive bool) (provider.ProbeOutcome, error) {
	if service != "flexpostgres" {
		return provider.ProbeOutcome{}, fmt.Errorf(
			"azure driver: probes for service %q are not wired yet", service)
	}
	sub, rg, name, err := splitFlexProviderID(providerID)
	if err != nil {
		return provider.ProbeOutcome{}, err
	}
	// a forged/stale binding must not redirect a probe (and its BILLED intrusive
	// restore) onto another subscription — the ARM URL is built from the driver's
	// subscription regardless, so a mismatch cannot be honestly concluded.
	if d.Subscription != "" && sub != d.Subscription {
		return provider.ProbeOutcome{}, fmt.Errorf(
			"providerId names subscription %q, not the driver's %q — refusing to probe across subscriptions",
			sub, d.Subscription)
	}

	doc, found, rerr := d.getProbeFlex(rg, name)
	if rerr != nil {
		return provider.ProbeOutcome{}, rerr
	}
	if !found {
		return provider.ProbeOutcome{}, fmt.Errorf("flexible server %s not found — nothing to probe", name)
	}

	var out provider.ProbeOutcome
	d.probeExposure(doc.Properties.FullyQualifiedDomainName,
		doc.Properties.Network.PublicNetworkAccess, &out)

	if allowIntrusive {
		// the intrusive path PUTs/restores/deletes a BILLED scratch server — gate it
		// on ownership before spending. The Prober interface carries only the
		// capability (no environment), so match that (parity with GCP): a server with
		// no groundhold-capability tag, or a different one, is not ours to probe.
		if doc.Tags["groundhold-capability"] != sanitizeAzTag(capability) {
			return provider.ProbeOutcome{}, fmt.Errorf(
				"flexible server capability tag does not match — refusing an intrusive " +
					"probe on a resource that is not ours")
		}
		d.probeRTO(sub, rg, name, doc.Location, doc.SKU.Name, doc.SKU.Tier, &out)
	}
	return out, nil
}

// probeExposure: dial the public endpoint if the server has one. A successful TCP
// handshake PROVES exposure; publicNetworkAccess Disabled or no FQDN means there is
// no public endpoint to reach (which IS the measured outcome); a public FQDN that
// will not answer cannot conclude either way — the path may exist, the packet died —
// so it is a FAILURE, never a fabricated false.
func (d *Driver) probeExposure(fqdn, publicNetworkAccess string,
	out *provider.ProbeOutcome) {
	// D775, the Azure twin of the same fold: `publicNetworkAccess: Enabled` with an
	// EMPTY FQDN is a server whose name is not readable yet, not a server without a
	// public endpoint. Reporting it as a measured `false` invents a proven negative out
	// of missing data.
	if publicNetworkAccess != "Disabled" && fqdn == "" {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "network.publicExposure", Method: "tcp-connect",
			Reason: "publicNetworkAccess is not Disabled and the server returned no FQDN " +
				"— there is nothing to dial yet, and an unknown name is not a proven " +
				"absence of exposure",
			Retryable: true})
		return
	}
	if publicNetworkAccess == "Disabled" {
		out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
			Path: "network.publicExposure", Value: false,
			Method:   "provider-config",
			Evidence: "publicNetworkAccess is Disabled; nothing was dialled",
		})
		return
	}
	dial := d.Dial
	if dial == nil {
		dial = net.DialTimeout
	}
	host := net.JoinHostPort(fqdn, flexPostgresPort)
	conn, err := dial("tcp", host, 5*time.Second)
	if err == nil {
		_ = conn.Close()
		out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
			Path: "network.publicExposure", Value: true,
			Method:   "tcp-connect",
			Evidence: fmt.Sprintf("TCP handshake to %s succeeded", host)})
		return
	}
	out.Failures = append(out.Failures, provider.ProbeFailure{
		Path: "network.publicExposure", Method: "tcp-connect",
		Reason: fmt.Sprintf("public endpoint %s allocated but handshake failed (%v) "+
			"— filtered or down; the path may still exist, cannot conclude", host, err),
		Retryable: true})
}

// flexScratchName derives a deterministic scratch server name from the source name +
// a restore marker, so a re-probe of the same source reuses the same scratch (the
// PITR PUT is idempotent). azNameOK-bounded: "pv-pgrto-" + 8 hex chars.
func flexScratchName(sourceName string) string {
	sum := sha256.Sum256([]byte(sourceName + "|rto-restore"))
	return "pv-pgrto-" + hex.EncodeToString(sum[:])[:8]
}

// probeRTO (INTRUSIVE): point-in-time restore the source into a scratch flexible
// server (same region + SKU — a toy-SKU RTO would be a lie), time it to Ready, delete
// the scratch. Cleanup is SACRED: any failure after the scratch PUT still attempts
// the delete, and a scratch that could not be deleted is surfaced LOUDLY.
func (d *Driver) probeRTO(sub, rg, sourceName, region, skuName, skuTier string,
	out *provider.ProbeOutcome) {
	fail := func(reason string, retryable bool) {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "recovery.rto", Method: "restore-test",
			Reason: reason, Retryable: retryable})
	}
	if region == "" || skuName == "" {
		fail("source server is missing region or SKU — cannot build a faithful "+
			"scratch (an RTO restored on a different shape would be a lie)", false)
		return
	}
	scratch := flexScratchName(sourceName)
	// the canonical ARM resource id (host-less, leading "/subscriptions/...").
	sourceID := fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforPostgreSQL/flexibleServers/%s",
		sub, rg, sourceName)

	pit := d.Now().Add(-5 * time.Minute).UTC().Format(time.RFC3339)
	started := d.Now()

	url, err := d.armURL(rg, d.flexPath(scratch), pgAPIVersion)
	if err != nil {
		fail(fmt.Sprintf("scratch URL build failed: %v", err), false)
		return
	}
	body, _ := json.Marshal(map[string]any{
		"location": region,
		"tags":     map[string]any{"groundhold-probe": "rto-scratch"},
		"sku":      map[string]any{"name": skuName, "tier": skuTier},
		"properties": map[string]any{
			"createMode":             "PointInTimeRestore",
			"sourceServerResourceId": sourceID,
			"pointInTimeUTC":         pit,
		},
	})
	st, resp, err := d.doARM("PUT", url, body)
	if err != nil || st < 200 || st >= 300 {
		// the PUT did not get accepted — no scratch to clean up (a re-probe reuses the
		// same deterministic name if a 5xx did in fact land).
		fail(fmt.Sprintf("scratch restore PUT failed (HTTP %d, %v): %s",
			st, err, mutDetailAz(resp)), true)
		return
	}
	// from here the scratch PUT was ACCEPTED — cleanup is sacred on any exit.

	if !d.pollScratchReady(rg, scratch, fail) {
		d.deleteScratchFlex(rg, scratch, out)
		return
	}
	elapsed := d.Now().Sub(started)
	d.deleteScratchFlex(rg, scratch, out)

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
		Evidence: fmt.Sprintf("point-in-time restore of %s into scratch %s reached Ready in %s",
			sourceName, scratch, elapsed.Round(time.Second)),
		Intrusive: true})
}

// pollScratchReady polls the scratch to properties.state == Ready. A terminal-failed
// state or the poll timeout is a probe FAILURE (the caller then deletes the scratch).
func (d *Driver) pollScratchReady(rg, scratch string, fail func(string, bool)) bool {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		state, readable := d.flexState(rg, scratch)
		if readable {
			switch state {
			case "Ready":
				return true
			case "Failed", "Dropping", "Disabled":
				fail("scratch restore entered terminal state "+state, true)
				return false
			}
		}
		if d.Now().After(deadline) {
			fail("scratch restore still provisioning at poll timeout — cannot conclude", true)
			return false
		}
		time.Sleep(d.PollInterval)
	}
}

// deleteScratchFlex is best-effort cleanup; a leftover scratch server COSTS MONEY, so
// a delete that does not confirm is surfaced LOUDLY, never silently leaked.
func (d *Driver) deleteScratchFlex(rg, scratch string, out *provider.ProbeOutcome) {
	url, err := d.armURL(rg, d.flexPath(scratch), pgAPIVersion)
	if err != nil {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "recovery.rto", Method: "restore-test",
			Reason: fmt.Sprintf("scratch %s NOT deleted (bad URL: %v) — delete it "+
				"manually, it costs money", scratch, err),
			Retryable: true})
		return
	}
	st, _, err := d.doARM("DELETE", url, nil)
	if err != nil || st < 200 || st >= 300 {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "recovery.rto", Method: "restore-test",
			Reason: fmt.Sprintf("scratch %s NOT deleted (HTTP %d, %v) — delete it "+
				"manually, it costs money", scratch, st, err),
			Retryable: true})
	}
}
