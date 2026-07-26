// EBS volume network shell (D367): auth, HTTP, polling and the reverse mapping.
// No semantics live here — those are in ebs.go.
//
// The honesty rules the executor depends on (D29), stated where they are easy to
// check: a transport error or a 5xx on a MUTATING call is `unknown`, never
// `failed`, because a 502 can front a volume that was created. A 2xx that carries
// no volume id is `unknown` too — a truncated body is not a successful create.
// Only a definitive 4xx is `failed`. Every one of these is reconcilable, because
// the ClientToken the pure core derives is deterministic: a lost create can be
// found again rather than duplicated.
//
// For a STATEFUL capability the stakes on that rule are different in kind. A
// duplicated stateless resource costs money; a duplicated volume splits the data
// across two of them, and the operator finds out later, from the half that is
// missing writes.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"groundhold/internal/provider"
)

// ebsVolIDOK bounds a server-assigned volume id before it reaches a request.
var ebsVolIDOK = regexp.MustCompile(`^vol-[0-9a-f]{8,17}$`)

// ebsVolProviderID is region-scoped: a volume id is unique per region.
func ebsVolProviderID(region, account, id string) string {
	return "ebs:" + region + ":" + account + ":" + id
}

func splitEBSVolProviderID(providerID string) (region, account, id string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "ebs" {
		return "", "", "", fmt.Errorf("providerId %q is not an ebs volume id (want ebs:<region>:<account>:<vol-...>)", providerID)
	}
	region, account, id = parts[1], parts[2], parts[3]
	if region == "" || !ebsVolIDOK.MatchString(id) {
		return "", "", "", fmt.Errorf("providerId %q has no valid region/volume id", providerID)
	}
	return region, account, id, nil
}

func (d *Driver) createEBSVolume(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {

	plan, err := BuildEBSVolumeCreate(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, body, err := d.ec2PostBase(region, plan.createBody())
	switch {
	case err != nil:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; recover by ClientToken): %v", err)}
	case st == http.StatusOK:
		var resp struct {
			VolumeID string `xml:"volumeId"`
		}
		if xml.Unmarshal(body, &resp) != nil || resp.VolumeID == "" {
			return provider.CreateResult{Status: "unknown",
				Reason: "create returned no volume id — reconcile by ClientToken"}
		}
		return d.pollEBSVolume(region, account, resp.VolumeID)
	case strings.Contains(ec2ErrCode(body), "IdempotentParameterMismatch"):
		// our ClientToken already made a volume with different parameters: this is a
		// conflict, not a retry, and guessing which one is "ours" would bind the
		// wrong disk — which for a stateful capability means binding the wrong data.
		return provider.CreateResult{Status: "failed",
			Reason: "the idempotency token already names a volume created with different parameters — refusing to bind it"}
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile by ClientToken", st)}
	default:
		if r := provider.MutationResult(st, ec2ErrCode(body), nil, "", "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s)", st, ec2ErrCode(body))}
	}
}

// pollEBSVolume waits for the volume to become usable. `available` and `in-use`
// both mean the disk exists and can hold data; `error` failed; anything still
// `creating` at the deadline is `unknown`, never assumed good.
func (d *Driver) pollEBSVolume(region, account, id string) provider.CreateResult {
	pid := ebsVolProviderID(region, account, id)
	deadline := d.Now().Add(d.PollTimeout)
	for {
		vol, found, rerr := d.describeEC2Volume(region, id)
		if rerr == nil && found {
			switch vol.State {
			case "available", "in-use":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "error":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "volume entered state error instead of available"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "volume still creating at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// observeEBSVolume is the reverse mapping. Where a fact cannot be read it is
// REPORTED AS UNREAD rather than defaulted — an unreadable encryption state that
// silently became `false` would fail a CMK constraint reality satisfies, and one
// that silently became `true` would pass one reality violates.
func (d *Driver) observeEBSVolume(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, id, err := splitEBSVolProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	vol, found, rerr := d.describeEC2Volume(region, id)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"volume not found — nothing to observe"}, nil
	}
	return []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// An EBS volume lives in exactly one availability zone, always — this is
		// measured rather than assumed only in the sense that the API confirms the
		// zone it sits in; the CLASS could not be anything else.
		{Path: "availability.class", Value: "zonal", Derivation: "measured"},
		{Path: "encryption.atRest", Value: vol.Encrypted, Derivation: "measured"},
		// An AWS-managed default key is NOT customer-managed: reporting true here
		// would certify a BYOK control the customer cannot revoke.
		{Path: "encryption.customerManagedKeys",
			Value:      vol.Encrypted && vol.KmsKeyID != "" && !isAWSManagedKMSKey(vol.KmsKeyID, "ebs"),
			Derivation: "measured"},
	}, nil, nil
}

// deleteEBSVolume destroys the volume AND the data on it, and refuses to touch
// one whose ownership tags are not ours.
//
// The stateful gates (D47) sit above this in the executor: reaching here at all
// means the plan pinned this volume as a retirement target and the operator
// consented to the data loss. What this function owes them is that it deletes
// exactly what was pinned and nothing else.
func (d *Driver) deleteEBSVolume(capability, environment, providerID string) provider.CreateResult {
	region, _, id, err := splitEBSVolProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	vol, found, rerr := d.describeEC2Volume(region, id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(vol.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "volume tags do not match — refusing to destroy data that is not ours"}
	}
	st, body, e := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DeleteVolume", "Version": ec2Version, "VolumeId": id,
	}))
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case strings.Contains(ec2ErrCode(body), "NotFound"):
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, ec2ErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("delete HTTP %d (%s)", st, ec2ErrCode(body))}
	}
}

// discoverEBSVolumes enumerates volumes in the region as capability.storage.block.
// Every observable service must be discoverable (spec/drivers.md §2) — and an
// unmanaged, unencrypted volume nobody is watching is one of the more expensive
// blind spots a proactive posture can have, because the data on it is already
// there.
func (d *Driver) discoverEBSVolumes(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("ebs: %v", err)
	}
	vols, err := d.describeEC2Volumes(region, nil)
	if err != nil {
		return nil, nil, err
	}
	var out []provider.Discovered
	var diags []string
	for _, v := range vols {
		if v.VolumeID == "" {
			continue
		}
		pid := ebsVolProviderID(region, account, v.VolumeID)
		obs, odiags, oerr := d.observeEBSVolume("", pid)
		if oerr != nil {
			diags = append(diags, v.VolumeID+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, v.VolumeID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.storage.block",
			Observations: obs,
		})
	}
	return out, diags, nil
}
