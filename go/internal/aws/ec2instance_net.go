// EC2 instance network shell (D358): auth, HTTP, polling and the reverse
// mapping. No semantics live here — those are in ec2instance.go.
//
// The honesty rules the executor depends on (D29), stated where they are easy to
// check: a transport error or a 5xx on a MUTATING call is `unknown`, never
// `failed`, because a 502 can front a machine that started. A 2xx that carries no
// instance id is `unknown` too — a truncated body is not a successful create. Only
// a definitive 4xx is `failed`. Every one of these is reconcilable, because the
// ClientToken the pure core derives is deterministic: a lost create can be found
// again rather than duplicated.
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

// ec2InstanceIDOK bounds a server-assigned instance id before it reaches a request.
var ec2InstanceIDOK = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)

// ec2InstanceProviderID is region-scoped: an instance id is unique per region.
func ec2InstanceProviderID(region, account, id string) string {
	return "ec2:" + region + ":" + account + ":" + id
}

func splitEC2InstanceProviderID(providerID string) (region, account, id string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "ec2" {
		return "", "", "", fmt.Errorf("providerId %q is not an ec2 instance id (want ec2:<region>:<account>:<i-...>)", providerID)
	}
	region, account, id = parts[1], parts[2], parts[3]
	if region == "" || !ec2InstanceIDOK.MatchString(id) {
		return "", "", "", fmt.Errorf("providerId %q has no valid region/instance id", providerID)
	}
	return region, account, id, nil
}

// ec2Instance is the slice of DescribeInstances this driver reads.
type ec2Instance struct {
	InstanceID string
	State      string
	PublicIP   string
	SubnetID   string
	VolumeIDs  []string
	Tags       map[string]string
}

// describeEC2Instances runs a DescribeInstances query and returns the first
// instance it names. `found=false` with no error means the API answered and the
// instance is not there — which is different from "the read failed", and the
// difference is what keeps a delete idempotent instead of guessing.
func (d *Driver) describeEC2Instances(region string, extra map[string]string) (ec2Instance, bool, error) {
	params := map[string]string{"Action": "DescribeInstances", "Version": ec2Version}
	for k, v := range extra {
		params[k] = v
	}
	st, body, err := d.ec2PostBase(region, encodeForm(params))
	if err != nil {
		return ec2Instance{}, false, readTransport("DescribeInstances", err)
	}
	if st == http.StatusBadRequest && strings.Contains(ec2ErrCode(body), "NotFound") {
		return ec2Instance{}, false, nil
	}
	if st != http.StatusOK {
		return ec2Instance{}, false, readHTTP("DescribeInstances", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			InstanceID string `xml:"instanceId"`
			State      string `xml:"instanceState>name"`
			PublicIP   string `xml:"publicIpAddress"`
			SubnetID   string `xml:"subnetId"`
			Devices    []struct {
				VolumeID string `xml:"ebs>volumeId"`
			} `xml:"blockDeviceMapping>item"`
			Tags []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"tagSet>item"`
		} `xml:"reservationSet>item>instancesSet>item"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return ec2Instance{}, false, readBody("DescribeInstances", st)
	}
	for _, it := range resp.Items {
		// A terminated machine is gone as far as the contract is concerned; reading
		// one as present would make a delete look unfinished forever.
		if it.State == "terminated" {
			continue
		}
		inst := ec2Instance{
			InstanceID: it.InstanceID, State: it.State,
			PublicIP: it.PublicIP, SubnetID: it.SubnetID,
			Tags: map[string]string{},
		}
		for _, dev := range it.Devices {
			if dev.VolumeID != "" {
				inst.VolumeIDs = append(inst.VolumeIDs, dev.VolumeID)
			}
		}
		for _, t := range it.Tags {
			inst.Tags[t.Key] = t.Value
		}
		return inst, true, nil
	}
	return ec2Instance{}, false, nil
}

// ec2Volume is the slice of DescribeVolumes the encryption attributes need.
type ec2Volume struct {
	Encrypted bool
	KmsKeyID  string
}

func (d *Driver) describeEC2Volume(region, volumeID string) (ec2Volume, bool, error) {
	st, body, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeVolumes", "Version": ec2Version, "VolumeId.1": volumeID,
	}))
	if err != nil {
		return ec2Volume{}, false, readTransport("DescribeVolumes", err)
	}
	if st == http.StatusBadRequest && strings.Contains(ec2ErrCode(body), "NotFound") {
		return ec2Volume{}, false, nil
	}
	if st != http.StatusOK {
		return ec2Volume{}, false, readHTTP("DescribeVolumes", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			Encrypted bool   `xml:"encrypted"`
			KmsKeyID  string `xml:"kmsKeyId"`
		} `xml:"volumeSet>item"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return ec2Volume{}, false, readBody("DescribeVolumes", st)
	}
	if len(resp.Items) == 0 {
		return ec2Volume{}, false, nil
	}
	return ec2Volume{Encrypted: resp.Items[0].Encrypted, KmsKeyID: resp.Items[0].KmsKeyID}, true, nil
}

func (d *Driver) createEC2Instance(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {

	plan, err := BuildEC2InstanceCreate(environment, capability, attrs, impl, generation)
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
			InstanceID string `xml:"instancesSet>item>instanceId"`
		}
		if xml.Unmarshal(body, &resp) != nil || resp.InstanceID == "" {
			return provider.CreateResult{Status: "unknown",
				Reason: "create returned no instance id — reconcile by ClientToken"}
		}
		return d.pollEC2Instance(region, account, resp.InstanceID)
	case strings.Contains(ec2ErrCode(body), "IdempotentParameterMismatch"):
		// our ClientToken already made a machine with different parameters: this is
		// a conflict, not a retry, and guessing which one is "ours" would bind the
		// wrong resource.
		return provider.CreateResult{Status: "failed",
			Reason: "the idempotency token already names an instance created with different parameters — refusing to bind it"}
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

// pollEC2Instance waits for the machine to reach `running`. A machine that is
// shutting down or terminated failed; one still pending at the deadline is
// `unknown`, never assumed good.
func (d *Driver) pollEC2Instance(region, account, id string) provider.CreateResult {
	pid := ec2InstanceProviderID(region, account, id)
	deadline := d.Now().Add(d.PollTimeout)
	for {
		inst, found, rerr := d.describeEC2Instances(region, map[string]string{"InstanceId.1": id})
		if rerr == nil && found {
			switch inst.State {
			case "running":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "shutting-down", "terminated", "stopping", "stopped":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "instance entered state " + inst.State + " instead of running"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "instance still starting at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// observeEC2Instance is the reverse mapping. Where a fact cannot be read, it is
// REPORTED AS UNREAD rather than defaulted — an unreadable encryption state that
// silently became `false` would fail a CMK constraint that reality satisfies, and
// one that silently became `true` would pass one reality violates.
func (d *Driver) observeEC2Instance(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, id, err := splitEC2InstanceProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	inst, found, rerr := d.describeEC2Instances(region, map[string]string{"InstanceId.1": id})
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"instance not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// An instance is placed in exactly one availability zone, always.
		{Path: "availability.class", Value: "zonal", Derivation: "measured"},
		// A public address is the whole of public exposure for a machine: no
		// address, no path from the internet, whatever the security groups say.
		{Path: "network.publicExposure", Value: inst.PublicIP != "", Derivation: "measured"},
	}
	var unread []string
	if len(inst.VolumeIDs) == 0 {
		unread = append(unread, "instance reported no block devices — disk encryption unread")
		return obs, unread, nil
	}
	vol, vfound, verr := d.describeEC2Volume(region, inst.VolumeIDs[0])
	switch {
	case verr != nil:
		// the diagnostic names the call, the status and the service's own code
		// (D296), so an operator can tell a throttle from a permission gap.
		unread = append(unread, "disk encryption unread: "+verr.Error())
	case !vfound:
		unread = append(unread, "root volume "+inst.VolumeIDs[0]+" not found — disk encryption unread")
	default:
		obs = append(obs, provider.Observation{
			Path: "encryption.atRest", Value: vol.Encrypted, Derivation: "measured"})
		// An AWS-managed default key is NOT customer-managed: reporting true here
		// would certify a BYOK control the customer cannot revoke.
		obs = append(obs, provider.Observation{
			Path:       "encryption.customerManagedKeys",
			Value:      vol.Encrypted && vol.KmsKeyID != "" && !isAWSManagedKMSKey(vol.KmsKeyID, "ebs"),
			Derivation: "measured"})
	}
	return obs, unread, nil
}

// deleteEC2Instance terminates the machine, and refuses to touch one whose
// ownership tags are not ours.
func (d *Driver) deleteEC2Instance(capability, environment, providerID string) provider.CreateResult {
	region, _, id, err := splitEC2InstanceProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	inst, found, rerr := d.describeEC2Instances(region, map[string]string{"InstanceId.1": id})
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(inst.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "instance tags do not match — refusing to terminate a machine that is not ours"}
	}
	st, body, e := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "TerminateInstances", "Version": ec2Version, "InstanceId.1": id,
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

// discoverEC2Instances enumerates running machines in the region as
// capability.compute.instance. Every observable service must be discoverable
// (spec/drivers.md §2) — a machine the proactive posture cannot see is a machine
// nobody is watching, which for a VM is exactly the wrong blind spot.
//
// Terminated instances are skipped by describeEC2Instances, so a torn-down
// machine does not linger in discovery as something to adopt.
func (d *Driver) discoverEC2Instances(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("ec2: %v", err)
	}
	st, body, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeInstances", "Version": ec2Version,
	}))
	if err != nil {
		return nil, nil, readTransport("DescribeInstances", err)
	}
	if st != http.StatusOK {
		return nil, nil, readHTTP("DescribeInstances", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			InstanceID string `xml:"instanceId"`
			State      string `xml:"instanceState>name"`
		} `xml:"reservationSet>item>instancesSet>item"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return nil, nil, readBody("DescribeInstances", st)
	}
	var out []provider.Discovered
	var diags []string
	for _, it := range resp.Items {
		if it.InstanceID == "" || it.State == "terminated" {
			continue
		}
		pid := ec2InstanceProviderID(region, account, it.InstanceID)
		obs, odiags, oerr := d.observeEC2Instance("", pid)
		if oerr != nil {
			diags = append(diags, it.InstanceID+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, it.InstanceID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.compute.instance",
			Observations: obs,
		})
	}
	return out, diags, nil
}
