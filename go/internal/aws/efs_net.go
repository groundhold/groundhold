// EFS network shell (D111): the SigV4-signed, REST-JSON half of the AWS
// capability.storage.filesystem driver. CreateFileSystem is async — the
// FileSystemId is SERVER-ASSIGNED, so the providerId is parsed from the response
// (DeterministicID=false); a deterministic CreationToken is the idempotency key,
// so a lost create is recovered by DescribeFileSystems + CreationToken match,
// never a stranded resource. The share is polled to LifeCycleState=available.
// Ownership is TAGS (ListTagsForResource on the fs id). D29/D87 honesty throughout.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

const efsPath = "/2015-02-01"

func (d *Driver) efsBase(region string) string {
	if d.EFSBaseURL != "" {
		return d.EFSBaseURL
	}
	return "https://elasticfilesystem." + region + ".amazonaws.com"
}

func efsProviderID(region, account, id string) string {
	return "efs:" + region + ":" + account + ":" + id
}

func splitEFSProviderID(providerID string) (region, account, id string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "efs" {
		return "", "", "", fmt.Errorf("providerId %q is not efs:region:account:id", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !efsIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId file-system id %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// efsDo signs and sends a REST-JSON request.
func (d *Driver) efsDo(method, region, path, body string) (int, []byte, error) {
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	return d.doSigned(method, d.efsBase(region)+path, "elasticfilesystem", region,
		map[string]string{"Content-Type": "application/json"}, b)
}

// efsErr pulls the ErrorCode out of an EFS JSON error body.
func efsErr(body []byte) string {
	var e struct {
		ErrorCode string `json:"ErrorCode"`
		Message   string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	if e.ErrorCode != "" {
		return e.ErrorCode
	}
	return "" // D309: never the raw body — this string reaches a persisted receipt
}

type efsFileSystem struct {
	FileSystemId         string `json:"FileSystemId"`
	CreationToken        string `json:"CreationToken"`
	LifeCycleState       string `json:"LifeCycleState"`
	Encrypted            bool   `json:"Encrypted"`
	KmsKeyId             string `json:"KmsKeyId"`
	AvailabilityZoneName string `json:"AvailabilityZoneName"`
}

// describeEFS reads a file system by id OR creation token (whichever query is
// non-empty). found=false + readable=true is an authoritative "does not exist".
func (d *Driver) describeEFS(region, query string) (efsFileSystem, bool, error) {
	const op = "DescribeFileSystems"
	st, resp, err := d.efsDo("GET", region, efsPath+"/file-systems?"+query, "")
	if err != nil {
		return efsFileSystem{}, false, readTransport(op, err)
	}
	if strings.Contains(efsErr(resp), "FileSystemNotFound") {
		return efsFileSystem{}, false, nil
	}
	if st != http.StatusOK {
		return efsFileSystem{}, false, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		FileSystems []efsFileSystem `json:"FileSystems"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return efsFileSystem{}, false, readBody(op, st)
	}
	if len(out.FileSystems) == 0 {
		return efsFileSystem{}, false, nil
	}
	return out.FileSystems[0], true, nil
}

// efsTags reads the file system's ownership tags. readable=false on any failure.
func (d *Driver) efsTags(region, id string) (map[string]string, error) {
	const op = "DescribeTags"
	st, resp, err := d.efsDo("GET", region, efsPath+"/resource-tags/"+id, "")
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var out struct {
		Tags []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

func (d *Driver) createEFS(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildEFSCreate(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, err := d.efsDo("POST", region, efsPath+"/file-systems", jsonBody(plan.createBody(capability, environment)))
	switch {
	case err != nil:
		// server-assigned id: no deterministic pid, but the CreationToken lets a
		// retry recover — unknown, reconcilable by token.
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; recover by CreationToken): %v", err)}
	case st == http.StatusCreated || st == http.StatusOK:
		var fs efsFileSystem
		if json.Unmarshal(resp, &fs) != nil || fs.FileSystemId == "" {
			return provider.CreateResult{Status: "unknown", Reason: "create returned no file-system id — reconcile by CreationToken"}
		}
		return d.pollEFS(region, account, fs.FileSystemId)
	case strings.Contains(efsErr(resp), "FileSystemAlreadyExists"):
		// our deterministic CreationToken already made this fs — recover its id.
		return d.recoverEFS(region, account, plan, capability, environment)
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile by CreationToken", st)}
	default:
		if r := provider.MutationResult(st, efsErr(resp), nil, "", "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s): %s", st, efsErr(resp), mutDetail(resp))}
	}
}

// recoverEFS finds the fs our CreationToken already created, so a duplicate
// create returns the same handle.
func (d *Driver) recoverEFS(region, account string, plan EFSPlan, capability, environment string) provider.CreateResult {
	fs, found, rerr := d.describeEFS(region, "CreationToken="+plan.CreationToken)
	if rerr != nil {
		return provider.CreateResult{Status: "unknown", Reason: "fs exists (our CreationToken) but describe failed — reconcile"}
	}
	if !found {
		return provider.CreateResult{Status: "unknown", Reason: "CreationToken conflict but fs not found — reconcile"}
	}
	tags, terr := d.efsTags(region, fs.FileSystemId)
	if terr != nil || !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "a file system with this CreationToken exists but is not ours (tags do not match) — refusing"}
	}
	return d.pollEFS(region, account, fs.FileSystemId)
}

// pollEFS polls a file system to LifeCycleState=available. Still-creating at
// timeout is unknown WITH the providerId (the fs that landed is never orphaned).
func (d *Driver) pollEFS(region, account, id string) provider.CreateResult {
	pid := efsProviderID(region, account, id)
	deadline := d.Now().Add(d.PollTimeout)
	for {
		fs, found, rerr := d.describeEFS(region, "FileSystemId="+id)
		if rerr == nil && found {
			switch fs.LifeCycleState {
			case "available":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "error", "deleting", "deleted":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "file system entered lifecycle state " + fs.LifeCycleState}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "file system still creating at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

func (d *Driver) observeEFS(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, id, err := splitEFSProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	fs, found, rerr := d.describeEFS(region, "FileSystemId="+id)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"file system not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "encryption.atRest", Value: fs.Encrypted, Derivation: "measured"},
		// EFS speaks NFSv4.1.
		{Path: "protocol", Value: "nfs/4.1", Derivation: "config-intent"},
	}
	// One Zone storage pins an AZ; Standard is multi-AZ (regional).
	if fs.AvailabilityZoneName != "" {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "zonal", Derivation: "measured"})
	} else {
		obs = append(obs, provider.Observation{Path: "availability.class", Value: "regional", Derivation: "measured"})
	}
	if fs.KmsKeyId != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteEFS(capability, environment, providerID string) provider.CreateResult {
	region, _, id, err := splitEFSProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, found, rerr := d.describeEFS(region, "FileSystemId="+id)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.efsTags(region, id)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "file system tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.efsDo("DELETE", region, efsPath+"/file-systems/"+id, "")
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(efsErr(resp), "FileSystemNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if strings.Contains(efsErr(resp), "FileSystemInUse") {
		return provider.CreateResult{Status: "failed",
			Reason: "the file system still has mount targets and cannot be deleted — remove them first (never forced)"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, efsErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, efsErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
