// ECR network shell (D110): the SigV4-signed (regional, JSON protocol) half of the AWS
// capability.registry.image driver. The repository name is deterministic (content-
// addressed); a RepositoryAlreadyExists continues only if the existing repo is ours
// (tags). observe reverse-maps encryption + tag mutability. Ownership is tags.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

const ecrTarget = "AmazonEC2ContainerRegistry_V20150921"

func (d *Driver) ecrBase(region string) string {
	if d.ECRBaseURL != "" {
		return d.ECRBaseURL
	}
	return "https://api.ecr." + region + ".amazonaws.com"
}

func (d *Driver) ecrCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": ecrTarget + "." + action,
	}
	return d.doSigned("POST", d.ecrBase(region)+"/", "ecr", region, h, []byte(body))
}

func ecrArn(region, account, name string) string {
	return "arn:aws:ecr:" + region + ":" + account + ":repository/" + name
}

func ecrProviderID(region, account, name string) string {
	return "ecr:" + region + ":" + account + ":" + name
}

func splitECRProviderID(providerID string) (region, account, name string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "ecr" {
		return "", "", "", fmt.Errorf("providerId %q is not ecr:region:account:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !ecrRepoNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId repository name %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) ecrTags(region, arn string) (map[string]string, error) {
	const op = "ListTagsForResource"
	st, resp, err := d.ecrCall(region, "ListTagsForResource", `{"resourceArn":"`+arn+`"}`)
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Tags []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"tags"`
	}
	if json.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range r.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

func (d *Driver) createECR(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildECR(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := ecrArn(region, account, plan.RepoName)
	pid := ecrProviderID(region, account, plan.RepoName)
	st, resp, e := d.ecrCall(region, "CreateRepository", plan.createBody(capability, environment))
	if e != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("create outcome unknown: %v", e)}
	}
	switch {
	case st == http.StatusOK:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case strings.Contains(ecsErr(resp), "RepositoryAlreadyExists"):
		tags, terr := d.ecrTags(region, arn)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict, existing repository tags gave no answer — reconcile: " + terr.Error()}
		}
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed", Reason: "a repository with this name exists and is not ours (tags do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("create HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, ecsErr(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(resp))}
	}
}

func (d *Driver) observeECR(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, name, err := splitECRProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	st, resp, e := d.ecrCall(region, "DescribeRepositories", `{"repositoryNames":["`+name+`"]}`)
	if e != nil {
		return nil, nil, fmt.Errorf("DescribeRepositories: %v", e)
	}
	if strings.Contains(ecsErr(resp), "RepositoryNotFound") {
		// F-LC3 (D521): a BOUND resource the API says is GONE. A diagnostic
		// alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"registry not found — bound resource is gone (will re-create)"}, nil
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("DescribeRepositories: HTTP %d", st)
	}
	var r struct {
		Repositories []struct {
			ImageTagMutability      string `json:"imageTagMutability"`
			EncryptionConfiguration struct {
				EncryptionType string `json:"encryptionType"`
				KmsKey         string `json:"kmsKey"`
			} `json:"encryptionConfiguration"`
			ImageScanningConfiguration struct {
				ScanOnPush bool `json:"scanOnPush"`
			} `json:"imageScanningConfiguration"`
		} `json:"repositories"`
	}
	if json.Unmarshal(resp, &r) != nil || len(r.Repositories) == 0 {
		return nil, nil, fmt.Errorf("DescribeRepositories: unparseable or empty")
	}
	repo := r.Repositories[0]
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "immutable.tags", Value: repo.ImageTagMutability == "IMMUTABLE", Derivation: "measured"},
		{Path: "security.scanOnPush", Value: repo.ImageScanningConfiguration.ScanOnPush, Derivation: "measured"},
		// an ECR private registry is never public.
		{Path: "network.publicExposure", Value: false, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	// encryption.customerManagedKeys: encryptionType=="KMS" is NOT customer-managed by
	// itself (D954). When no customer key is given ECR resolves the config to the
	// AWS-managed aws/ecr key and STILL reports encryptionType=KMS (field 2026-08-08:
	// kmsKey is a KeyManager=AWS key, "Default key that protects my ECR data when no
	// other key is defined"). So the type is a proxy that reads true for a repo with no
	// customer key — the D800 lesson (a key id present is not a customer key). Trace the
	// actual key to KMS (KeyManager) like RDS/elasticache; AES256 is the AWS-owned key.
	ec := repo.EncryptionConfiguration
	if ec.EncryptionType == "KMS" && ec.KmsKey != "" {
		if customer, kerr := d.kmsKeyIsCustomerManaged(region, ec.KmsKey); kerr == nil {
			obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
				Value: customer, Derivation: "measured"})
		} else {
			diags = append(diags, "encryption.customerManagedKeys not observed: KMS key trace failed: "+
				kerr.Error()+" — probe/reconcile")
		}
	} else {
		// AES256 (AWS-owned key), or KMS with no resolvable key id: not a customer key.
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: false, Derivation: "measured"})
	}
	return obs, diags, nil
}

// classifyECRChange (D46): PURE — can this capability.registry.image transition be
// honored in place? Tag mutability (PutImageTagMutability) and scan-on-push
// (PutImageScanningConfiguration) are re-assertable in place, so they are mutable
// (updateECR is the updater — never mutable-without-updater). Encryption config and
// region are fixed at CreateRepository, so a change is a replacement. Public
// exposure is refused at build (ECR Public is a distinct service); platform/
// projection properties have nothing to patch.
func classifyECRChange(path string) (string, string) {
	switch path {
	case "immutable.tags":
		return "mutable", ""
	case "security.scanOnPush":
		return "mutable", ""
	case "encryption.customerManagedKeys":
		return "immutable", "ECR encryption configuration is fixed at repository " +
			"creation and cannot be changed in place — a replacement"
	case "location.region":
		return "immutable", "an ECR repository is regional; its region is fixed at creation — a replacement"
	case "network.publicExposure":
		return "unsupported", "an ECR private registry is never public (refused at build) — nothing to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no ECR in-place mapping for " + path
	}
}

// updateECR: ownership (tags) re-check FIRST, then ONE call per changed path —
// PutImageTagMutability for immutable.tags, PutImageScanningConfiguration for
// security.scanOnPush. The desired values come from the SAME builder (BuildECR) so
// an update and a create make identical choices. Honest per D29/D87: an ambiguous
// outcome (transport / 5xx) is unknown WITH the providerId; a 4xx is failed.
func (d *Driver) updateECR(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, account, name, err := splitECRProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := ecrArn(region, account, name)
	tags, terr := d.ecrTags(region, arn)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "registry tags do not match — refusing to patch a resource that is not ours"}
	}
	plan, err := BuildECR(environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	for _, path := range changes {
		var action, body string
		switch path {
		case "immutable.tags":
			mut := "MUTABLE"
			if plan.ImmutableTags {
				mut = "IMMUTABLE"
			}
			action = "PutImageTagMutability"
			body = `{"repositoryName":"` + name + `","imageTagMutability":"` + mut + `"}`
		case "security.scanOnPush":
			scan := "false"
			if plan.ScanOnPush {
				scan = "true"
			}
			action = "PutImageScanningConfiguration"
			body = `{"repositoryName":"` + name + `","imageScanningConfiguration":{"scanOnPush":` + scan + `}}`
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("ecr path %s is not patchable in place", path)}
		}
		st, resp, e := d.ecrCall(region, action, body)
		if e != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("%s outcome unknown — reconcile: %v", action, e)}
		}
		if st >= 500 {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: fmt.Sprintf("%s HTTP %d (server error) — reconcile", action, st)}
		}
		if st != http.StatusOK {
			if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, action); r != nil {
				return *r
			}
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("%s HTTP %d: %s", action, st, mutDetail(resp))}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

func (d *Driver) deleteECR(capability, environment, providerID string) provider.CreateResult {
	region, account, name, err := splitECRProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := ecrArn(region, account, name)
	tags, terr := d.ecrTags(region, arn)
	if terr != nil {
		// distinguish not-found from unreadable via a describe
		dst, dresp, _ := d.ecrCall(region, "DescribeRepositories", `{"repositoryNames":["`+name+`"]}`)
		if strings.Contains(ecsErr(dresp), "RepositoryNotFound") || dst == http.StatusNotFound {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
		}
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed", Reason: "registry tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.ecrCall(region, "DeleteRepository", `{"repositoryName":"`+name+`","force":true}`)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusOK || strings.Contains(ecsErr(resp), "RepositoryNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if r := provider.MutationResult(st, ecsErr(resp), nil, providerID, "delete"); r != nil {
		return *r
	}
	return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(resp))}
}
