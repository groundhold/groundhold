// GCP Artifact Registry network shell (D110): the bearer-signed half of the
// capability.registry.image driver. repositories.create is an LRO; public exposure is a
// second call (an allUsers reader IAM binding). Ownership is labels. observe reverse-maps
// format/CMEK/immutability + reads the IAM policy for public reach. D29 honesty throughout.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) arBase() string {
	if d.ARBaseURL != "" {
		return d.ARBaseURL
	}
	return artifactRegistryBaseURL
}

// suBaseOverride lets the httptest suite point Service Usage at a local server without
// threading a new field through the shared Driver struct (this driver owns only its own
// files; a Driver.SUBaseURL field would be the cleaner home if the shared struct is
// touched later). Production leaves it "" and the real endpoint is used.
var suBaseOverride string

func (d *Driver) suBase() string {
	if suBaseOverride != "" {
		return suBaseOverride
	}
	return serviceUsageBaseURL
}

// containerScanningEnabled reads the PROJECT's Container Scanning API state via Service
// Usage. This is how GCP exposes security.scanOnPush — a project posture, not a repo
// field (the honest divergence from ECR). Returns (enabled, readable): an unreadable API
// (transport, permission, non-200, unparseable) is NEVER collapsed into "disabled" — the
// caller emits a diagnostic and withholds the observation (D29), it does not guess false.
func (d *Driver) containerScanningEnabled(project string) (enabled bool, err error) {
	const op = "services.get"
	url := fmt.Sprintf("%s/projects/%s/services/%s", d.suBase(), project, containerScanningService)
	st, body, cerr := d.call("GET", url, nil)
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc struct {
		State string `json:"state"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return false, readBody(op, st)
	}
	return doc.State == "ENABLED", nil
}

// applyARScanning enables the project's Container Scanning API when the plan asks for
// scanOnPush. Enabling is additive and idempotent (a no-op if already enabled), so it is a
// reasonable create-time posture even though the API is project-scoped. groundhold NEVER
// disables it — turning a project-wide API off from a repo driver would affect every other
// repository. nil = ok (or nothing to do); non-nil = a terminal result carrying the pid.
func (d *Driver) applyARScanning(plan ARRepoPlan, pid string) *provider.CreateResult {
	if !plan.ScanOnPush {
		return nil
	}
	url := fmt.Sprintf("%s/projects/%s/services/%s:enable", d.suBase(), d.Project, containerScanningService)
	st, body, err := d.call("POST", url, map[string]any{})
	if err != nil || st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "repository created; enabling the Container Scanning API (security.scanOnPush) outcome unknown — reconcile"}
		return &r
	}
	if st < 200 || st >= 300 {
		r := provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("repository created but enabling the Container Scanning API failed: HTTP %d: %s", st, mutDetail(body))}
		return &r
	}
	// A 2xx :enable returns an LRO; enabling is idempotent and observe measures the true
	// state, so a still-running operation is not an error — the posture is on its way.
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) == nil && op.Name != "" {
		res := d.pollSUOperation(op.Name)
		if res.Status == "failed" {
			res.ProviderID = pid
			res.Reason = "repository created but enabling the Container Scanning API failed: " + res.Reason
			return &res
		}
	}
	return nil
}

func (d *Driver) pollSUOperation(opName string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, body, err := d.call("GET", d.suBase()+"/"+opName, nil)
		if err == nil && st == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Done {
				if op.Error != nil {
					return provider.CreateResult{Status: "failed", OperationID: opName, Reason: "operation failed: " + op.Error.Message}
				}
				return provider.CreateResult{Status: "succeeded", OperationID: opName}
			}
		}
		if d.Now().After(deadline) {
			// enabling is idempotent and observe measures the truth — a still-running
			// enable at timeout is not fatal to the create; treat as succeeded-in-flight.
			return provider.CreateResult{Status: "succeeded", OperationID: opName}
		}
		time.Sleep(d.PollInterval)
	}
}

func garProviderID(project, region, repoID string) string {
	return "gar:" + project + ":" + region + ":" + repoID
}

func splitGARProviderID(providerID string) (project, region, repoID string, err error) {
	parts := strings.SplitN(providerID, ":", 4)
	if len(parts) != 4 || parts[0] != "gar" {
		return "", "", "", fmt.Errorf("providerId %q is not gar:project:region:repoId", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !arRepoIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId repository id %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

type arRepoDoc struct {
	Labels       map[string]string `json:"labels"`
	Format       string            `json:"format"`
	KmsKeyName   string            `json:"kmsKeyName"`
	DockerConfig struct {
		ImmutableTags bool `json:"immutableTags"`
	} `json:"dockerConfig"`
}

func (d *Driver) getARRepo(project, region, repoID string) (arRepoDoc, bool, error) {
	const op = "aRRepo.get"
	url := fmt.Sprintf("%s/projects/%s/locations/%s/repositories/%s", d.arBase(), project, region, repoID)
	st, body, err := d.call("GET", url, nil)
	if err != nil {
		return arRepoDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return arRepoDoc{}, false, nil
	}
	if st != http.StatusOK {
		return arRepoDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc arRepoDoc
	if json.Unmarshal(body, &doc) != nil {
		return arRepoDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createARRepo(capability, environment string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildARRepo(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := garProviderID(d.Project, plan.Region, plan.RepoID)
	// D1009: the create query param is `repositoryId` (camelCase) per the artifactregistry
	// v1 discovery doc — and per every sibling here (instanceId, certificateId, keyRingId …).
	// This was the lone snake_case `repository_id`; if the API ignored it and auto-named the
	// repo, the create would land under a name the providerId (built from RepoID above) does
	// not match, so observe would read a live repository as absent. Aligned to the documented
	// form, which is provably accepted.
	url := fmt.Sprintf("%s/projects/%s/locations/%s/repositories?repositoryId=%s",
		d.arBase(), d.Project, plan.Region, plan.RepoID)
	st, body, e := d.call("POST", url, plan.createBody(capability, environment))
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("create outcome unknown: %v", e)}
	case st == http.StatusOK:
		// LRO started — poll below
	case st == http.StatusConflict:
		doc, found, rerr := d.getARRepo(d.Project, plan.Region, plan.RepoID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "name conflict, existing repository gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed", Reason: "a repository with this id exists and is not ours (labels do not match)"}
		}
		// ours — fall through to re-assert public exposure + scanning posture
		if r := d.applyARPublic(plan, pid); r != nil {
			return *r
		}
		if r := d.applyARScanning(plan, pid); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "create response carried no operation — reconcile"}
	}
	res := d.pollAROperation(op.Name)
	if res.Status != "succeeded" {
		if res.ProviderID == "" {
			res.ProviderID = pid
		}
		return res
	}
	if r := d.applyARPublic(plan, pid); r != nil {
		return *r
	}
	if r := d.applyARScanning(plan, pid); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

func (d *Driver) pollAROperation(opName string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, body, err := d.call("GET", d.arBase()+"/"+opName, nil)
		if err == nil && st == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Done {
				if op.Error != nil {
					return provider.CreateResult{Status: "failed", OperationID: opName, Reason: "operation failed: " + op.Error.Message}
				}
				return provider.CreateResult{Status: "succeeded", OperationID: opName}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{Status: "unknown", OperationID: opName, Reason: "artifact registry operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// applyARPublic grants (or the absence leaves) allUsers the reader role for a public
// registry. nil = ok, non-nil = a terminal result with the pid.
func (d *Driver) applyARPublic(plan ARRepoPlan, pid string) *provider.CreateResult {
	if !plan.Public {
		return nil
	}
	base := fmt.Sprintf("%s/projects/%s/locations/%s/repositories/%s",
		d.arBase(), d.Project, plan.Region, plan.RepoID)
	st, body, err := d.call("GET", base+":getIamPolicy", nil)
	if err != nil || st != http.StatusOK {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "repository created; getIamPolicy for public grant failed — reconcile"}
		return &r
	}
	var pol map[string]any
	if json.Unmarshal(body, &pol) != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "repository created; IAM policy unparseable — reconcile"}
		return &r
	}
	bindings, _ := pol["bindings"].([]any)
	bindings = append(bindings, map[string]any{"role": "roles/artifactregistry.reader", "members": []any{"allUsers"}})
	pol["bindings"] = bindings
	sst, _, se := d.call("POST", base+":setIamPolicy", map[string]any{"policy": pol})
	if se != nil || sst >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: "repository created; public grant outcome unknown — reconcile"}
		return &r
	}
	if sst < 200 || sst >= 300 {
		r := provider.CreateResult{ProviderID: pid, Status: "failed", Reason: fmt.Sprintf("repository created but public grant failed: HTTP %d", sst)}
		return &r
	}
	return nil
}

func (d *Driver) readARPublic(project, region, repoID string) (public bool, err error) {
	const op = "repositories.getIamPolicy"
	base := fmt.Sprintf("%s/projects/%s/locations/%s/repositories/%s", d.arBase(), project, region, repoID)
	st, body, cerr := d.call("GET", base+":getIamPolicy", nil)
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, gcpErrCode(body))
	}
	var pol struct {
		Bindings []struct {
			Members []string `json:"members"`
		} `json:"bindings"`
	}
	if json.Unmarshal(body, &pol) != nil {
		return false, readBody(op, st)
	}
	for _, b := range pol.Bindings {
		for _, m := range b.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				return true, nil
			}
		}
	}
	return false, nil
}

func (d *Driver) observeARRepo(capability, providerID string) ([]provider.Observation, []string, error) {
	project, region, repoID, err := splitGARProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getARRepo(project, region, repoID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D519): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"registry not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "immutable.tags", Value: doc.DockerConfig.ImmutableTags, Derivation: "measured"},
		{Path: "encryption.customerManagedKeys", Value: doc.KmsKeyName != "", Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	var diags []string
	if pub, perr := d.readARPublic(project, region, repoID); perr == nil {
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: pub, Derivation: "measured"})
	} else {
		diags = append(diags, "network.publicExposure not observed: "+perr.Error())
	}
	// security.scanOnPush is measured from the PROJECT's Container Scanning API state, not
	// from the repository (GCP has no per-repo scanning field — the honest divergence from
	// ECR, whose scanOnPush is read off imageScanningConfiguration per repository). An
	// unreadable API is a diagnostic, never a false reading.
	if scan, serr := d.containerScanningEnabled(project); serr == nil {
		obs = append(obs, provider.Observation{Path: "security.scanOnPush", Value: scan, Derivation: "measured"})
		diags = append(diags, "security.scanOnPush measured from the project-level Container Scanning API "+
			"(containerscanning.googleapis.com), not a per-repository setting — it is a project posture shared by every repository")
	} else {
		diags = append(diags, "security.scanOnPush not observed: the project Container "+
			"Scanning API state (serviceusage) gave no answer: "+serr.Error())
	}
	return obs, diags, nil
}

func (d *Driver) deleteARRepo(capability, environment, providerID string) provider.CreateResult {
	project, region, repoID, err := splitGARProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getARRepo(project, region, repoID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed", Reason: "registry labels do not match — refusing to delete a resource that is not ours"}
	}
	url := fmt.Sprintf("%s/projects/%s/locations/%s/repositories/%s", d.arBase(), project, region, repoID)
	st, body, e := d.call("DELETE", url, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st == http.StatusOK {
		var op struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(body, &op) == nil && op.Name != "" {
			res := d.pollAROperation(op.Name)
			res.ProviderID = providerID
			return res
		}
		// a 2xx delete MUST return an operation; an empty name is a truncated body
		// (the delete may have landed, D29) — unknown, never a confident success.
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
		return *r
	}
	return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
}
