// Typed create outputs (D226/D275/D283) — the GCP half of the F13 wiring
// (D284): the same OutputProducer/OutputReader pair the AWS driver carries
// (D276), mapped per-cloud honestly rather than force-symmetrically. Every
// output derives from the create's provider id — present on every succeeded
// path including the already-ours repair branches — except vpc's subnetworks,
// which come from one read of the standing network (the honest source for a
// created AND an adopted network alike). An underivable output demotes the
// create to unknown, mirroring the executor's receipt gate.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// gcpOutputs declares ONLY what every succeeded create path can truthfully
// derive. Names are GCP-native (a consumer references what the cloud calls
// the thing), not AWS-lookalikes — per-cloud honesty over forced symmetry.
var gcpOutputs = map[string][]provider.OutputSpec{
	"vpc": {
		{Name: "network", Kind: "string", Sample: "gh-preflight-net"},
		{Name: "networkSelfLink", Kind: "string", Sample: "https://www.googleapis.com/compute/v1/projects/acme/global/networks/gh-preflight-net"},
		{Name: "region", Kind: "string", Sample: "europe-west1"},
		{Name: "subnetworks", Kind: "list", Sample: []any{"https://www.googleapis.com/compute/v1/projects/acme/regions/europe-west1/subnetworks/gh-preflight-sub"}},
	},
	// cloudsql (capability.database.relational): the connection endpoints a
	// consumer app (e.g. a Cloud Function reaching a private DB) wires by $ref
	// instead of a hand-pasted literal. connectionName (project:region:instance)
	// is fully in the pid — no read, always attestable. privateIpAddress + port
	// come from one instances.get (the private endpoint is server-assigned, not
	// in the pid) — the honest source for a created AND an adopted instance alike,
	// exactly as vpc's subnetworks and AWS aurora's endpoints. A public-only
	// instance has no PRIVATE address, so those two are omitted (never fabricated)
	// while the pid-derived connectionName still travels. The PASSWORD is NEVER an
	// output — it stays off-ledger.
	"cloudsql": {
		{Name: "connectionName", Kind: "string", Sample: "acme-prod:europe-west1:orders-db"},
		{Name: "privateIpAddress", Kind: "string", Sample: "10.1.2.3"},
		{Name: "port", Kind: "string", Sample: "5432"},
	},
	// cloudrun (capability.workload.container): uri is the public *.run.app host a
	// consumer wires by $ref and the post-apply reachability probe (D330) targets.
	// It is SERVER-ASSIGNED (not derivable from the pid), so it comes from ONE
	// services.get — the honest source for a created AND an adopted service alike,
	// exactly as cloudsql's privateIpAddress and AWS cloudfront's domainName. It is
	// published regardless of ingress (it IS the service's URL); the reachability
	// probe gates PUBLIC-only separately (network.publicExposure), so an internal
	// service still exposes its uri for a same-network $ref without being probed.
	"cloudrun": {{Name: "uri", Kind: "string", Sample: "https://gh-preflight-abc123-ew.a.run.app"}},
	// cloudfunctionsfn (capability.function.serverless): url is the public HTTPS
	// trigger, the GCP twin of AWS lambda's functionUrl. Server-assigned (one
	// functions.get), and — like functionUrl — present ONLY for a PUBLIC function
	// (ingress ALLOW_ALL), so a private function publishes no url and the
	// reachability probe measures nothing (no false unknown).
	"cloudfunctionsfn": {{Name: "url", Kind: "string", Sample: "https://gh-preflight-abc123-ew.a.run.app"}},
	"gcs":              {{Name: "bucketName", Kind: "string", Sample: "gh-preflight-bucket"}},
	"pubsub-topic":     {{Name: "topicId", Kind: "string", Sample: "projects/acme/topics/gh-preflight"}, {Name: "topicName", Kind: "string", Sample: "gh-preflight"}},
	"serviceaccount": {
		{Name: "accountId", Kind: "string", Sample: "gh-preflight"},
		{Name: "email", Kind: "string", Sample: "gh-preflight@acme.iam.gserviceaccount.com"},
		{Name: "member", Kind: "string", Sample: "serviceAccount:gh-preflight@acme.iam.gserviceaccount.com"},
	},
	"cloudkms":    {{Name: "keyName", Kind: "string", Sample: "projects/acme/locations/europe-west1/keyRings/gh/cryptoKeys/gh-preflight"}},
	"gke":         {{Name: "clusterName", Kind: "string", Sample: "gh-preflight"}, {Name: "location", Kind: "string", Sample: "europe-west1"}},
	"certmanager": {{Name: "certificateName", Kind: "string", Sample: "projects/acme/locations/global/certificates/gh-preflight"}},
	// artifactregistry (capability.registry.image, F-registry): repositoryUri is
	// the Docker push base a workload.container/function.serverless consumer wires
	// as image: {$ref: {capability: <ar>, output: repositoryUri}}. Fully in the
	// gar:project:region:repoId pid — no read.
	"artifactregistry": {{Name: "repositoryUri", Kind: "string", Sample: "europe-west1-docker.pkg.dev/acme/gh-preflight"}},
	// backupvault (capability.backup.vault, D127): backupVault is the full
	// resource name a backup.plan consumer wires as {$ref: {capability: <vault>,
	// output: backupVault}} — backupdr writes recovery points to a vault that
	// must exist first. Both fields are fully in the gbkv:project:location:vaultId
	// pid — no read.
	"backupvault": {
		{Name: "backupVault", Kind: "string", Sample: "projects/acme/locations/europe-west1/backupVaults/gh-preflight"},
		{Name: "vaultName", Kind: "string", Sample: "gh-preflight"},
	},
}

// OutputsFor implements provider.OutputProducer (D226).
func (d *Driver) OutputsFor(service string) []provider.OutputSpec {
	return gcpOutputs[service]
}

// ReadOutputs implements provider.OutputReader (D283): re-read the declared
// outputs of a BOUND resource by its provider id.
func (d *Driver) ReadOutputs(service, providerID string) (map[string]any, error) {
	if len(gcpOutputs[service]) == 0 {
		return nil, nil
	}
	return d.deriveOutputs(service, providerID)
}

// attachOutputs fills cr.Outputs for a succeeded create of a declaring
// service; a derivation failure demotes to unknown with the cause named.
func (d *Driver) attachOutputs(service string, cr *provider.CreateResult) {
	if cr.Status != "succeeded" || len(gcpOutputs[service]) == 0 {
		return
	}
	outs, err := d.deriveOutputs(service, cr.ProviderID)
	if err != nil {
		cr.Status = "unknown"
		cr.Reason = fmt.Sprintf("%s create succeeded but its declared outputs "+
			"are underivable — reconcile: %v", service, err)
		return
	}
	cr.Outputs = outs
}

func (d *Driver) deriveOutputs(service, pid string) (map[string]any, error) {
	switch service {
	case "cloudsql":
		project, region, name, err := splitProviderID(pid)
		if err != nil {
			return nil, err
		}
		// connectionName is the canonical Cloud SQL connection identifier
		// (project:region:instance) — fully pid-derived, always attestable, no read.
		out := map[string]any{"connectionName": project + ":" + region + ":" + name}
		// privateIpAddress + port need one instances.get. A read that gives no
		// answer, or an instance with no PRIVATE address (a public-only instance),
		// omits them rather than demoting the create — the pid-derived
		// connectionName still travels, and a consumer that $refs an absent output
		// refuses at apply (refuse-before-mutate), reconcilable by re-observe once
		// the private IP is assigned.
		status, body, cerr := d.call("GET", fmt.Sprintf(
			"%s/projects/%s/instances/%s", d.BaseURL, project, name), nil)
		if cerr != nil || status != http.StatusOK {
			return out, nil
		}
		var inst struct {
			DatabaseVersion string `json:"databaseVersion"`
			IPAddresses     []struct {
				Type      string `json:"type"`
				IPAddress string `json:"ipAddress"`
			} `json:"ipAddresses"`
		}
		if json.Unmarshal(body, &inst) != nil {
			return out, nil
		}
		for _, a := range inst.IPAddresses {
			if a.Type == "PRIVATE" && a.IPAddress != "" {
				out["privateIpAddress"] = a.IPAddress
				if p := portOf(inst.DatabaseVersion); p != "" {
					out["port"] = p
				}
				break
			}
		}
		return out, nil
	case "cloudrun":
		project, region, name, err := splitRunProviderID(pid)
		if err != nil {
			return nil, err
		}
		// one services.get for the server-assigned *.run.app uri. A read FAILURE
		// (transport/non-200/unparseable) IS an error (reconcile), never a
		// fabricated absence — mirroring AWS cloudfront's domainName derivation. An
		// empty uri on a readable service is a real "not ready yet" error too.
		uri, err := d.runServiceURI(project, region, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{"uri": uri}, nil
	case "cloudfunctionsfn":
		project, region, name, err := splitFnServerlessProviderID(pid)
		if err != nil {
			return nil, err
		}
		// one functions.get for the public HTTPS trigger + ingress. Present ONLY
		// for a PUBLIC function (ingress ALLOW_ALL) — a private function omits url
		// (no-public-output), exactly as AWS lambda's functionUrl for a private
		// function. A read failure is an error; a definitive private is not.
		url, err := d.fnServerlessPublicURL(project, region, name)
		if err != nil {
			return nil, err
		}
		out := map[string]any{}
		if url != "" {
			out["url"] = url
		}
		return out, nil
	case "gcs":
		_, name, err := splitGcsProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{"bucketName": name}, nil
	case "pubsub-topic":
		project, name, err := splitPubSubProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"topicName": name,
			"topicId":   "projects/" + project + "/topics/" + name,
		}, nil
	case "serviceaccount":
		project, accountID, err := splitGSAProviderID(pid)
		if err != nil {
			return nil, err
		}
		email := accountID + "@" + project + ".iam.gserviceaccount.com"
		return map[string]any{
			"accountId": accountID,
			"email":     email,
			"member":    "serviceAccount:" + email,
		}, nil
	case "cloudkms":
		project, location, ring, key, err := splitGKMSProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"keyName": "projects/" + project + "/locations/" + location +
				"/keyRings/" + ring + "/cryptoKeys/" + key,
		}, nil
	case "gke":
		_, location, cluster, err := splitGKEProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{"clusterName": cluster, "location": location}, nil
	case "certmanager":
		project, location, certID, err := splitCertManagerProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"certificateName": "projects/" + project + "/locations/" + location +
				"/certificates/" + certID,
		}, nil
	case "artifactregistry":
		project, region, repoID, err := splitGARProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"repositoryUri": region + "-docker.pkg.dev/" + project + "/" + repoID,
		}, nil
	case "backupvault":
		project, location, vaultID, err := splitBackupDRProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"vaultName": vaultID,
			"backupVault": "projects/" + project + "/locations/" + location +
				"/backupVaults/" + vaultID,
		}, nil
	case "vpc":
		project, region, name, err := splitVPCProviderID(pid)
		if err != nil {
			return nil, err
		}
		// subnetworks come from the live network — the API's own self-links,
		// truthful for a created and an adopted network alike.
		doc, found, rerr := d.getNetwork(project, name)
		if rerr != nil {
			return nil, fmt.Errorf("network %s: %w", name, rerr)
		}
		if !found {
			return nil, fmt.Errorf("network %s: not found — no outputs to publish", name)
		}
		subs := make([]any, 0, len(doc.Subnetworks))
		for _, s := range doc.Subnetworks {
			subs = append(subs, s)
		}
		return map[string]any{
			"network": name,
			"networkSelfLink": "https://www.googleapis.com/compute/v1/projects/" +
				project + "/global/networks/" + name,
			"region":      region,
			"subnetworks": subs,
		}, nil
	}
	return nil, fmt.Errorf("service %q declares outputs but has no derivation", service)
}
