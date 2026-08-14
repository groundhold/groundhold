// MSK network shell (D115): the SigV4-signed, REST-JSON half of the AWS
// capability.messaging.kafka driver. The cluster ARN is SERVER-ASSIGNED, but the
// cluster NAME is deterministic, so the providerId is the name (knowable before the
// response, D29) and the ARN is resolved by ListClustersV2 name filter for every
// op. CreateClusterV2 is polled to State=ACTIVE. Ownership is TAGS (returned inline
// by ListClustersV2). D29/D87 honesty throughout.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"groundhold/internal/adoptcheck"
	"groundhold/internal/provider"
)

const mskPath = "/api/v2/clusters"

// mskDeletePath — MSK carries two API versions and they do NOT cover the same verbs.
// Create, List and Describe have V2 forms under /api/v2/clusters; DeleteCluster has
// only the V1 form. Measured against real AWS with no credentials (D717):
//
//	GET    /api/v2/clusters/<arn> -> "Missing Authentication Token"                real
//	DELETE /v1/clusters/<arn>     -> "Missing Authentication Token"                real
//	DELETE /api/v2/clusters/<arn> -> "Unable to determine service/operation name"  absent
//
// An unmatched route answers 403, which the mutation classifier reads as a denied
// permission — so a wrong URL here does not look like a wrong URL. It looks like the
// account is missing an IAM grant.
const mskDeletePath = "/v1/clusters"

func (d *Driver) mskBase(region string) string {
	if d.MSKBaseURL != "" {
		return d.MSKBaseURL
	}
	return "https://kafka." + region + ".amazonaws.com"
}

func mskProviderID(region, account, cluster string) string {
	return "msk:" + region + ":" + account + ":" + cluster
}

func splitMSKProviderID(providerID string) (region, account, cluster string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "msk" {
		return "", "", "", fmt.Errorf("providerId %q is not msk:region:account:cluster", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !mskNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId cluster %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) mskDo(method, region, path string, body []byte) (int, []byte, error) {
	return d.doSigned(method, d.mskBase(region)+path, "kafka", region,
		map[string]string{"Content-Type": "application/json"}, body)
}

// D879: restJson1 camelCase wire names. PascalCase tags parsed every field to its
// zero value on a real ListClustersV2 response — an empty ClusterName never matched
// our name (so a live cluster read as absent) and State/tags/encryption read blank,
// the same golden-hidden defect as apigateway (D878), here in the read direction.
type mskCluster struct {
	ClusterArn  string            `json:"clusterArn"`
	ClusterName string            `json:"clusterName"`
	State       string            `json:"state"`
	Tags        map[string]string `json:"tags"`
	Provisioned struct {
		CurrentBrokerSoftwareInfo struct {
			KafkaVersion string `json:"kafkaVersion"`
		} `json:"currentBrokerSoftwareInfo"`
		EncryptionInfo struct {
			EncryptionInTransit struct {
				ClientBroker string `json:"clientBroker"`
			} `json:"encryptionInTransit"`
			EncryptionAtRest struct {
				DataVolumeKMSKeyId string `json:"dataVolumeKMSKeyId"`
			} `json:"encryptionAtRest"`
		} `json:"encryptionInfo"`
	} `json:"provisioned"`
}

// getMSKByName resolves the cluster our deterministic name identifies (ListClustersV2
// returns full ClusterInfo including tags + encryption). found=false + readable=true
// is authoritative "does not exist".
func (d *Driver) getMSKByName(region, name string) (mskCluster, bool, error) {
	const op = "ListClustersV2"
	st, resp, err := d.mskDo("GET", region, mskPath+"?clusterNameFilter="+url.QueryEscape(name), nil)
	// D521: this read `err != nil || st != StatusOK` and handed BOTH to
	// readTransport, which dereferences err.Error() — so every HTTP error
	// response (err nil, status not 200) panicked the process. The third
	// instance of this exact shape; the absence probe is what reaches it.
	if err != nil {
		return mskCluster{}, false, readTransport(op, err)
	}
	if st != http.StatusOK {
		return mskCluster{}, false, readHTTP(op, st, awsErrCode(resp))
	}
	var out struct {
		ClusterInfoList []mskCluster `json:"clusterInfoList"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return mskCluster{}, false, readBody(op, st)
	}
	for _, c := range out.ClusterInfoList {
		if c.ClusterName == name { // the filter is a prefix; match exactly
			return c, true, nil
		}
	}
	return mskCluster{}, false, nil
}

// mskAdoptControls: MSK sets the customer key INLINE in CreateClusterV2, so on a
// 409-adopt it never applied to the pre-existing cluster (D1062). At-rest encryption
// with a customer key is fixed at create, so a miss FAILS. In-transit encryption is
// always TLS-enforced on MSK (the audit's moot case), so it is not an adopt control.
var mskAdoptControls = []adoptcheck.Control{
	{Path: "encryption.customerManagedKeys", Direction: adoptcheck.SecureTrue, ImmutableAtCreate: true},
}

func (d *Driver) createMSK(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildMSK(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := mskProviderID(region, account, plan.Cluster)
	adopted := false
	body, _ := json.Marshal(plan.createBody(capability, environment))
	st, resp, err := d.mskDo("POST", region, mskPath, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK || st == http.StatusCreated:
		// creating — poll below
	case strings.Contains(mskErr(resp), "Conflict") || st == http.StatusConflict:
		c, found, rerr := d.getMSKByName(region, plan.Cluster)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing cluster gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || !groundholdTagsMatch(c.Tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a cluster with this name exists and is not ours (tags do not match)"}
		}
		// ours — poll, then re-check declared controls (D1062)
		adopted = true
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed): %s", st, mutDetail(resp))}
	default:
		if r := provider.MutationResult(st, mskErr(resp), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s)", st, mskErr(resp))}
	}

	deadline := d.Now().Add(d.PollTimeout)
	for {
		c, found, rerr := d.getMSKByName(region, plan.Cluster)
		if rerr == nil && found {
			switch c.State {
			case "ACTIVE":
				// D1062: an ADOPTED cluster (409, ours) never received the create body's
				// inline customer key — fixed at create. Re-check it against this driver's
				// OWN measured observation (cmek KMS-traced) before reporting succeeded; a
				// missing customer key fails rather than lying that BYOK is in place.
				if adopted {
					obs, _, oerr := d.observeMSK(capability, pid)
					if oerr != nil {
						return provider.CreateResult{ProviderID: pid, Status: "unknown",
							Reason: "adopted cluster re-observe gave no answer — reconcile: " + oerr.Error()}
					}
					switch v := adoptcheck.Compare(attrs, obs, mskAdoptControls); v.Status {
					case "failed":
						return provider.CreateResult{Status: "failed", Reason: v.Reason}
					case "unknown":
						return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: v.Reason}
					}
				}
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "FAILED":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "cluster entered state FAILED"}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "cluster still creating at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

// mskErr pulls a message out of an MSK JSON error body.
func mskErr(body []byte) string {
	var e struct {
		Message          string `json:"message"`
		Msg              string `json:"Message"`
		InvalidParameter string `json:"invalidParameter"`
	}
	_ = json.Unmarshal(body, &e)
	if e.Message != "" {
		return boundMsg(e.Message)
	}
	if e.Msg != "" {
		return boundMsg(e.Msg)
	}
	return "" // D309: never the raw body — this string reaches a persisted receipt
}

func (d *Driver) observeMSK(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, cluster, err := splitMSKProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	c, found, rerr := d.getMSKByName(region, cluster)
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
		// an MSK cluster is always multi-AZ.
		{Path: "availability.class", Value: "regional", Derivation: "platform-invariant"},
	}
	var diags []string
	// encryption.inTransit reads Provisioned.EncryptionInfo.ClientBroker.
	// ListClustersV2 returns SERVERLESS clusters too, which carry no Provisioned
	// block — an absent ClientBroker must not fabricate inTransit=false (MSK
	// Serverless mandates TLS). Only emit when the field is actually present.
	if cb := c.Provisioned.EncryptionInfo.EncryptionInTransit.ClientBroker; cb != "" {
		obs = append(obs, provider.Observation{Path: "encryption.inTransit",
			Value: cb == "TLS", Derivation: "measured"})
	} else {
		diags = append(diags, "encryption.inTransit not observed: no "+
			"Provisioned.EncryptionInfo.ClientBroker (a serverless cluster, which mandates "+
			"TLS, or a response that carried no such field) — never fabricated as false")
	}
	if v := c.Provisioned.CurrentBrokerSoftwareInfo.KafkaVersion; v != "" {
		obs = append(obs, provider.Observation{Path: "engine.protocol",
			Value: "kafka/" + strings.SplitN(v, ".", 2)[0], Derivation: "measured"})
	}
	// encryption.customerManagedKeys: MSK always encrypts at rest with SOME key; with
	// no key specified it uses the account default aws/kafka key, whose ARN is
	// indistinguishable from a customer key WITHOUT a KMS trace. Trace DataVolumeKMSKeyId
	// to KMS (DescribeKey -> KeyManager) so a real CMK is MEASURED, not punted — the same
	// fix as RDS/DynamoDB (D954/D1057) and the read the adopt-check needs. An unreadable
	// trace stays a diagnostic, never a false; an absent key id (no at-rest key reported)
	// is definitively not a customer key → a measured false (D1040/D1003).
	if kid := c.Provisioned.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId; kid != "" {
		if customer, kerr := d.kmsKeyIsCustomerManaged(region, kid); kerr == nil {
			obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
				Value: customer, Derivation: "measured"})
		} else {
			diags = append(diags, "encryption.customerManagedKeys not observed on the "+
				"cluster's KMS key: "+kerr.Error()+" — probe/reconcile")
		}
	} else {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: false, Derivation: "measured"})
	}
	return obs, diags, nil
}

func (d *Driver) deleteMSK(capability, environment, providerID string) provider.CreateResult {
	region, _, cluster, err := splitMSKProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	c, found, rerr := d.getMSKByName(region, cluster)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(c.Tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster tags do not match — refusing to delete a resource that is not ours"}
	}
	// D880: the cluster ARN is single-encoded on the wire (rfc3986: colons AND slashes,
	// one path segment), exactly as botocore serializes DeleteCluster against the
	// non-greedy /v1/clusters/{clusterArn} route — raw slashes would split into extra
	// segments and 404. The signer double-encodes the canonical (%253A/%252F) to match
	// what AWS computes. url.PathEscape was wrong twice over: it left colons raw and it
	// single-encoded a wire the old signer then single-encoded again — a guaranteed 403.
	st, resp, e := d.mskDo("DELETE", region, mskDeletePath+"/"+rfc3986(c.ClusterArn), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound || strings.Contains(mskErr(resp), "NotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, mskErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, mskErr(resp))}
	}
	// ---- poll to absence (D968 class, D974) ----
	// The delete is async: the cluster enters DELETING, not gone. Reporting succeeded
	// here tombstones a data-bearing Kafka cluster still live. Poll to a confirmed
	// not-found as createMSK polls to ACTIVE; unknown on timeout keeps the handle.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		if _, found, rerr := d.getMSKByName(region, cluster); rerr == nil && !found {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // confirmed gone
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "cluster still deleting at poll timeout — reconcile via ListClusters"}
		}
		time.Sleep(d.PollInterval)
	}
}
