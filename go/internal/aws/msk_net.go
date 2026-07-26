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

	"groundhold/internal/provider"
)

const mskPath = "/api/v2/clusters"

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

type mskCluster struct {
	ClusterArn  string            `json:"ClusterArn"`
	ClusterName string            `json:"ClusterName"`
	State       string            `json:"State"`
	Tags        map[string]string `json:"Tags"`
	Provisioned struct {
		CurrentBrokerSoftwareInfo struct {
			KafkaVersion string `json:"KafkaVersion"`
		} `json:"CurrentBrokerSoftwareInfo"`
		EncryptionInfo struct {
			EncryptionInTransit struct {
				ClientBroker string `json:"ClientBroker"`
			} `json:"EncryptionInTransit"`
			EncryptionAtRest struct {
				DataVolumeKMSKeyId string `json:"DataVolumeKMSKeyId"`
			} `json:"EncryptionAtRest"`
		} `json:"EncryptionInfo"`
	} `json:"Provisioned"`
}

// getMSKByName resolves the cluster our deterministic name identifies (ListClustersV2
// returns full ClusterInfo including tags + encryption). found=false + readable=true
// is authoritative "does not exist".
func (d *Driver) getMSKByName(region, name string) (mskCluster, bool, error) {
	const op = "ListClustersV2"
	st, resp, err := d.mskDo("GET", region, mskPath+"?clusterNameFilter="+url.QueryEscape(name), nil)
	if err != nil || st != http.StatusOK {
		return mskCluster{}, false, readTransport(op, err)
	}
	var out struct {
		ClusterInfoList []mskCluster `json:"ClusterInfoList"`
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

func (d *Driver) createMSK(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildMSK(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := mskProviderID(region, account, plan.Cluster)
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
		// ours — fall through to poll
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
		return nil, []string{"cluster not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// an MSK cluster is always multi-AZ.
		{Path: "availability.class", Value: "regional", Derivation: "config-intent"},
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
	// DataVolumeKMSKeyId is an opaque ARN — MSK always encrypts at rest and, with
	// no key specified, uses an AWS-managed key whose ARN is indistinguishable from
	// a customer key (the RDS/DynamoDB case). Refuse rather than false-certify BYOK.
	if c.Provisioned.EncryptionInfo.EncryptionAtRest.DataVolumeKMSKeyId != "" {
		diags = append(diags, "encryption.customerManagedKeys not observed: the "+
			"DataVolumeKMSKeyId ARN cannot distinguish the AWS-managed key from a customer "+
			"key without a KMS DescribeKey (KeyManager) lookup — probe/reconcile")
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
	st, resp, e := d.mskDo("DELETE", region, mskPath+"/"+url.PathEscape(c.ClusterArn), nil)
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
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}
