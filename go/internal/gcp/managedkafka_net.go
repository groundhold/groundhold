// GCP Managed Kafka network shell (D115): the bearer-signed REST half of the
// capability.messaging.kafka driver. Create/delete are async (LRO). The clusterId
// is deterministic, so the providerId is knowable before the create response (D29).
// Ownership is labels. D29/D87 honesty throughout.
package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
)

func (d *Driver) managedKafkaBase() string {
	if d.ManagedKafkaBaseURL != "" {
		return d.ManagedKafkaBaseURL
	}
	return managedKafkaBaseURL
}

func managedKafkaProviderID(project, location, cluster string) string {
	return "gmkafka:" + project + ":" + location + ":" + cluster
}

func splitManagedKafkaProviderID(providerID string) (project, location, cluster string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "gmkafka" {
		return "", "", "", fmt.Errorf("providerId %q is not gmkafka:project:location:cluster", providerID)
	}
	if !projectOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId project %q is invalid", parts[1])
	}
	if !redisRegionOK.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId location %q is invalid", parts[2])
	}
	if !kafkaClusterIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId cluster %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func (d *Driver) managedKafkaURL(project, location, cluster string) string {
	return fmt.Sprintf("%s/projects/%s/locations/%s/clusters/%s",
		d.managedKafkaBase(), project, location, cluster)
}

type managedKafkaDoc struct {
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
	State     string            `json:"state"`
	GcpConfig struct {
		KmsKey string `json:"kmsKey"`
	} `json:"gcpConfig"`
}

func (d *Driver) getManagedKafka(project, location, cluster string) (managedKafkaDoc, bool, error) {
	const op = "managedKafka.get"
	st, body, err := d.call("GET", d.managedKafkaURL(project, location, cluster), nil)
	if err != nil {
		return managedKafkaDoc{}, false, readTransport(op, err)
	}
	if st == http.StatusNotFound {
		return managedKafkaDoc{}, false, nil
	}
	if st != http.StatusOK {
		return managedKafkaDoc{}, false, readHTTP(op, st, gcpErrCode(body))
	}
	var doc managedKafkaDoc
	if json.Unmarshal(body, &doc) != nil {
		return managedKafkaDoc{}, false, readBody(op, st)
	}
	return doc, true, nil
}

func (d *Driver) createManagedKafka(environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildManagedKafka(d.Project, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := managedKafkaProviderID(d.Project, plan.Location, plan.ClusterID)
	url := fmt.Sprintf("%s/projects/%s/locations/%s/clusters?clusterId=%s",
		d.managedKafkaBase(), d.Project, plan.Location, plan.ClusterID)
	st, body, err := d.call("POST", url, plan.createBody(capability, environment))
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed): %v", err)}
	case st == http.StatusOK:
		// LRO started — poll below
	case st == http.StatusConflict:
		doc, found, rerr := d.getManagedKafka(d.Project, plan.Location, plan.ClusterID)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "name conflict, existing cluster gave no answer — reconcile: " + rerr.Error()}
		}
		if !found || doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
			doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
			return provider.CreateResult{Status: "failed",
				Reason: "a cluster with this id exists and is not ours (labels do not match)"}
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"} // ours, present
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, gcpErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "create response carried no operation — reconcile"}
	}
	res := d.pollManagedKafkaOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = pid
	}
	return res
}

func (d *Driver) pollManagedKafkaOperation(opName string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		st, body, err := d.call("GET", d.managedKafkaBase()+"/"+opName, nil)
		if err == nil && st == http.StatusOK {
			var op struct {
				Done  bool `json:"done"`
				Error *struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &op) == nil && op.Done {
				if op.Error != nil {
					return provider.CreateResult{Status: "failed", OperationID: opName,
						Reason: fmt.Sprintf("operation failed: %s", op.Error.Message)}
				}
				return provider.CreateResult{Status: "succeeded", OperationID: opName}
			}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{Status: "unknown", OperationID: opName,
				Reason: "managed kafka operation still running at poll timeout — reconcile"}
		}
		time.Sleep(d.PollInterval)
	}
}

func (d *Driver) observeManagedKafka(capability, providerID string) ([]provider.Observation, []string, error) {
	project, location, cluster, err := splitManagedKafkaProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameProject(project); err != nil {
		return nil, nil, err
	}
	doc, found, rerr := d.getManagedKafka(project, location, cluster)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"cluster not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: location, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// a Managed Kafka cluster is always regional; the endpoint is TLS/mTLS.
		{Path: "availability.class", Value: "regional", Derivation: "config-intent"},
		{Path: "encryption.inTransit", Value: true, Derivation: "config-intent"},
		{Path: "engine.protocol", Value: "kafka/3", Derivation: "config-intent"},
	}
	if doc.GcpConfig.KmsKey != "" {
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys", Value: true, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteManagedKafka(capability, environment, providerID string) provider.CreateResult {
	project, location, cluster, err := splitManagedKafkaProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameProject(project); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, found, rerr := d.getManagedKafka(project, location, cluster)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if doc.Labels["groundhold-capability"] != sanitizeLabel(capability) ||
		doc.Labels["groundhold-environment"] != sanitizeLabel(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "cluster labels do not match — refusing to delete a resource that is not ours"}
	}
	st, body, e := d.call("DELETE", d.managedKafkaURL(project, location, cluster), nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if st == http.StatusNotFound {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, gcpErrCode(body), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{ProviderID: providerID, Status: "failed", Reason: fmt.Sprintf("delete HTTP %d: %s", st, mutDetail(body))}
	}
	var op struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(body, &op) != nil || op.Name == "" {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "delete response carried no operation — reconcile"}
	}
	res := d.pollManagedKafkaOperation(op.Name)
	if res.Status == "succeeded" || res.ProviderID == "" {
		res.ProviderID = providerID
	}
	return res
}
