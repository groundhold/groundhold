// GCP Managed Kafka request building (D115): the semantic core of the GCP
// capability.messaging.kafka driver — the SAME vocabulary AWS MSK and Azure Event
// Hubs Kafka fulfil. Google Cloud Managed Service for Apache Kafka (GA 2024) is a
// managed regional Kafka cluster. vCPU/memory capacity and rebalance config are
// implementation sizing; residency, Kafka protocol, availability and encryption are
// the capability. A Managed Kafka cluster is ALWAYS regional (spread across zones),
// so availability.class=zonal is an honest refusal here. encryption.inTransit is
// true-only (the bootstrap endpoint is TLS/mTLS).
package gcp

import (
	"fmt"
	"regexp"
	"strings"
)

const managedKafkaBaseURL = "https://managedkafka.googleapis.com/v1"

// kafkaClusterIDOK bounds a Managed Kafka cluster id: lowercase letters, digits,
// hyphens, starting with a letter (1-63).
var kafkaClusterIDOK = regexp.MustCompile(`^[a-z][a-z0-9-]{0,61}[a-z0-9]$`)

// ManagedKafkaClusterID is the deterministic cluster id (the idempotency handle).
func ManagedKafkaClusterID(project, environment, capability string, generation int) string {
	return resourceName(project, environment, capability, generation, 63)
}

// ManagedKafkaPlan is the attribute-derived shape a create assembles.
type ManagedKafkaPlan struct {
	ClusterID string
	Location  string
	Subnet    string // gcpConfig.accessConfig.networkConfigs[].subnet (impl)
	KmsKey    string // gcpConfig.kmsKey (CMEK); "" = google-managed
}

// kafkaProtocolOK accepts kafka/N and refuses a non-kafka protocol.
func kafkaProtocolOK(protocol string) error {
	engine, _, ok := strings.Cut(protocol, "/")
	if !ok || strings.ToLower(engine) != "kafka" {
		return fmt.Errorf("engine.protocol %q is not a kafka/N protocol", protocol)
	}
	return nil
}

// BuildManagedKafka maps capability.messaging.kafka attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildManagedKafka(project, environment, capability string,
	attrs, impl map[string]any, generation int) (ManagedKafkaPlan, error) {
	p := ManagedKafkaPlan{ClusterID: ManagedKafkaClusterID(project, environment, capability, generation)}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Location, _ = raw.(string)
		case "engine.protocol":
			proto, _ := raw.(string)
			if err := kafkaProtocolOK(proto); err != nil {
				return ManagedKafkaPlan{}, err
			}
		case "availability.class":
			switch raw {
			case "regional":
				// a Managed Kafka cluster is always regional (spread across zones)
			case "zonal":
				return ManagedKafkaPlan{}, fmt.Errorf(
					"availability.class=zonal cannot be honored by Managed Kafka — a cluster is " +
						"always regional; refusing rather than misrepresenting it as zonal")
			default:
				return ManagedKafkaPlan{}, fmt.Errorf("availability.class %v has no Managed Kafka mapping", raw)
			}
		case "encryption.inTransit":
			if raw != true {
				return ManagedKafkaPlan{}, fmt.Errorf(
					"encryption.inTransit=false cannot be honored — the bootstrap endpoint is TLS/mTLS")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKey, _ = impl["kms_key_name"].(string)
				if p.KmsKey == "" {
					return ManagedKafkaPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_name")
				}
			}
		case "service.managed":
			if raw != true {
				return ManagedKafkaPlan{}, fmt.Errorf("service.managed=false cannot be honored by Managed Kafka")
			}
		default:
			return ManagedKafkaPlan{}, fmt.Errorf(
				"attribute %s has no Managed Kafka mapping — refusing rather than silently dropping it "+
					"(vCPU/memory capacity, rebalance config are implementation sizing)", path)
		}
	}
	if p.Location == "" {
		return ManagedKafkaPlan{}, fmt.Errorf("kafka cluster requires location.region")
	}
	// a cluster attaches to a VPC subnet — topology (impl).
	p.Subnet, _ = impl["subnet"].(string)
	if p.Subnet == "" {
		return ManagedKafkaPlan{}, fmt.Errorf(
			"a Managed Kafka cluster requires implementation.subnet (the VPC subnet to attach to)")
	}
	if !kafkaClusterIDOK.MatchString(p.ClusterID) {
		return ManagedKafkaPlan{}, fmt.Errorf("derived cluster id %q is invalid", p.ClusterID)
	}
	if !projectOK.MatchString(project) {
		return ManagedKafkaPlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

// createBody is the clusters.create request body. Ownership is labels.
func (p ManagedKafkaPlan) createBody(capability, environment string) map[string]any {
	gcpConfig := map[string]any{
		"accessConfig": map[string]any{
			"networkConfigs": []any{map[string]any{"subnet": p.Subnet}},
		},
	}
	if p.KmsKey != "" {
		gcpConfig["kmsKey"] = p.KmsKey
	}
	return map[string]any{
		"capacityConfig": map[string]any{"vcpuCount": "3", "memoryBytes": "3221225472"},
		"gcpConfig":      gcpConfig,
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
}
