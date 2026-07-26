// Azure Event Hubs Kafka request building (D115): the semantic core of the Azure
// capability.messaging.kafka driver — the SAME vocabulary AWS MSK and GCP Managed
// Kafka fulfil. Azure's managed Kafka is an Event Hubs namespace with the Kafka
// endpoint enabled (kafkaEnabled=true): unmodified Kafka clients connect to the
// namespace's SASL_SSL bootstrap endpoint. Unlike the streaming.pipe composite
// (D114), messaging.kafka binds to the NAMESPACE alone — Kafka topics are created
// by clients, not provisioned here. Throughput units are implementation sizing;
// residency, availability and encryption are the capability. CMK forces a Premium
// namespace (+ managed identity), matching the MSK/Managed-Kafka CMK shape.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const azKafkaAPIVersion = "2024-01-01"

// AzKafkaPlan is the attribute-derived shape a create assembles into the ARM body.
type AzKafkaPlan struct {
	Namespace      string
	Region         string
	SKU            string // Standard | Premium (Premium required for CMK)
	ZoneRedundant  bool
	CMEK           bool
	KmsKeyVaultURI string
	KmsIdentity    string
}

func azKafkaNamespaceName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-kfk-" + hex.EncodeToString(sum[:])[:12] // 7 + 12 = 19 chars (6-50 bound)
}

// BuildAzKafka maps capability.messaging.kafka attributes to a plan. Every error is
// a refusal apply surfaces in preflight.
func BuildAzKafka(environment, capability string,
	attrs, impl map[string]any, generation int) (AzKafkaPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := AzKafkaPlan{
		Namespace: azKafkaNamespaceName(environment, capability, generation),
		SKU:       "Standard",
	}

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "engine.protocol":
			proto, _ := raw.(string)
			engine, _, ok := strings.Cut(proto, "/")
			if !ok || strings.ToLower(engine) != "kafka" {
				return AzKafkaPlan{}, fmt.Errorf("engine.protocol %q is not a kafka/N protocol", proto)
			}
		case "availability.class":
			switch raw {
			case "zonal":
				p.ZoneRedundant = false
			case "regional":
				p.ZoneRedundant = true
			default:
				return AzKafkaPlan{}, fmt.Errorf("availability.class %v has no Event Hubs Kafka mapping", raw)
			}
		case "encryption.inTransit":
			if raw != true {
				return AzKafkaPlan{}, fmt.Errorf(
					"encryption.inTransit=false cannot be honored — the Kafka endpoint is SASL_SSL (TLS-only)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.CMEK = true
				p.SKU = "Premium"
				p.KmsKeyVaultURI, _ = impl["key_vault_key_uri"].(string)
				p.KmsIdentity, _ = impl["user_assigned_identity"].(string)
				if p.KmsKeyVaultURI == "" || p.KmsIdentity == "" {
					return AzKafkaPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.key_vault_key_uri " +
							"AND implementation.user_assigned_identity")
				}
			}
		case "service.managed":
			if raw != true {
				return AzKafkaPlan{}, fmt.Errorf("service.managed=false cannot be honored by Event Hubs Kafka")
			}
		default:
			return AzKafkaPlan{}, fmt.Errorf(
				"attribute %s has no Event Hubs Kafka mapping — refusing rather than silently dropping it "+
					"(throughput units, partition defaults are implementation sizing)", path)
		}
	}
	if p.Region == "" {
		return AzKafkaPlan{}, fmt.Errorf("kafka cluster requires location.region")
	}
	if !azNameOK.MatchString(p.Namespace) {
		return AzKafkaPlan{}, fmt.Errorf("derived namespace name %q is invalid", p.Namespace)
	}
	return p, nil
}

// createBody is the namespaces PUT body with the Kafka endpoint enabled.
func (p AzKafkaPlan) createBody(tags map[string]any) map[string]any {
	props := map[string]any{
		"kafkaEnabled":  true,
		"zoneRedundant": p.ZoneRedundant,
	}
	body := map[string]any{
		"location":   p.Region,
		"sku":        map[string]any{"name": p.SKU, "tier": p.SKU},
		"tags":       tags,
		"properties": props,
	}
	if p.CMEK {
		body["identity"] = map[string]any{
			"type":                   "UserAssigned",
			"userAssignedIdentities": map[string]any{p.KmsIdentity: map[string]any{}},
		}
		props["encryption"] = map[string]any{
			"keySource": "Microsoft.KeyVault",
			"keyVaultProperties": []any{map[string]any{
				"keyVaultUri":          p.KmsKeyVaultURI,
				"userAssignedIdentity": p.KmsIdentity,
			}},
		}
	}
	return body
}
