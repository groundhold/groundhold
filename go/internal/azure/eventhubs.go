// Azure Event Hubs request building (D114): the semantic core of the Azure
// capability.streaming.pipe driver — the SAME vocabulary AWS Kinesis fulfils (GCP
// has no managed streaming twin, so the domain is honestly two-cloud). Event Hubs
// is a namespace+entity COMPOSITE (the servicebus D99 shape): the namespace carries
// the SKU / zone-redundancy / CMK, the event hub carries partitions and retention.
// Partition count is implementation sizing; residency, retention, availability and
// encryption are the capability.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"groundhold/internal/scalars"
)

const eventHubsAPIVersion = "2024-01-01"

// EventHubsPlan is the attribute-derived shape a create assembles into ARM bodies.
type EventHubsPlan struct {
	Namespace      string
	Hub            string
	Region         string
	SKU            string // Standard | Premium (Premium required for CMK)
	ZoneRedundant  bool
	RetentionDays  int
	CMEK           bool
	KmsKeyVaultURI string
	KmsIdentity    string
}

func eventHubsNamespaceName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-eh-" + hex.EncodeToString(sum[:])[:12] // 6 + 12 = 18 chars (6-50 bound)
}

// daysFromHours rounds a duration up to whole days (Event Hubs retention is
// day-granular). Sub-hour is refused, never rounded to zero.
func daysFromHours(raw any) (int, error) {
	sc, err := scalars.Parse(raw)
	if err != nil || sc.Kind != scalars.Duration {
		return 0, fmt.Errorf("not a duration")
	}
	ms, _ := sc.Value.(float64)
	hours := int(ms) / 3600000
	if hours < 1 {
		return 0, fmt.Errorf("below 1 hour cannot be honored")
	}
	days := (hours + 23) / 24 // ceil to whole days
	return days, nil
}

// BuildEventHubs maps capability.streaming.pipe attributes to a plan. Every error
// is a refusal apply surfaces in preflight.
func BuildEventHubs(environment, capability string,
	attrs, impl map[string]any, generation int) (EventHubsPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := EventHubsPlan{
		Namespace:     eventHubsNamespaceName(environment, capability, generation),
		Hub:           azResourceName("pv-hub", environment, capability, generation),
		SKU:           "Standard",
		RetentionDays: 1,
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
		case "retention.window":
			days, err := daysFromHours(raw)
			if err != nil {
				return EventHubsPlan{}, fmt.Errorf("retention.window: %v", err)
			}
			p.RetentionDays = days
		case "availability.class":
			switch raw {
			case "zonal":
				p.ZoneRedundant = false
			case "regional":
				p.ZoneRedundant = true
			default:
				return EventHubsPlan{}, fmt.Errorf("availability.class %v has no Event Hubs mapping", raw)
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.CMEK = true
				p.SKU = "Premium" // CMK requires a Premium namespace
				p.KmsKeyVaultURI, _ = impl["key_vault_key_uri"].(string)
				p.KmsIdentity, _ = impl["user_assigned_identity"].(string)
				if p.KmsKeyVaultURI == "" || p.KmsIdentity == "" {
					return EventHubsPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.key_vault_key_uri " +
							"AND implementation.user_assigned_identity")
				}
			}
		case "service.managed":
			if raw != true {
				return EventHubsPlan{}, fmt.Errorf("service.managed=false cannot be honored by Event Hubs")
			}
		default:
			return EventHubsPlan{}, fmt.Errorf(
				"attribute %s has no Event Hubs mapping — refusing rather than silently dropping it "+
					"(partition count, capture, throughput units are implementation sizing)", path)
		}
	}
	if p.Region == "" {
		return EventHubsPlan{}, fmt.Errorf("stream requires location.region")
	}
	// retention ceiling depends on the SKU: Standard tops out at 7 days; Premium
	// (which CMK forces) allows up to 90. Refuse rather than silently truncate.
	maxDays := 7
	if p.SKU == "Premium" {
		maxDays = 90
	}
	if p.RetentionDays > maxDays {
		return EventHubsPlan{}, fmt.Errorf(
			"retention.window rounds to %d days, above the %s-tier ceiling of %d days — "+
				"a longer window needs a higher tier (Premium); refusing rather than truncating",
			p.RetentionDays, p.SKU, maxDays)
	}
	return p, nil
}

// namespaceBody is the namespaces PUT body (the constitutive substrate).
func (p EventHubsPlan) namespaceBody(tags map[string]any) map[string]any {
	props := map[string]any{"zoneRedundant": p.ZoneRedundant}
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

// hubBody is the eventhubs (entity) PUT body.
func (p EventHubsPlan) hubBody() map[string]any {
	return map[string]any{
		"properties": map[string]any{
			"partitionCount":         4,
			"messageRetentionInDays": p.RetentionDays,
		},
	}
}
