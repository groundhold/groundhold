// DynamoDB request building (D112): the semantic core of the AWS
// capability.database.nosql driver — the SAME vocabulary Azure Cosmos DB and GCP
// Firestore fulfil. DynamoDB is a managed regional NoSQL key-value/document
// store. The partition-key schema, throughput mode and indexes are implementation
// detail (a single string partition key "pk" and on-demand billing are the
// reference defaults); residency, encryption, point-in-time recovery and deletion
// protection are the capability. availability.class=multi-regional (global tables)
// is refused in v0.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// dynamoNameOK bounds a DynamoDB table name (3-255: alnum, dot, dash, underscore).
var dynamoNameOK = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,255}$`)

// DynamoTableName is the deterministic table name (the idempotency handle).
func DynamoTableName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, slug)
	slug = strings.Trim(slug, "-")
	return "pv-" + slug + "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
}

// DynamoPlan is the attribute-derived shape a create assembles.
type DynamoPlan struct {
	Table              string
	CMEK               bool
	KmsKeyId           string // from impl; "" = AWS-owned key
	PITR               bool   // point-in-time recovery (a SEPARATE UpdateContinuousBackups call)
	DeletionProtection bool
}

// BuildDynamoDB maps capability.database.nosql attributes + impl to a plan. Every
// error is a preflight refusal, never a silent drop.
func BuildDynamoDB(environment, capability string,
	attrs, impl map[string]any, generation int) (DynamoPlan, error) {
	p := DynamoPlan{Table: DynamoTableName(environment, capability, generation)}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// region is the driver scope (createScope); nothing in the body.
		case "availability.class":
			switch raw {
			case "regional":
				// the default single-region table
			case "multi-regional":
				return DynamoPlan{}, fmt.Errorf(
					"availability.class=multi-regional cannot be honored in v0 — DynamoDB global " +
						"tables are a heavier multi-region replica setup; refusing rather than faking it")
			default:
				return DynamoPlan{}, fmt.Errorf("availability.class %v has no DynamoDB mapping", raw)
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.CMEK = true
				p.KmsKeyId, _ = impl["kms_key_id"].(string)
				if p.KmsKeyId == "" {
					return DynamoPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_id")
				}
			}
		case "backup.pointInTimeRecovery":
			p.PITR, _ = raw.(bool)
		case "deletion.protection":
			p.DeletionProtection, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return DynamoPlan{}, fmt.Errorf("service.managed=false cannot be honored by DynamoDB")
			}
		default:
			return DynamoPlan{}, fmt.Errorf(
				"attribute %s has no DynamoDB mapping — refusing rather than silently dropping it "+
					"(key schema, indexes, throughput are implementation modelling/sizing)", path)
		}
	}
	if !dynamoNameOK.MatchString(p.Table) {
		return DynamoPlan{}, fmt.Errorf("derived table name %q is invalid", p.Table)
	}
	return p, nil
}

// classifyDynamoDBChange (D46, D1004): backup.pointInTimeRecovery and
// deletion.protection change on a LIVE table (UpdateContinuousBackups / UpdateTable),
// so a change to either is a PATCH, not a replacement. Without this, dynamodb had no
// explicit ClassifyChange and fell to the default (replacement) — so disabling PITR on
// a stateful table read as "replace the table (data loss), consent-required", a false
// claim that a destructive rebuild was the only path (field: acme). A table's region
// and its immutable schema (key, billing) stay a replacement.
func classifyDynamoDBChange(path string) (string, string) {
	switch path {
	case "backup.pointInTimeRecovery":
		return "mutable", "PITR toggled in place via UpdateContinuousBackups (no replacement)"
	case "deletion.protection":
		return "mutable", "deletion protection toggled in place via UpdateTable (no replacement)"
	case "location.region":
		return "immutable", "a DynamoDB table's region is fixed at creation — a change is a replacement"
	default:
		return "immutable", "a DynamoDB table's key schema/billing are fixed at creation — a change is a replacement"
	}
}

// createBody is the CreateTable request body. A single string partition key "pk"
// and on-demand billing are the reference defaults (schema/throughput are impl).
func (p DynamoPlan) createBody(capability, environment string) map[string]any {
	body := map[string]any{
		"TableName":                 p.Table,
		"BillingMode":               "PAY_PER_REQUEST",
		"AttributeDefinitions":      []any{map[string]any{"AttributeName": "pk", "AttributeType": "S"}},
		"KeySchema":                 []any{map[string]any{"AttributeName": "pk", "KeyType": "HASH"}},
		"DeletionProtectionEnabled": p.DeletionProtection,
		"Tags": []any{
			map[string]any{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
			map[string]any{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
		},
	}
	if p.CMEK {
		body["SSESpecification"] = map[string]any{
			"Enabled": true, "SSEType": "KMS", "KMSMasterKeyId": p.KmsKeyId,
		}
	}
	return body
}
