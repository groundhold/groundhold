// Azure AI Search request building (D113): the semantic core of the Azure
// capability.search.index driver — the SAME vocabulary AWS OpenSearch fulfils
// (GCP has no managed search twin, so the domain is honestly two-cloud). A
// Microsoft.Search/searchServices resource is the managed search service; the
// service name is GLOBALLY unique. SKU, replica and partition counts are
// implementation sizing; residency, exposure, availability and encryption are the
// capability. availability.class drives the SKU floor (Standard + >=3 replicas is
// zone-redundant; Basic is single-zone).
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
)

const searchAPIVersion = "2023-11-01"

// searchNameOK bounds an AI Search service name: 2-60 lowercase alnum + hyphen,
// globally unique, no leading/trailing/consecutive hyphens (conservative subset).
var searchNameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,58}[a-z0-9]$`)

// AISearchPlan is the attribute-derived shape a create assembles.
type AISearchPlan struct {
	Name         string
	Region       string
	SKU          string // basic | standard
	ReplicaCount int
	Public       bool
	CMEK         bool
}

func aiSearchName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pv-search-" + hex.EncodeToString(sum[:])[:12] // 10 + 12 = 22 chars
}

// BuildAISearch maps capability.search.index attributes to an AI Search plan.
// Every error is a refusal apply surfaces in preflight.
func BuildAISearch(environment, capability string,
	attrs, impl map[string]any, generation int) (AISearchPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := AISearchPlan{
		Name:         aiSearchName(environment, capability, generation),
		SKU:          "basic",
		ReplicaCount: 1,
		Public:       true,
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
		case "availability.class":
			switch raw {
			case "zonal":
				p.SKU = "basic"
				p.ReplicaCount = 1
			case "regional":
				// zone redundancy needs Standard + >=3 replicas
				p.SKU = "standard"
				p.ReplicaCount = 3
			default:
				return AISearchPlan{}, fmt.Errorf("availability.class %v has no AI Search mapping", raw)
			}
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return AISearchPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by AI Search (always encrypted at rest)")
			}
		case "encryption.inTransit":
			if raw != true {
				return AISearchPlan{}, fmt.Errorf(
					"encryption.inTransit=false cannot be honored by AI Search (HTTPS-only)")
			}
		case "encryption.customerManagedKeys":
			p.CMEK, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return AISearchPlan{}, fmt.Errorf("service.managed=false cannot be honored by AI Search")
			}
		default:
			return AISearchPlan{}, fmt.Errorf(
				"attribute %s has no AI Search mapping — refusing rather than silently dropping it "+
					"(sku, replica/partition counts, index schema are implementation sizing/modelling)", path)
		}
	}
	if p.Region == "" {
		return AISearchPlan{}, fmt.Errorf("search service requires location.region")
	}
	if !searchNameOK.MatchString(p.Name) {
		return AISearchPlan{}, fmt.Errorf("derived service name %q is invalid", p.Name)
	}
	return p, nil
}

// createBody is the searchServices PUT body. Ownership is tags.
func (p AISearchPlan) createBody(tags map[string]any) map[string]any {
	access := "enabled"
	if !p.Public {
		access = "disabled"
	}
	props := map[string]any{
		"replicaCount":        p.ReplicaCount,
		"partitionCount":      1,
		"hostingMode":         "default",
		"publicNetworkAccess": access,
	}
	if p.CMEK {
		// service-level enforcement that all objects must use a customer key (the
		// key itself is attached per-index at data time).
		props["encryptionWithCmk"] = map[string]any{"enforcement": "Enabled"}
	}
	return map[string]any{
		"location":   p.Region,
		"sku":        map[string]any{"name": p.SKU},
		"tags":       tags,
		"properties": props,
	}
}
