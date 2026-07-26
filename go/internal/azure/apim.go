// Azure API Management request building (D119): the semantic core of the Azure
// capability.apigateway.http driver — the SAME vocabulary AWS API Gateway v2 fulfils
// (GCP API Gateway is an api+config+gateway composite requiring an OpenAPI doc, so the
// domain is honestly two-cloud). An APIM (Consumption-tier) service is Azure's managed
// HTTP API gateway. Invariant #4: the APIs, routes and policies APIM hosts are OPAQUE
// config carried under implementation. websocket is REFUSED — APIM has no service-level
// websocket-API primitive.
package azure

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
)

const apimAPIVersion = "2023-05-01-preview"

// apimNameOK bounds an APIM service name: 1-50 alnum, globally unique, starts with a letter.
var apimNameOK = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9]{0,49}$`)

// apimEmailOK is a permissive email bound for the required publisher email.
var apimEmailOK = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// APIMPlan is the attribute-derived shape a create assembles into the ARM body.
type APIMPlan struct {
	Name           string
	Region         string
	PublisherEmail string
	PublisherName  string
}

func apimServiceName(environment, capability string, generation int) string {
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	return "pvapim" + hex.EncodeToString(sum[:])[:16] // alnum, starts with a letter
}

// BuildAPIM maps capability.apigateway.http attributes to a plan. Every error is a
// refusal apply surfaces in preflight.
func BuildAPIM(environment, capability string,
	attrs, impl map[string]any, generation int) (APIMPlan, error) {
	p := APIMPlan{Name: apimServiceName(environment, capability, generation)}
	protoSet := false

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
		case "protocol":
			protoSet = true
			switch raw {
			case "http":
				// APIM serves HTTP
			case "websocket":
				return APIMPlan{}, fmt.Errorf(
					"protocol=websocket cannot be honored by Azure API Management — APIM has no " +
						"service-level websocket-API primitive; refusing rather than downgrading to http")
			default:
				return APIMPlan{}, fmt.Errorf("protocol %v has no APIM mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return APIMPlan{}, fmt.Errorf("service.managed=false cannot be honored by APIM")
			}
		default:
			return APIMPlan{}, fmt.Errorf(
				"attribute %s has no APIM mapping — refusing rather than silently dropping it "+
					"(APIs, routes, policies are opaque implementation config)", path)
		}
	}
	if p.Region == "" {
		return APIMPlan{}, fmt.Errorf("api gateway requires location.region")
	}
	if !protoSet {
		return APIMPlan{}, fmt.Errorf("api gateway requires protocol (http | websocket)")
	}
	// APIM REQUIRES a publisher email + name (the service owner contact) — impl detail.
	p.PublisherEmail, _ = impl["publisher_email"].(string)
	p.PublisherName, _ = impl["publisher_name"].(string)
	if !apimEmailOK.MatchString(p.PublisherEmail) || p.PublisherName == "" {
		return APIMPlan{}, fmt.Errorf(
			"APIM requires implementation.publisher_email (a valid email) AND " +
				"implementation.publisher_name (the API publisher/owner contact)")
	}
	if !apimNameOK.MatchString(p.Name) {
		return APIMPlan{}, fmt.Errorf("derived service name %q is invalid", p.Name)
	}
	return p, nil
}

// createBody is the API Management service PUT body (Consumption tier). Ownership is tags.
func (p APIMPlan) createBody(tags map[string]any) map[string]any {
	return map[string]any{
		"location": p.Region,
		"sku":      map[string]any{"name": "Consumption", "capacity": 0},
		"tags":     tags,
		"properties": map[string]any{
			"publisherEmail": p.PublisherEmail,
			"publisherName":  p.PublisherName,
		},
	}
}
