// API Gateway v2 request building (D119): the semantic core of the AWS
// capability.apigateway.http driver — the SAME vocabulary Azure API Management
// fulfils (GCP API Gateway is an api+config+gateway composite requiring an OpenAPI
// doc, so the domain is honestly two-cloud). An apigatewayv2 API is a lightweight
// HTTP (or WebSocket) front door. Invariant #4: routes, integrations and authorizers
// are OPAQUE config carried under implementation, never a vocabulary attribute.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// apigwNameOK bounds an API name (1-128).
var apigwNameOK = regexp.MustCompile(`^[a-zA-Z0-9 _-]{1,128}$`)

// ApiGWName is the deterministic API name (a readable handle; the ApiId is server-assigned).
func ApiGWName(environment, capability string, generation int) string {
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

// ApiGWPlan is the attribute-derived shape a create assembles.
type ApiGWPlan struct {
	Name         string
	ProtocolType string // HTTP | WEBSOCKET
}

// BuildApiGWv2 maps capability.apigateway.http attributes to a plan. Every error is
// a preflight refusal, never a silent drop.
func BuildApiGWv2(environment, capability string,
	attrs, impl map[string]any, generation int) (ApiGWPlan, error) {
	p := ApiGWPlan{Name: ApiGWName(environment, capability, generation), ProtocolType: "HTTP"}
	protoSet := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// region is the driver scope (createScope); nothing in the body.
		case "protocol":
			protoSet = true
			switch raw {
			case "http":
				p.ProtocolType = "HTTP"
			case "websocket":
				p.ProtocolType = "WEBSOCKET"
			default:
				return ApiGWPlan{}, fmt.Errorf("protocol %v has no API Gateway mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return ApiGWPlan{}, fmt.Errorf("service.managed=false cannot be honored by API Gateway")
			}
		default:
			return ApiGWPlan{}, fmt.Errorf(
				"attribute %s has no API Gateway mapping — refusing rather than silently dropping it "+
					"(routes, integrations, authorizers are opaque implementation config)", path)
		}
	}
	if !protoSet {
		return ApiGWPlan{}, fmt.Errorf("api gateway requires protocol (http | websocket)")
	}
	if !apigwNameOK.MatchString(p.Name) {
		return ApiGWPlan{}, fmt.Errorf("derived api name %q is invalid", p.Name)
	}
	return p, nil
}

// createBody is the CreateApi request body. Ownership is tags. The apigatewayv2
// wire protocol is restJson1 and the members carry camelCase locationNames
// (name, protocolType, tags, routeSelectionExpression) — a PascalCase body is
// silently ignored by AWS, which then reports protocolType empty as "Invalid
// protocol specified" (D878: the real-account defect the PascalCase golden hid).
func (p ApiGWPlan) createBody(capability, environment string) map[string]any {
	body := map[string]any{
		"name":         p.Name,
		"protocolType": p.ProtocolType,
		"tags": map[string]any{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
	if p.ProtocolType == "WEBSOCKET" {
		// a WebSocket API requires a route-selection expression.
		body["routeSelectionExpression"] = "$request.body.action"
	}
	return body
}
