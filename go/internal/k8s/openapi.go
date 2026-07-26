// Live OpenAPI fetch for the schema-drift guard. Kubernetes serves its machine
// contract at /openapi/v3: a discovery document mapping each API group to a
// per-group OpenAPI document under components.schemas. fetchOpenAPISchema resolves
// the group/version a mapping declares and returns its schemas map, which the
// drift guard fingerprints against the mapping's pin. It is wired only on the
// production (kubeconfig) driver; the test constructor leaves SchemaFetch nil so
// golden tests read unfingerprinted. guardDrift caches per group/version, so this
// runs at most once per group per session.
package k8s

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func (d *Driver) fetchOpenAPISchema(group, version string) (map[string]any, error) {
	// 1. the discovery document lists per-group schema URLs.
	st, body, err := d.call("GET", "/openapi/v3", nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("/openapi/v3: HTTP %d", st)
	}
	var disco struct {
		Paths map[string]struct {
			ServerRelativeURL string `json:"serverRelativeURL"`
		} `json:"paths"`
	}
	if json.Unmarshal(body, &disco) != nil {
		return nil, fmt.Errorf("/openapi/v3: unreadable")
	}
	key := "apis/" + group + "/" + version
	if group == "" || group == "core" {
		key = "api/" + version
	}
	entry, ok := disco.Paths[key]
	if !ok || entry.ServerRelativeURL == "" {
		return nil, fmt.Errorf("/openapi/v3 lists no schema for %q", key)
	}
	// 2. the group's OpenAPI document -> components.schemas.
	st, body, err = d.call("GET", entry.ServerRelativeURL, nil)
	if err != nil {
		return nil, err
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", entry.ServerRelativeURL, st)
	}
	var doc struct {
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if json.Unmarshal(body, &doc) != nil {
		return nil, fmt.Errorf("%s: unreadable", entry.ServerRelativeURL)
	}
	if doc.Components.Schemas == nil {
		return nil, fmt.Errorf("%s: no components.schemas", entry.ServerRelativeURL)
	}
	return doc.Components.Schemas, nil
}
