package hetzner

import (
	"encoding/json"
	"fmt"
	"net/http"

	"groundhold/internal/provider"
)

// List enumerates existing Hetzner Cloud resources as vocabulary capabilities —
// the hetzner half of the gentle crawl (D141). Strictly read-only. Unlike aws
// discovery, the region argument is OPTIONAL: the Hetzner API is not
// region-scoped (one call returns objects across every location, each carrying
// its own location/zone) and the token itself IS the project scope, so an empty
// region means "the whole project" and is never refused. When set, region is the
// pairing's declared scope, carried through for the providerId discriminator.
//
// v0 sweeps ONLY networks: it is the sole Hetzner resource with an existing
// capability vocabulary (capability.network.private). Servers and volumes have no
// compute-VM / block-storage vocabulary yet, so mapping them would be a lie — they
// wait on new vocab, never a speculative mapping (D10). Each sweep is isolated: a
// sweep that errors becomes a diagnostic, never a hard failure that hides another.
func (d *Driver) List(region string) ([]provider.Discovered, []string, error) {
	if !d.hasToken() {
		return nil, nil, fmt.Errorf("hetzner discovery requires HCLOUD_TOKEN in the environment")
	}
	var out []provider.Discovered
	var diags []string
	for _, sweep := range []func() ([]provider.Discovered, []string, error){
		d.discoverNetworks,
	} {
		found, ds, err := sweep()
		if err != nil {
			diags = append(diags, err.Error())
			continue
		}
		out = append(out, found...)
		diags = append(diags, ds...)
	}
	return out, diags, nil
}

// network is the subset of GET /v1/networks each item we reverse-map. The list
// response returns full objects, so discovery maps inline — no per-resource GET
// (gentler on the rate limit than aws's list-then-observe).
type network struct {
	ID      int64 `json:"id"`
	Subnets []struct {
		NetworkZone string `json:"network_zone"`
	} `json:"subnets"`
}

// discoverNetworks enumerates private networks as capability.network.private.
func (d *Driver) discoverNetworks() ([]provider.Discovered, []string, error) {
	pages, diags, err := d.getPages("/networks")
	if err != nil {
		return nil, nil, fmt.Errorf("networks.list: %v", err)
	}
	var out []provider.Discovered
	for _, body := range pages {
		var doc struct {
			Networks []network `json:"networks"`
		}
		if json.Unmarshal(body, &doc) != nil {
			return nil, nil, fmt.Errorf("networks.list: unreadable")
		}
		for _, n := range doc.Networks {
			out = append(out, provider.Discovered{
				ProviderID:   d.providerID("network", n.ID),
				ResourceType: "capability.network.private",
				Observations: networkObservations(n),
			})
		}
	}
	return out, diags, nil
}

// networkObservations is the PURE reverse map (no I/O): a Hetzner network to the
// capability.network.private attributes it can honestly measure. location.region
// maps to the (first) subnet's network_zone — the value the vocab's location.region
// maps to ("subnetwork region"). service.managed is always true (a managed cloud
// network). ingress.public / egress.restricted / flowLogs.enabled are deliberately
// LEFT OUT, not faked: a Hetzner network carries no per-network firewall or
// flow-log flag readable here, so emitting a bool would be a guess (D44). CIDR /
// subnet names / route topology are implementation noise the vocab excludes.
func networkObservations(n network) []provider.Observation {
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if len(n.Subnets) > 0 && n.Subnets[0].NetworkZone != "" {
		obs = append(obs, provider.Observation{
			Path: "location.region", Value: n.Subnets[0].NetworkZone, Derivation: "measured"})
	}
	return obs
}

// providerID formats a resource identity. Hetzner ids are numeric and unique
// within a project; there is no API to resolve a project id from a token (no
// aws-STS analog), so the pairing's scope label — when declared — prefixes the id
// to avoid cross-project id collisions. Empty scope yields the simple form.
func (d *Driver) providerID(kind string, id int64) string {
	if d.Scope != "" {
		return fmt.Sprintf("hetzner:%s:%s:%d", d.Scope, kind, id)
	}
	return fmt.Sprintf("hetzner:%s:%d", kind, id)
}

// getPages fetches path following meta.pagination.next_page, returning each
// page's raw body. Following pagination is load-bearing for honesty: a silently
// truncated list is exactly what the gentle crawl forbids. A 429 becomes a
// retryable error (the pace scheduler backs off), never a hard stop.
func (d *Driver) getPages(path string) ([][]byte, []string, error) {
	var pages [][]byte
	page := 1
	for {
		st, body, err := d.get(fmt.Sprintf("%s?page=%d&per_page=50", path, page))
		if err != nil {
			return nil, nil, err
		}
		switch st {
		case http.StatusOK:
			// fall through
		case http.StatusTooManyRequests:
			return nil, nil, fmt.Errorf("HTTP 429 rate limited (retryable)")
		default:
			return nil, nil, fmt.Errorf("HTTP %d", st)
		}
		pages = append(pages, body)
		var meta struct {
			Meta struct {
				Pagination struct {
					NextPage *int `json:"next_page"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		if json.Unmarshal(body, &meta) != nil {
			return nil, nil, fmt.Errorf("unreadable pagination")
		}
		if meta.Meta.Pagination.NextPage == nil {
			return pages, nil, nil
		}
		page = *meta.Meta.Pagination.NextPage
	}
}
