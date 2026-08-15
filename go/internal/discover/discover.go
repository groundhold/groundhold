// Package discover implements read-only brownfield discovery (D52):
// enumerate resources the runtime did not create, reverse-mapped into
// semantic observations, with a MECHANICAL candidate skeleton per
// resource. Discovery never writes the ledger and never mutates the
// cloud; interpreting which observations are intent and which are
// accidents belongs to the author (D49), not to this code.
package discover

import (
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/canonical"
	"groundhold/internal/provider"
)

type Observation struct {
	Path       string `json:"path"`
	Value      any    `json:"value"`
	Derivation string `json:"derivation"`
}

type Resource struct {
	ProviderID   string        `json:"providerId"`
	ResourceType string        `json:"resourceType"`
	Observations []Observation `json:"observations"`
	// CandidateSkeleton is deterministic plumbing output: observed
	// attribute values in candidate shape, every one an
	// observed-not-intent fact until an author says otherwise.
	CandidateSkeleton map[string]any `json:"candidateSkeleton"`
}

type Document struct {
	Provider  string     `json:"provider"`
	Project   string     `json:"project,omitempty"`
	Region    string     `json:"region,omitempty"`
	At        string     `json:"at"`
	Resources []Resource `json:"resources"`
}

type Result struct {
	Discovery Document `json:"discovery"`
	// DiscoveryHash: canonical identity of the Discovery tree (domain
	// groundhold/canon/v1:discovery) — drafts and adoptions cite the exact
	// enumeration they derive from.
	DiscoveryHash string   `json:"discoveryHash"`
	Diagnostics   []string `json:"diagnostics,omitempty"`
	// Incomplete is true when the driver reported a listing that did not finish —
	// a page went unread, or a sub-sweep failed — and returned no error (D803/D873).
	// The resources found are real; the COUNT is a lower bound. Surfaced on the Result
	// so every caller (crawl's live fetch AND react's targeted re-list) reads ONE
	// truncation signal instead of each re-deciding completeness for itself.
	Incomplete       bool   `json:"incomplete,omitempty"`
	IncompleteReason string `json:"incompleteReason,omitempty"`
}

// tree renders the document as the raw map the canonical hasher sees —
// the same shape a YAML round-trip of the output would produce.
func (d Document) tree() map[string]any {
	resources := make([]any, 0, len(d.Resources))
	for _, r := range d.Resources {
		obs := make([]any, 0, len(r.Observations))
		for _, o := range r.Observations {
			obs = append(obs, map[string]any{"path": o.Path,
				"value": o.Value, "derivation": o.Derivation})
		}
		resources = append(resources, map[string]any{
			"providerId":        r.ProviderID,
			"resourceType":      r.ResourceType,
			"observations":      obs,
			"candidateSkeleton": r.CandidateSkeleton,
		})
	}
	t := map[string]any{
		"apiVersion": "discovery/v0", "kind": "DiscoveryDocument",
		"provider": d.Provider, "at": d.At, "resources": resources,
	}
	if d.Project != "" {
		t["project"] = d.Project
	}
	if d.Region != "" {
		t["region"] = d.Region
	}
	return t
}

func Run(prov provider.Provider, project, region,
	at string) (*Result, error) {
	disc, ok := prov.(provider.Discoverer)
	if !ok {
		return nil, fmt.Errorf(
			"provider %s does not support discovery", prov.Name())
	}
	found, diags, err := disc.List(region)
	if err != nil {
		return nil, err
	}
	sort.Slice(found, func(i, j int) bool {
		return found[i].ProviderID < found[j].ProviderID
	})
	res := &Result{Discovery: Document{
		Provider: prov.Name(), Project: project, Region: region,
		At: at, Resources: []Resource{}}, Diagnostics: diags}
	for _, d := range found {
		obs := make([]Observation, 0, len(d.Observations))
		for _, o := range d.Observations {
			obs = append(obs, Observation{
				Path: o.Path, Value: o.Value, Derivation: o.Derivation})
		}
		// Total order (determinism follows meaning): Path alone is not a total
		// order — two observations sharing a path but differing in value/derivation
		// would land in an unstable order that FEEDS the discovery hash, so identical
		// reality could hash differently. Break ties on value then derivation. (For
		// the normal case of unique paths this is identical to the old sort, so no
		// real-input hash changes.)
		sort.Slice(obs, func(i, j int) bool {
			if obs[i].Path != obs[j].Path {
				return obs[i].Path < obs[j].Path
			}
			if vi, vj := fmt.Sprintf("%v", obs[i].Value), fmt.Sprintf("%v", obs[j].Value); vi != vj {
				return vi < vj
			}
			return obs[i].Derivation < obs[j].Derivation
		})
		// build the skeleton from the SORTED observations, so a duplicate path's
		// last-write-wins collapse is deterministic too (not input-order dependent).
		attrs := map[string]any{}
		for _, o := range obs {
			attrs[o.Path] = o.Value
		}
		res.Discovery.Resources = append(res.Discovery.Resources, Resource{
			ProviderID:   d.ProviderID,
			ResourceType: d.ResourceType,
			Observations: obs,
			CandidateSkeleton: map[string]any{
				"attributes": attrs,
			},
		})
	}
	// The sweep succeeded — and the driver may have said there was more. Ask the optional
	// completeness capability ONCE, here, so no caller re-decides it: react hardcoded
	// "complete" and laundered a truncated re-list into an affirmative complete claim
	// (overwriting a prior honest incomplete and exiting 0), while the crawl path asked.
	// TruncatedListings RESETS the record, so this must be the single interrogation site.
	if lc, ok := prov.(provider.ListingCompleteness); ok {
		if notes := lc.TruncatedListings(); len(notes) > 0 {
			calls := make([]string, 0, len(notes))
			for _, n := range notes {
				calls = append(calls, n.Call)
			}
			sort.Strings(calls)
			res.Incomplete = true
			res.IncompleteReason = "the scope is incomplete — a listing did not finish (a page went " +
				"unread, or a discovery sweep failed): " + strings.Join(calls, ", ") +
				" — the resources found are real, the count is a lower bound (D803/D873)"
		}
	}
	h, err := canonical.HashDiscovery(res.Discovery.tree())
	if err != nil {
		return nil, err
	}
	res.DiscoveryHash = h
	return res, nil
}
