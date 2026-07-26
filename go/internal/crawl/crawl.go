// Package crawl is the gentle context crawler (D141). It walks the pairing registry
// and, through the pace scheduler, runs the READ-ONLY discoverer per (provider,
// scope), assembling a ContextDocument — discovered resources as CONTEXT, never
// ownership (odkrywać ≠ posiadać). It sits outside the verifier (#6). Partiality is
// a first-class VISIBLE outcome: a budget stop, a tripped breaker, or an
// unreachable scope marks that scope `incomplete` with the reason — never a silently
// truncated list. The document's identity hashes CONTENT only; the operational
// timing of gentleness (backoff/jitter/retry counts) and each resource's fetch time
// are honesty metadata that never enter identity (the D102 sig-exclusion instinct).
package crawl

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"groundhold/internal/canonical"
	"groundhold/internal/discover"
	"groundhold/internal/pace"
	"groundhold/internal/pair"
)

const contextDomain = "groundhold/canon/v1:crawl-context"

// Fetched is one scope's read-only listing plus the pace outcome that classifies it.
type Fetched struct {
	Resources []discover.Resource
	Pace      pace.Result
}

// Fetcher runs one listing for a (connection, scope). It must be READ-ONLY. The
// crawl drives it through the scheduler, so it does the request and reports an
// Outcome; it never sleeps or retries itself.
type Fetcher func(conn pair.Connection, scope string) Fetched

// EnumResult is a scope enumeration's outcome: the scopes to crawl, diagnostics for
// what could not be listed, and the pace classification of the enumeration request.
type EnumResult struct {
	Scopes []string
	Diags  []string
	Pace   pace.Result
}

// Enumerator lists a connection's crawlable scopes when the pairing declared none.
// Read-only; driven through the scheduler like any request. nil = no enumeration
// (the crawl falls back to a single default scope, its prior behaviour).
type Enumerator func(conn pair.Connection) EnumResult

// Resource is a discovered resource plus the ACTUAL time it was fetched (distinct
// from the run's declared --at, so a slow crawl never looks uniformly fresh).
// ObservedAt is honesty metadata: excluded from the content hash.
type Resource struct {
	ProviderID   string                 `json:"providerId"`
	ResourceType string                 `json:"resourceType"`
	Observations []discover.Observation `json:"observations"`
	ObservedAt   string                 `json:"observedAt"`
}

// ScopeContext is one crawled scope. Status is complete | incomplete; Reason names
// why an incomplete scope stopped short (never a silent short list).
type ScopeContext struct {
	Scope     string     `json:"scope"`
	Status    string     `json:"status"`
	Reason    string     `json:"reason,omitempty"`
	Resources []Resource `json:"resources"`
}

// ProviderContext groups a provider's crawled scopes.
type ProviderContext struct {
	Provider    string         `json:"provider"`
	Diagnostics []string       `json:"diagnostics,omitempty"`
	Scopes      []ScopeContext `json:"scopes"`
}

// Stats is the gentleness honesty block — how hard the crawl leaned on the world.
type Stats struct {
	RequestsMade int    `json:"requestsMade"`
	Budget       int    `json:"budget"`
	Throttled    int    `json:"throttled"`
	Backoffs     int    `json:"backoffs"`
	StoppedEarly string `json:"stoppedEarly,omitempty"` // budget | breaker
	// Rate/Burst state the gentleness the world was ACTUALLY subjected to, and
	// PolicyFloored names any field the caller left unset that fell back to the
	// default (D321). An honesty block that reports how hard we leaned must also
	// report under which limits — otherwise "requestsMade: 2000" is unreadable.
	Rate          float64  `json:"rate"`
	Burst         int      `json:"burst"`
	PolicyFloored []string `json:"policyFloored,omitempty"`
}

// Document is the crawl output. ContextHash pins CONTENT only.
type Document struct {
	At          string            `json:"at"`
	Providers   []ProviderContext `json:"providers"`
	Crawl       Stats             `json:"crawl"`
	ContextHash string            `json:"contextHash"`
}

// resolveScopes decides which scopes to crawl for a connection: its declared scope
// verbatim (no enumeration), or — when it declared none — the enumerator's list
// (one paced request). A nil enumerator falls back to the single default scope.
func resolveScopes(conn pair.Connection, enum Enumerator, sched *pace.Scheduler) ([]string, []string, error) {
	if conn.Scope != "" {
		return []string{conn.Scope}, nil, nil
	}
	if enum == nil {
		return []string{""}, nil, nil
	}
	var er EnumResult
	_, err := sched.Do(conn.Provider, func() pace.Result {
		er = enum(conn)
		return er.Pace
	})
	if err != nil {
		return nil, nil, err
	}
	// Enumerators return scopes in provider-API order (ARM subscriptions.list,
	// DescribeRegions), which is not contractually stable. Sort so the emitted
	// document — and the ContextHash it feeds — do not depend on that order, the
	// same discipline discover.Run applies to resources and observations.
	sort.Strings(er.Scopes)
	return er.Scopes, er.Diags, nil
}

// Run crawls every pairing through the scheduler and assembles the document. When a
// pairing declares no scope, the enumerator fans it out to the provider's scopes.
// now stamps each resource's actual fetch time (excluded from identity). A global
// budget exhaustion stops the whole crawl; a failed enumeration or a tripped breaker
// abandons that provider — both recorded as visible incomplete, never hidden.
func Run(reg *pair.Registry, fetch Fetcher, enum Enumerator, sched *pace.Scheduler,
	budget int, at string, now func() time.Time) (*Document, error) {

	conns := append([]pair.Connection(nil), reg.Pairings...)
	sort.Slice(conns, func(i, j int) bool {
		if conns[i].Provider != conns[j].Provider {
			return conns[i].Provider < conns[j].Provider
		}
		return conns[i].Scope < conns[j].Scope
	})

	byProvider := map[string]*ProviderContext{}
	var order []string
	stoppedEarly := ""

	for _, conn := range conns {
		if stoppedEarly == "budget" {
			break
		}
		pc := byProvider[conn.Provider]
		if pc == nil {
			pc = &ProviderContext{Provider: conn.Provider}
			byProvider[conn.Provider] = pc
			order = append(order, conn.Provider)
		}
		scopes, enumDiags, enumErr := resolveScopes(conn, enum, sched)
		pc.Diagnostics = append(pc.Diagnostics, enumDiags...)
		if enumErr != nil {
			// the provider's scopes are unknown — one visible incomplete marker,
			// never a silently empty provider
			pc.Scopes = append(pc.Scopes, ScopeContext{Scope: "*", Status: "incomplete",
				Reason: "scope enumeration failed: " + enumErr.Error(), Resources: []Resource{}})
			switch {
			case errors.Is(enumErr, pace.ErrBudget):
				stoppedEarly = "budget"
			case errors.Is(enumErr, pace.ErrBroken):
				if stoppedEarly == "" {
					stoppedEarly = "breaker"
				}
			}
			continue
		}
		for _, scope := range scopes {
			var fetched Fetched
			_, err := sched.Do(conn.Provider, func() pace.Result {
				fetched = fetch(conn, scope)
				return fetched.Pace
			})
			sc := ScopeContext{Scope: scope, Resources: []Resource{}}
			if err != nil {
				sc.Status = "incomplete"
				sc.Reason = err.Error()
				switch {
				case errors.Is(err, pace.ErrBudget):
					stoppedEarly = "budget"
				case errors.Is(err, pace.ErrBroken):
					if stoppedEarly == "" {
						stoppedEarly = "breaker"
					}
				}
			} else {
				sc.Status = "complete"
				stamp := now().UTC().Format(time.RFC3339)
				for _, r := range fetched.Resources {
					sc.Resources = append(sc.Resources, Resource{
						ProviderID:   r.ProviderID,
						ResourceType: r.ResourceType,
						Observations: r.Observations,
						ObservedAt:   stamp,
					})
				}
			}
			pc.Scopes = append(pc.Scopes, sc)
			if stoppedEarly == "budget" {
				break
			}
		}
	}

	eff := sched.Policy()
	doc := &Document{At: at, Crawl: Stats{
		RequestsMade: sched.Spent(), Budget: budget,
		Throttled: sched.Throttles, Backoffs: sched.Backoffs, StoppedEarly: stoppedEarly,
		Rate: eff.Rate, Burst: eff.Burst, PolicyFloored: sched.Floored,
	}}
	for _, p := range order {
		doc.Providers = append(doc.Providers, *byProvider[p])
	}
	h, err := canonical.Hash(contextDomain, contentModel(doc))
	if err != nil {
		return nil, err
	}
	doc.ContextHash = h
	return doc, nil
}

// ContentHash recomputes a document's content-only fingerprint — used after a
// splice (the react ingress) rebuilds a single scope, so identity reflects the new
// content, not the crawl timing.
func ContentHash(doc *Document) (string, error) {
	return canonical.Hash(contextDomain, contentModel(doc))
}

// contentModel is the hashed projection: provider/scope/resource CONTENT, with
// status (partiality is content — a scope that was cut short is a different fact
// than a complete one), and WITHOUT any timing (observedAt, crawl stats, at).
func contentModel(doc *Document) map[string]any {
	// Identity is owned here, not by the caller: canonical.Canon sorts object
	// keys but preserves array ORDER, so every array that feeds the hash is
	// sorted on a stable key first (scope, providerId, path). A fetcher or
	// enumerator that returns API order must not change the ContextHash. Copies
	// are sorted so hashing never mutates the emitted document.
	provs := []any{}
	providers := append([]ProviderContext(nil), doc.Providers...)
	sort.Slice(providers, func(i, j int) bool { return providers[i].Provider < providers[j].Provider })
	for _, p := range providers {
		pscopes := append([]ScopeContext(nil), p.Scopes...)
		sort.Slice(pscopes, func(i, j int) bool { return pscopes[i].Scope < pscopes[j].Scope })
		scopes := []any{}
		for _, s := range pscopes {
			resources := append([]Resource(nil), s.Resources...)
			sort.Slice(resources, func(i, j int) bool { return resources[i].ProviderID < resources[j].ProviderID })
			res := []any{}
			for _, r := range resources {
				obsRecs := append([]discover.Observation(nil), r.Observations...)
				// Total order (determinism follows meaning): Path alone is not a
				// total order — two observations sharing a path but differing in
				// value/derivation land in an unstable order that FEEDS the
				// ContextHash, so identical reality could hash differently. Break
				// ties on value then derivation (mirrors discover.Run, #159). For
				// the normal unique-path case this equals the old sort.
				sort.Slice(obsRecs, func(i, j int) bool {
					if obsRecs[i].Path != obsRecs[j].Path {
						return obsRecs[i].Path < obsRecs[j].Path
					}
					if vi, vj := fmt.Sprintf("%v", obsRecs[i].Value), fmt.Sprintf("%v", obsRecs[j].Value); vi != vj {
						return vi < vj
					}
					return obsRecs[i].Derivation < obsRecs[j].Derivation
				})
				obs := []any{}
				for _, o := range obsRecs {
					obs = append(obs, map[string]any{
						"path": o.Path, "value": o.Value, "derivation": o.Derivation})
				}
				res = append(res, map[string]any{
					"providerId": r.ProviderID, "resourceType": r.ResourceType, "observations": obs})
			}
			scopes = append(scopes, map[string]any{
				"scope": s.Scope, "status": s.Status, "resources": res})
		}
		provs = append(provs, map[string]any{"provider": p.Provider, "scopes": scopes})
	}
	return map[string]any{"providers": provs}
}
