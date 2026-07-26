// Package apireq is the requirement-invariant registry (D329, API-drift #3b): a
// human-curated, enumerated catalog of KNOWN cloud-provider API requirements —
// server-side authorization or protocol facts a driver must honour that are
// invisible to version-pinning (apiver, D236) and shape fixtures (D234/D235).
//
// The motivating class: AWS silently began requiring a NEW action
// (lambda:InvokeFunction) on Lambda Function URL invocation via CloudFront OAC
// ~Oct 2025, at a FIXED API version — a purely server-side authz change. A
// dev-host cannot see it (creds-free, deterministic), a version pin cannot see
// it (the version never moved), and a shape fixture cannot see it (the request
// shape never changed). What we can do is REMEMBER it and refuse to regress it.
//
// Two honesty rules, mirrored from apiver:
//
//   - The registry is the single ENUMERATED catalog of what we know. It records
//     a CLAIM plus its human sources (SinceDate + SourceURL); it does NOT itself
//     prove the requirement is still current — a live functional canary does
//     that (built separately, API-drift #3a, which iterates these entries as
//     DATA via CanaryTargets). Read SinceDate as "when we learned this", not as
//     a provider-verification stamp.
//   - Every entry with a driver binding is fenced by a regression guard
//     (apireq_guard_test.go, in the driver package) that asserts the driver
//     STILL honours the requirement. Dropping the requirement in a future edit
//     fails that guard, and the failure message cites the GuardID + SourceURL so
//     the operator knows it is a known provider requirement, not an arbitrary
//     assertion.
//
// The mechanism is cloud-agnostic via the Provider field, but only REAL, sourced
// requirements are seeded. We do not fabricate GCP/Azure entries to fake parity;
// the registry is ready for them (agnostic by construction) and stays honest
// until a real one is catalogued.
//
// Invariant #4 (closed operator set): a Requirement is a closed enumerated
// struct with plain-string fields. There is NO expression language here.
package apireq

import "sort"

// Requirement is one known provider API requirement: a fact the driver must
// honour, bound to a stable GuardID that its regression guard keys off.
type Requirement struct {
	Provider    string   `json:"provider"`    // aws | gcp | azure
	Service     string   `json:"service"`     // stable kebab id, e.g. "lambda"
	Operation   string   `json:"operation"`   // the operation the requirement governs
	Requirement string   `json:"requirement"` // short human statement of what must be true
	SinceDate   string   `json:"sinceDate"`   // when the provider began requiring it, e.g. "2025-10"
	SourceURL   []string `json:"sourceUrl"`   // one or more human-checkable references
	GuardID     string   `json:"guardId"`     // stable key the regression guard cites on failure
}

// GuardCloudFrontOACDualInvoke is the stable key for the first (AWS) entry. The
// driver's regression guard imports this so the registry and the guard cannot
// drift apart: rename here and the guard fails to compile.
const GuardCloudFrontOACDualInvoke = "aws-lambda-functionurl-oac-dual-invoke"

// registry is the enumerated catalog. Deterministic, no I/O, no network. Every
// entry with a driver binding is fenced by a guard in the driver's test package.
var registry = []Requirement{
	{
		Provider:  "aws",
		Service:   "lambda",
		Operation: "InvokeFunctionUrl (via CloudFront OAC)",
		Requirement: "a Function URL created after ~2025-10 requires the caller's resource " +
			"policy to allow BOTH lambda:InvokeFunctionUrl AND lambda:InvokeFunction " +
			"(older URLs work with InvokeFunctionUrl alone). The CloudFront invoke grant " +
			"must emit both actions, principal cloudfront.amazonaws.com, scoped by SourceArn.",
		SinceDate: "2025-10",
		SourceURL: []string{
			"https://github.com/aws-samples/remote-swe-agents/issues/361",
			"https://github.com/hashicorp/terraform-provider-aws/issues/39396",
		},
		GuardID: GuardCloudFrontOACDualInvoke,
	},
	// GCP / Azure: none catalogued yet. The mechanism is cloud-agnostic via the
	// Provider field — seed a real, sourced requirement here when one is known.
	// Do NOT add speculative entries to fake parity.
}

// All returns a copy of the registry, sorted by provider, service, then GuardID.
func All() []Requirement {
	out := make([]Requirement, len(registry))
	copy(out, registry)
	sortReqs(out)
	return out
}

// For returns the requirements for one provider (aws|gcp|azure), sorted.
func For(provider string) []Requirement {
	var out []Requirement
	for _, r := range registry {
		if r.Provider == provider {
			out = append(out, r)
		}
	}
	sortReqs(out)
	return out
}

// Get returns the requirement with the given GuardID.
func Get(guardID string) (Requirement, bool) {
	for _, r := range registry {
		if r.GuardID == guardID {
			return r, true
		}
	}
	return Requirement{}, false
}

// CanaryTargets returns the full catalog as the list of critical operations a
// future functional canary (API-drift #3a) iterates as DATA. It is All() under
// an intention-revealing name: these entries ARE the "which operations matter"
// source of truth. This package builds only the accessor, never the canary.
func CanaryTargets() []Requirement { return All() }

func sortReqs(rs []Requirement) {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].Provider != rs[j].Provider {
			return rs[i].Provider < rs[j].Provider
		}
		if rs[i].Service != rs[j].Service {
			return rs[i].Service < rs[j].Service
		}
		return rs[i].GuardID < rs[j].GuardID
	})
}
