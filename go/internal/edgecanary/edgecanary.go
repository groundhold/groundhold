// Package edgecanary is the DETERMINISTIC decision core of the AWS public-edge
// functional canary (API-drift #3a, D329). The canary converges a real
// CloudFront-OAC -> Lambda Function URL edge on a throwaway account and reads
// the OUTCOME; this package turns that observed outcome into the shared canary
// incident class (0 green / 10 provider-drift / 20 groundhold-regression / 30
// infra-flake) and, on provider-drift, cites the relevant apireq registry entry.
//
// Why a Go core for a shell canary: the target list and the verdict logic are
// the two parts a version-pin/shape-fixture cannot express, so they are the two
// parts worth unit-testing. The shell owns the live cloud I/O (converge, poll,
// GET, sweep) which cannot run without creds; it delegates target selection and
// classification here (via `groundhold apireq classify`), so the truth table
// lives in ONE tested place and the red message is DATA-driven from the registry
// (never a hardcoded citation).
//
// The verdict UPGRADE (a 401/403 on a KNOWN-GOOD, freshly-converged, fully
// Deployed edge -> RED) lives ONLY here, inside the canary that OWNS its
// environment. It is NOT a change to the customer-facing D330 reach probe, which
// correctly keeps a 401/403 as `unknown` because it cannot know the edge is
// known-good. The canary can, because it just built it.
package edgecanary

import (
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/apireq"
)

// Class is the canary incident classification, shared verbatim with the S3/SQS/
// RDS AWS canary modes (see scripts/canary-aws.sh).
type Class string

const (
	Green         Class = "green"
	ProviderDrift Class = "provider-drift"
	Regression    Class = "groundhold-regression"
	Flake         Class = "infra-flake"
)

// ExitCode maps a class to the canary exit taxonomy the workflow triages on.
func (c Class) ExitCode() int {
	switch c {
	case Green:
		return 0
	case ProviderDrift:
		return 10
	case Regression:
		return 20
	default: // Flake and any unclassified case fail SAFE as a retryable flake
		return 30
	}
}

// Outcome is everything the shell observed about one edge-canary run, reduced to
// the deterministic inputs the verdict depends on. The shell fills it from
// converge's JSON status, the CloudFront distribution's deployment state, and a
// raw viewer GET against the distribution domain.
type Outcome struct {
	// Applied is true when `groundhold converge` reported status=applied — the
	// edge (lambda + Function URL + CloudFront/OAC) actually stood up. converge's
	// process EXIT is deliberately NOT used here: this edge always exits 2 because
	// the lambda's own IAM-auth Function URL 403s a converge-time anonymous probe
	// BY DESIGN, and the CloudFront domain is probed before it finishes
	// propagating. Status is the honest "did it build" signal; the verdict comes
	// from the canary's own post-Deployed probe below.
	Applied bool
	// Deployed is true when the CloudFront distribution reached Status=Deployed
	// within the propagation budget (~15-20 min). A false here is a flake, never a
	// finding: an un-propagated edge has not yet answered for itself.
	Deployed bool
	// Transport is true when the viewer GET failed below HTTP (DNS/TLS/timeout/
	// connection refused) — no status was seen. After Deployed this is a runner/
	// network flake, still never a finding (it names no provider behaviour).
	Transport bool
	// HTTPStatus is the viewer GET status code against the CloudFront domain (0
	// when Transport). This is the load-bearing signal: on a KNOWN-GOOD edge it
	// MUST be 2xx/3xx.
	HTTPStatus int
}

// Result is the classification decision plus its operator-facing message.
type Result struct {
	Class   Class  `json:"class"`
	Exit    int    `json:"exit"`
	Cite    bool   `json:"cite"` // whether the message cites an apireq entry
	GuardID string `json:"guardId,omitempty"`
	Message string `json:"message"`
}

// Edge describes the CLOUD-SPECIFIC facets of a public-edge canary that the
// otherwise cloud-agnostic verdict truth table needs: how to name the edge in
// the operator message, and which apireq registry entries (if any) a drift
// verdict cites. The truth table itself (Applied/Deployed/Transport/HTTPStatus
// -> class) is IDENTICAL across clouds — only the wording and the citation vary,
// so a new cloud is a data value here, never a change to ClassifyFor.
type Edge struct {
	Provider    string // aws|gcp — selects the apireq citation targets
	Subject     string // the edge noun, e.g. "CloudFront edge", "public Cloud Run service"
	ReadyNoun   string // the readiness noun, e.g. "CloudFront distribution", "Cloud Run service"
	ReadyBudget string // the readiness window phrase, e.g. "the propagation budget (~15-20 min)"
	GreenPath   string // what a green proves is intact, e.g. "the OAC->Function-URL invoke path", "the public path"
	DriftCause  string // the cloud-specific "what could have changed" clause for a drift verdict
	targets     func() []apireq.Requirement
}

// Targets returns the apireq entries the edge cites on drift. Sorted by GuardID.
func (e Edge) Targets() []apireq.Requirement {
	if e.targets == nil {
		return nil
	}
	out := e.targets()
	sort.Slice(out, func(i, j int) bool { return out[i].GuardID < out[j].GuardID })
	return out
}

// AWSEdge is the CloudFront-OAC -> Lambda Function URL edge (D329/D336). Its drift
// citation is data-driven from the apireq registry (never a hardcoded list) so a
// new sourced entry on this operation is picked up automatically.
var AWSEdge = Edge{
	Provider:    "aws",
	Subject:     "CloudFront edge",
	ReadyNoun:   "CloudFront distribution",
	ReadyBudget: "the propagation budget (~15-20 min)",
	GreenPath:   "the OAC->Function-URL invoke path",
	DriftCause: "CloudFront could not invoke the Lambda Function URL. AWS may have " +
		"changed the Function-URL invoke requirement again and our OAC->Lambda grant " +
		"may now be insufficient.",
	targets: func() []apireq.Requirement {
		var out []apireq.Requirement
		for _, r := range apireq.CanaryTargets() {
			if r.Provider == "aws" && r.Service == "lambda" && strings.Contains(r.Operation, "OAC") {
				out = append(out, r)
			}
		}
		return out
	},
}

// GCPEdge is the public Cloud Run service edge (D336 twin). GCP is SIMPLER than
// AWS — a public Cloud Run service serves its *.run.app uri directly, with no CDN
// or OAC front, so there is no OAC-dual-invoke guard and the edge target is the
// Cloud Run service ITSELF. The apireq registry has no GCP entry (none is
// catalogued yet, and we do not fabricate one to fake parity), so a GCP drift
// verdict is HONEST about carrying no registry citation.
var GCPEdge = Edge{
	Provider:    "gcp",
	Subject:     "public Cloud Run service",
	ReadyNoun:   "Cloud Run service",
	ReadyBudget: "the readiness budget",
	GreenPath:   "the public path",
	DriftCause: "a public Cloud Run service on a known-good converged edge must serve " +
		"an anonymous request — GCP may have changed public-invoker behaviour or our " +
		"allUsers roles/run.invoker grant may now be insufficient.",
	targets: nil, // no GCP apireq entry catalogued; the edge target is the service itself
}

// EdgeFor selects the edge by provider. Defaults to the AWS edge so the existing
// AWS canary (which calls `apireq classify` without --provider) is unaffected.
func EdgeFor(provider string) Edge {
	if provider == "gcp" {
		return GCPEdge
	}
	return AWSEdge
}

// Targets returns the AWS edge's apireq entries — kept as a package function for
// the AWS canary path and its guard. Equivalent to AWSEdge.Targets().
func Targets() []apireq.Requirement { return AWSEdge.Targets() }

// Citation renders the "AWS may have changed the requirement again" evidence
// line for the red message: each entry's GuardID + SinceDate + human sources, so
// the operator can check the claim against the world, not just trust the canary.
func Citation(reqs []apireq.Requirement) string {
	if len(reqs) == 0 {
		return "(no apireq entry catalogues this operation yet — file one with a source before relying on the citation)"
	}
	var b strings.Builder
	b.WriteString("see apireq: ")
	for i, r := range reqs {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s (since %s: %s) [%s]", r.GuardID, r.SinceDate,
			strings.Join(r.SourceURL, ", "), r.Requirement)
	}
	return b.String()
}

// Classify is the AWS edge verdict — Classify(o) == ClassifyFor(AWSEdge, o).
// Kept for the AWS canary path and its tests.
func Classify(o Outcome) Result { return ClassifyFor(AWSEdge, o) }

// ClassifyFor is the whole verdict truth table, parameterized by the cloud's Edge
// descriptor. It is pure and total, and CLOUD-AGNOSTIC — the same table serves
// AWS's CloudFront-OAC edge and GCP's public Cloud Run edge; only the message
// wording and the drift citation come from e.
//
//	!Applied                          -> groundhold-regression (20): our driver/tooling
//	                                     could not stand up a KNOWN-GOOD edge.
//	Applied && !Deployed              -> infra-flake (30): the edge is not ready yet
//	                                     — it has not answered for itself; retry, never red.
//	Applied && Deployed && Transport  -> infra-flake (30): GET failed below HTTP from
//	                                     this vantage; names no provider behaviour.
//	Deployed, 2xx/3xx                 -> green (0): the public path served an anonymous
//	                                     request TODAY. Evidence, not proof (D75).
//	Deployed, 401/403/502/503         -> provider-drift (10): the origin could not serve
//	                                     an anonymous request on a KNOWN-GOOD edge — CITED
//	                                     when the cloud has an apireq entry, else honestly
//	                                     uncited. THE catch this layer exists for.
//	Deployed, any other status        -> groundhold-regression (20): a shape we cannot
//	                                     pin on a known provider requirement — triage as ours.
func ClassifyFor(e Edge, o Outcome) Result {
	res := func(c Class, drift bool, msg string) Result {
		r := Result{Class: c, Exit: c.ExitCode(), Message: msg}
		if drift {
			// cite only when the cloud actually has a registry entry to cite; a GCP
			// drift (no catalogued entry) stays honest — the edge target is the
			// service itself, not a registry fact.
			if t := e.Targets(); len(t) > 0 {
				r.Cite = true
				r.GuardID = t[0].GuardID
				r.Message = msg + " " + Citation(t)
			} else {
				r.Message = msg + " (no apireq entry catalogues this operation yet — " +
					"the edge target is the converged service itself; file a sourced " +
					"entry before relying on a citation.)"
			}
		}
		return r
	}

	if !o.Applied {
		return res(Regression, false,
			"converge did not stand up the known-good edge (status != applied) — a "+
				"groundhold-regression in the edge build path, not a provider change.")
	}
	if !o.Deployed {
		return res(Flake, false, fmt.Sprintf(
			"the %s did not reach a ready state within %s — the edge has not answered "+
				"for itself yet; retry, this is not a finding.", e.ReadyNoun, e.ReadyBudget))
	}
	if o.Transport {
		return res(Flake, false, fmt.Sprintf(
			"the viewer GET failed below HTTP (DNS/TLS/timeout/refused) after the %s "+
				"was ready — a vantage/network flake; retry.", e.ReadyNoun))
	}
	switch {
	case o.HTTPStatus >= 200 && o.HTTPStatus < 400:
		return res(Green, false, fmt.Sprintf(
			"the %s served an anonymous GET (HTTP %d) — %s is intact TODAY (evidence "+
				"this edge served now, not proof no drift exists anywhere).",
			e.Subject, o.HTTPStatus, e.GreenPath))
	case o.HTTPStatus == 401 || o.HTTPStatus == 403 || o.HTTPStatus == 502 || o.HTTPStatus == 503:
		return res(ProviderDrift, true, fmt.Sprintf(
			"the KNOWN-GOOD, freshly-converged, fully-ready %s returned HTTP %d to an "+
				"anonymous request — %s", e.Subject, o.HTTPStatus, e.DriftCause))
	default:
		return res(Regression, false, fmt.Sprintf(
			"the %s returned HTTP %d — a shape that does not match the known "+
				"invoke-drift signature (401/403/502/503); treat as a "+
				"groundhold-regression until triaged.", e.Subject, o.HTTPStatus))
	}
}
