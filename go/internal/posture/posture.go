// Package posture is the proactive classifier (candidate D142). Given a read-only
// sweep (a crawl ContextDocument), the ledger's bindings + freshness, and audit
// verdicts, it classifies every resource into ONE of five honest states and attaches
// a ready-to-run remediation recipe. It is a PURE, deterministic fold — no network,
// no clock (the --at IS the clock, N1), no verdicts of its own beyond composing the
// ones groundhold already computed. Shadow findings never enter the ledger (D52); the
// PostureDocument is a derived artifact like the ContextDocument, hashed over its
// CLASSIFICATION content only (the --at and prose reasons never enter identity).
//
// The five classes are the four-valued discipline extended by an explicit fifth:
//
//	managed-ok — bound, every hard verdict satisfied at --at, evidence fresh
//	drifted    — bound, a hard constraint is violated at --at
//	shadow     — discovered, under no binding (created outside groundhold's control)
//	decayed    — bound, no violation, but a backing proof outlived its own ttl
//	unknown    — a hard verdict is unverifiable, or scope was incomplete (we can't say)
//
// Precedence for a bound capability: drifted > unknown(unverifiable) > decayed > ok.
// Vanished-by-absence drift (a bound id missing from a COMPLETE covering scope) needs
// provider-specific scope coverage and is deferred to a later slice.
package posture

import (
	"sort"

	"groundhold/internal/canonical"
)

const postureDomain = "groundhold/canon/v1:posture"

// Discovered is one resource the sweep saw, with the completeness of its scope.
type Discovered struct {
	ProviderID    string
	Scope         string
	ScopeComplete bool
}

// Input is everything the classifier folds — all already computed upstream.
type Input struct {
	At         string
	Discovered []Discovered      // from the crawl ContextDocument
	Bindings   map[string]string // capability -> providerId (ledger)
	Deposed    map[string]bool   // providerId -> deposed (D58)
	Decayed    map[string]bool   // capability -> its weakest proof outlived ttl at --at
	Verdict    map[string]string // capability -> audit class: satisfied|violated|unverifiable
}

// Remediation is the on-a-plate fix a read-only consumer displays (never runs). Steps are
// ready-to-run groundhold commands; consent flags are NEVER pre-baked (the human adds
// friction with their own hands).
type Remediation struct {
	Action string   `json:"action"` // adopt | converge | observe | none
	Steps  []string `json:"steps,omitempty"`
	Note   string   `json:"note,omitempty"`
}

// Row is one classified resource.
type Row struct {
	ProviderID  string      `json:"providerId"`
	Capability  string      `json:"capability,omitempty"`
	Class       string      `json:"class"`
	Reason      string      `json:"reason,omitempty"`
	Remediation Remediation `json:"remediation"`
}

// Summary is the proactive posture headline.
type Summary struct {
	At               string `json:"at"`
	ManagedOK        int    `json:"managedOk"`
	Drifted          int    `json:"drifted"`
	Shadow           int    `json:"shadow"`
	Decayed          int    `json:"decayed"`
	Unknown          int    `json:"unknown"`
	ShadowLowerBound bool   `json:"shadowLowerBound"` // true when a scope was incomplete
}

// Document is the posture report.
type Document struct {
	At          string  `json:"at"`
	Summary     Summary `json:"summary"`
	Rows        []Row   `json:"rows"`
	PostureHash string  `json:"postureHash"`
}

// Classify folds the inputs into the posture document. Deterministic and pure.
func Classify(in Input) *Document {
	pidToCap := map[string]string{}
	for cap, pid := range in.Bindings {
		pidToCap[pid] = cap
	}

	rows := []Row{}
	anyIncomplete := false
	sawDiscovered := map[string]bool{}

	// discovered resources under no binding are SHADOW — created outside control.
	disc := append([]Discovered(nil), in.Discovered...)
	sort.Slice(disc, func(i, j int) bool { return disc[i].ProviderID < disc[j].ProviderID })
	for _, d := range disc {
		if !d.ScopeComplete {
			anyIncomplete = true
		}
		if sawDiscovered[d.ProviderID] {
			continue
		}
		sawDiscovered[d.ProviderID] = true
		if _, bound := pidToCap[d.ProviderID]; bound {
			continue // classified below by its capability
		}
		rows = append(rows, shadowRow(d.ProviderID, in.Deposed[d.ProviderID]))
	}

	// every bound capability is classified by its verdict + freshness.
	caps := make([]string, 0, len(in.Bindings))
	for c := range in.Bindings {
		caps = append(caps, c)
	}
	sort.Strings(caps)
	for _, cap := range caps {
		rows = append(rows, capRow(cap, in.Bindings[cap], in))
	}

	doc := &Document{At: in.At, Rows: rows}
	for _, r := range rows {
		switch r.Class {
		case "managed-ok":
			doc.Summary.ManagedOK++
		case "drifted":
			doc.Summary.Drifted++
		case "shadow":
			doc.Summary.Shadow++
		case "decayed":
			doc.Summary.Decayed++
		case "unknown":
			doc.Summary.Unknown++
		}
	}
	doc.Summary.At = in.At
	doc.Summary.ShadowLowerBound = anyIncomplete
	doc.PostureHash = contentHash(rows)
	return doc
}

// capRow classifies a bound capability. Precedence: a fresh violation outranks a
// stale sibling; an unverifiable verdict is honest unknown, never green or red.
func capRow(cap, pid string, in Input) Row {
	v := in.Verdict[cap]
	switch {
	case v == "violated":
		return Row{ProviderID: pid, Capability: cap, Class: "drifted",
			Reason: "a hard constraint is violated at " + in.At, Remediation: convergeRemediation()}
	case v == "unverifiable":
		return Row{ProviderID: pid, Capability: cap, Class: "unknown",
			Reason: "a hard verdict is unverifiable (incomparable) at " + in.At + " — a modeling problem, not drift"}
	case in.Decayed[cap]:
		return Row{ProviderID: pid, Capability: cap, Class: "decayed",
			Reason: "the backing proof outlived its own ttl — we no longer know", Remediation: observeRemediation()}
	case v == "satisfied":
		return Row{ProviderID: pid, Capability: cap, Class: "managed-ok"}
	default:
		return Row{ProviderID: pid, Capability: cap, Class: "unknown",
			Reason: "no audit verdict at " + in.At + " — cannot claim ok without a proof"}
	}
}

func shadowRow(pid string, deposed bool) Row {
	note := "groundhold deliberately will not delete what it does not manage: to remove it, ADOPT it under a minimal contract, then declare state: retired and converge (the delete flows through every gate). A provider-native delete leaves no tombstone or receipt."
	if deposed {
		note = "previously managed, now deposed and reappeared — " + note
	}
	return Row{ProviderID: pid, Class: "shadow",
		Reason: "exists in the sweep but under no contract — created outside groundhold's control",
		Remediation: Remediation{Action: "adopt",
			Steps: []string{
				"groundhold discover --provider <p> --region <scope> --at <ts> > discovery.json",
				"groundhold adopt <contract> <candidate> --map <cap>=" + pid + " --discovery discovery.json --ledger <l> --at <ts>",
			},
			Note: note}}
}

func convergeRemediation() Remediation {
	return Remediation{Action: "converge",
		Steps: []string{"groundhold converge <contract> <candidate> --ledger <l> --provider <p> --at <ts>"},
		Note:  "if the drift implies data loss, converge refuses until you add the friction flag yourself (--allow-data-loss)"}
}

func observeRemediation() Remediation {
	return Remediation{Action: "observe",
		Steps: []string{
			"groundhold refresh --ledger <l> --provider <p> --at <ts>",
			"groundhold audit <contract> --ledger <l> --at <ts>",
		},
		Note: "re-observe to renew the proof, then re-audit against fresh evidence"}
}

// contentHash pins the CLASSIFICATION only — sorted (providerId, capability, class)
// triples — so two runs that reach the same conclusion hash identically; the --at,
// prose reasons and remediation text never enter identity.
func contentHash(rows []Row) string {
	model := make([]any, 0, len(rows))
	ordered := append([]Row(nil), rows...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].ProviderID != ordered[j].ProviderID {
			return ordered[i].ProviderID < ordered[j].ProviderID
		}
		return ordered[i].Capability < ordered[j].Capability
	})
	for _, r := range ordered {
		model = append(model, map[string]any{
			"providerId": r.ProviderID, "capability": r.Capability, "class": r.Class})
	}
	h, _ := canonical.Hash(postureDomain, map[string]any{"rows": model})
	return h
}
