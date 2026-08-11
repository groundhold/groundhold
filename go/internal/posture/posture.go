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

// Scope is one crawled scope and whether the sweep LISTED IT COMPLETELY.
//
// D650: completeness used to travel only on discovered RESOURCES, so a scope that
// was cut short before listing anything — which is what crawl emits for every auth
// error, throttle, budget stop and breaker trip — could not be represented at all,
// and posture called its shadow count exact. Completeness is a property of the
// scope; it now travels as one.
type Scope struct {
	Provider string
	Scope    string
	Complete bool
	Reason   string // why it was incomplete, for the row a human reads
}

// Input is everything the classifier folds — all already computed upstream.
type Input struct {
	At         string
	Scopes     []Scope           // every scope the crawl attempted (D650)
	Discovered []Discovered      // from the crawl ContextDocument
	Bindings   map[string]string // capability -> providerId (ledger)
	Deposed    map[string]bool   // providerId -> deposed (D58)
	Decayed    map[string]bool   // capability -> its weakest proof outlived ttl at --at
	// Absent (D652) is the capability whose FRESH `resource.absent` marker says the
	// provider answered with an authoritative 404. Observations are latest-per-path,
	// so a stale `service.managed: true` stands beside it and the audit verdict from
	// it stays `satisfied` — without this the vanished resource read managed-ok.
	Absent  map[string]bool
	Verdict map[string]string // capability -> audit class: satisfied|violated|unverifiable
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
	// ManagedOKUpperBound is ALWAYS true, and says so in the output rather than only
	// in this file's header (D506). managed-ok means "bound, hard verdicts satisfied at
	// --at, evidence fresh" — it does NOT mean the resource still exists. Vanished-by-
	// absence drift (a bound id missing from a COMPLETE covering scope) needs
	// provider-specific scope coverage and is deferred, so a resource deleted
	// out-of-band since its last fresh observation is still counted here.
	//
	// A constant field looks odd and is the point: a consumer — the console projects
	// this — must not read "managedOk: 12" as twelve resources confirmed present. When
	// the deferred slice lands, this becomes conditional on whether the covering scope
	// was complete, exactly as shadowLowerBound already is.
	ManagedOKUpperBound bool `json:"managedOkUpperBound"`
}

// Document is the posture report.
type Document struct {
	At          string  `json:"at"`
	Summary     Summary `json:"summary"`
	Rows        []Row   `json:"rows"`
	PostureHash string  `json:"postureHash"`
}

// ExitCode is posture's terminal signal for an unattended run, where the exit code is the
// only alert (D649). Non-zero (2) means the estate demands action OR could not be fully
// judged: shadow/drift are findings; `unknown` is a hard verdict we could not confirm
// (unverifiable/no-verdict); `shadowLowerBound` means a crawl scope was incomplete — expired
// creds, throttle, budget — so a clean shadow/drift count is only a LOWER BOUND, not a clean
// estate (D650). Reporting exit 0 for `unknown` or an incomplete sweep would read "all clear"
// over an estate whose compliance is genuinely unknown or which posture could not fully see —
// the unverifiable-as-success inversion the sibling `audit` verb refuses (audit exits 2 on the
// identical evidence). `decayed` alone does NOT fail: a proof that outlived its ttl is renewed
// (refresh), not a violation. D958 (user-directed).
func (s Summary) ExitCode() int {
	if s.Shadow > 0 || s.Drifted > 0 || s.Unknown > 0 || s.ShadowLowerBound {
		return 2
	}
	return 0
}

// Classify folds the inputs into the posture document. Deterministic and pure.
func Classify(in Input) *Document {
	pidToCap := map[string]string{}
	for cap, pid := range in.Bindings {
		pidToCap[pid] = cap
	}

	rows := []Row{}
	// D650: nothing swept is the strongest lower bound there is. A posture with no
	// crawl at all reported `shadow: 0, shadowLowerBound: false` — an affirmative
	// claim of exactness about an estate it never looked at.
	anyIncomplete := len(in.Scopes) == 0
	for _, sc := range in.Scopes {
		if !sc.Complete {
			anyIncomplete = true
		}
	}
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
	// Always an upper bound today: nothing here detects a bound resource that vanished.
	doc.Summary.ManagedOKUpperBound = true
	doc.PostureHash = contentHash(rows)
	return doc
}

// capRow classifies a bound capability. Precedence: a fresh violation outranks a
// stale sibling; an unverifiable verdict is honest unknown, never green or red.
func capRow(cap, pid string, in Input) Row {
	v := in.Verdict[cap]
	switch {
	case in.Absent[cap]:
		// D652: first, because it explains the rest. A hard constraint failing on a
		// resource that does not exist is noise, and the compiler agrees — a fresh
		// absence marker makes it plan a re-create rather than an update.
		return Row{ProviderID: pid, Capability: cap, Class: "drifted",
			Reason: "the provider answered that this resource is GONE (a fresh " +
				"resource.absent marker at " + in.At + ") while the ledger still " +
				"binds it — converge re-creates it under the same identity",
			Remediation: convergeRemediation()}
	case v == "violated":
		return Row{ProviderID: pid, Capability: cap, Class: "drifted",
			Reason: "a hard constraint is violated at " + in.At, Remediation: convergeRemediation()}
	case v == "unverifiable":
		return Row{ProviderID: pid, Capability: cap, Class: "unknown",
			Reason:      "a hard verdict is unverifiable (incomparable) at " + in.At + " — a modeling problem, not drift",
			Remediation: remodelRemediation()}
	case v == "unknown":
		// D965: a HARD constraint whose proof is stale or otherwise unprovable is
		// unknown — invariant #1 blocks it, and audit exits 2 on the same evidence.
		// This ranks ABOVE decayed: when the aged proof is the ONLY backing for a
		// hard constraint, "we no longer know if a non-negotiable holds" is not a
		// benign refresh. A decayed proof that backs NO hard constraint still lands
		// in decayed below.
		return Row{ProviderID: pid, Capability: cap, Class: "unknown",
			Reason: "a hard constraint is unknown at " + in.At +
				" — its proof is stale or unprovable; audit blocks the same evidence",
			Remediation: observeRemediation()}
	case in.Decayed[cap]:
		return Row{ProviderID: pid, Capability: cap, Class: "decayed",
			Reason: "the backing proof outlived its own ttl — we no longer know", Remediation: observeRemediation()}
	case v == "satisfied":
		return Row{ProviderID: pid, Capability: cap, Class: "managed-ok"}
	default:
		return Row{ProviderID: pid, Capability: cap, Class: "unknown",
			Reason:      "no audit verdict at " + in.At + " — cannot claim ok without a proof",
			Remediation: auditRemediation()}
	}
}

// D568: the class an operator lands in the moment they finish adopting. Posture
// promises a recipe per class and this one carried `{"action": ""}`, which reads as
// "nothing to do" while meaning "nobody wrote one". The verb is not a judgement
// call — the decayed recipe already names it as its own second step.
func auditRemediation() Remediation {
	return Remediation{Action: "audit",
		Steps: []string{
			"groundhold audit <contract> --ledger <l> --at <ts>",
			// D568: without --contract posture reads no verdicts, so the audit that
			// just succeeded stays invisible and the advice reads as having failed.
			"groundhold posture --ledger <l> --at <ts> --crawl <c> --contract <contract>",
		},
		Note: "nothing is wrong — nothing has been PROVEN right yet. A binding without " +
			"a verdict is the normal state straight after adopt; audit reads the " +
			"recorded observations against the contract and produces one."}
}

// remodelRemediation: an incomparable verdict is not fixed by running anything, so
// the steps name the two documents rather than a verb. Advising `audit` here would
// send the operator around a loop that cannot terminate.
func remodelRemediation() Remediation {
	return Remediation{Action: "remodel",
		Steps: []string{
			"groundhold explain <attribute-path>   # what the vocabulary says the value IS",
			"edit the contract's constraint (or the candidate's declared value) so the two are comparable",
		},
		Note: "re-observing cannot help: the observation and the constraint are not the " +
			"same kind of thing, so no amount of fresh evidence makes them comparable."}
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
				// D569: --provider is not optional decoration. adopt is in the CLI's
				// providerVerbs set and refuses without it (F4: the fake driver must
				// never be a silent default), so a recipe missing it does not run —
				// and step 1 above already carries it, so the two lines disagreed
				// about the same tool.
				"groundhold adopt <contract> <candidate> --map <cap>=" + pid +
					" --discovery discovery.json --ledger <l> --provider <p> --at <ts>",
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
			"groundhold posture --ledger <l> --at <ts> --crawl <c> --contract <contract>",
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
