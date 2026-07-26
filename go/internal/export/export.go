// Package export folds the ledger into an event stream for external
// systems (D54): violation.detected feeds alerting, apply/delete/adopt
// feed SIEM audit. The fold is DETERMINISTIC and STATELESS — same
// ledger + same cursor = byte-identical output; stdout is the only
// sink and transport belongs to the operator (D39: the runtime never
// talks to third-party tools). The canonical event hash rides as the
// record id, so at-least-once delivery is consumer-side dedupable.
package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"groundhold/internal/canonical"
	"groundhold/internal/ledger"
)

type Options struct {
	LedgerPath string
	Since      int      // skip the first Since lines (operator's cursor)
	Format     string   // ndjson | cloudevents
	Types      []string // empty = every type
	From       string   // occurredAt lower bound (RFC3339, inclusive); "" = open
	To         string   // occurredAt upper bound (RFC3339, inclusive); "" = open
	Out        io.Writer
}

// Record is the ndjson shape: the raw ledger event plus its identity
// and cursor — nothing is summarized away; consumers filter, we don't.
type Record struct {
	Index       int            `json:"index"` // next cursor = index + 1
	ID          string         `json:"id"`    // canonical event hash
	Type        string         `json:"type"`
	Environment string         `json:"environment,omitempty"`
	Event       map[string]any `json:"event"`
}

func Run(o Options) (int, error) {
	raw, err := os.ReadFile(o.LedgerPath)
	if err != nil {
		return 0, err
	}
	// D137: under a snapshot the file holds only the tail — indices
	// stay ABSOLUTE (cursor consumers keep their meaning) and the
	// identity every signature claims comes from the snapshot.
	base := 0
	var snapID string
	var snapHeads map[string]string
	var snapFrom string
	if snap, err := ledger.LoadSnapshotFile(
		ledger.SnapshotPath(o.LedgerPath)); err != nil {
		return 0, err
	} else if snap != nil {
		if err := ledger.VerifySnapshotTrust(snap); err != nil {
			return 0, err
		}
		base = snap.BaseEvents
		snapID = snap.LedgerId
		snapHeads = snap.Heads
		if snap.VerifiedUnder != nil && snap.VerifiedUnder.Mode == "trust" {
			snapFrom = snap.VerifiedUnder.From
		}
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		return 0, fmt.Errorf(
			"ledger has a torn final line — repair required")
	}
	want := map[string]bool{}
	for _, t := range o.Types {
		want[t] = true
	}
	// The 4D window (D14x): a PROJECTION over occurredAt, never a change to the
	// fold — every line is still trust-checked below; the window only decides
	// what is EMITTED. This is the deterministic core primitive; correlation
	// across the window is an interpretation that lives OUTSIDE the verifier
	// (invariant #6), in the dr-forensics skill and downstream 4D views.
	fromTs, toTs := int64(0), int64(0)
	haveFrom, haveTo := o.From != "", o.To != ""
	if haveFrom {
		t, err := ledger.ParseTs(o.From)
		if err != nil {
			return 0, fmt.Errorf("--from %q is not an RFC3339 time: %v", o.From, err)
		}
		fromTs = int64(t)
	}
	if haveTo {
		t, err := ledger.ParseTs(o.To)
		if err != nil {
			return 0, fmt.Errorf("--to %q is not an RFC3339 time: %v", o.To, err)
		}
		toTs = int64(t)
	}
	if haveFrom && haveTo && toTs < fromTs {
		return 0, fmt.Errorf("--from %s is after --to %s — an empty window", o.From, o.To)
	}
	trust := ledger.NewTrustChecker()
	// D137: a --trust-from boundary compacted into the archive is
	// honored via the snapshot receipt, exactly as ReplayFile does —
	// otherwise export both over-refuses and streams the tail unchecked.
	if snapFrom != "" && snapFrom == ledger.ArmedTrustFrom() {
		trust.SeedBoundaryHonored()
	}
	// buffer every record: a Finish refusal (or any mid-stream refusal)
	// must reach the operator BEFORE a single line hits stdout, or a
	// `groundhold export | consumer` pipeline consumes unverified data
	// despite the non-zero exit (review fix).
	var buf bytes.Buffer
	emitted := 0
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	// export must be as strict as replay about CONTINUITY, not only
	// signatures (review fix): a reordered or mid-deleted tail leaves
	// every remaining signature valid (a sig covers only its own event),
	// so without a per-capability chain check `export --trust` would
	// stream doctored history that ReplayFile refuses. Seed the heads
	// from the snapshot (a compacted tail continues the snapshot heads,
	// not genesis); every event's prev must pin the current head.
	heads := map[string]string{}
	for c, h := range snapHeads {
		heads[c] = h
	}
	// D315 (hardening): pin the identity on the first EVENT, not on loop index 0.
	// A leading blank line — which the loop skips — made `i == 0` fall on the
	// blank and ExpectLedger never run, so the stream's own genesis was never
	// cross-checked against what the signatures claim. Not shown to be
	// exploitable (verifySig binds the ledger id into the signed message, so a
	// consistent file is caught there anyway), but it is a defence D134 put in
	// deliberately and it should not be skippable by whitespace.
	firstEvent := true
	// D315: the exported index counts EVENTS, not raw lines. It was `base + i`,
	// the loop index, so a single blank line renumbered every record in the stream —
	// and `index` is exactly what a consumer correlates and dedupes on.
	evIndex := 0
	for i, line := range lines {
		if line == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			return 0, fmt.Errorf("ledger line %d: %v", i+1, err)
		}
		hash, err := canonical.HashEvent(doc)
		if err != nil {
			return 0, fmt.Errorf("ledger line %d: %v", i+1, err)
		}
		ev, _ := doc["event"].(map[string]any)
		// D315: export must be as strict as REPLAY about time, not only about
		// chain continuity and signatures. ReplayFile parses occurredAt and
		// refuses the file when it will not; export verifies the chain itself and
		// never replays, so without this it accepted a ledger every other verb
		// rejects — and then, under --from/--to, dropped the unplaceable event
		// with a bare `continue`, handing a consumer a short stream with nothing
		// saying an event had been withheld.
		if occ, _ := ev["occurredAt"].(string); occ == "" {
			return 0, fmt.Errorf("ledger line %d: event.occurredAt is missing — "+
				"export refuses what replay refuses", i+1)
		} else if _, perr := ledger.ParseTs(occ); perr != nil {
			return 0, fmt.Errorf("ledger line %d: event.occurredAt %q is not an "+
				"RFC3339 time (%v) — export refuses what replay refuses, rather "+
				"than silently dropping the event from a --from/--to window",
				i+1, occ, perr)
		}
		prev, _ := ev["prev"].(map[string]any)
		caps, _ := ev["capabilities"].([]any)
		for _, ca := range caps {
			c, _ := ca.(string)
			wantHead := heads[c]
			if wantHead == "" {
				wantHead = "genesis"
			}
			if got, _ := prev[c].(string); got != wantHead {
				return 0, fmt.Errorf("ledger line %d: hash chain broken on "+
					"%s: prev is %q but the current head is %q — the tail was "+
					"reordered, truncated or spliced (export is as strict as "+
					"replay)", i+1, c, got, wantHead)
			}
		}
		for _, ca := range caps {
			c, _ := ca.(string)
			heads[c] = hash
		}
		if firstEvent {
			firstEvent = false
			id := hash
			if snapID != "" {
				id = snapID // tail line 1 is not genesis (D137)
			}
			if err := trust.ExpectLedger(id); err != nil {
				return 0, err
			}
		}
		// D102/D133: export is the handover surface — under --trust a
		// fold must refuse an unsigned or foreign line exactly like replay.
		if err := trust.Check(doc, i+1); err != nil {
			return 0, err
		}
		pos := base + evIndex
		evIndex++
		if pos < o.Since {
			continue
		}
		etype, _ := ev["type"].(string)
		if len(want) > 0 && !want[etype] {
			continue
		}
		if haveFrom || haveTo {
			occ, _ := ev["occurredAt"].(string)
			ts, err := ledger.ParseTs(occ)
			if err != nil {
				// unreachable: the per-line gate above already refused. Kept as a
				// refusal rather than a `continue` so that if it ever becomes
				// reachable again it fails loudly instead of silently shortening
				// the stream (D315).
				return 0, fmt.Errorf("ledger line %d: unplaceable occurredAt %q "+
					"reached the window filter", i+1, occ)
			}
			if (haveFrom && int64(ts) < fromTs) || (haveTo && int64(ts) > toTs) {
				continue
			}
		}
		env, _ := ev["environment"].(string)
		var out any
		switch o.Format {
		case "", "ndjson":
			out = Record{Index: pos, ID: hash, Type: etype,
				Environment: env, Event: ev}
		case "cloudevents":
			out = cloudEvent(pos, hash, etype, env, ev)
		default:
			return 0, fmt.Errorf("unknown format %q", o.Format)
		}
		enc, err := json.Marshal(out)
		if err != nil {
			return 0, err
		}
		fmt.Fprintln(&buf, string(enc))
		emitted++
	}
	if err := trust.Finish(); err != nil {
		return 0, err
	}
	if _, err := o.Out.Write(buf.Bytes()); err != nil {
		return 0, err
	}
	return emitted, nil
}

// cloudEvent wraps a ledger event in a CloudEvents 1.0 envelope.
//   - id: the canonical event hash — globally unique AND
//     content-derived, so redelivery dedupes;
//   - source: groundhold://<environment>/ledger — the authority, not the
//     file path (paths differ per machine, sources must not);
//   - type: io.groundhold.<ledger type> in the reverse-DNS convention;
//   - subject: the affected capabilities, comma-joined;
//   - time: occurredAt VERBATIM — decision time, never export time
//     (re-exporting must not re-date history).
func cloudEvent(index int, hash, etype, env string,
	ev map[string]any) map[string]any {
	var subjects []string
	if caps, ok := ev["capabilities"].([]any); ok {
		for _, c := range caps {
			if s, ok := c.(string); ok {
				subjects = append(subjects, s)
			}
		}
	}
	ce := map[string]any{
		"specversion":     "1.0",
		"id":              hash,
		"source":          "groundhold://" + env + "/ledger",
		"type":            "io.groundhold." + etype,
		"datacontenttype": "application/json",
		"groundholdindex": index, // extension attr: the operator's cursor
		"data":            ev,
	}
	if t, ok := ev["occurredAt"].(string); ok {
		ce["time"] = t
	}
	if len(subjects) > 0 {
		ce["subject"] = strings.Join(subjects, ",")
	}
	return ce
}
