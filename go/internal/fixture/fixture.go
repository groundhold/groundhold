// Package fixture is the response-fixture replay harness for API-drift
// resilience (D234). A driver parses a provider's response into semantic
// observations; a HAND-WRITTEN httptest fake matches the driver's own
// assumption, so it cannot catch API drift. A fixture instead records the
// provider's response shape INDEPENDENTLY, and replay feeds those bytes to the
// REAL driver parser — so a shape change is caught by a failing test, not a live
// incident.
//
// Two honesty rules make this real, not theatre:
//   - Provenance is mandatory and machine-checked. Only `live` (captured by the
//     canary, carrying a run id) counts as drift EVIDENCE. A
//     `handwritten-pending-canary` fixture may exercise the harness end-to-end
//     (it still catches DRIVER drift against a doc-realistic shape) but must not
//     be mistaken for provider-verified coverage — the label says so, in the file
//     and enforced by TestFixtureProvenance.
//   - The shape signature (a sorted field-path → JSON-kind skeleton, values
//     erased) is committed next to the raw bytes and recomputed on Load, so a
//     re-record that changes the provider's STRUCTURE is a loud, reviewable diff
//     — never a silent rubber-stamp.
package fixture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Provenance is the honesty enum. Only Live is drift EVIDENCE.
const (
	// Live: captured from the real provider by the canary; requires CapturedBy.
	ProvenanceLive = "live"
	// PendingCanary: a doc-realistic body, NOT yet provider-verified. Exercises
	// the harness + catches driver drift, but is not drift-coverage evidence.
	ProvenancePendingCanary = "handwritten-pending-canary"
)

// ExpectedObs is one observation the driver SHOULD extract — the semantic the
// replay asserts (raw bytes alone would only prove "did not crash"; the
// motivating GCS incident was a semantic misread of a well-formed response).
type ExpectedObs struct {
	Path       string `json:"path"`
	Value      any    `json:"value"`
	Derivation string `json:"derivation"`
}

// Fixture is one recorded request/response exchange plus its expected parse.
type Fixture struct {
	Schema    string `json:"schema"`   // "groundhold/fixture/v1"
	Provider  string `json:"provider"` // gcp | aws | azure
	Service   string `json:"service"`  // gcs | rds | ...
	Operation string `json:"operation"`
	Variant   string `json:"variant"` // ok | 404 | perm-denied | ...

	// honesty block
	Provenance string   `json:"provenance"`           // live | handwritten-pending-canary
	CapturedAt string   `json:"capturedAt,omitempty"` // RFC3339; capture-time only, never read at replay
	CapturedBy string   `json:"capturedBy,omitempty"` // "canary-gcp@<run-id>" — REQUIRED for live
	APIVersion string   `json:"apiVersion,omitempty"`
	Note       string   `json:"note,omitempty"`     // for pending fixtures: why it is not yet live
	Scrubbed   []string `json:"scrubbed,omitempty"` // placeholders a live capture applied (audit trail)

	Request struct {
		Method string            `json:"method"`
		Path   string            `json:"path"`
		Query  map[string]string `json:"query,omitempty"`
	} `json:"request"`

	Response struct {
		Status  int               `json:"status"`
		Headers map[string]string `json:"headers,omitempty"`
		Raw     json.RawMessage   `json:"raw"` // VERBATIM provider bytes (scrubbed)
	} `json:"response"`

	// Shape is the structural skeleton of Response.Raw (sorted path -> JSON kind,
	// values erased); ShapeHash is its sha256. Both recomputed on Load — a
	// committed hash that disagrees with the raw bytes is a corrupt/tampered
	// fixture and fails before the driver runs.
	Shape     map[string]string `json:"shape"`
	ShapeHash string            `json:"shapeHash"`

	Expected struct {
		Observations []ExpectedObs `json:"observations,omitempty"`
		ErrContains  string        `json:"errContains,omitempty"` // the parse must refuse with this
	} `json:"expected"`
}

// Load reads and validates a fixture: schema, provenance enum, a mandatory
// Expected block (empty Expected would let replay assert only "didn't crash"),
// and — the corruption guard — the committed ShapeHash must equal the hash
// recomputed from the raw bytes. Returns an error, never a partial fixture.
func Load(path string) (*Fixture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f Fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("fixture %s: %w", path, err)
	}
	if f.Schema != "groundhold/fixture/v1" {
		return nil, fmt.Errorf("fixture %s: unknown schema %q", path, f.Schema)
	}
	if f.Provenance != ProvenanceLive && f.Provenance != ProvenancePendingCanary {
		return nil, fmt.Errorf("fixture %s: provenance must be %q or %q, got %q",
			path, ProvenanceLive, ProvenancePendingCanary, f.Provenance)
	}
	if f.Provenance == ProvenanceLive && f.CapturedBy == "" {
		return nil, fmt.Errorf("fixture %s: provenance:live requires capturedBy "+
			"(a canary run id) — a live claim without a capture source is not evidence", path)
	}
	if len(f.Expected.Observations) == 0 && f.Expected.ErrContains == "" {
		return nil, fmt.Errorf("fixture %s: expected block is mandatory "+
			"(observations or errContains) — replay must assert the semantic, not just no-crash", path)
	}
	// corruption guard: recompute the shape from the raw bytes and compare.
	shape, hash, serr := ShapeOf(f.Response.Raw)
	if serr != nil {
		return nil, fmt.Errorf("fixture %s: response.raw not valid JSON: %w", path, serr)
	}
	if f.ShapeHash != "" && f.ShapeHash != hash {
		return nil, fmt.Errorf("fixture %s: committed shapeHash %s disagrees with "+
			"the raw bytes (%s) — corrupt or tampered fixture", path, f.ShapeHash, hash)
	}
	// backfill the derived fields for consumers that read them
	f.Shape, f.ShapeHash = shape, hash
	return &f, nil
}

// ShapeOf computes the structural signature of a JSON document: a sorted map of
// dotted field-path -> JSON kind (values erased), plus its sha256. Arrays fold
// to their element kind-union (so a new element field moves the signature). This
// is the drift tripwire — a provider adding/renaming/retyping a field changes the
// shape; a mere value change (new etag, timestamp) does not.
func ShapeOf(raw json.RawMessage) (map[string]string, string, error) {
	if len(raw) == 0 {
		return map[string]string{}, hashShape(map[string]string{}), nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, "", err
	}
	shape := map[string]string{}
	walkShape("$", v, shape)
	return shape, hashShape(shape), nil
}

func kindOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "bool"
	case float64:
		return "number"
	case string:
		return "string"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	}
	return "unknown"
}

func walkShape(path string, v any, out map[string]string) {
	switch t := v.(type) {
	case map[string]any:
		if path != "$" {
			out[path] = "object"
		}
		for k, child := range t {
			walkShape(path+"."+k, child, out)
		}
	case []any:
		out[path+"[]"] = "array"
		// fold every element into the SAME element path, so any field appearing
		// in any element is captured (kind-union via the object walk).
		for _, e := range t {
			walkShape(path+"[]", e, out)
		}
	default:
		out[path] = kindOf(v)
	}
}

func hashShape(shape map[string]string) string {
	keys := make([]string, 0, len(shape))
	for k := range shape {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(shape[k])
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ShapeText renders the shape as the sorted human-readable path:kind listing
// (what a capture writes to shape.txt for reviewers). Deterministic.
func ShapeText(shape map[string]string) string {
	keys := make([]string, 0, len(shape))
	for k := range shape {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\n", k, shape[k])
	}
	return b.String()
}
