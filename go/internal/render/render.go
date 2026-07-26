// Package render is the presentation layer (D89, spec/presentation.md):
// the closed banner vocabulary, shape-first verdict glyphs and the color
// discipline. Nothing here is a machine interface — machines route on
// exit codes and JSON `code` fields, never on banners or glyphs.
package render

import (
	"os"
	"strings"
)

type Mode struct {
	Color bool // ANSI escapes allowed
	ASCII bool // pinned fallback glyph set (OK X ? NA)
}

// Detect resolves the mode from the --color flag (auto|never|always),
// the environment and the destination: color only on a TTY, NO_COLOR
// honored, glyphs only under a UTF-8 locale.
func Detect(colorFlag string, ascii bool, out *os.File) Mode {
	m := Mode{ASCII: ascii || !utf8Locale()}
	switch colorFlag {
	case "always":
		m.Color = true
	case "never":
		m.Color = false
	default:
		m.Color = isTTY(out) && os.Getenv("NO_COLOR") == "" &&
			os.Getenv("TERM") != "dumb"
	}
	return m
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func utf8Locale() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(k); v != "" {
			u := strings.ToUpper(v)
			return strings.Contains(u, "UTF-8") || strings.Contains(u, "UTF8")
		}
	}
	return false
}

// Color is an SGR parameter string. The palette is closed
// (spec/presentation.md): nothing else, no shades.
type Color string

const (
	Green      Color = "32"
	Red        Color = "31"
	Yellow     Color = "33"
	Blue       Color = "34"
	Magenta    Color = "35"
	RedInverse Color = "31;7"
)

func (m Mode) Paint(c Color, s string) string {
	if !m.Color {
		return s
	}
	return "\033[" + string(c) + "m" + s + "\033[0m"
}

// Dim carries provenance: color says WHAT we know, brightness says HOW
// FIRMLY. The [inferred]/[assumed] marker stays as the NO_COLOR carrier.
func (m Mode) Dim(s string) string {
	if !m.Color {
		return s
	}
	return "\033[2m" + s + "\033[0m"
}

// Glyph is shape-first: meaning must survive with color stripped.
// The ASCII fallback set is pinned by the spec — NA, never "-".
func (m Mode) Glyph(verdict string) string {
	if m.ASCII {
		switch verdict {
		case "satisfied":
			return "OK"
		case "violated":
			return "X"
		case "unknown":
			return "?"
		case "unverifiable":
			return "NA"
		}
		return "?"
	}
	switch verdict {
	case "satisfied":
		return "✓"
	case "violated":
		return "✗"
	case "unknown":
		return "?"
	case "unverifiable":
		return "∅"
	}
	return "?"
}

// PhaseGlyph is the shape-first mark for a converge phase's state (D232).
// The closed set is pending/active/done/refused/failed/skipped. `refused` is
// deliberately DISTINCT from `failed` (⊘ vs ✗): refusal-is-not-failure (D89) —
// a sub-verb that refuses did its job. Meaning survives color-stripping.
func (m Mode) PhaseGlyph(state string) string {
	if m.ASCII {
		switch state {
		case "pending":
			return "."
		case "active":
			return "~"
		case "done":
			return "OK"
		case "refused":
			return "REF"
		case "failed":
			return "X"
		case "skipped":
			return "SKIP"
		}
		return "?"
	}
	switch state {
	case "pending":
		return "·"
	case "active":
		return "~"
	case "done":
		return "✓"
	case "refused":
		return "⊘"
	case "failed":
		return "✗"
	case "skipped":
		return "»"
	}
	return "?"
}

// PhaseColor maps a phase state to its color (shape still carries meaning
// without it). refused is blue (a benign refusal, like the converge banner),
// failed is red, done green, active/pending neutral.
func PhaseColor(state string) Color {
	switch state {
	case "done":
		return Green
	case "failed":
		return Red
	case "refused":
		return Blue
	case "active":
		return Yellow
	}
	return ""
}

func VerdictColor(verdict string) Color {
	switch verdict {
	case "satisfied":
		return Green
	case "violated":
		return Red
	case "unknown":
		return Yellow
	}
	return Magenta
}

// Rollup carries the hard-constraint verdict ids that refine the exit
// code into a banner: exit 2 alone cannot tell VIOLATED from BLOCKED.
type Rollup struct {
	Violated     []string
	Unknown      []string
	Unverifiable []string
}

// Pick selects the banner word by (exit, code, rollup) precedence
// (spec/presentation.md): corruption > death > staleness > invalid >
// proven falsehood > missing knowledge > refusal > success. A proven
// falsehood outranks missing knowledge; a refusal is never a failure.
func Pick(verb string, exit int, code string, r Rollup) (string, Color) {
	switch exit {
	case 5:
		return "CORRUPTED", RedInverse
	case 4:
		return "DIED", Red
	case 3:
		return "STALE", Yellow
	case 1:
		return "INVALID", Red
	}
	if len(r.Violated) > 0 {
		return "VIOLATED", Red
	}
	if len(r.Unknown)+len(r.Unverifiable) > 0 {
		return "BLOCKED", Yellow
	}
	if exit == 2 {
		if code != "" {
			return "REFUSED " + code, Blue
		}
		return "REFUSED", Blue
	}
	// green ONLY on exit 0 (D194): a green word is a success claim, and an
	// unenumerated nonzero code (a signal, a future exit) is NOT success —
	// fail-closed to a non-green failure banner rather than let the default
	// arm render an unknown outcome as PROVEN/APPLIED.
	if exit != 0 {
		return "FAILED", Red
	}
	return greenWord(verb), Green
}

// greenWord: a green banner only where success is a crisp human-facing
// claim (D90). PROVEN and CONVERGED are epistemic, APPLIED and SEALED
// executional (the plan artifact is literally a hash-pinned Sealed
// Plan), OK procedural. Product verbs suppress green entirely — that
// decision lives with the caller, not here.
func greenWord(verb string) string {
	switch verb {
	case "verify", "audit":
		return "PROVEN"
	case "converge":
		return "CONVERGED"
	case "apply":
		return "APPLIED"
	case "plan":
		return "SEALED"
	}
	return "OK"
}

// Friction renders the teaching line for a vocabulary path — joined
// only at the moment of friction, never on the happy path. Empty when
// the vocabulary has nothing to say.
func Friction(path string, attrs map[string]any) string {
	if attrs == nil {
		return ""
	}
	desc, _ := attrs["description"].(string)
	note, _ := attrs["verification"].(string)
	switch {
	case desc == "" && note == "":
		return ""
	case desc == "":
		return path + " — " + note
	case note == "":
		return path + " — " + desc
	}
	return path + " — " + strings.ToLower(desc[:1]) + desc[1:] + "; " + note
}
