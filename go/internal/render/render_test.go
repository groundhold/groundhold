package render

import (
	"os"
	"testing"
)

// The banner precedence is normative (spec/presentation.md): first
// match wins, a proven falsehood outranks missing knowledge, and the
// green word is per-verb.
func TestPickPrecedence(t *testing.T) {
	viol := Rollup{Violated: []string{"c-a"}}
	unk := Rollup{Unknown: []string{"c-b"}}
	both := Rollup{Violated: []string{"c-a"}, Unknown: []string{"c-b"}}
	cases := []struct {
		name  string
		verb  string
		exit  int
		code  string
		r     Rollup
		word  string
		color Color
	}{
		{"corrupted-wins-over-everything", "verify", 5, "ledger-corrupted", both, "CORRUPTED", RedInverse},
		{"died", "apply", 4, "apply-failed", Rollup{}, "DIED", Red},
		{"stale", "apply", 3, "stale-decision", Rollup{}, "STALE", Yellow},
		{"invalid-not-violated", "verify", 1, "structural-error", Rollup{}, "INVALID", Red},
		{"violated-outranks-unknown", "verify", 2, "not-executable", both, "VIOLATED", Red},
		{"unknown-blocks", "verify", 2, "not-executable", unk, "BLOCKED", Yellow},
		{"violated", "verify", 2, "not-executable", viol, "VIOLATED", Red},
		{"unverifiable-blocks", "verify", 2, "not-executable",
			Rollup{Unverifiable: []string{"c-c"}}, "BLOCKED", Yellow},
		{"refusal-carries-its-code", "apply", 2, "consent-required", Rollup{}, "REFUSED consent-required", Blue},
		{"refusal-without-code", "apply", 2, "", Rollup{}, "REFUSED", Blue},
		{"verify-green-is-proven", "verify", 0, "", Rollup{}, "PROVEN", Green},
		{"audit-green-is-proven", "audit", 0, "", Rollup{}, "PROVEN", Green},
		{"converge-green-is-converged", "converge", 0, "", Rollup{}, "CONVERGED", Green},
		{"apply-green-is-applied", "apply", 0, "", Rollup{}, "APPLIED", Green},
		{"plan-green-is-sealed", "plan", 0, "", Rollup{}, "SEALED", Green},
		{"procedural-green-is-ok", "publish", 0, "", Rollup{}, "OK", Green},
	}
	for _, c := range cases {
		word, color := Pick(c.verb, c.exit, c.code, c.r)
		if word != c.word || color != c.color {
			t.Errorf("%s: got (%q, %q), want (%q, %q)",
				c.name, word, color, c.word, c.color)
		}
	}
}

// Glyphs are pinned including the ASCII fallbacks; NA never "-".
func TestGlyphSets(t *testing.T) {
	uni := Mode{ASCII: false}
	asc := Mode{ASCII: true}
	for verdict, want := range map[string][2]string{
		"satisfied":    {"✓", "OK"},
		"violated":     {"✗", "X"},
		"unknown":      {"?", "?"},
		"unverifiable": {"∅", "NA"},
	} {
		if g := uni.Glyph(verdict); g != want[0] {
			t.Errorf("unicode %s: got %q want %q", verdict, g, want[0])
		}
		if g := asc.Glyph(verdict); g != want[1] {
			t.Errorf("ascii %s: got %q want %q", verdict, g, want[1])
		}
	}
}

func TestPhaseGlyphSets(t *testing.T) {
	uni := Mode{ASCII: false}
	asc := Mode{ASCII: true}
	for state, want := range map[string][2]string{
		"pending": {"·", "."},
		"active":  {"~", "~"},
		"done":    {"✓", "OK"},
		"refused": {"⊘", "REF"},
		"failed":  {"✗", "X"},
		"skipped": {"»", "SKIP"},
	} {
		if g := uni.PhaseGlyph(state); g != want[0] {
			t.Errorf("unicode phase %s: got %q want %q", state, g, want[0])
		}
		if g := asc.PhaseGlyph(state); g != want[1] {
			t.Errorf("ascii phase %s: got %q want %q", state, g, want[1])
		}
	}
	// refusal-is-not-failure (D89): the two must never share a glyph.
	if uni.PhaseGlyph("refused") == uni.PhaseGlyph("failed") ||
		asc.PhaseGlyph("refused") == asc.PhaseGlyph("failed") {
		t.Fatal("refused and failed must be visually distinct")
	}
}

func TestVerdictColors(t *testing.T) {
	for verdict, want := range map[string]Color{
		"satisfied": Green, "violated": Red,
		"unknown": Yellow, "unverifiable": Magenta,
	} {
		if c := VerdictColor(verdict); c != want {
			t.Errorf("%s: got %q want %q", verdict, c, want)
		}
	}
}

// Meaning must survive monochrome: painting under Color=false is the
// identity, and painted text still contains the naked word.
func TestPaintDiscipline(t *testing.T) {
	off := Mode{Color: false}
	if s := off.Paint(Red, "VIOLATED"); s != "VIOLATED" {
		t.Errorf("no-color paint must be identity, got %q", s)
	}
	if s := off.Dim("x"); s != "x" {
		t.Errorf("no-color dim must be identity, got %q", s)
	}
	on := Mode{Color: true}
	if s := on.Paint(Blue, "REFUSED"); s != "\033[34mREFUSED\033[0m" {
		t.Errorf("painted: got %q", s)
	}
	if s := on.Paint(RedInverse, "CORRUPTED"); s != "\033[31;7mCORRUPTED\033[0m" {
		t.Errorf("inverse: got %q", s)
	}
}

func TestDetectHonorsNoColorAndFlag(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer tmp.Close()
	t.Setenv("NO_COLOR", "")
	t.Setenv("LANG", "C.UTF-8")

	if m := Detect("auto", false, tmp); m.Color {
		t.Error("auto on a non-TTY must not color")
	}
	if m := Detect("always", false, tmp); !m.Color {
		t.Error("always must color even off-TTY")
	}
	t.Setenv("NO_COLOR", "1")
	if m := Detect("always", false, tmp); !m.Color {
		t.Error("explicit always outranks NO_COLOR")
	}
	if m := Detect("never", false, tmp); m.Color {
		t.Error("never must not color")
	}
	if m := Detect("auto", false, tmp); m.ASCII {
		t.Error("UTF-8 locale must keep glyphs")
	}
	t.Setenv("LANG", "C")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")
	if m := Detect("auto", false, tmp); !m.ASCII {
		t.Error("non-UTF-8 locale must fall back to ASCII")
	}
	t.Setenv("LANG", "C.UTF-8")
	if m := Detect("auto", true, tmp); !m.ASCII {
		t.Error("--ascii must force the fallback set")
	}
}

// The teaching line joins description and verification note; silence
// when the vocabulary has nothing to say.
func TestFriction(t *testing.T) {
	got := Friction("recovery.rto", map[string]any{
		"kind":         "duration",
		"description":  "Time to restore service after failure",
		"verification": "probe-only — a value here is a claim until a restore test measures it",
	})
	want := "recovery.rto — time to restore service after failure; " +
		"probe-only — a value here is a claim until a restore test measures it"
	if got != want {
		t.Errorf("got %q\nwant %q", got, want)
	}
	if Friction("x.y", nil) != "" || Friction("x.y", map[string]any{"kind": "bool"}) != "" {
		t.Error("no material -> no line")
	}
}

// TestPickNeverGreensNonzeroExit pins D194: a green word is a success claim, so
// an unenumerated nonzero exit (a signal, a future code) must NOT render green —
// fail-closed to a non-green failure banner. Before the fix the default arm
// returned greenWord for any exit outside {1..5}.
func TestPickNeverGreensNonzeroExit(t *testing.T) {
	for _, exit := range []int{6, 42, 255, -1} {
		word, color := Pick("apply", exit, "", Rollup{})
		if color == Green {
			t.Fatalf("exit %d must not render green, got %q", exit, word)
		}
	}
	// exit 0 still greens
	if word, color := Pick("apply", 0, "", Rollup{}); color != Green || word != "APPLIED" {
		t.Fatalf("exit 0 apply must be green APPLIED, got %q", word)
	}
}
