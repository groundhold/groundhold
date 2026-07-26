package restore

import (
	"path/filepath"
	"strings"
	"testing"

	"groundhold/internal/ledger"
)

// D312: a refusal must name the SAME capability every run — the RestoreReport is
// machine-readable output, and two identical restores of the same broken backup
// must not give two different answers (D186's rule, applied to the recovery path).
//
// What actually makes this true is the sorted classify loop: it walks the anchor's
// capabilities in order and the first unsound one refuses. Two later checks (the
// full-mode manifest gate, the restored-head check) walked raw maps; they are
// sorted now too, but honestly — they are shadowed by this loop, so that change is
// hardening, not a bug fixed. This test pins the property where it is real.
func TestRefusalNamesTheSameCapabilityEveryRun(t *testing.T) {
	ledger.ResetSigning()
	dir := t.TempDir()
	// three capabilities in the anchor, ONE capsule supplied — so the manifest
	// gate has TWO offenders and must pick deterministically between them.
	src := buildThreeCapLedger(t)
	anchorPath, capsules := emitAnchorAndCapsules(t, src, filepath.Join(dir, "backup"),
		"a-cap", "b-cap", "c-cap")
	only := capsules[:1] // "a-cap" — b-cap and c-cap are both missing
	var first string
	for i := 0; i < 40; i++ {
		rep, code := Run(Options{
			Out:          filepath.Join(dir, "restored.jsonl"),
			AnchorPath:   anchorPath,
			CapsulePaths: only,
		})
		if code == ExitOK {
			t.Fatalf("an incomplete capsule set must refuse; got %+v", rep)
		}
		if len(rep.Reasons) == 0 {
			t.Fatal("a refusal must carry a reason")
		}
		if i == 0 {
			first = rep.Reasons[0]
			continue
		}
		if !strings.Contains(rep.Reasons[0], `"b-cap"`) {
			t.Fatalf("the refusal must name the lexicographically first unsound "+
				"capability (b-cap); got: %s", rep.Reasons[0])
		}
		if rep.Reasons[0] != first {
			t.Fatalf("two identical runs gave different reasons — map order is "+
				"deciding the report:\n  run 0: %s\n  run %d: %s", first, i, rep.Reasons[0])
		}
	}
}

// buildThreeCapLedger writes a ledger with three capabilities, so a refusal path
// has more than one offender to choose between.
func buildThreeCapLedger(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	led, err := ledger.ReplayFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := &ledger.Writer{Path: path, Led: led, Env: "test", Actor: "t"}
	bind := func(pid string) map[string]any {
		return map[string]any{"resources": []any{map[string]any{
			"id": "primary", "type": "fake.thing", "providerId": pid, "generation": 1}}}
	}
	clock := 1000
	for _, cap := range []string{"a-cap", "b-cap", "c-cap"} {
		w.Clock = clock
		tok, err := w.AppendLease([]string{cap}, map[string]any{"ttlSeconds": 100000})
		if err != nil {
			t.Fatal(err)
		}
		w.Clock = clock + 1
		if err := w.Append("binding.updated", []string{cap}, bind("fake:"+cap), tok); err != nil {
			t.Fatal(err)
		}
		w.Clock = clock + 2
		if err := w.Append("lease.released", []string{cap}, nil, tok); err != nil {
			t.Fatal(err)
		}
		clock += 100
	}
	return path
}
