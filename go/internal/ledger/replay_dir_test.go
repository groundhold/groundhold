package ledger

import (
	"os"
	"path/filepath"
	"testing"
)

// The quickstart's own example is `--ledger state/prod.jsonl` in a
// fresh directory: naming a path IS the consent to create it — the
// file was always O_CREATE'd, so refusing on its missing parent was an
// inconsistency, and surfacing that as a mid-converge failure after
// plan/forecast had already succeeded was a misleading first-run
// experience (found by a fresh-eyes quickstart walk).
func TestWriterCreatesTheLedgersParentDirectory(t *testing.T) {
	td := t.TempDir()
	path := filepath.Join(td, "state", "prod.jsonl")
	w := &Writer{Path: path, Led: New(), Env: "test",
		Clock: 1752566400, Actor: "t"}
	if err := w.Append("contract.published", []string{"db"},
		map[string]any{"contract": "orders"}, 0); err != nil {
		t.Fatalf("append into a nested, not-yet-existing dir: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("ledger file missing after append: %v", err)
	}
	fi, _ := os.Stat(filepath.Dir(path))
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("ledger dir must be private (0700), got %v", fi.Mode().Perm())
	}
}
