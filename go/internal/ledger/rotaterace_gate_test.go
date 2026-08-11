package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// D655. `commitUnderLock` is the linearizable persisted-append, and its own
// comment says a concurrent append cannot interleave a lost write. It opens the
// path, THEN takes the flock. `Rotate` renames the file out from under it while
// holding the lock on the same inode. A writer that opened before the rename wakes
// up holding a lock on the ARCHIVED inode, replays the new path, and appends to the
// old one.
//
// Measured by an adversarial audit against the real binary, 12 of 15 trials:
//
//	snapshot exit=0   observe exit=0 (stderr empty)
//	snapshot.baseEvents=421   archive lines on disk=422   tail=1
//
// The 422nd line exists nowhere in the fold, and the ledger is then permanently
// un-exportable: `attest` reports archive "mismatched", `repair` exits 5, `export`
// and `backup` refuse. The writer reported success.
//
// This test recreates the window deterministically: hold the lock, let a writer
// block on it, rename the file away, release. The writer must not append into the
// file that is no longer the ledger.
func TestAnAppendNeverLandsInARenamedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l.jsonl")
	led := New()
	w0 := &Writer{Path: path, Led: led, Env: "test", Clock: 1767225600, Actor: "t"}
	if err := w0.Append("contract.published", []string{"db"},
		map[string]any{"contractHash": "sha256:a", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}

	// Hold the lock the way Rotate does.
	lf, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lf.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	// A writer arrives, opens the path (getting the CURRENT inode) and blocks.
	done := make(chan error, 1)
	go func() {
		led2, rerr := ReplayFile(path)
		if rerr != nil {
			done <- rerr
			return
		}
		w := &Writer{Path: path, Led: led2, Env: "test", Clock: 1767225660, Actor: "t"}
		done <- w.Append("contract.published", []string{"db"},
			map[string]any{"contractHash": "sha256:b", "version": 2}, 0)
	}()
	time.Sleep(150 * time.Millisecond) // let it reach the flock and block

	// Rotate's rename, then a fresh file at the path.
	archived := path + ".archive.1"
	if err := os.Rename(path, archived); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	syscall.Flock(int(lf.Fd()), syscall.LOCK_UN)
	lf.Close()

	err = <-done

	archivedAfter, rerr := os.ReadFile(archived)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if n := countLines(archivedAfter); n != 1 {
		t.Errorf("the append landed in the ARCHIVED file (%d lines, was 1). It is "+
			"in no fold: the snapshot pinned the archive's hash before the write, "+
			"so the ledger is now permanently un-exportable and the writer said "+
			"nothing", n)
	}
	live, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	if err == nil && countLines(live) == 0 {
		t.Error("the writer reported success and wrote nowhere at all — a lost " +
			"write is worse than a refusal")
	}
	if err != nil {
		// Refusing is a correct outcome: the caller retries against the new file.
		t.Logf("writer refused (acceptable): %v", err)
	}
}

func countLines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}

// D655 (control): the identity check must not turn an ordinary append into a
// refusal, and compaction of a path that does not exist stays an operator error
// rather than quietly creating an empty ledger (the D617 distinction).
func TestOrdinaryAppendsAndCompactionAreUnaffected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l.jsonl")
	led := New()
	for i := 0; i < 5; i++ {
		w := &Writer{Path: path, Led: led, Env: "test",
			Clock: 1767225600 + i*60, Actor: "t"}
		if err := w.Append("contract.published", []string{"db"},
			map[string]any{"contractHash": "sha256:a", "version": i + 1}, 0); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if _, _, err := Rotate(path); err != nil {
		t.Fatalf("compaction of a real ledger must still work: %v", err)
	}
	if _, _, err := Rotate(filepath.Join(dir, "not-there.jsonl")); err == nil {
		t.Error("compacting a path that does not exist reported success — a typo " +
			"must not create an empty ledger and call it compacted")
	}
}

// D675. `os.Rename` acts on the LINK. Compacting through a symlink moved the link
// into the archive, left a fresh regular file at the operator's path, and the next
// write through the REAL path made the ledger permanently un-exportable — measured
// with no concurrency at all:
//
//	ln -s real/o.jsonl link.jsonl
//	snapshot --ledger link.jsonl        exit 0
//	  link.jsonl.archive.423 is now a SYMLINK to real/o.jsonl
//	observe --ledger real/o.jsonl …     exit 0
//	attest --ledger link.jsonl          archive "mismatched"
//	repair --ledger link.jsonl          exit 5
func TestCompactingThroughASymlinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.jsonl")
	if err := os.WriteFile(real, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	led := New()
	w := &Writer{Path: real, Led: led, Env: "test", Clock: 1767225600, Actor: "t"}
	if err := w.Append("contract.published", []string{"db"},
		map[string]any{"contractHash": "sha256:a", "version": 1}, 0); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}

	_, _, err := Rotate(link)
	if err == nil {
		t.Fatal("compacted through a symlink — the link is now the archive and the " +
			"ledger cannot be exported again")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if fi, lerr := os.Lstat(link); lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the refusal still disturbed the link: %v", lerr)
	}
	// The control: the real path still compacts.
	if _, _, err := Rotate(real); err != nil {
		t.Errorf("the target path must still compact: %v", err)
	}
}

// D675. A writer blocked on the lock said nothing. Measured with a held flock: a
// 12-second `observe` produced exit 124 (the caller's timeout) with an EMPTY stdout
// and stderr — an operator cannot tell a held lock from a hang, and the detach
// launcher reported "run did not start within 5s" (exit 1) for a process that was
// alive, blocked, and later woke up and mutated infrastructure.
func TestABlockedWriterSaysSo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	holder, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}

	// Capture what a blocked writer says while it waits.
	r, wpipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = wpipe
	done := make(chan error, 1)
	go func() {
		led := New()
		w := &Writer{Path: path, Led: led, Env: "test", Clock: 1767225600, Actor: "t"}
		done <- w.Append("contract.published", []string{"db"},
			map[string]any{"contractHash": "sha256:a", "version": 1}, 0)
	}()
	time.Sleep(200 * time.Millisecond)
	syscall.Flock(int(holder.Fd()), syscall.LOCK_UN)
	holder.Close()
	if err := <-done; err != nil {
		t.Fatalf("the writer failed once the lock was free: %v", err)
	}
	os.Stderr = saved
	wpipe.Close()
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	said := string(buf[:n])

	if !strings.Contains(said, "waiting for the ledger lock") {
		t.Errorf("a writer that blocked on the lock said %q — silence is "+
			"indistinguishable from a hang, and this is the state a --detach run "+
			"was in when the launcher reported it had not started", said)
	}
}
