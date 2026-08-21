// JSONL replay (D42): state = fold(events), reconstructed through the
// same rules every writer obeyed. A torn final line is corruption,
// never auto-truncated.
package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"groundhold/internal/canonical"
	"groundhold/internal/state"
)

func ParseTs(s string) (int, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, err
	}
	return int(t.Unix()), nil
}

// MaxLedgerBytes bounds a whole-file ledger read. The file backend
// reads and folds the entire ledger on every verb (D42); a generous
// ceiling — far above the documented comfortable range of tens of
// thousands of events (~10s of MiB) — turns a pathological or malicious
// file into a clear refusal instead of an OOM. A deployment that
// legitimately outgrows this is the signal to activate snapshots (D137)
// or a real backend, not to lift the cap.
const MaxLedgerBytes = 512 << 20 // 512 MiB

func readLedger(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > MaxLedgerBytes {
		return nil, fmt.Errorf("ledger is %d bytes, over the %d-byte "+
			"file-backend ceiling — activate snapshots (D137) or a real "+
			"backend; refusing to load it into memory", fi.Size(),
			int64(MaxLedgerBytes))
	}
	return os.ReadFile(path)
}

// SnapshotPath is the sidecar the replay seeds from when present (D137).
func SnapshotPath(ledgerPath string) string { return ledgerPath + ".snapshot" }

// ReplayExisting is ReplayFile for a reader that is ASKING ABOUT a ledger rather than
// preparing to write one (D617).
//
// ReplayFile treats a missing file as an empty ledger — a bootstrap affordance for
// writers, since the first append creates it. Six read-only verbs inherited it and
// answered questions about a file that was not there:
//
//	attest  --ledger gone.jsonl   exit 0, a clean IntegrityReport
//	repair  --ledger gone.jsonl   exit 0, {"status":"healthy"}      ← the diagnose verb
//	anchor  --ledger gone.jsonl   exit 0, emits an events:0 anchor  ← which D613 shows
//	                                                                  rubber-stamps
//	deposed/posture/refresh       exit 0
//
// while `export` and `snapshot` exit 1 and `backup` exits 5 on the identical input.
// A typo in a path is the ordinary case here, and "healthy" is the worst possible
// answer to it.
func ReplayExisting(path string) (*Ledger, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w at %s — a question about a ledger that is not "+
				"there has no answer, and an empty one is not the same as a healthy one",
				ErrNoLedger, path)
		}
		return nil, err
	}
	return ReplayFile(path)
}

// ErrNoLedger separates "the path is wrong" from "the bytes do not replay" (D617).
// They are different operator problems and they had four different exit codes between
// them; a caller that branches on the status must be able to tell them apart.
var ErrNoLedger = errors.New("no ledger")

func ReplayFile(path string) (*Ledger, error) {
	led := New()
	led.Lenient = true // existing history is tolerated, never re-judged
	// D137: a snapshot beside the ledger seeds the fold; the live file
	// carries only the tail. Positions stay absolute.
	if snap, err := LoadSnapshotFile(SnapshotPath(path)); err != nil {
		return nil, err
	} else if snap != nil {
		if err := VerifySnapshotTrust(snap); err != nil {
			return nil, err
		}
		led, err = SeedLedger(snap)
		if err != nil {
			return nil, err
		}
		// D710: the ledger side of the same pin. An empty hash here makes
		// CheckAnchor report DIVERGED against any anchor that has one — fail-closed,
		// but with a reason that blames a swap when the truth is that the fold could
		// not be hashed. Say which it is.
		var snapDoc map[string]any
		rawSnap, merr := json.Marshal(snap)
		if merr != nil {
			return nil, fmt.Errorf("cannot re-encode the snapshot to hash it: %v", merr)
		}
		if err := json.Unmarshal(rawSnap, &snapDoc); err != nil {
			return nil, fmt.Errorf("cannot re-read the snapshot to hash it: %v", err)
		}
		normalize(snapDoc)
		h, herr := HashSnapshot(snapDoc)
		if herr != nil {
			return nil, fmt.Errorf("cannot hash the snapshot this ledger seeds from "+
				"(%v) — an anchor comparison would report a swapped fold when the "+
				"truth is that the fold is unhashable", herr)
		}
		led.snapshotHash = h
		led.Lenient = true
	}
	raw, err := readLedger(path)
	if os.IsNotExist(err) {
		return led, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 && raw[len(raw)-1] != '\n' {
		return nil, fmt.Errorf("ledger has a torn final line — repair required")
	}
	trust := NewTrustChecker()
	if led.BaseEvents > 0 && led.LedgerId() != "" {
		// the tail's line 1 is not genesis — the snapshot carries the
		// identity every tail signature must keep claiming (D134)
		if err := trust.ExpectLedger(led.LedgerId()); err != nil {
			return nil, err
		}
	}
	// D137: a --trust-from boundary compacted into the archive is
	// honored via the snapshot's verifiedUnder receipt — and ONLY when
	// the receipt names exactly the armed boundary; anything else
	// leaves the obligation live (found in the tail, or refused).
	if led.BaseEvents > 0 && trustFrom != "" && led.verifiedFrom == trustFrom {
		trust.SeedBoundaryHonored()
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	for i, line := range lines {
		if line == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(line), &doc); err != nil {
			return nil, fmt.Errorf("ledger line %d: %v", i+1, err)
		}
		normalize(doc)
		ev, _ := doc["event"].(map[string]any)
		occurred, _ := ev["occurredAt"].(string)
		clock, err := ParseTs(occurred)
		if err != nil {
			return nil, fmt.Errorf("ledger line %d: %v", i+1, err)
		}
		if clock > led.Clock {
			led.Clock = clock // monotonic: a backdated legacy event
		} //                     must not rewind lease arithmetic (D56)
		// verify the hash chain (C2): every event pins the head it
		// extends per capability; a tampered, reordered or truncated
		// line breaks the chain and is corruption, not a silent
		// projection change.
		if err := verifyPrev(led, ev, i+1); err != nil {
			if led.BaseEvents > 0 && i == 0 {
				return nil, fmt.Errorf("%v — a snapshot is active but the "+
					"file does not continue it; if a rotation was "+
					"interrupted, the pre-rotation file is complete in "+
					"the archive (D137)", err)
			}
			return nil, err
		}
		// D102/D133: under --trust every line (past any --trust-from
		// boundary) must verify by a key in the trust set — an unsigned
		// or foreign line is tamper evidence, the same refusal channel
		// as a broken chain.
		if err := trust.Check(doc, i+1); err != nil {
			return nil, err
		}
		res, err := led.Append(doc, nil)
		if err != nil {
			// D1154: a type this build does not know is almost certainly a
			// type a NEWER build wrote — the registry is additive-only. Fold
			// no further (an event we cannot interpret must not be skipped
			// past: silently omitting it would move every projection that
			// depends on it), but do not call the file corrupt either.
			// Sweep the rest for chain integrity so the refusal can say
			// which of the two conditions actually holds.
			var unknown *state.UnknownTypeError
			if errors.As(err, &unknown) {
				return nil, newVersionAhead(lines, i, doc, led.Heads, unknown.Type)
			}
			return nil, fmt.Errorf("ledger line %d: %v", i+1, err)
		}
		if res.Status != "ok" {
			return nil, fmt.Errorf(
				"ledger line %d: replay %s (%s)", i+1, res.Status, res.Reason)
		}
		// D134: the stream's identity is its genesis hash — known the
		// moment line 1 folds; every signature's claim must match it.
		// Under a snapshot (D137) the identity was seeded already.
		if led.BaseEvents == 0 && len(led.EventHashes) == 1 {
			led.ledgerId = led.EventHashes[0]
			if err := trust.ExpectLedger(led.EventHashes[0]); err != nil {
				return nil, err
			}
		}
	}
	if err := trust.Finish(); err != nil {
		return nil, err
	}
	led.Lenient = false // the fold is done; new appends are strict (D56)
	led.canonEmpty()    // one canonical in-memory form (D137 fuzz find)
	return led, nil
}

// VersionAheadError says the ledger carries an event type this build does not
// know — additive-only registry, so: written by a newer build (D1154).
//
// It exists to keep that condition out of the corruption channel. Replay used to
// return it as an ordinary error, all eleven call sites answered any replay error
// with exit 5, and exit 5's banner is CORRUPTED. A tester who upgraded, wrote one
// event of a new type and then went back to the previous binary was told their
// ledger was corrupt. It was not: the chain verified end to end. The danger is not
// the refusal — refusing is correct — it is the WORD, because the honest response to
// "your ledger is corrupted" is to restore it from a backup or delete it, and the
// ledger is the one file here whose loss cannot be recovered from anywhere else.
//
// ChainIntact is why the sweep below exists. "Refuse and say which build wrote it"
// would already beat CORRUPTED, but it still leaves the reader wondering whether the
// file is also damaged — and a reader who wonders that reaches for the backup. So the
// question is answered rather than left open, and answered honestly in both
// directions: the two conditions are independent and a file can have both.
type VersionAheadError struct {
	Line        int    // 1-based line carrying the unreadable event
	Type        string // the event type this build does not know
	Lines       int    // total non-empty lines in the file
	ChainIntact bool   // did the hash chain verify over ALL of them
	ChainErr    error  // when it did not: where it broke
}

func (e *VersionAheadError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "ledger line %d: event type %q is not known to this build — "+
		"the event-type registry is additive-only, so this ledger was almost "+
		"certainly written by a NEWER groundhold than the one you are running",
		e.Line, e.Type)
	if e.ChainIntact {
		ev := "events"
		if e.Lines == 1 {
			ev = "event"
		}
		fmt.Fprintf(&b, ".\nThe ledger is NOT damaged: the hash chain verifies over "+
			"all %d %s. Do not repair, quarantine or restore it — there is "+
			"nothing wrong with the file. Run the newer build against it, or "+
			"upgrade this one", e.Lines, ev)
	} else {
		fmt.Fprintf(&b, ".\nThe hash chain ALSO does not verify (%v), so upgrading "+
			"alone will not be enough — treat that separately", e.ChainErr)
	}
	return b.String()
}

// newVersionAhead builds the refusal, sweeping the REST of the file for chain
// integrity (projection-free: this answers "is the file damaged", nothing else).
//
// It starts from the offending line, whose own prev was already verified against
// the heads passed in, so that event's hash advances the sweep exactly as a fold
// would have. A line that cannot be hashed or parsed at all counts as a broken
// chain — an unanswerable question is not a clean bill of health.
func newVersionAhead(lines []string, idx int, doc map[string]any,
	heads map[string]string, etype string) *VersionAheadError {

	e := &VersionAheadError{Line: idx + 1, Type: etype, ChainIntact: true}
	local := make(map[string]string, len(heads))
	for k, v := range heads {
		local[k] = v
	}
	advance := func(d map[string]any) error {
		h, err := canonical.HashEvent(d)
		if err != nil {
			return err
		}
		ev, _ := d["event"].(map[string]any)
		capsAny, _ := ev["capabilities"].([]any)
		for _, ca := range capsAny {
			if c, _ := ca.(string); c != "" {
				local[c] = h
			}
		}
		return nil
	}
	for i := idx; i < len(lines); i++ {
		if lines[i] == "" {
			continue
		}
		e.Lines++
		d := doc
		if i != idx {
			d = map[string]any{}
			if err := json.Unmarshal([]byte(lines[i]), &d); err != nil {
				e.ChainIntact, e.ChainErr = false, fmt.Errorf("ledger line %d: %v", i+1, err)
				return e
			}
			normalize(d)
			ev, _ := d["event"].(map[string]any)
			if err := verifyPrevHeads(local, ev, i+1); err != nil {
				e.ChainIntact, e.ChainErr = false, err
				return e
			}
		}
		if err := advance(d); err != nil {
			e.ChainIntact, e.ChainErr = false, fmt.Errorf("ledger line %d: %v", i+1, err)
			return e
		}
	}
	for i := 0; i < idx; i++ { // the lines already folded, whose chain replay verified
		if lines[i] != "" {
			e.Lines++
		}
	}
	return e
}

// verifyPrev checks that an event's prev map pins the current head of
// each capability it lists (C2). Genesis is the empty-head sentinel.
func verifyPrev(led *Ledger, ev map[string]any, line int) error {
	return verifyPrevHeads(led.Heads, ev, line)
}

// verifyPrevHeads is the chain check itself, over a bare head map so the
// integrity sweep (D1154) can run it without a folded Ledger. One
// implementation, two callers: a second copy would be free to agree with
// this one by luck and diverge on the case that matters.
func verifyPrevHeads(heads map[string]string, ev map[string]any, line int) error {
	prev, ok := ev["prev"].(map[string]any)
	if !ok {
		return fmt.Errorf(
			"ledger line %d: event has no prev — the hash chain is "+
				"unverifiable; every event must pin the head it extends", line)
	}
	capsAny, _ := ev["capabilities"].([]any)
	for _, ca := range capsAny {
		c, _ := ca.(string)
		want := heads[c]
		if want == "" {
			want = "genesis"
		}
		got, _ := prev[c].(string)
		if got != want {
			return fmt.Errorf(
				"ledger line %d: hash chain broken on %s: prev is %q but "+
					"the current head is %q (tampered or reordered)",
				line, c, got, want)
		}
	}
	return nil
}

// PersistLine appends one canonical JSON event line to a JSONL ledger
// file: flock + O_APPEND + fsync per line, the lock never held during
// provider calls (D42).
func PersistLine(path string, doc map[string]any) error {
	line, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// normalize converts json-decoded numbers back to the int shapes the
// rules expect (json.Unmarshal gives float64).
func normalize(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if f, ok := val.(float64); ok && f == float64(int(f)) {
				x[k] = int(f)
			} else {
				normalize(val)
			}
		}
	case []any:
		for _, it := range x {
			normalize(it)
		}
	}
}

// FormatTs is ParseTs's inverse — the ledger's canonical event
// timestamp format.
func FormatTs(clock int) string {
	return time.Unix(int64(clock), 0).UTC().Format("2006-01-02T15:04:05Z")
}

// Writer appends events to the in-memory ledger AND persists each line
// — write-ahead, shared by apply (D42) and adopt (D52). Actor names the
// runtime component; Events (when set) accumulates appended type names
// for result reporting.
type Writer struct {
	Path  string
	Led   *Ledger
	Env   string
	Clock int
	Actor string
	// ActorType is human|agent|runtime (default runtime). publish (D74)
	// records authorship, so it sets human — the ledger can then answer
	// "who published this contract", not only "the runtime executed it".
	ActorType string
	Events    *[]string
}

func (w *Writer) BuildDoc(etype string, caps []string,
	body map[string]any, token int) map[string]any {
	capsAny := make([]any, len(caps))
	prev := map[string]any{}
	for i, c := range caps {
		capsAny[i] = c
		h, ok := w.Led.Heads[c]
		if !ok {
			h = "genesis"
		}
		prev[c] = h
	}
	actorType := w.ActorType
	if actorType == "" {
		actorType = "runtime"
	}
	ev := map[string]any{
		"type": etype, "environment": w.Env, "capabilities": capsAny,
		"occurredAt": FormatTs(w.Clock),
		"actor":      map[string]any{"id": w.Actor, "type": actorType},
		"prev":       prev,
	}
	if body != nil {
		ev["body"] = body
	}
	if token > 0 {
		ev["fencingToken"] = token
	}
	return map[string]any{
		"apiVersion": "state/v0", "kind": "LedgerEvent", "event": ev}
}

// lockLedger opens the ledger and takes the exclusive lock, then CHECKS that the
// descriptor it holds is still the file at that path.
//
// D655: the open and the lock are two steps, and `Rotate` renames the ledger to its
// archive while holding the lock on the same inode. A writer that opened before the
// rename woke up holding a lock on the ARCHIVED file, replayed the new path, and
// appended to the old one — reporting success. The line then exists in no fold, and
// because the snapshot pinned the archive's hash BEFORE that write, the ledger is
// permanently un-exportable: attest says the archive is mismatched, repair exits 5,
// export and backup refuse. Measured 12 times in 15 trials against the real binary,
// with `observe` and `converge` both printing success.
//
// The check is dev+inode, which is what "the same file" means to the kernel. A
// rotation that beat us is not an error, it is a race we lost — so retry against
// the new file, bounded, and refuse loudly rather than write into a ghost.
func lockLedger(path string) (*os.File, error) {
	for attempt := 0; attempt < 8; attempt++ {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		// D675: a blocked writer used to wait forever in silence — measured, a
		// 12-second `observe` against a held lock produced exit 124 with an EMPTY
		// stdout and stderr. Try without blocking first, so the wait can be
		// announced; an operator who sees nothing for a minute has no way to tell a
		// held lock from a hang.
		if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			fmt.Fprintf(os.Stderr,
				"waiting for the ledger lock on %s — another groundhold process is "+
					"writing; this run continues as soon as it releases\n", path)
			if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
				f.Close()
				return nil, err
			}
		}
		same, serr := sameFile(f, path)
		if serr != nil {
			syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			f.Close()
			return nil, serr
		}
		if same {
			return f, nil
		}
		// The ledger was rotated (or replaced) while we waited. Drop everything and
		// take the lock on whatever is at the path now.
		syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}
	return nil, fmt.Errorf("%s was replaced repeatedly while waiting for the "+
		"ledger lock — refusing to append into a file that is no longer the "+
		"ledger (D655)", path)
}

// sameFile reports whether the open descriptor and the path name one file.
func sameFile(f *os.File, path string) (bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	pi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil // rotated away and not yet recreated
		}
		return false, err
	}
	a, aok := fi.Sys().(*syscall.Stat_t)
	b, bok := pi.Sys().(*syscall.Stat_t)
	if !aok || !bok {
		// Without inode identity we cannot tell — and this decides whether a write
		// lands in the ledger or in a ghost, so it does not guess.
		return false, fmt.Errorf("cannot establish file identity for %s on this "+
			"platform — refusing to append rather than guess (D655)", path)
	}
	return a.Dev == b.Dev && a.Ino == b.Ino, nil
}

// commitUnderLock is the linearizable persisted-append (D67): under a
// file lock held across replay/validate/token-alloc/append/fsync (never
// across provider calls), it RE-REPLAYS the current file, builds the
// event against the FRESH heads, validates the rules against fresh
// state, allocates the fencing token from the fresh maxToken, and only
// then writes the line. This makes lease acquisition atomic — two
// concurrent processes cannot both win the lease, so fencing tokens are
// never duplicated and the ledger cannot fork. w.Led is refreshed to
// the post-append state for the caller's projections.
func (w *Writer) commitUnderLock(etype string, caps []string,
	body map[string]any, token int) (Result, error) {
	// naming the path is the consent to create it — the file was always
	// O_CREATE'd; refusing on a missing parent dir was an inconsistency
	if err := os.MkdirAll(filepath.Dir(w.Path), 0o700); err != nil {
		return Result{}, err
	}
	f, err := lockLedger(w.Path)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)

	fresh, err := ReplayFile(w.Path)
	if err != nil {
		return Result{}, err
	}
	// the fresh replay leaves Clock at the last persisted occurredAt;
	// the rules (lease expiry, regression) must run against THIS write's
	// evaluation time, or a lease acquired before a crash would never
	// expire — no later event can advance the clock past its TTL, since
	// the acquire itself is what gets rejected (F1). BuildDoc already
	// stamps occurredAt from w.Clock; align the rule clock with it.
	fresh.Clock = w.Clock
	w.Led = fresh
	doc := w.BuildDoc(etype, caps, body, token)
	res, err := fresh.Append(doc, nil)
	if err != nil {
		return Result{}, err
	}
	if res.Status != "ok" {
		return res, nil
	}
	// D102: sign last — the event is final now. The hash chain is
	// unaffected (HashEvent excludes `sig`); only the persisted line
	// carries the envelope. D134: the signature binds this ledger's
	// identity — the genesis hash: line 1's (possibly this very doc's
	// own — computable because the hash excludes sig), or the one the
	// snapshot carried when genesis lives in the archive (D137).
	if err := signDoc(doc, fresh.LedgerId()); err != nil {
		return Result{}, err
	}
	line, err := json.Marshal(doc)
	if err != nil {
		return Result{}, err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Result{}, err
	}
	if err := f.Sync(); err != nil {
		return Result{}, err
	}
	if w.Events != nil {
		*w.Events = append(*w.Events, etype)
	}
	return res, nil
}

// AppendLease acquires a lease over caps; body must carry ttlSeconds.
// The token is allocated inside the lock against current history (D67),
// so a concurrent acquirer either loses the lease or gets a distinct
// token — never a duplicate.
func (w *Writer) AppendLease(caps []string,
	body map[string]any) (int, error) {
	res, err := w.commitUnderLock("lease.acquired", caps, body, 0)
	if err != nil {
		return 0, err
	}
	if res.Status != "ok" {
		return 0, fmt.Errorf("lease not acquired: %s", res.Reason)
	}
	return res.Token, nil
}

func (w *Writer) Append(etype string, caps []string,
	body map[string]any, token int) error {
	res, err := w.commitUnderLock(etype, caps, body, token)
	if err != nil {
		return err
	}
	if res.Status != "ok" {
		return fmt.Errorf("%s rejected: %s", etype, res.Reason)
	}
	return nil
}
