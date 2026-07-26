// JSONL replay (D42): state = fold(events), reconstructed through the
// same rules every writer obeyed. A torn final line is corruption,
// never auto-truncated.
package ledger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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
		var snapDoc map[string]any
		rawSnap, _ := json.Marshal(snap)
		if err := json.Unmarshal(rawSnap, &snapDoc); err == nil {
			normalize(snapDoc)
			if h, err := HashSnapshot(snapDoc); err == nil {
				led.snapshotHash = h
			}
		}
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
	for i, line := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
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

// verifyPrev checks that an event's prev map pins the current head of
// each capability it lists (C2). Genesis is the empty-head sentinel.
func verifyPrev(led *Ledger, ev map[string]any, line int) error {
	prev, ok := ev["prev"].(map[string]any)
	if !ok {
		return fmt.Errorf(
			"ledger line %d: event has no prev — the hash chain is "+
				"unverifiable; every event must pin the head it extends", line)
	}
	capsAny, _ := ev["capabilities"].([]any)
	for _, ca := range capsAny {
		c, _ := ca.(string)
		want := led.Heads[c]
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
	f, err := os.OpenFile(w.Path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return Result{}, err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return Result{}, err
	}
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
