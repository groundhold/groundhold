// Package detach launches a background run without a second source of truth
// (D229). Detaching changes WHO watches — the ledger + lease keep every
// guarantee (D56/D57/D67). The child is byte-for-byte the foreground code path;
// detach adds zero run logic. The only artifact on disk is a WRITE-ONCE pointer
// (.groundhold/runs/<handle>.json) answering exactly one question the ledger
// cannot: which ledger file this handle lives in. Any field the ledger can
// answer — state, liveness, outcome — is forbidden here; the lease is the
// liveness signal, and `pid` is listing garnish, never a liveness claim.
package detach

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// Entry is the write-once registry pointer. It carries no derivable run state.
type Entry struct {
	Handle     string `json:"handle"`
	Kind       string `json:"kind"` // apply | converge
	LedgerPath string `json:"ledgerPath"`
	LogPath    string `json:"logPath"`
	PID        int    `json:"pid"` // listing garnish only — the lease is liveness
	LaunchedAt string `json:"launchedAt"`
}

// Runner starts the detached child. Production re-execs the binary in a new
// session; tests inject a synchronous in-process runner so the launcher —
// admission, registry, handle — is exercised hermetically (the fork is a seam,
// not a subject: the child IS the tested foreground path).
type Runner interface {
	Start(argv []string, logPath string) (pid int, err error)
}

// OSRunner re-execs the binary detached: a new session (setsid) so it survives
// the parent's terminal, stdin from nowhere, stdout+stderr appended to the run
// log.
type OSRunner struct{ Self string }

func (o OSRunner) Start(argv []string, logPath string) (int, error) {
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, err
	}
	defer logf.Close()
	cmd := exec.Command(o.Self, argv...)
	cmd.Stdin = nil
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	// release the child: we do not reap it (it outlives us). The ledger lease,
	// not this process handle, is how anyone learns it is alive.
	_ = cmd.Process.Release()
	return pid, nil
}

// runsDir is the registry directory beside the run's ledger.
func runsDir(ledgerPath string) string {
	return filepath.Join(filepath.Dir(ledgerPath), ".groundhold", "runs")
}

// LogPath returns where a handle's detached output lands.
func LogPath(ledgerPath, handle string) string {
	return filepath.Join(runsDir(ledgerPath), handle+".log")
}

// ListRegistry returns the write-once pointers in a ledger's run directory
// (D231). These are the DETACHED runs' handles — a convenience census the ledger
// alone cannot give for a run that was launched but never admitted (it wrote no
// events, e.g. it died pre-admission). The caller unions these handles into the
// ledger-derived list; the pointer NEVER contributes to a verdict (the ledger
// remains the sole run truth, D229) — only to the question set. A missing
// directory is not an error (no detached runs). Sorted by handle for determinism.
func ListRegistry(ledgerPath string) ([]Entry, error) {
	dir := runsDir(ledgerPath)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Entry
	for _, de := range ents {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue // a pointer we cannot read is not truth; skip it
		}
		var e Entry
		if json.Unmarshal(raw, &e) == nil && e.Handle != "" {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Handle < out[j].Handle })
	return out, nil
}

// Launch forks a detached run: it prepares the run dir, starts the child, and
// writes the write-once registry pointer once the pid is known. The handle is
// precomputed by the caller (it must equal what the child writes as applyRunId).
func Launch(r Runner, e Entry, childArgv []string) (Entry, error) {
	dir := runsDir(e.LedgerPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return e, err
	}
	e.LogPath = filepath.Join(dir, e.Handle+".log")
	pid, err := r.Start(childArgv, e.LogPath)
	if err != nil {
		return e, err
	}
	e.PID = pid
	b, _ := json.MarshalIndent(e, "", "  ")
	// 0600: the pointer names a ledger path; keep it operator-private.
	if err := os.WriteFile(filepath.Join(dir, e.Handle+".json"), b, 0o600); err != nil {
		return e, err
	}
	return e, nil
}
