// Package notify is the terminal-run doorbell (D229): a fire-and-forget hook
// that CANNOT corrupt the run. The notifier receives an immutable payload and
// has no ledger handle — it is physically incapable of writing truth. Delivery
// is best-effort-once (a hard timeout, no retries; a retry queue would be a
// second store, and the ledger is the only truth — anyone needing guarantees
// runs `wait` or polls `export`). A failed webhook is a log line, never a run
// failure. Because a dead process cannot report its own terminal state, the
// documented pattern for guaranteed notification is `wait <handle> --notify-*`:
// a LIVE watcher that fires on done, failed, AND stalled.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"
)

// Schema is the versioned payload tag.
const Schema = "groundhold/notify/v1"

// Payload is the immutable ping. lastEventHash turns it into evidence: the
// receiver can verify it against `export` or a D103 capsule.
type Payload struct {
	Schema        string `json:"schema"`
	Handle        string `json:"handle"`
	Kind          string `json:"kind"`  // apply | converge
	State         string `json:"state"` // done | failed | stalled | needs-reconcile
	Code          string `json:"code"`
	ExitCode      int    `json:"exitCode"`
	ConcludedAt   string `json:"concludedAt,omitempty"`
	LastEventHash string `json:"lastEventHash,omitempty"`
}

// Build assembles a payload — a pure function, so tests pin exact bytes.
func Build(handle, kind, state, code string, exitCode int, concludedAt, lastEventHash string) Payload {
	return Payload{
		Schema: Schema, Handle: handle, Kind: kind, State: state, Code: code,
		ExitCode: exitCode, ConcludedAt: concludedAt, LastEventHash: lastEventHash,
	}
}

// Notifier delivers one terminal payload. Implementations MUST NOT block beyond
// their timeout and MUST NOT be able to touch the ledger.
type Notifier interface {
	Notify(Payload) error
}

type urlNotifier struct {
	url     string
	timeout time.Duration
}

// URL posts the payload as JSON to a webhook. 10s hard timeout, no retries.
func URL(url string) Notifier { return &urlNotifier{url: url, timeout: 10 * time.Second} }

func (n *urlNotifier) Notify(p Payload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notify webhook returned %d", resp.StatusCode)
	}
	return nil
}

type cmdNotifier struct {
	argv    []string
	timeout time.Duration
}

// Cmd execs argv with the JSON payload on stdin — portable to Slack/pager/desktop
// with no OS-desktop coupling. The command's exit code is ignored.
func Cmd(argv []string) Notifier { return &cmdNotifier{argv: argv, timeout: 10 * time.Second} }

func (n *cmdNotifier) Notify(p Payload) error {
	if len(n.argv) == 0 {
		return fmt.Errorf("empty notify command")
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), n.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, n.argv[0], n.argv[1:]...)
	cmd.Stdin = bytes.NewReader(body)
	return cmd.Run()
}
