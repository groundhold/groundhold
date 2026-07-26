package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildPayloadIsExact(t *testing.T) {
	p := Build("abc123", "apply", "done", "run-done", 0, "2026-07-11T14:02:00Z", "sha256:tip")
	b, _ := json.Marshal(p)
	want := `{"schema":"groundhold/notify/v1","handle":"abc123","kind":"apply","state":"done","code":"run-done","exitCode":0,"concludedAt":"2026-07-11T14:02:00Z","lastEventHash":"sha256:tip"}`
	if string(b) != want {
		t.Fatalf("payload bytes drifted:\n got %s\nwant %s", b, want)
	}
}

func TestURLNotifierPostsPayload(t *testing.T) {
	var got Payload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("content-type = %q", ct)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	p := Build("h1", "converge", "failed", "run-failed", 4, "", "")
	if err := URL(srv.URL).Notify(p); err != nil {
		t.Fatalf("notify: %v", err)
	}
	if got.Handle != "h1" || got.State != "failed" || got.ExitCode != 4 {
		t.Fatalf("server got wrong payload: %+v", got)
	}
}

func TestURLNotifierErrorsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()
	// a failing webhook returns an error the caller LOGS and ignores — it must
	// never be able to fail the run, so the contract is just "returns an error".
	if err := URL(srv.URL).Notify(Build("h", "apply", "done", "run-done", 0, "", "")); err == nil {
		t.Fatal("a 500 webhook must surface an error (to be logged, not to fail the run)")
	}
}
