package azure

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D295: a read that produced no document must SAY why. The four-valued
// semantics are unchanged (404 is an authoritative absence; everything else is
// no-evidence) — only the diagnosis is new.
func TestArmReadNamesTheCause(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    []string
		wantErr bool
		found   bool
	}{
		{name: "403 carries the provider's code and message", status: 403,
			body:    `{"error":{"code":"AuthorizationFailed","message":"The client does not have authorization to perform action"}}`,
			want:    []string{"virtualNetworks.get", "HTTP 403", "AuthorizationFailed", "does not have authorization"},
			wantErr: true},
		{name: "retired api-version reads as a 400 with its code", status: 400,
			body:    `{"error":{"code":"NoRegisteredProviderFound","message":"No registered resource provider found for api version"}}`,
			want:    []string{"HTTP 400", "NoRegisteredProviderFound"},
			wantErr: true},
		{name: "404 is an absence, not a failure", status: 404, body: `{}`,
			wantErr: false, found: false},
		{name: "200 with a garbled body is refused, not read", status: 200,
			body: `{"location":`, want: []string{"HTTP 200", "did not parse"}, wantErr: true},
		{name: "200 populates the document", status: 200,
			body: `{"location":"westeurope"}`, wantErr: false, found: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(c.status)
				fmt.Fprint(w, c.body)
			}))
			defer srv.Close()
			d := NewDriver(testSub)
			d.BaseURL = srv.URL
			d.token = "t"
			var doc struct {
				Location string `json:"location"`
			}
			found, err := d.armGetInto("virtualNetworks.get", "rg1",
				"Microsoft.Network/virtualNetworks/x", "2023-11-01", &doc)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected a described error, got none (found=%v)", found)
				}
				for _, w := range c.want {
					if !strings.Contains(err.Error(), w) {
						t.Fatalf("error %q must contain %q", err.Error(), w)
					}
				}
				if found {
					t.Fatal("a failed read must not report found")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if found != c.found {
				t.Fatalf("found = %v, want %v", found, c.found)
			}
			if c.found && doc.Location != "westeurope" {
				t.Fatalf("document not populated: %+v", doc)
			}
		})
	}
}

// The scope guard (an unpinned subscription, a malformed resource group) fails
// BEFORE any request — and must say so rather than looking like a network
// failure, which is exactly the confusion that cost a live debugging session.
func TestArmReadNamesAScopeRefusal(t *testing.T) {
	d := NewDriver("") // no subscription pinned
	d.token = "t"
	var doc struct{}
	_, err := d.armGetInto("virtualNetworks.get", "rg1",
		"Microsoft.Network/virtualNetworks/x", "2023-11-01", &doc)
	if err == nil || !strings.Contains(err.Error(), "refused before the request") {
		t.Fatalf("a scope refusal must be distinguishable from a transport failure, got: %v", err)
	}
}

// A diagnostic must not become a leak: the provider's message is bounded and
// the raw body never travels.
func TestArmReadBoundsTheDetail(t *testing.T) {
	long := strings.Repeat("x", 900)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprintf(w, `{"error":{"code":"Internal","message":%q},"secret":"hunter2"}`, long)
	}))
	defer srv.Close()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "t"
	_, err := d.armGetInto("x.get", "rg1", "P/x", "2023-11-01", nil)
	if err == nil {
		t.Fatal("a 500 must be an error")
	}
	if len(err.Error()) > 400 {
		t.Fatalf("diagnostic must stay bounded, got %d chars", len(err.Error()))
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Fatal("the raw body must never travel into a diagnostic")
	}
}

// The discover paths collect diagnostics as strings, not errors — a partial
// enumeration is a fact, not a failure (D242). They must carry the SAME
// information and the same bounds.
func TestAzReadWhyNamesTheCause(t *testing.T) {
	got := azReadWhy(403, []byte(`{"error":{"code":"AuthorizationFailed","message":"no rights"}}`), nil)
	for _, want := range []string{"HTTP 403", "AuthorizationFailed", "no rights"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q must contain %q", got, want)
		}
	}
	if got := azReadWhy(0, nil, fmt.Errorf("dial tcp: timeout")); !strings.Contains(got, "no answer") {
		t.Fatalf("a transport failure must read as no answer, got %q", got)
	}
	// "unreadable" as a bare word is exactly what this slice removes
	if strings.Contains(azReadWhy(500, []byte(`{}`), nil), "unreadable") {
		t.Fatal("the bare word must not survive")
	}
}

// TestAzErrDetailParsesTopLevelShape (D929): not every ARM error wraps itself in "error".
// A managedClusters (AKS) 400 carries {"code","message"} at the top level, and the
// wrapped-only read used to swallow it entirely ("no error code or message"), leaving an
// operator debugging a failed create with nothing. Both shapes must be read.
func TestAzErrDetailParsesTopLevelShape(t *testing.T) {
	topLevel := []byte(`{"code":"K8sVersionNotSupported","message":"version 1.29.15 which is not supported in this region","subcode":""}`)
	if got := azErrCode(topLevel); got != "K8sVersionNotSupported" {
		t.Errorf("top-level code = %q, want K8sVersionNotSupported", got)
	}
	if got := azErrMessage(topLevel); got == "" || !strings.Contains(got, "not supported in this region") {
		t.Errorf("top-level message = %q", got)
	}
	if got := mutDetailAz(topLevel); got == "" || strings.Contains(got, "no error code or message") {
		t.Errorf("mutDetailAz swallowed a top-level ARM error: %q", got)
	}
	// the wrapped shape still works
	wrapped := []byte(`{"error":{"code":"BadRequest","message":"wrapped msg"}}`)
	if azErrCode(wrapped) != "BadRequest" || azErrMessage(wrapped) != "wrapped msg" {
		t.Errorf("wrapped shape regressed: code=%q msg=%q", azErrCode(wrapped), azErrMessage(wrapped))
	}
}
