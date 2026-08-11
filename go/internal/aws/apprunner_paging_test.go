package aws

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D860. App Runner's ListServices returns at most TWENTY services per page (the model
// caps MaxResults at 20) and hands back a NextToken. `resolveServiceArn` read one page,
// matched the name locally, and returned `found=false, err=nil` for a name it had not
// seen — a comment on that line called it "a real gone/never-created".
//
// It is not. On an account with more than twenty services the name may simply be on page
// two, and every caller reads that answer as a fact: create mints a SECOND service (the
// billed-duplicate class of D391-D438), delete reports gone while it stands, observe
// reports absent, claim cannot take it over.
//
// The fake serves a full first page with a token and the wanted service on the second.
func TestResolveServiceArnReadsPastTheFirstPage(t *testing.T) {
	const want = "arn:aws:apprunner:eu-central-1:000000000000:service/wanted/abc"
	var pages int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var in struct {
			NextToken string `json:"NextToken"`
		}
		_ = json.Unmarshal(body, &in)
		pages++
		if in.NextToken == "" {
			// A FULL page (the service's own maximum) and more to come.
			var b strings.Builder
			b.WriteString(`{"ServiceSummaryList":[`)
			for i := 0; i < 20; i++ {
				if i > 0 {
					b.WriteString(",")
				}
				fmt.Fprintf(&b, `{"ServiceName":"other-%d","ServiceArn":"arn:aws:apprunner:eu-central-1:000000000000:service/other-%d/x"}`, i, i)
			}
			b.WriteString(`],"NextToken":"page2"}`)
			_, _ = w.Write([]byte(b.String()))
			return
		}
		_, _ = w.Write([]byte(`{"ServiceSummaryList":[{"ServiceName":"wanted","ServiceArn":"` + want + `"}]}`))
	}))
	defer srv.Close()

	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.AppRunnerBaseURL = srv.URL

	arn, found, err := d.resolveServiceArn("eu-central-1", "wanted")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !found {
		t.Fatalf("the service was on page two and the resolver reported it ABSENT after %d "+
			"page(s). Every caller treats that as a fact: create mints a second service, "+
			"delete reports gone, observe reports absent (D860).", pages)
	}
	if arn != want {
		t.Fatalf("arn = %q, want %q", arn, want)
	}
}

// TestResolveServiceArnRefusesAnUnboundedSweep: a list that never stops handing back a
// token must end as an ERROR, not as an absence. An absence derived from giving up is the
// same lie as an absence derived from one page.
func TestResolveServiceArnRefusesAnUnboundedSweep(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ServiceSummaryList":[{"ServiceName":"x","ServiceArn":"arn:x"}],"NextToken":"more"}`))
	}))
	defer srv.Close()

	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.AppRunnerBaseURL = srv.URL

	_, found, err := d.resolveServiceArn("eu-central-1", "never-there")
	if err == nil {
		t.Fatalf("an endless page chain ended as found=%v with no error — the resolver "+
			"gave up and called it an absence", found)
	}
	if found {
		t.Fatal("found=true on an error path")
	}
}
