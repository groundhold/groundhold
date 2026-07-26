package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A fake EC2 endpoint serving DescribeRegions: the golden contract for scope
// enumeration. Asserts the request is SigV4-signed, that it is the DescribeRegions
// action, and that the enabled region names are returned verbatim.
func TestEnumerateReturnsEnabledRegions(t *testing.T) {
	var gotAction, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			gotAction = formAction(string(body))
			gotAuth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`<DescribeRegionsResponse><regionInfo>` +
				`<item><regionName>eu-central-1</regionName><optInStatus>opt-in-not-required</optInStatus></item>` +
				`<item><regionName>us-east-1</regionName><optInStatus>opt-in-not-required</optInStatus></item>` +
				`<item><regionName>ap-southeast-2</regionName><optInStatus>opted-in</optInStatus></item>` +
				`</regionInfo></DescribeRegionsResponse>`))
		}))
	defer srv.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.EC2BaseURL = srv.URL

	scopes, diags, err := d.Enumerate()
	if err != nil {
		t.Fatalf("Enumerate: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diags: %v", diags)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256") {
		t.Fatalf("DescribeRegions was not SigV4-signed: Authorization=%q", gotAuth)
	}
	if gotAction != "DescribeRegions" {
		t.Fatalf("wrong EC2 action: got %q, want DescribeRegions", gotAction)
	}
	want := []string{"eu-central-1", "us-east-1", "ap-southeast-2"}
	if len(scopes) != len(want) {
		t.Fatalf("got %v, want %v", scopes, want)
	}
	for i, r := range want {
		if scopes[i] != r {
			t.Fatalf("scope[%d] = %q, want %q (full: %v)", i, scopes[i], r, scopes)
		}
	}
}

// A non-200 from DescribeRegions is an error (the crawl records the provider
// incomplete), never a fabricated empty scope list.
func TestEnumerateErrorsOnHTTPFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`<Response><Errors><Error>` +
				`<Code>UnauthorizedOperation</Code></Error></Errors></Response>`))
		}))
	defer srv.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.EC2BaseURL = srv.URL

	scopes, _, err := d.Enumerate()
	if err == nil {
		t.Fatalf("want error on HTTP 403, got scopes=%v nil err", scopes)
	}
	if scopes != nil {
		t.Fatalf("want nil scopes on failure, got %v", scopes)
	}
}
