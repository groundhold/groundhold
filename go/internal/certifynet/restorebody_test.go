package certifynet

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D392: a Classifier that reaches for the request rather than the peeked bytes —
// req.ParseForm() is the easy mistake — used to drain the body the driver had not sent
// yet, and the driver then failed with "ContentLength=N with Body length 0". That reads
// as a driver bug and is not one; it cost real time to diagnose while enrolling
// custompolicy. The harness re-seats the body after classification so no author can
// spend that time again. This pins the property with a classifier that drains on
// purpose.
func TestClassifierCannotDrainTheDriversBody(t *testing.T) {
	const want = "Action=CreatePolicy&PolicyName=viewer"
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	drains := func(req *http.Request, _ []byte) Role {
		_ = req.ParseForm() // the mistake, made deliberately
		return RoleMutateOpaque
	}
	rt := &countRT{inner: http.DefaultTransport, classify: drains}

	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(want))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("the classifier drained the body the driver was about to send: %v", err)
	}
	resp.Body.Close()

	if got != want {
		t.Errorf("server received %q, want %q — the body did not survive classification", got, want)
	}
	if rt.mutations != 1 {
		t.Errorf("mutations = %d, want 1", rt.mutations)
	}
}
