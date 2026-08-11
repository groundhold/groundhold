package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// exposureFake serves a function whose URL config says AuthType=NONE — so whether the
// world can invoke it depends entirely on the RESOURCE POLICY — and then refuses the
// policy read the way a missing lambda:GetPolicy grant does.
type exposureFake struct{ policyStatus int }

func (f *exposureFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "GET" && strings.HasSuffix(p, "/policy"):
			w.WriteHeader(f.policyStatus)
			_, _ = w.Write([]byte(`{"message":"User is not authorized to perform: lambda:GetPolicy"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/url"):
			_, _ = w.Write([]byte(`{"AuthType":"NONE","FunctionUrl":"https://x.lambda-url.eu-central-1.on.aws/"}`))
		case r.Method == "GET" && strings.Contains(p, "/functions/"):
			_, _ = w.Write([]byte(`{"Configuration":{"State":"Active","Timeout":300},` +
				`"Code":{"ImageUri":"img:sha1"},` +
				`"Tags":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func exposureDriver(t *testing.T, policyStatus int) (*Driver, func()) {
	t.Helper()
	srv := httptest.NewServer((&exposureFake{policyStatus: policyStatus}).handler())
	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.Account = "000000000000"
	d.LambdaBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d, srv.Close
}

// TestAnUnreadableGrantIsNotObservedAsPrivate (D847).
//
// AuthType=NONE means the Function URL itself demands no signature, so the only thing
// standing between the world and this function is the resource policy. When that policy
// cannot be READ, nothing about the exposure has been established.
//
// The driver used to answer `network.publicExposure = false` with
// `Derivation: "measured"` and put the truth — "reported private on the AuthType alone,
// NOT measured" — in a diagnostic string. Diagnostics do not travel with the value:
// observe copies the derivation onto the record, `audit.evidenceRank` demotes only
// `config-intent` and `platform-invariant`, so a stamped-measured false SATISFIES a hard
// `publicExposure == false` constraint. A world-invokable function passes the check that
// exists to catch it, and the operator reads a green verdict.
//
// Absence of evidence stays the signal (D242) — the branch immediately below this one in
// the same switch already did exactly that for an unreadable URL config.
func TestAnUnreadableGrantIsNotObservedAsPrivate(t *testing.T) {
	d, done := exposureDriver(t, http.StatusForbidden)
	defer done()

	obs, diags, err := d.observeLambda("api", operandPID)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			t.Fatalf("the resource policy was DENIED and publicExposure was still observed "+
				"as %v (derivation %q) — a function the world may invoke passes a hard "+
				"publicExposure==false constraint (D847)", o.Value, o.Derivation)
		}
	}
	if !strings.Contains(strings.Join(diags, "\n"), "publicExposure") {
		t.Fatalf("no diagnostic named the unread grant: %v", diags)
	}
}

// TestAReadableGrantIsStillObserved keeps the fix from being a refusal to answer: when the
// policy READS, the observation must still be emitted and still be measured. A gate that
// silences the readable case would trade a false pass for a false blind spot.
func TestAReadableGrantIsStillObserved(t *testing.T) {
	d, done := exposureDriver(t, http.StatusNotFound) // no resource policy at all
	defer done()

	obs, _, err := d.observeLambda("api", operandPID)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			if o.Value != false || o.Derivation != "measured" {
				t.Fatalf("a readable absent policy must observe publicExposure=false measured, "+
					"got %v / %q", o.Value, o.Derivation)
			}
			return
		}
	}
	t.Fatal("publicExposure was not observed at all for a function whose policy read cleanly")
}
