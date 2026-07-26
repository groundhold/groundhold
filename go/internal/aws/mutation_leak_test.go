// D309 (the failing test that opens the debt): a MUTATION that fails must not
// paste the provider's raw response body into the receipt.
//
// The read side already forbids this in writing — internal/aws/awsread.go and
// internal/azure/armread.go both say an unbounded body in a diagnostic is how
// secrets leak into logs, and lift only the provider's own error CODE, bounded.
// The mutation side does the opposite: it pastes up to 400 raw bytes into
// CreateResult.Reason, which apply.go copies verbatim into receipt["reason"] —
// a PERSISTED ledger event that `export` publishes and `capsule` signs and is
// explicitly designed to travel to a third party.
//
// The channel is not theoretical: this very driver sends MasterUserPassword in
// the CreateDBCluster body, and a provider that echoes any part of the request
// in its error (AWS Query-protocol services do echo parameter values in
// InvalidParameterValue messages) lands that value in signed evidence.
package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// TestMutationFailureNeverEchoesTheRequestBody: a CreateDBCluster that fails
// with an error body echoing the request must produce a receipt reason that
// carries the diagnosis (status + the service's own code) and NOT the echoed
// secret.
func TestMutationFailureNeverEchoesTheRequestBody(t *testing.T) {
	const password = "hunter2-should-never-be-persisted"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		// the pre-create ownership read answers honestly ("no such cluster") so the
		// create is actually attempted — the leak lives on the MUTATION response.
		if !strings.Contains(string(b), "Action=CreateDBCluster") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>DBClusterNotFoundFault</Code></Error></ErrorResponse>`))
			return
		}
		// the provider echoes the request it rejected — the realistic worst case
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InvalidParameterValue</Code>` +
			`<Message>Invalid value for MasterUserPassword=` + password +
			` in request</Message></Error></ErrorResponse>`))
	}))
	defer srv.Close()

	d := auroraTestDriver(t, srv)
	impl := auroraImpl()
	impl["masterPassword"] = password
	// through the PUBLIC boundary the executor calls — the scrub lives there, so a
	// test that reached past it would prove nothing about what gets persisted.
	res := d.Create("aurora", "db", "prod", auroraAttrs(), impl, "k", 1)

	if res.Status == "succeeded" {
		t.Fatalf("a 400 must not be succeeded; got %+v", res)
	}
	if strings.Contains(res.Reason, password) {
		t.Errorf("the receipt reason carries the provider's echoed secret — it is persisted "+
			"in the ledger, exported and signed into capsules.\nreason: %s", res.Reason)
	}
	// the diagnosis must survive the redaction: status + the service's own code.
	if !strings.Contains(res.Reason, "400") || !strings.Contains(res.Reason, "InvalidParameterValue") {
		t.Errorf("the reason must still NAME the failure (status + provider code); got: %s", res.Reason)
	}
	// and the redaction must be VISIBLE — an operator reading a receipt has to be
	// able to tell a removed credential from a truncated message.
	if !strings.Contains(res.Reason, provider.RedactionMark) {
		t.Errorf("the echoed credential must be replaced by a visible mark; got: %s", res.Reason)
	}
}
