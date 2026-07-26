// D309: the Azure half of the receipt-redaction pin. See
// internal/aws/mutation_leak_test.go for the argument and
// internal/provider/redact.go for the design.
package azure

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// TestMutationFailureNeverEchoesTheAdminPassword: a flexible-server PUT that
// fails with an ARM error echoing administratorLoginPassword must not carry that
// value into the receipt — apply.go persists the Reason and capsules sign it.
func TestMutationFailureNeverEchoesTheAdminPassword(t *testing.T) {
	const password = "S3cret-never-persisted-pw"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			// the ownership pre-read answers "absent" so the PUT is attempted
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"ResourceNotFound"}}`))
			return
		}
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"InvalidParameter","message":` +
			`"administratorLoginPassword '` + password + `' does not meet the policy"}}`))
	}))
	defer srv.Close()

	d := vnetTestDriver(t, srv)
	impl := flexImpl()
	impl["admin_password"] = password

	res := d.Create("flexpostgres", "db", "prod", flexAttrs(), impl, "k", 1)
	if res.Status == "succeeded" {
		t.Fatalf("a 400 must not be succeeded; got %+v", res)
	}
	if strings.Contains(res.Reason, password) {
		t.Errorf("the receipt reason carries the echoed admin password — it is persisted "+
			"in the ledger, exported and signed into capsules.\nreason: %s", res.Reason)
	}
	if !strings.Contains(res.Reason, provider.RedactionMark) {
		t.Errorf("the redaction must be visible in the reason; got: %s", res.Reason)
	}
}
