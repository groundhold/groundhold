package aws

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTheBudgetNotificationTargetsAnOperationAWSHas pins the fix D853 made, and exists
// because the mutation meter proved nothing else did.
//
// The defect: the driver sent `X-Amz-Target: AWSBudgetServiceGateway.
// CreateNotificationWithSubscribers`, and AWS has no such operation —
// `NotificationsWithSubscribers` is a FIELD of CreateBudget. Every budget alert failed on
// the target name alone, so `capability.cost.budget` (whose whole point on AWS is the
// threshold notification) could never finish its create.
//
// The route gate found it, but the route gate reads the RECORDED route file: re-injecting
// the bug into the driver leaves that file untouched, so the gate passes. The recorded file
// only disagrees on an UNFILTERED package run, which a `-run` filter skips by design. So the
// fix was held by a check that cannot see the code it protects. This test asks the driver
// directly, and checks the answer against the same published list of AWS operations.
func TestTheBudgetNotificationTargetsAnOperationAWSHas(t *testing.T) {
	var mu sync.Mutex
	var targets []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if tg := r.Header.Get("X-Amz-Target"); tg != "" {
			targets = append(targets, tg)
		}
		mu.Unlock()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	// The DRIVER chooses the target; the test must not hand it one. An earlier draft of
	// this test called budgetCall("CreateNotification", ...) itself and would have passed
	// with the defect re-injected — a test tied to the driver's opinion instead of its
	// behaviour, which is the same knot the fixtures were in (D853).
	d := NewDriver("us-east-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.Account = budgetTestAccount
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = time.Second
	prev := budgetsBaseURLOverride
	budgetsBaseURLOverride = srv.URL
	defer func() { budgetsBaseURLOverride = prev }()
	_ = d.createBudget(budgetTestAccount, "prod", "inference", budgetAttrs(), budgetImpl(), 1)

	mu.Lock()
	got := append([]string(nil), targets...)
	mu.Unlock()
	if len(got) == 0 {
		t.Fatal("the create sent no targeted call — this test would prove nothing")
	}

	// The authority, not a second copy of the driver's opinion: the operations AWS
	// publishes for this service (refresh: scripts/refresh-aws-opactions.sh).
	blob, err := os.ReadFile(filepath.Join("..", "provider", "testdata", "aws_operation_actions.verified"))
	if err != nil {
		t.Fatalf("read the verified operations: %v", err)
	}
	modelled := map[string]bool{}
	for _, line := range strings.Split(string(blob), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.SplitN(line, "\t", 3)
		if len(p) == 3 && p[0] == "budgets" {
			modelled[p[1]] = true
		}
	}
	if len(modelled) < 10 {
		t.Fatalf("only %d budgets operations in the verified file — this test would be "+
			"vacuous (D328)", len(modelled))
	}
	for _, full := range got {
		op := full
		if i := strings.LastIndex(op, "."); i >= 0 {
			op = op[i+1:]
		}
		if modelled[op] {
			continue
		}
		t.Errorf("the create targets %q, which AWS does not have. "+
			"`NotificationsWithSubscribers` is a FIELD of CreateBudget, not a call; the "+
			"operation is CreateNotification, and its four required inputs are exactly the "+
			"body this driver already builds (D853).", op)
	}
}
