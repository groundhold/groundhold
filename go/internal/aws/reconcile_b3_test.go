package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// BATCH 3 reconcile: rolepolicy, custompolicy, iam, waf, budgets. Each service
// reuses its own *_test.go fake/server helper. Reconcile is called through the
// public d.Reconcile dispatch on a create receipt, so these also pin the switch.

// ---- iam ------------------------------------------------------------------

func TestReconcileIAMSucceeded(t *testing.T) {
	srv := iamServer(t, "runner") // GetRole returns our tags (runner/prod)
	defer srv.Close()
	d := iamRoleDriver(t, srv)
	res := d.Reconcile("runner", "prod", map[string]any{
		"target": "aws.iam/x", "operation": "create", "generation": 1})
	wantPID := iamRoleProviderID("000000000000", IAMRoleName("prod", "runner", 1))
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("iam reconcile: got %+v, want succeeded %s", res, wantPID)
	}
}

func TestReconcileIAMAbsentFailed(t *testing.T) {
	// GetRole returns an authoritative NoSuchEntity — a readable absence.
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>NoSuchEntity</Code>` +
				`<Message>role not found</Message></Error></ErrorResponse>`))
		}))
	defer srv.Close()
	d := iamRoleDriver(t, srv)
	res := d.Reconcile("runner", "prod", map[string]any{
		"target": "aws.iam/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("iam reconcile of absent role: got %+v, want failed", res)
	}
}

func TestReconcileIAMForeignUnknown(t *testing.T) {
	// a role exists at our name but carries someone else's ownership tags.
	srv := iamServer(t, "someone-else")
	defer srv.Close()
	d := iamRoleDriver(t, srv)
	res := d.Reconcile("runner", "prod", map[string]any{
		"target": "aws.iam/x", "operation": "create", "generation": 1})
	if res.Status != "unknown" {
		t.Fatalf("iam reconcile of foreign role: got %+v, want unknown", res)
	}
}

// ---- custompolicy ---------------------------------------------------------

func TestReconcileCustomPolicySucceeded(t *testing.T) {
	srv := customPolicyServer(t) // GetPolicy returns success (found)
	defer srv.Close()
	d := customPolicyDriver(t, srv)
	res := d.Reconcile("viewer", "prod", map[string]any{
		"target": "aws.custompolicy/x", "operation": "create", "generation": 1})
	wantPID := customPolicyProviderID(customPolicyArn("000000000000", awsPolicyName("prod", "viewer", 1)))
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("custompolicy reconcile: got %+v, want succeeded %s", res, wantPID)
	}
}

func TestReconcileCustomPolicyAbsentFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>NoSuchEntity</Code>` +
				`<Message>no such policy</Message></Error></ErrorResponse>`))
		}))
	defer srv.Close()
	d := customPolicyDriver(t, srv)
	res := d.Reconcile("viewer", "prod", map[string]any{
		"target": "aws.custompolicy/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("custompolicy reconcile of absent policy: got %+v, want failed", res)
	}
}

// ---- waf ------------------------------------------------------------------

func TestReconcileWAFSucceeded(t *testing.T) {
	srv := wafServer(t, "edge", true, true, true) // ListWebACLs + tags (edge/prod)
	defer srv.Close()
	d := wafDriver(t, srv)
	res := d.Reconcile("edge", "prod", map[string]any{
		"target": "aws.waf/x", "operation": "create", "generation": 1})
	wantPID := wafProviderID("000000000000", WAFACLName("prod", "edge", 1))
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("waf reconcile: got %+v, want succeeded %s", res, wantPID)
	}
}

func TestReconcileWAFAbsentFailed(t *testing.T) {
	// ListWebACLs returns an empty, readable list — the WebACL never landed.
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"WebACLs":[]}`))
		}))
	defer srv.Close()
	d := wafDriver(t, srv)
	res := d.Reconcile("edge", "prod", map[string]any{
		"target": "aws.waf/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("waf reconcile of absent WebACL: got %+v, want failed", res)
	}
}

func TestReconcileWAFForeignUnknown(t *testing.T) {
	// present at our name but tagged as someone else's.
	srv := wafServer(t, "someone-else", true, false, false)
	defer srv.Close()
	d := wafDriver(t, srv)
	res := d.Reconcile("edge", "prod", map[string]any{
		"target": "aws.waf/x", "operation": "create", "generation": 1})
	if res.Status != "unknown" {
		t.Fatalf("waf reconcile of foreign WebACL: got %+v, want unknown", res)
	}
}

// ---- budgets --------------------------------------------------------------

func TestReconcileBudgetSucceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch budgetTarget2(r) {
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST",` +
					`"TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700.0","Unit":"EUR"}}}`))
			case "DescribeNotificationsForBudget":
				// F25-b: the alert notification IS present -> a complete create.
				_, _ = w.Write([]byte(`{"Notifications":[{"NotificationType":"ACTUAL",` +
					`"Threshold":80.0,"ThresholdType":"PERCENTAGE"}]}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	res := d.Reconcile("inference", "prod", map[string]any{
		"target": "aws.budgets/x", "operation": "create", "generation": 1})
	wantPID := budgetProviderID(budgetTestAccount, BudgetName("prod", "inference", 1))
	if res.Status != "succeeded" || res.ProviderID != wantPID {
		t.Fatalf("budgets reconcile: got %+v, want succeeded %s", res, wantPID)
	}
}

// TestReconcileBudgetPartialNotificationMissing pins F25-b: the budget object
// exists but its alert notification does not (a partial create) -> reconcile must
// NOT bind a budget without its alert; it concludes FAILED so a re-apply re-runs
// createBudget and heals the missing notification.
func TestReconcileBudgetPartialNotificationMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch budgetTarget2(r) {
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST",` +
					`"TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700.0","Unit":"EUR"}}}`))
			case "DescribeNotificationsForBudget":
				// readable, but NO notifications -> the alert half never landed.
				_, _ = w.Write([]byte(`{"Notifications":[]}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	res := d.Reconcile("inference", "prod", map[string]any{
		"target": "aws.budgets/x", "operation": "create", "generation": 1})
	if res.Status != "failed" || !strings.Contains(res.Reason, "alert notification is missing") {
		t.Fatalf("partial budget (no notification) must conclude failed to force a re-create heal, got %+v", res)
	}
}

func TestReconcileBudgetAbsentFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"NotFoundException","message":"no such budget"}`))
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	res := d.Reconcile("inference", "prod", map[string]any{
		"target": "aws.budgets/x", "operation": "create", "generation": 1})
	if res.Status != "failed" {
		t.Fatalf("budgets reconcile of absent budget: got %+v, want failed", res)
	}
}

// ---- rolepolicy -----------------------------------------------------------

func TestReconcileRolePolicySucceeded(t *testing.T) {
	srv := rolePolicyServer(t) // stateful: attach then ListAttachedRolePolicies
	defer srv.Close()
	d := rolePolicyDriver(t, srv)
	// establish the live attachment the way apply would, so the read is truthful.
	cr := d.createRolePolicyAttachment("prod", "viewer", awsAuthzAttrs(), nil, 1)
	if cr.Status != "succeeded" {
		t.Fatalf("setup attach: %+v", cr)
	}
	res := d.Reconcile("viewer", "prod", map[string]any{
		"target": "aws.rolepolicy/x", "operation": "create", "generation": 1,
		"targetProviderId": cr.ProviderID})
	if res.Status != "succeeded" || res.ProviderID != cr.ProviderID {
		t.Fatalf("rolepolicy reconcile: got %+v, want succeeded %s", res, cr.ProviderID)
	}
}

func TestReconcileRolePolicyNoPinUnknown(t *testing.T) {
	// a bare create receipt pins no targetProviderId — the attribute-derived
	// identity cannot be recomputed, so the honest verdict is unknown.
	srv := rolePolicyServer(t)
	defer srv.Close()
	d := rolePolicyDriver(t, srv)
	res := d.Reconcile("viewer", "prod", map[string]any{
		"target": "aws.rolepolicy/x", "operation": "create", "generation": 1})
	if res.Status != "unknown" || !strings.Contains(res.Reason, "attribute-derived") {
		t.Fatalf("rolepolicy reconcile without pin: got %+v, want unknown", res)
	}
}
