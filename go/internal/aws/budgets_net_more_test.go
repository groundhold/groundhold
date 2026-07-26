package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file rounds out budgets_net.go coverage: updateBudget and
// budgetPatchOutcome were previously untested (0% each) — the in-place patch
// path (D151) for a global, name-owned resource with no tags to gate ownership.

// ---- updateBudget: budget.limit -------------------------------------------

func TestUpdateBudget_LimitPatchesInPlace(t *testing.T) {
	var updateBody []byte
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch budgetTarget2(r) {
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700","Unit":"EUR"}}}`))
			case "UpdateBudget":
				updateBody = body
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, "pv-x")

	a := budgetAttrs()
	a["budget.limit"] = "900 EUR"
	res := d.updateBudget("inference", "prod", pid, a, budgetImpl(), []string{"budget.limit"})
	if res.Status != "succeeded" || res.ProviderID != pid {
		t.Fatalf("budget.limit update: %+v", res)
	}
	var ub struct {
		AccountId string `json:"AccountId"`
		NewBudget struct {
			BudgetName  string `json:"BudgetName"`
			BudgetLimit struct {
				Amount string `json:"Amount"`
				Unit   string `json:"Unit"`
			} `json:"BudgetLimit"`
		} `json:"NewBudget"`
	}
	if err := json.Unmarshal(updateBody, &ub); err != nil {
		t.Fatalf("UpdateBudget body did not parse: %s", updateBody)
	}
	if ub.NewBudget.BudgetName != "pv-x" {
		t.Fatalf("UpdateBudget must address the EXISTING name from the pid, not a re-derived one: %s", updateBody)
	}
	if ub.NewBudget.BudgetLimit.Amount != "900" || ub.NewBudget.BudgetLimit.Unit != "EUR" {
		t.Fatalf("UpdateBudget must carry the new limit: %s", updateBody)
	}
}

// ---- updateBudget: alert.threshold, existing notification -----------------

func TestUpdateBudget_ThresholdPatchesExistingNotification(t *testing.T) {
	var updateBody []byte
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch budgetTarget2(r) {
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700","Unit":"EUR"}}}`))
			case "DescribeNotificationsForBudget":
				_, _ = w.Write([]byte(`{"Notifications":[{"NotificationType":"ACTUAL","Threshold":80.0,"ThresholdType":"PERCENTAGE"}]}`))
			case "UpdateNotification":
				updateBody = body
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, "pv-x")

	a := budgetAttrs()
	a["alert.threshold"] = 95
	res := d.updateBudget("inference", "prod", pid, a, budgetImpl(), []string{"alert.threshold"})
	if res.Status != "succeeded" {
		t.Fatalf("alert.threshold update: %+v", res)
	}
	var un struct {
		OldNotification struct{ Threshold float64 } `json:"OldNotification"`
		NewNotification struct{ Threshold float64 } `json:"NewNotification"`
	}
	if err := json.Unmarshal(updateBody, &un); err != nil {
		t.Fatalf("UpdateNotification body did not parse: %s", updateBody)
	}
	if un.OldNotification.Threshold != 80 || un.NewNotification.Threshold != 95 {
		t.Fatalf("UpdateNotification must move 80 -> 95, got %+v", un)
	}
}

// ---- updateBudget: alert.threshold, no existing notification --------------

func TestUpdateBudget_ThresholdCreatesWhenAbsent(t *testing.T) {
	var created bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch budgetTarget2(r) {
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700","Unit":"EUR"}}}`))
			case "DescribeNotificationsForBudget":
				_, _ = w.Write([]byte(`{"Notifications":[]}`))
			case "CreateNotificationWithSubscribers":
				created = true
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, "pv-x")

	res := d.updateBudget("inference", "prod", pid, budgetAttrs(), budgetImpl(), []string{"alert.threshold"})
	if res.Status != "succeeded" || !created {
		t.Fatalf("a budget with no notification must have one created: %+v (created=%v)", res, created)
	}
}

// TestUpdateBudget_ThresholdCreateDuplicateIsIdempotent: a race where the
// notification landed between the read and the create — DuplicateRecordException
// is idempotent success, not a failure.
func TestUpdateBudget_ThresholdCreateDuplicateIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch budgetTarget2(r) {
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700","Unit":"EUR"}}}`))
			case "DescribeNotificationsForBudget":
				_, _ = w.Write([]byte(`{"Notifications":[]}`))
			case "CreateNotificationWithSubscribers":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"DuplicateRecordException"}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, "pv-x")
	res := d.updateBudget("inference", "prod", pid, budgetAttrs(), budgetImpl(), []string{"alert.threshold"})
	if res.Status != "succeeded" {
		t.Fatalf("a raced duplicate notification create must be idempotent success, got %+v", res)
	}
}

// ---- updateBudget: refusals + ambiguity ------------------------------------

func TestUpdateBudget_UnmappedPathRefuses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if budgetTarget2(r) == "DescribeBudget" {
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700","Unit":"EUR"}}}`))
				return
			}
			w.WriteHeader(400)
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, "pv-x")
	res := d.updateBudget("inference", "prod", pid, budgetAttrs(), budgetImpl(), []string{"budget.period"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "does not honor") {
		t.Fatalf("an unmapped path must refuse, got %+v", res)
	}
}

func TestUpdateBudget_VanishedFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"NotFoundException"}`))
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, "pv-x")
	res := d.updateBudget("inference", "prod", pid, budgetAttrs(), budgetImpl(), []string{"budget.limit"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "no longer exists") {
		t.Fatalf("a vanished budget must refuse update, got %+v", res)
	}
}

func TestUpdateBudget_PreUpdateReadUnknown(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = budgetTestAccount
	budgetsBaseURLOverride = "http://127.0.0.1:1"
	t.Cleanup(func() { budgetsBaseURLOverride = "" })
	pid := budgetProviderID(budgetTestAccount, "pv-x")
	res := d.updateBudget("inference", "prod", pid, budgetAttrs(), budgetImpl(), []string{"budget.limit"})
	if res.Status != "unknown" || res.ProviderID != pid {
		t.Fatalf("an unreachable pre-update read must be unknown WITH the pid, got %+v", res)
	}
}

func TestUpdateBudget_InvalidPIDFails(t *testing.T) {
	d := NewDriver("eu-central-1")
	res := d.updateBudget("inference", "prod", "not-a-pid", budgetAttrs(), budgetImpl(), []string{"budget.limit"})
	if res.Status != "failed" {
		t.Fatalf("a malformed pid must refuse, got %+v", res)
	}
}

// ---- budgetPatchOutcome: PURE fold, every branch ---------------------------

func TestBudgetPatchOutcome(t *testing.T) {
	pid := "budgets:000000000000:pv-x"
	if r := budgetPatchOutcome("update limit", pid, 200, nil, nil); r != nil {
		t.Fatalf("a 200 must be nil (keep going), got %+v", r)
	}
	if r := budgetPatchOutcome("update limit", pid, 0, nil, errTransport("boom")); r == nil ||
		r.Status != "unknown" || r.ProviderID != pid {
		t.Fatalf("a transport error must be unknown WITH the pid, got %+v", r)
	}
	if r := budgetPatchOutcome("update limit", pid, 503, nil, nil); r == nil ||
		r.Status != "unknown" || r.ProviderID != pid {
		t.Fatalf("a 5xx must be unknown WITH the pid, got %+v", r)
	}
	if r := budgetPatchOutcome("update limit", pid, 400,
		[]byte(`{"__type":"InvalidParameterException","message":"bad"}`), nil); r == nil ||
		r.Status != "failed" || r.ProviderID != "" {
		t.Fatalf("a 4xx must be a clean failed with NO providerId, got %+v", r)
	}
}
