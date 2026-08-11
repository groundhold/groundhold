package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

const budgetTestAccount = "000000000000"
const budgetTestTopic = "arn:aws:sns:us-east-1:000000000000:groundhold-cost-alerts"

func budgetAttrs() map[string]any {
	return map[string]any{
		"budget.limit":    "700 EUR",
		"budget.period":   "monthly",
		"alert.threshold": 80,
		"service.managed": true,
	}
}

func budgetImpl() map[string]any {
	return map[string]any{"notificationTopicArn": budgetTestTopic}
}

func budgetTarget2(r *http.Request) string {
	full := r.Header.Get("X-Amz-Target")
	return full[strings.LastIndex(full, ".")+1:]
}

func budgetDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = budgetTestAccount // pinned; Budgets is global/account-scoped
	budgetsBaseURLOverride = srv.URL
	t.Cleanup(func() { budgetsBaseURLOverride = "" })
	d.Now = time.Now
	return d
}

// ---- pure-builder refusals (refuse-before-mutate) -------------------------

func TestBuildBudgetRefusals(t *testing.T) {
	// missing notificationTopicArn operand
	if _, err := BuildBudget("prod", "inference", budgetAttrs(), map[string]any{}, 1); err == nil {
		t.Error("missing notificationTopicArn must refuse")
	}
	// unmapped attribute
	a := budgetAttrs()
	a["budget.rollover"] = true
	if _, err := BuildBudget("prod", "inference", a, budgetImpl(), 1); err == nil {
		t.Error("unmapped attribute must refuse")
	}
	// service.managed=false
	a = budgetAttrs()
	a["service.managed"] = false
	if _, err := BuildBudget("prod", "inference", a, budgetImpl(), 1); err == nil {
		t.Error("service.managed=false must refuse")
	}
	// bad period
	a = budgetAttrs()
	a["budget.period"] = "biweekly"
	if _, err := BuildBudget("prod", "inference", a, budgetImpl(), 1); err == nil {
		t.Error("bad period must refuse")
	}
	// threshold out of range
	a = budgetAttrs()
	a["alert.threshold"] = 150
	if _, err := BuildBudget("prod", "inference", a, budgetImpl(), 1); err == nil {
		t.Error("threshold >100 must refuse")
	}
	// non-money limit
	a = budgetAttrs()
	a["budget.limit"] = "lots"
	if _, err := BuildBudget("prod", "inference", a, budgetImpl(), 1); err == nil {
		t.Error("non-money limit must refuse")
	}
	// missing limit entirely
	a = map[string]any{"budget.period": "monthly", "alert.threshold": 80, "service.managed": true}
	if _, err := BuildBudget("prod", "inference", a, budgetImpl(), 1); err == nil {
		t.Error("missing budget.limit must refuse")
	}
}

func TestBuildBudgetHonors(t *testing.T) {
	p, err := BuildBudget("prod", "inference", budgetAttrs(), budgetImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.LimitAmount != 700 || p.LimitUnit != "EUR" || p.TimeUnit != "MONTHLY" ||
		p.Threshold != 80 || p.NotificationTopicArn != budgetTestTopic {
		t.Fatalf("plan = %+v", p)
	}
	if !strings.HasPrefix(p.Name, "pv-inference-prod-") {
		t.Fatalf("name = %q", p.Name)
	}
	b := p.createBudgetBody(budgetTestAccount)
	budget := b["Budget"].(map[string]any)
	if budget["BudgetType"] != "COST" || budget["TimeUnit"] != "MONTHLY" {
		t.Fatalf("budget body = %+v", budget)
	}
	lim := budget["BudgetLimit"].(map[string]any)
	if lim["Amount"] != "700" || lim["Unit"] != "EUR" {
		t.Fatalf("limit = %+v", lim)
	}
}

// ---- create: two calls, SigV4, body assertions, succeeded+pid -------------

func TestCreateBudget(t *testing.T) {
	var createBody, notifBody []byte
	var createAuth, notifAuth string
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch budgetTarget2(r) {
			case "CreateBudget":
				createBody = body
				createAuth = r.Header.Get("Authorization")
				_, _ = w.Write([]byte(`{}`))
			case "CreateNotification":
				notifBody = body
				notifAuth = r.Header.Get("Authorization")
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)

	res := d.createBudget(budgetTestAccount, "prod", "inference", budgetAttrs(), budgetImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if !strings.HasPrefix(res.ProviderID, "budgets:"+budgetTestAccount+":pv-inference-prod-") {
		t.Fatalf("pid = %q", res.ProviderID)
	}

	// SigV4 on both calls, scoped to us-east-1/budgets.
	for _, a := range []string{createAuth, notifAuth} {
		if !strings.HasPrefix(a, "AWS4-HMAC-SHA256") {
			t.Fatalf("not SigV4-signed: %q", a)
		}
		if !strings.Contains(a, "/us-east-1/budgets/aws4_request") {
			t.Fatalf("SigV4 scope is not us-east-1/budgets: %q", a)
		}
	}

	// CreateBudget carries limit/period/COST.
	var cb struct {
		AccountId string `json:"AccountId"`
		Budget    struct {
			BudgetName  string `json:"BudgetName"`
			BudgetType  string `json:"BudgetType"`
			TimeUnit    string `json:"TimeUnit"`
			BudgetLimit struct {
				Amount string `json:"Amount"`
				Unit   string `json:"Unit"`
			} `json:"BudgetLimit"`
		} `json:"Budget"`
	}
	if err := json.Unmarshal(createBody, &cb); err != nil {
		t.Fatal(err)
	}
	if cb.AccountId != budgetTestAccount || cb.Budget.BudgetType != "COST" ||
		cb.Budget.TimeUnit != "MONTHLY" || cb.Budget.BudgetLimit.Amount != "700" ||
		cb.Budget.BudgetLimit.Unit != "EUR" {
		t.Fatalf("CreateBudget body = %s", createBody)
	}

	// Notification carries threshold + SNS subscriber.
	var nb struct {
		BudgetName   string `json:"BudgetName"`
		Notification struct {
			NotificationType   string  `json:"NotificationType"`
			ComparisonOperator string  `json:"ComparisonOperator"`
			Threshold          float64 `json:"Threshold"`
			ThresholdType      string  `json:"ThresholdType"`
		} `json:"Notification"`
		Subscribers []struct {
			SubscriptionType string `json:"SubscriptionType"`
			Address          string `json:"Address"`
		} `json:"Subscribers"`
	}
	if err := json.Unmarshal(notifBody, &nb); err != nil {
		t.Fatal(err)
	}
	if nb.Notification.NotificationType != "ACTUAL" || nb.Notification.ComparisonOperator != "GREATER_THAN" ||
		nb.Notification.Threshold != 80 || nb.Notification.ThresholdType != "PERCENTAGE" {
		t.Fatalf("notification = %s", notifBody)
	}
	if len(nb.Subscribers) != 1 || nb.Subscribers[0].SubscriptionType != "SNS" ||
		nb.Subscribers[0].Address != budgetTestTopic {
		t.Fatalf("subscribers = %s", notifBody)
	}
}

// ---- partial: budget created, notification fails -> unknown+pid -----------

func TestCreateBudgetNotificationFailsPartial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch budgetTarget2(r) {
			case "CreateBudget":
				_, _ = w.Write([]byte(`{}`))
			case "CreateNotification":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"InvalidParameterException","message":"bad topic"}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)

	res := d.createBudget(budgetTestAccount, "prod", "inference", budgetAttrs(), budgetImpl(), 1)
	if res.Status != "unknown" {
		t.Fatalf("partial must be unknown, got %+v", res)
	}
	if res.ProviderID == "" || !strings.HasPrefix(res.ProviderID, "budgets:") {
		t.Fatalf("partial must carry the providerId, got %+v", res)
	}
}

// ---- observe reverse-map --------------------------------------------------

func TestObserveBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch budgetTarget2(r) {
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700.0","Unit":"EUR"}}}`))
			case "DescribeNotificationsForBudget":
				_, _ = w.Write([]byte(`{"Notifications":[{"NotificationType":"ACTUAL","Threshold":80.0,"ThresholdType":"PERCENTAGE"}]}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)

	pid := budgetProviderID(budgetTestAccount, BudgetName("prod", "inference", 1))
	obs, diags, err := d.observeBudget("inference", pid)
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 0 {
		t.Fatalf("diags = %v", diags)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["service.managed"] != true {
		t.Fatalf("service.managed = %v", got["service.managed"])
	}
	if got["budget.period"] != "monthly" {
		t.Fatalf("budget.period = %v", got["budget.period"])
	}
	if got["alert.threshold"] != 80.0 {
		t.Fatalf("alert.threshold = %v", got["alert.threshold"])
	}
	lim, ok := got["budget.limit"].(map[string]any)
	if !ok || lim["amount"] != 700.0 || lim["currency"] != "EUR" {
		t.Fatalf("budget.limit = %v", got["budget.limit"])
	}
}

func TestObserveBudgetNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"NotFoundException","message":"no such budget"}`))
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, BudgetName("prod", "inference", 1))
	obs, diags, err := d.observeBudget("inference", pid)
	if err != nil {
		t.Fatalf("not-found must not error: %v", err)
	}
	// Corrected with D520: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if !absentMarked(obs) || len(diags) != 1 {
		t.Fatalf("not-found = obs %v diags %v", obs, diags)
	}
}

// ---- delete ---------------------------------------------------------------

func TestDeleteBudget(t *testing.T) {
	var deleted bool
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch budgetTarget2(r) {
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700","Unit":"EUR"}}}`))
			case "DeleteBudget":
				deleted = true
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, BudgetName("prod", "inference", 1))
	res := d.deleteBudget("inference", "prod", pid)
	if res.Status != "succeeded" || !deleted {
		t.Fatalf("delete: %+v (deleted=%v)", res, deleted)
	}
}

func TestDeleteBudgetIdempotentWhenGone(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"NotFoundException"}`))
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, BudgetName("prod", "inference", 1))
	res := d.deleteBudget("inference", "prod", pid)
	if res.Status != "succeeded" {
		t.Fatalf("gone budget must delete idempotently, got %+v", res)
	}
}

// ---- classify -------------------------------------------------------------

func TestClassifyBudgetChange(t *testing.T) {
	if c, _ := classifyBudgetChange("budget.limit"); c != "mutable" {
		t.Errorf("budget.limit -> %s", c)
	}
	if c, _ := classifyBudgetChange("alert.threshold"); c != "mutable" {
		t.Errorf("alert.threshold -> %s", c)
	}
	// D806: this asserted "immutable", which is what the driver used to claim and what
	// AWS's own UpdateBudget documentation contradicts in one sentence — "you can change
	// every part of a budget except for the budgetName and the calculatedSpend". The
	// expectation was pinning a false statement about the provider's API, and the cost
	// of it was a DELETE and a CREATE where one call would do.
	if c, _ := classifyBudgetChange("budget.period"); c != "mutable" {
		t.Errorf("budget.period -> %s", c)
	}
}

// ---- discover -------------------------------------------------------------

func TestDiscoverBudgets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch budgetTarget2(r) {
			case "DescribeBudgets":
				_, _ = w.Write([]byte(`{"Budgets":[{"BudgetName":"pv-inference-prod-abcdefgh"}]}`))
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-inference-prod-abcdefgh","BudgetType":"COST","TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700","Unit":"EUR"}}}`))
			case "DescribeNotificationsForBudget":
				_, _ = w.Write([]byte(`{"Notifications":[{"NotificationType":"ACTUAL","Threshold":80.0,"ThresholdType":"PERCENTAGE"}]}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	found, diags, err := d.discoverBudgets("us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 0 {
		t.Fatalf("diags = %v", diags)
	}
	if len(found) != 1 || found[0].ResourceType != "capability.cost.budget" ||
		found[0].ProviderID != "budgets:"+budgetTestAccount+":pv-inference-prod-abcdefgh" {
		t.Fatalf("discover = %+v", found)
	}
}

func budgetRole(req *http.Request, _ []byte) certifynet.Role {
	switch budgetTarget2(req) {
	case "DescribeBudget", "DescribeBudgets", "DescribeNotificationsForBudget":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingBudget enrols budgets in the D391 gate. A budget is NAME-addressed
// and the name is itself the ownership marker (there are no tags on a budget), so a
// DuplicateRecordException is answered by re-reading the standing budget and continuing
// onto its notification — the D250 partial-heal path, now asserted as a class.
func TestAdoptsExistingBudget(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/budgets",
		Classify: budgetRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch budgetTarget2(r) {
					case "CreateBudget":
						w.WriteHeader(400)
						_, _ = w.Write([]byte(`{"__type":"DuplicateRecordException","message":"exists"}`))
					case "DescribeBudget":
						_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"x","BudgetType":"COST",` +
							`"TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700","Unit":"EUR"}}}`))
					case "CreateNotification", "DescribeNotificationsForBudget":
						_, _ = w.Write([]byte(`{}`))
					default:
						w.WriteHeader(400)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = budgetTestAccount
			budgetsBaseURLOverride = happyURL
			t.Cleanup(func() { budgetsBaseURLOverride = "" })
			d.Now = time.Now
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("budgets", "inference", "prod", budgetAttrs(), budgetImpl(), "inf", 1)
		},
		AllowedMutations: 2, // the refused CreateBudget + the idempotent notification
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// TestDeleteBudgetForeignNameRefused (D443): the bug this fixes. A budget carries no
// tags, so its deterministic NAME is the only ownership evidence — and the delete never
// checked it. A providerId naming any budget in the account destroyed that budget.
func TestDeleteBudgetForeignNameRefused(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if budgetTarget2(r) == "DeleteBudget" {
			t.Errorf("delete must not be issued for a budget outside our naming scheme")
		}
		_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"finance-team-quarterly"}}`))
	}))
	defer srv.Close()
	d := budgetDriver(t, srv)

	res := d.deleteBudget("inference", "prod",
		"budgets:"+budgetTestAccount+":finance-team-quarterly")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not named by groundhold") {
		t.Fatalf("a budget outside our naming scheme must refuse, got %+v", res)
	}
}

// TestDeleteBudgetOursProceeds: the check must not break the real path.
func TestDeleteBudgetOursProceeds(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	name := BudgetName("prod", "inference", 1)
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if budgetTarget2(r) == "DeleteBudget" {
			deleted = true
		}
		_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"` + name + `"}}`))
	}))
	defer srv.Close()
	d := budgetDriver(t, srv)

	res := d.deleteBudget("inference", "prod", "budgets:"+budgetTestAccount+":"+name)
	if res.Status != "succeeded" || !deleted {
		t.Fatalf("our own budget must still delete, got %+v (deleted=%v)", res, deleted)
	}
}

// TestRefusesForeignDeleteBudgets enrols budgets in the D439 class gate.
func TestRefusesForeignDeleteBudgets(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ForeignProbe{
		Name:     "aws/budgets",
		Classify: budgetRole,
		ForeignServer: func() *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"finance-team-quarterly"}}`))
			}))
			t.Cleanup(srv.Close)
			return srv
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = budgetTestAccount
			budgetsBaseURLOverride = happyURL
			t.Cleanup(func() { budgetsBaseURLOverride = "" })
			d.Now = time.Now
			return d
		},
		Delete: func(pr provider.Provider) provider.CreateResult {
			return pr.Delete("budgets", "inference", "prod",
				"budgets:"+budgetTestAccount+":finance-team-quarterly", "k")
		},
		// A budget carries no tags at all: the name is the whole of the evidence, so the
		// refusal is decided from the providerId without an estate read (D455).
		OwnershipFromIDAlone: true,
	}
	certifynet.CertifyDeleteRefusesForeign(t, p)
}

// D806. The three clouds implement one capability.cost.budget, and two of them called
// budget.period mutable while AWS called it immutable — a single-cloud outlier on a
// directly comparable service, which is the same smell that found D798. Here the
// provider settled it: UpdateBudget's own documentation says every part of a budget can
// change except the name and the calculated spend.
//
// `immutable` is not an opinion about how hard something is. It tells the compiler an
// in-place change is impossible, so the plan carries a REPLACEMENT — a delete and a
// create — and the budget loses its identity and its history to make a change one call
// could have made.
func TestBudgetPeriodIsHonouredInPlace(t *testing.T) {
	if c, _ := classifyBudgetChange("budget.period"); c != "mutable" {
		t.Fatalf("budget.period classified %q — AWS UpdateBudget can change it, and "+
			"claiming otherwise plans a destroy-and-recreate", c)
	}
	// And the updater must actually honour it — classifying a path mutable while the
	// updater refuses it is the same false claim wearing the other face (D805).
	var sent []byte
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch budgetTarget2(r) {
			case "DescribeBudget":
				_, _ = w.Write([]byte(`{"Budget":{"BudgetName":"pv-x","BudgetType":"COST",` +
					`"TimeUnit":"MONTHLY","BudgetLimit":{"Amount":"700","Unit":"EUR"}}}`))
			case "UpdateBudget":
				sent = body
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := budgetDriver(t, srv)
	pid := budgetProviderID(budgetTestAccount, BudgetName("prod", "inference", 1))
	res := d.updateBudget("inference", "prod", pid, budgetAttrs(), budgetImpl(),
		[]string{"budget.period"})
	if res.Status != "succeeded" {
		t.Fatalf("a period change the API honours was refused: %+v", res)
	}
	if !strings.Contains(string(sent), "TimeUnit") {
		t.Fatalf("the update did not carry the period: %s", sent)
	}
}
