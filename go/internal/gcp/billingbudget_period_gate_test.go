package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D1234. Three states of a budget's usage period, three different sentences — and the
// structural gate over in internal/provider cannot tell whether the sentence is TRUE,
// only that a branch exists. These witness the content.
//
// What was there before: `calendarPeriod == ""` produced "the budget uses a custom
// period", read from the absence of one field without ever decoding the other. The
// API makes that likely (an unset calendarPeriod is the default for a custom period)
// and likely is not measured — the D1225 shape, where a check declines to answer and
// then explains its silence with a cause nothing established.
//
// And a calendarPeriod the mapping did not know produced NOTHING at all: no
// observation, because the map returned empty; no diagnostic, because the only one
// fired on the EMPTY string. Silence reads as "this budget has no period", which is a
// different fact from "we could not map the one it has".

func budgetDocServer(t *testing.T, filterJSON string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/budgets/") {
			_, _ = w.Write([]byte(`{"name":"billingAccounts/012345-ABCDEF-012345/budgets/b1",` +
				`"displayName":"gh","budgetFilter":` + filterJSON + `,` +
				`"amount":{"specifiedAmount":{"currencyCode":"EUR","units":"100"}}}`))
			return
		}
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error":{"code":404}}`))
	}))
}

func budgetPeriodObserve(t *testing.T, filterJSON string) (map[string]any, []string) {
	t.Helper()
	srv := budgetDocServer(t, filterJSON)
	defer srv.Close()
	d := budgetDriver(t, srv)
	obs, diags, err := d.observeBillingBudget("budget",
		"gcp-billingbudget:012345-ABCDEF-012345:b1")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	return got, diags
}

func budgetDiagWith(t *testing.T, diags []string, substr string) string {
	t.Helper()
	for _, d := range diags {
		if strings.Contains(d, substr) {
			return d
		}
	}
	t.Fatalf("no diagnostic containing %q in %v", substr, diags)
	return ""
}

// A mapped calendar period is measured, and says nothing about custom periods.
func TestMappedCalendarPeriodIsMeasured(t *testing.T) {
	got, diags := budgetPeriodObserve(t, `{"calendarPeriod":"QUARTER"}`)
	if got["budget.period"] != "quarterly" {
		t.Fatalf("QUARTER maps to quarterly, got %v", got["budget.period"])
	}
	for _, d := range diags {
		if strings.Contains(d, "budget.period") {
			t.Fatalf("a mapped period needs no budget.period diagnostic: %q", d)
		}
	}
}

// A CUSTOM period: withheld, and the cause is read from the field rather than assumed.
func TestCustomPeriodIsNamedFromTheFieldThatProvesIt(t *testing.T) {
	got, diags := budgetPeriodObserve(t,
		`{"customPeriod":{"startDate":{"year":2026,"month":3,"day":1}}}`)
	if _, present := got["budget.period"]; present {
		t.Fatalf("a static custom period has no recurring equivalent — it must be withheld")
	}
	d := budgetDiagWith(t, diags, "budget.period not observed")
	if !strings.Contains(d, "CUSTOM") {
		t.Fatalf("the custom period must be named: %q", d)
	}
	if !strings.Contains(d, "2026-03-01") {
		t.Fatalf("the cause must be read from the field, and the date is the proof that it "+
			"was: %q", d)
	}
	if !strings.Contains(d, "no end date") {
		t.Fatalf("an open-ended custom period must say so — the API makes endDate optional "+
			"and its absence is a fact about the budget: %q", d)
	}
}

// The closed window, so the endDate branch is reachable in BOTH its values.
func TestCustomPeriodWithAnEndDateNamesTheWindow(t *testing.T) {
	_, diags := budgetPeriodObserve(t,
		`{"customPeriod":{"startDate":{"year":2026,"month":3,"day":1},`+
			`"endDate":{"year":2026,"month":6,"day":30}}}`)
	d := budgetDiagWith(t, diags, "budget.period not observed")
	if !strings.Contains(d, "2026-03-01 to 2026-06-30") {
		t.Fatalf("a bounded custom period must name its window: %q", d)
	}
}

// NEITHER set: the branch the old code described as a custom period that is not there.
func TestNeitherPeriodSetIsNotReportedAsACustomPeriod(t *testing.T) {
	got, diags := budgetPeriodObserve(t, `{}`)
	if _, present := got["budget.period"]; present {
		t.Fatalf("nothing to map — budget.period must be withheld")
	}
	d := budgetDiagWith(t, diags, "budget.period not observed")
	if strings.Contains(d, "CUSTOM period") {
		t.Fatalf("no customPeriod was returned, so the tool must not announce one: %q", d)
	}
	if !strings.Contains(d, "NEITHER") {
		t.Fatalf("say what was found — neither field — rather than guessing: %q", d)
	}
}

// An unmapped calendar period must be NAMED, not dropped. This is the silence.
func TestUnmappedCalendarPeriodIsDiagnosedNotDropped(t *testing.T) {
	for _, cal := range []string{"CALENDAR_PERIOD_UNSPECIFIED", "WEEK"} {
		got, diags := budgetPeriodObserve(t, `{"calendarPeriod":"`+cal+`"}`)
		if _, present := got["budget.period"]; present {
			t.Fatalf("%s: an unmapped value must not be coerced into the enum", cal)
		}
		d := budgetDiagWith(t, diags, "budget.period not mapped")
		if !strings.Contains(d, cal) {
			t.Fatalf("%s: the diagnostic must name the value it could not map: %q", cal, d)
		}
	}
}
