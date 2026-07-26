package costproj

import (
	"strings"
	"testing"
)

func TestComputeSameCurrencySumAndPeriods(t *testing.T) {
	p := Compute([]Item{
		{Amount: 100, Currency: "EUR", Basis: "declared"},
		{Amount: 50, Currency: "EUR", Basis: "declared"},
	}, "EUR", 2)
	if p.Monthly != 150 {
		t.Fatalf("monthly = %v, want 150", p.Monthly)
	}
	if p.yearly() != 1800 {
		t.Errorf("yearly = %v, want 1800", p.yearly())
	}
	if got := p.weekly(); got < 34.6 || got > 34.7 { // 150*12/52
		t.Errorf("weekly = %v, want ~34.62", got)
	}
	if p.Priced != 2 || p.Total != 2 {
		t.Errorf("coverage = %d/%d, want 2/2", p.Priced, p.Total)
	}
}

func TestComputeNeverConvertsForeignCurrency(t *testing.T) {
	p := Compute([]Item{
		{Amount: 120, Currency: "EUR", Basis: "declared"},
		{Amount: 30, Currency: "USD", Basis: "declared"},
	}, "EUR", 2)
	if p.Monthly != 120 {
		t.Errorf("reporting (EUR) monthly = %v, want 120 (USD must NOT be folded in)", p.Monthly)
	}
	if len(p.Other) != 1 || p.Other[0].Currency != "USD" || p.Other[0].Monthly != 30 {
		t.Errorf("USD must appear as a separate uncoerced line, got %+v", p.Other)
	}
}

func TestComputeReportsWeakestProvenance(t *testing.T) {
	p := Compute([]Item{
		{Amount: 100, Currency: "EUR", Basis: "declared"},
		{Amount: 20, Currency: "EUR", Basis: "assumed"},
	}, "EUR", 2)
	if p.Basis != "assumed" {
		t.Errorf("basis = %q, want assumed (weakest wins so it never reads as fact)", p.Basis)
	}
}

func TestComputeCoverageHonestAboutMissingCost(t *testing.T) {
	// 3 actions in the plan, only 1 declared a cost
	p := Compute([]Item{
		{Amount: 100, Currency: "EUR", Basis: "declared"},
		{Currency: ""}, // no cost.monthly
		{Currency: ""},
	}, "EUR", 3)
	if p.Priced != 1 || p.Total != 3 {
		t.Errorf("coverage = %d/%d, want 1/3", p.Priced, p.Total)
	}
}

func TestRenderStatesEstimateAndCoverage(t *testing.T) {
	var b strings.Builder
	Compute([]Item{{Amount: 100, Currency: "EUR", Basis: "assumed"}}, "EUR", 2).Render(&b)
	out := b.String()
	for _, want := range []string{"projection, not a quote", "assumed", "1 of 2 capabilities", "/ month", "/ week", "/ year"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q in:\n%s", want, out)
		}
	}
}

func TestRenderForeignCurrencyNotConverted(t *testing.T) {
	var b strings.Builder
	Compute([]Item{
		{Amount: 120, Currency: "EUR", Basis: "declared"},
		{Amount: 30, Currency: "USD", Basis: "declared"},
	}, "EUR", 2).Render(&b)
	if !strings.Contains(b.String(), "NOT converted") {
		t.Errorf("foreign currency must be flagged NOT converted:\n%s", b.String())
	}
}
