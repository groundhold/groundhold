package compiler

import (
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/scalars"
)

// D770. From the field, with the arithmetic: web ACL $5 + two rules $2 + Bot Control $10
// = $17/mo ≈ 14.6 EUR, against a declared `cost.monthly: 6 EUR` and a constraint of
// `lte 15`. The verdict was green. With 3.1% of the budget left, the one unpriced line
// consumed all of it.
//
// This is NOT a price model and the test says so by what it does not assert: no amount,
// no rate, no arithmetic. The only claim is that a switch the driver flips adds a
// component the provider bills separately — a fact the driver has without any table.
func TestChargeableComponentIsNamedWhenACostIsDeclared(t *testing.T) {
	cand := func(cost bool, bot any, svc string) *contract.Candidate {
		attrs := map[string]contract.Provenanced{}
		if cost {
			attrs["cost.monthly"] = contract.Provenanced{
				Scalar: &scalars.Scalar{Kind: scalars.Money, Raw: "6 EUR"}, Status: "declared"}
		}
		if bot != nil {
			attrs["bot.protection"] = contract.Provenanced{
				Scalar: &scalars.Scalar{Kind: scalars.Bool, Raw: bot}, Status: "declared"}
		}
		return &contract.Candidate{
			Capabilities: map[string]map[string]contract.Provenanced{"edge": attrs},
			Extras: map[string]map[string]any{
				"edge": {"provider": "aws", "service": svc}},
		}
	}
	c := &contract.Contract{Capabilities: map[string]map[string]any{
		"edge": {"type": "capability.security.waf"}}}

	for _, tc := range []struct {
		name string
		cand *contract.Candidate
		want int
	}{
		{"bot protection with a declared cost", cand(true, true, "wafv2"), 1},
		{"bot protection OFF is nothing extra", cand(true, false, "wafv2"), 0},
		{"no cost declared — no claim to contradict", cand(false, true, "wafv2"), 0},
		{"another service entirely", cand(true, true, "s3"), 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adv := adviseChargeableComponent(c, tc.cand)
			if len(adv) != tc.want {
				t.Fatalf("advisories = %d, want %d: %+v", len(adv), tc.want, adv)
			}
			if tc.want == 0 {
				return
			}
			if !strings.Contains(adv[0].Detail, "BotControl") {
				t.Errorf("the advisory must NAME the component that is billed, got %q", adv[0].Detail)
			}
			// It must not pretend to know the price — that is the oracle this
			// deliberately is not.
			for _, forbidden := range []string{"USD", "EUR", "$"} {
				if strings.Contains(adv[0].Detail+adv[0].Next, forbidden) {
					t.Errorf("the advisory quotes a currency (%q) — it is not a price model "+
						"and must not read as one: %q", forbidden, adv[0].Detail)
				}
			}
		})
	}
}
