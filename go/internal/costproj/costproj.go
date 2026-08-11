// Package costproj aggregates a plan's per-action cost.monthly claims into a
// reporting-currency estimate over week/month/year (D202). It is a PROJECTION,
// never a quote, and never FX: costs in a currency other than the reporting one
// are summed and shown SEPARATELY, never coerced (invariant #2). The result is
// rendered to stderr at the end of plan/converge, before apply — it is display,
// deliberately NOT part of the hashed plan (the reporting currency is a view
// choice; the same plan must hash identically whatever currency you read it in).
package costproj

import (
	"fmt"
	"io"
	"sort"
)

// Item is one action's cost claim, extracted from the plan + candidate.
type Item struct {
	Amount   float64
	Currency string
	Basis    string // declared|inferred|assumed|unknown; "" when the action declared no cost.monthly
}

// Period factors from a MONTHLY base. A month is not four weeks, so weekly/yearly
// are documented derivations, not separate billing: yearly = monthly×12, weekly =
// yearly/52. Deterministic (#6).
const (
	monthsPerYear = 12.0
	weeksPerYear  = 52.0
)

type currencyTotal struct {
	Currency string
	Monthly  float64
}

// Projection is the computed estimate.
type Projection struct {
	Currency string          // reporting currency
	Monthly  float64         // reporting-currency subtotal
	Basis    string          // weakest provenance among contributing costs
	Priced   int             // capabilities with a declared cost.monthly
	Total    int             // all capabilities the plan touches
	Other    []currencyTotal // non-reporting currencies, sorted, uncoerced
}

func (p Projection) weekly() float64 { return p.Monthly * monthsPerYear / weeksPerYear }
func (p Projection) yearly() float64 { return p.Monthly * monthsPerYear }

// CurrencyAmount is a per-currency monthly total (JSON-serialized for the console).
type CurrencyAmount struct {
	Currency string  `json:"currency"`
	Monthly  float64 `json:"monthly"`
}

// Report is the machine-readable projection — the AUTHORITATIVE cost number
// `groundhold cost --json` emits and the console ingests verbatim, so a dashboard
// figure equals the CLI figure (grounding: no re-computation downstream).
type Report struct {
	Currency           string           `json:"currency"`
	Weekly             float64          `json:"weekly"`
	Monthly            float64          `json:"monthly"`
	Yearly             float64          `json:"yearly"`
	Basis              string           `json:"basis"`
	PricedCapabilities int              `json:"pricedCapabilities"`
	TotalCapabilities  int              `json:"totalCapabilities"`
	OtherCurrencies    []CurrencyAmount `json:"otherCurrencies,omitempty"`
}

// Report renders the projection as the serializable form.
func (p Projection) Report() Report {
	r := Report{
		Currency: p.Currency, Weekly: p.weekly(), Monthly: p.Monthly,
		Yearly: p.yearly(), Basis: p.Basis,
		PricedCapabilities: p.Priced, TotalCapabilities: p.Total,
	}
	for _, o := range p.Other {
		r.OtherCurrencies = append(r.OtherCurrencies, CurrencyAmount(o))
	}
	return r
}

// certainty ranks provenance so the weakest (least certain) is reported — a cost
// built on assumptions must not read as fact.
var certainty = map[string]int{"declared": 3, "inferred": 2, "assumed": 1, "unknown": 0}

// Compute aggregates items into a reporting-currency projection. Reporting
// currency costs form the headline; every other currency is a separate,
// uncoerced line. total is the count of capabilities the plan touches so
// coverage ("M of N") is honest about capabilities with no declared cost.
func Compute(items []Item, reportingCCY string, total int) Projection {
	byCCY := map[string]float64{}
	priced := 0
	weakest := ""
	for _, it := range items {
		if it.Currency == "" { // no cost.monthly declared for this capability
			continue
		}
		byCCY[it.Currency] += it.Amount
		priced++
		b := it.Basis
		if b == "" {
			b = "declared"
		}
		if weakest == "" || certainty[b] < certainty[weakest] {
			weakest = b
		}
	}
	p := Projection{
		Currency: reportingCCY,
		Monthly:  byCCY[reportingCCY],
		Basis:    weakest,
		Priced:   priced,
		Total:    total,
	}
	for ccy, amt := range byCCY {
		if ccy == reportingCCY {
			continue
		}
		p.Other = append(p.Other, currencyTotal{Currency: ccy, Monthly: amt})
	}
	sort.Slice(p.Other, func(i, j int) bool { return p.Other[i].Currency < p.Other[j].Currency })
	return p
}

// Render writes the human estimate. It always states it is an estimate and how
// much of the plan it covers, so a partial or assumption-based figure can never
// masquerade as a bill.
func (p Projection) Render(w io.Writer) {
	basis := p.Basis
	if basis == "" {
		basis = "no declared cost"
	}
	// D595: with partial coverage the figure can only be wrong ONE way — every
	// capability without a declared cost still costs something — so it is a floor,
	// not a central estimate, and a tilde reads as the latter. The project already
	// uses this word where a count rests on partial data (shadowLowerBound); a price
	// deserves it more, because the error runs toward "cheaper than it is".
	lead, mark := "Estimated cost", "~"
	if p.Priced < p.Total {
		lead, mark = "Estimated cost AT LEAST", "≥"
	}
	fmt.Fprintf(w, "%s (%s) — projection, not a quote:\n", lead, basis)
	fmt.Fprintf(w, "  %s %s / month   %s / week   %s / year\n", mark,
		money(p.Monthly, p.Currency), money(p.weekly(), p.Currency),
		money(p.yearly(), p.Currency))
	fmt.Fprintf(w, "  based on %d of %d capabilities with a declared cost.monthly\n",
		p.Priced, p.Total)
	for _, o := range p.Other {
		fmt.Fprintf(w, "  + %s / month (declared in %s - NOT converted)\n",
			money(o.Monthly, o.Currency), o.Currency)
	}
}

func money(amt float64, ccy string) string {
	return fmt.Sprintf("%.2f %s", amt, ccy)
}
