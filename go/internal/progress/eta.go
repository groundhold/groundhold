package progress

import "sort"

// Band computes an honest duration estimate from a history of MEASURED success
// durations (milliseconds) for one action key (D227). It never invents a number:
// with fewer than minSamples it returns nil (basis would be unknown), and the
// band it does return is basis: inferred — extrapolated from history, never a
// promise. atLeast is the fastest seen, typical an EWMA of the series (recent
// weighted heaviest), worst the p95.
//
// The caller supplies ONLY successful-run durations; failure durations predict
// nothing about a success ETA and are kept in a separate population (D227).
//
// Note on the durable source (D227 addendum): the deterministic ledger stamps
// receipts with the LOGICAL coordination clock, which does not advance within a
// run — so receipt brackets are zero-width and carry no wall-duration, and
// recording measured wall-time INTO the ledger would break its determinism (the
// conformance suite pins ledger hashes). An honest band therefore needs a durable
// timing store OUTSIDE the hash-chained ledger; until that exists the runtime
// emits no band (nil), which is the correct fail-closed behaviour, not a gap.
func Band(successMS []int64) *ETABand {
	const minSamples = 3
	if len(successMS) < minSamples {
		return nil
	}
	sorted := append([]int64(nil), successMS...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	atLeast := sorted[0]
	worst := percentile(sorted, 0.95)
	typical := ewma(successMS)

	// A degenerate band (atLeast > worst) can only come from a broken input;
	// refuse to emit rather than show something incoherent.
	if atLeast > worst {
		return nil
	}
	return &ETABand{
		AtLeastMS: atLeast,
		TypicalMS: typical,
		WorstMS:   worst,
		Basis:     BasisInferred,
		Samples:   len(successMS),
	}
}

// BandWithdrawn reports whether a live elapsed has already exceeded a band's
// worst case (D227): a band already beaten is a lie, so the renderer withdraws
// it for prose ("beyond seen worst ...") rather than showing a stale estimate.
func BandWithdrawn(b *ETABand, elapsedMS int64) bool {
	return b != nil && elapsedMS > b.WorstMS
}

// ewma weights recent samples heaviest (the series is in observation order).
func ewma(series []int64) int64 {
	const alpha = 0.4
	avg := float64(series[0])
	for _, v := range series[1:] {
		avg = alpha*float64(v) + (1-alpha)*avg
	}
	return int64(avg + 0.5)
}

// percentile returns the value at p in a SORTED slice (nearest-rank).
func percentile(sorted []int64, p float64) int64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p*float64(len(sorted)-1) + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
