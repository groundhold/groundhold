package progress

import "testing"

func TestBandNilBelowMinSamples(t *testing.T) {
	if Band(nil) != nil {
		t.Fatal("empty history must yield no band")
	}
	if Band([]int64{1000, 2000}) != nil {
		t.Fatal("fewer than 3 samples must yield no band (never a fabricated number)")
	}
}

func TestBandInferredWithHistory(t *testing.T) {
	b := Band([]int64{6000, 7000, 8000, 7000, 6500})
	if b == nil {
		t.Fatal("5 samples must yield a band")
	}
	if b.Basis != BasisInferred {
		t.Fatalf("basis=%q, want inferred", b.Basis)
	}
	if b.AtLeastMS != 6000 {
		t.Fatalf("atLeast=%d, want 6000 (fastest seen)", b.AtLeastMS)
	}
	if b.WorstMS < b.AtLeastMS {
		t.Fatalf("worst %d < atLeast %d", b.WorstMS, b.AtLeastMS)
	}
	if b.Samples != 5 {
		t.Fatalf("samples=%d, want 5", b.Samples)
	}
	// typical (EWMA) sits within the observed range
	if b.TypicalMS < b.AtLeastMS || b.TypicalMS > b.WorstMS {
		t.Fatalf("typical %d outside [%d,%d]", b.TypicalMS, b.AtLeastMS, b.WorstMS)
	}
}

func TestBandWithdrawnPastWorst(t *testing.T) {
	b := Band([]int64{5000, 6000, 7000})
	if b == nil {
		t.Fatal("expected a band")
	}
	if BandWithdrawn(b, b.WorstMS-1) {
		t.Fatal("within worst must not withdraw")
	}
	if !BandWithdrawn(b, b.WorstMS+1) {
		t.Fatal("beyond worst must withdraw (a beaten band is a lie)")
	}
	if BandWithdrawn(nil, 999999) {
		t.Fatal("no band cannot be withdrawn")
	}
}
