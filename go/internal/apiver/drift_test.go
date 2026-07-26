package apiver

import "testing"

// drift_test.go exercises the PURE comparator with constructed inputs. These are
// hand-authored inputs to a pure function (fine — deterministic, no I/O); any
// input that CLAIMS to be a real provider response is canary-captured, never
// hand-written (D234 discipline). The load-bearing property is F3: AWS can never
// be pinned-current.

func gcpLive(vers ...LiveVersion) *LiveVersions {
	return &LiveVersions{Provider: "gcp", Service: "x", Versions: vers, Source: "discovery", FetchedAt: "2026-07-23T00:00:00Z"}
}

func TestCompareNoSignalIsCannotVerify(t *testing.T) {
	for _, prov := range []string{"aws", "gcp", "azure"} {
		got := Compare(Pin{Provider: prov, Service: "x", Version: "v1"}, nil)
		if got.Verdict != CannotVerify {
			t.Errorf("%s nil live: verdict = %q, want cannot-verify", prov, got.Verdict)
		}
		got = Compare(Pin{Provider: prov, Service: "x", Version: "v1"}, &LiveVersions{Provider: prov})
		if got.Verdict != CannotVerify {
			t.Errorf("%s empty live: verdict = %q, want cannot-verify", prov, got.Verdict)
		}
	}
}

func TestCompareGCPPinnedCurrent(t *testing.T) {
	pin := Pin{Provider: "gcp", Service: "compute", Version: "compute/v1"}
	live := gcpLive(
		LiveVersion{ID: "compute/v1", Stable: true, Preferred: true},
		LiveVersion{ID: "compute/beta", Stable: false},
		LiveVersion{ID: "compute/alpha", Stable: false},
	)
	got := Compare(pin, live)
	if got.Verdict != PinnedCurrent {
		t.Fatalf("verdict = %q, want pinned-current (evidence: %s)", got.Verdict, got.Evidence)
	}
}

func TestCompareGCPBetaDoesNotSupersedeStable(t *testing.T) {
	pin := Pin{Provider: "gcp", Service: "x", Version: "v1"}
	// a preferred BETA must not raise newer-available against a stable pin.
	live := gcpLive(
		LiveVersion{ID: "v1", Stable: true, Preferred: false},
		LiveVersion{ID: "v2beta1", Stable: false, Preferred: true},
	)
	if got := Compare(pin, live); got.Verdict != PinnedCurrent {
		t.Errorf("verdict = %q, want pinned-current (a beta must not supersede a stable pin)", got.Verdict)
	}
}

func TestCompareGCPNewerPreferred(t *testing.T) {
	pin := Pin{Provider: "gcp", Service: "x", Version: "v1"}
	live := gcpLive(
		LiveVersion{ID: "v1", Stable: true, Preferred: false},
		LiveVersion{ID: "v2", Stable: true, Preferred: true},
	)
	got := Compare(pin, live)
	if got.Verdict != NewerAvailable {
		t.Fatalf("verdict = %q, want newer-available", got.Verdict)
	}
	if len(got.Newer) != 1 || got.Newer[0] != "v2" {
		t.Errorf("newer = %v, want [v2]", got.Newer)
	}
}

func TestCompareGCPDeprecatedWhenAbsent(t *testing.T) {
	pin := Pin{Provider: "gcp", Service: "x", Version: "v1beta4"}
	live := gcpLive(LiveVersion{ID: "v1", Stable: true, Preferred: true})
	if got := Compare(pin, live); got.Verdict != Deprecated {
		t.Errorf("verdict = %q, want deprecated (pin no longer advertised)", got.Verdict)
	}
}

func TestCompareGCPDeprecatedFlag(t *testing.T) {
	pin := Pin{Provider: "gcp", Service: "x", Version: "v1"}
	live := gcpLive(
		LiveVersion{ID: "v1", Stable: true, Deprecated: true},
		LiveVersion{ID: "v2", Stable: true, Preferred: true},
	)
	got := Compare(pin, live)
	if got.Verdict != Deprecated {
		t.Fatalf("verdict = %q, want deprecated (flag)", got.Verdict)
	}
	if len(got.Newer) != 1 || got.Newer[0] != "v2" {
		t.Errorf("newer = %v, want [v2] to aid the bump", got.Newer)
	}
}

func TestCompareAzureNewerByDate(t *testing.T) {
	pin := Pin{Provider: "azure", Service: "x", Version: "2023-05-01"}
	live := &LiveVersions{Provider: "azure", Service: "x", Versions: []LiveVersion{
		{ID: "2023-05-01", Stable: true},
		{ID: "2024-06-01", Stable: true},
		{ID: "2025-01-01-preview", Stable: false},
	}}
	got := Compare(pin, live)
	if got.Verdict != NewerAvailable {
		t.Fatalf("verdict = %q, want newer-available", got.Verdict)
	}
	// the preview must NOT be listed as a superseding stable version.
	for _, n := range got.Newer {
		if n == "2025-01-01-preview" {
			t.Errorf("newer %v must not include a preview version", got.Newer)
		}
	}
}

// TestCompareAWSNeverPinnedCurrent is the load-bearing honesty property (F3):
// across every shape of live input, AWS never returns pinned-current.
func TestCompareAWSNeverGreen(t *testing.T) {
	pin := Pin{Provider: "aws", Service: "ec2", Version: "2016-11-15"}
	cases := []*LiveVersions{
		// exact match in the SDK models — still not proof of currency.
		{Provider: "aws", Versions: []LiveVersion{{ID: "2016-11-15", Stable: true, Preferred: true}}},
		// a newer model exists.
		{Provider: "aws", Versions: []LiveVersion{
			{ID: "2016-11-15", Stable: true},
			{ID: "2020-01-01", Stable: true},
		}},
		// only older models.
		{Provider: "aws", Versions: []LiveVersion{{ID: "2010-01-01", Stable: true}}},
	}
	for i, live := range cases {
		got := Compare(pin, live)
		if got.Verdict == PinnedCurrent {
			t.Errorf("case %d: AWS returned pinned-current — must be structurally impossible", i)
		}
	}
	// exact-match case -> cannot-verify (match is not proof).
	if got := Compare(pin, cases[0]); got.Verdict != CannotVerify {
		t.Errorf("AWS exact match: verdict = %q, want cannot-verify", got.Verdict)
	}
	// newer-model case -> newer-available.
	if got := Compare(pin, cases[1]); got.Verdict != NewerAvailable {
		t.Errorf("AWS newer model: verdict = %q, want newer-available", got.Verdict)
	}
}
