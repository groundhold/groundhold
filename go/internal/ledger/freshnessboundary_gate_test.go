package ledger

import "testing"

// D666. `spec/state-model.md`: "at evaluation time T, an observation is usable iff
// `observedAt + ttlSeconds >= T`" — so it is expired iff its AGE EXCEEDS the ttl.
// Six places decided this. Four used `>`; `posture` and `refresh` used `>=`, so a
// proof decayed for them one second before it decayed for `audit`, `plan`, `apply`
// and `forecast`. Measured on one record (observedAt 00:00:10Z, ttl 100):
//
//	--at 00:01:49Z (age 99)   audit ok     posture managedOk=2 decayed=0
//	--at 00:01:50Z (age 100)  audit ok     posture managedOk=0 decayed=2   <- disagree
//	--at 00:01:51Z (age 101)  audit exit 2 posture decayed=2
//
// posture's own printed remediation chains refresh → audit → posture, so the
// operator was told to refresh a proof the auditor still accepted, and posture kept
// reporting decayed afterwards.
func TestTheFreshnessBoundaryIsTheSpecsBoundary(t *testing.T) {
	const obs = "2026-07-01T00:00:10Z"
	base, err := ParseTs(obs)
	if err != nil {
		t.Fatal(err)
	}
	const ttl = 100
	for _, tc := range []struct {
		age     int
		expired bool
		why     string
	}{
		{ttl - 1, false, "one second inside the window is usable"},
		{ttl, false, "AT the ttl the observation is still usable: the spec says " +
			"observedAt + ttl >= T, and at age == ttl those are equal"},
		{ttl + 1, true, "one second past the ttl is expired"},
	} {
		if got := ObservationExpired(obs, ttl, base+tc.age); got != tc.expired {
			t.Errorf("age %d: expired = %v, want %v — %s", tc.age, got, tc.expired, tc.why)
		}
	}
}

// An unreadable observedAt must be EXPIRED, never fresh: a freshness decision made
// against a clock nobody could read is the N1 failure this project keeps closing.
func TestAnUnreadableObservationTimeIsExpired(t *testing.T) {
	for _, bad := range []string{"", "not-a-time", "2026-13-45T99:99:99Z", "1783000000"} {
		if !ObservationExpired(bad, 100000, 1) {
			t.Errorf("observedAt %q was treated as fresh", bad)
		}
	}
}
