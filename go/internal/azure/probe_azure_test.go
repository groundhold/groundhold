package azure

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// tickClock returns a clock that advances a fixed step on every call — enough to make
// a sub-minute elapsed measurable (and round UP to 1m), never a wall-clock flake.
func tickClock(step time.Duration) func() time.Time {
	base := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	var n int64
	return func() time.Time {
		cur := base.Add(time.Duration(atomic.AddInt64(&n, 1)-1) * step)
		return cur
	}
}

// flexProbeFake serves the flex GET with a configurable FQDN / publicNetworkAccess /
// tags / sku / state. It captures whether the scratch PUT and DELETE happened.
type flexProbeState struct {
	fqdn, pubAccess, tagCap string
	putSeen, deleteSeen     atomic.Bool
	deleteStatus            int // status the scratch DELETE returns (default 202)
	scratchState            string
}

func flexProbeFake(t *testing.T, st *flexProbeState) *httptest.Server {
	t.Helper()
	if st.deleteStatus == 0 {
		st.deleteStatus = http.StatusAccepted
	}
	if st.scratchState == "" {
		st.scratchState = "Ready"
	}
	scratch := flexScratchName("pv-pg-src")
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			isScratch := strings.Contains(r.URL.Path, scratch)
			switch r.Method {
			case "PUT":
				st.putSeen.Store(true)
				w.WriteHeader(http.StatusAccepted)
				_, _ = w.Write([]byte(`{"properties":{"state":"Creating"}}`))
			case "DELETE":
				st.deleteSeen.Store(true)
				w.WriteHeader(st.deleteStatus)
			case "GET":
				if isScratch {
					_, _ = fmt.Fprintf(w, `{"location":"eastus","sku":{"name":"Standard_D2ds_v4","tier":"GeneralPurpose"},`+
						`"properties":{"state":%q}}`, st.scratchState)
					return
				}
				_, _ = fmt.Fprintf(w, `{"location":"eastus",`+
					`"tags":{"groundhold-capability":%q,"groundhold-environment":"prod"},`+
					`"sku":{"name":"Standard_D2ds_v4","tier":"GeneralPurpose"},`+
					`"properties":{"state":"Ready","fullyQualifiedDomainName":%q,`+
					`"network":{"publicNetworkAccess":%q}}}`, st.tagCap, st.fqdn, st.pubAccess)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

func probeSourcePID() string { return flexProviderID(testSub, "rg1", "pv-pg-src") }

func TestProbeUnwiredService(t *testing.T) {
	d := NewDriver(testSub)
	if _, err := d.Probe("blob", "store", "x", false); err == nil ||
		!strings.Contains(err.Error(), "not wired") {
		t.Fatalf("a non-flexpostgres service must refuse, got %v", err)
	}
}

func TestProbeExposureTrue(t *testing.T) {
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Enabled", tagCap: "db"}
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if addr != "src.postgres.database.azure.com:5432" {
			return nil, fmt.Errorf("unexpected addr %s", addr)
		}
		c, s := net.Pipe()
		go s.Close()
		return c, nil
	}
	out, err := d.Probe("flexpostgres", "db", probeSourcePID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Measurements) != 1 || out.Measurements[0].Path != "network.publicExposure" ||
		out.Measurements[0].Value != true {
		t.Fatalf("handshake success must measure exposure true: %+v", out)
	}
	if len(out.Failures) != 0 {
		t.Fatalf("no failures expected: %+v", out.Failures)
	}
}

func TestProbeExposureFalseNoEndpoint(t *testing.T) {
	// public FQDN present but access Disabled -> no endpoint to reach -> false
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Disabled", tagCap: "db"}
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		t.Fatalf("must not dial when there is no public endpoint (addr %s)", addr)
		return nil, nil
	}
	out, err := d.Probe("flexpostgres", "db", probeSourcePID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Measurements) != 1 || out.Measurements[0].Value != false {
		t.Fatalf("disabled public access must measure false: %+v", out)
	}
}

func TestProbeExposureInconclusive(t *testing.T) {
	// public endpoint present, handshake dies -> a FAILURE, never a fabricated value
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Enabled", tagCap: "db"}
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("timeout")
	}
	out, err := d.Probe("flexpostgres", "db", probeSourcePID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Measurements) != 0 || len(out.Failures) != 1 {
		t.Fatalf("filtered handshake must be a failure, not a value: %+v", out)
	}
	if out.Failures[0].Path != "network.publicExposure" || !out.Failures[0].Retryable {
		t.Fatalf("exposure failure shape: %+v", out.Failures[0])
	}
}

func TestProbeRTOHappyPath(t *testing.T) {
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Enabled", tagCap: "db"}
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.Now = tickClock(30 * time.Millisecond) // sub-minute elapsed -> rounds up to 1m
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		c, s := net.Pipe()
		go s.Close()
		return c, nil
	}
	out, err := d.Probe("flexpostgres", "db", probeSourcePID(), true)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range out.Failures {
		t.Errorf("unexpected failure: %+v", f)
	}
	found := false
	for _, m := range out.Measurements {
		if m.Path != "recovery.rto" {
			continue
		}
		found = true
		if !m.Intrusive {
			t.Error("restore-test must be marked intrusive")
		}
		if m.Value != "1m" {
			t.Errorf("rto = %v (want 1m, sub-minute rounds up)", m.Value)
		}
	}
	if !found {
		t.Fatalf("no rto measurement: %+v", out)
	}
	if !st.putSeen.Load() {
		t.Error("scratch PUT did not happen")
	}
	if !st.deleteSeen.Load() {
		t.Error("scratch was not deleted")
	}
}

func TestProbeIntrusiveRefusesForeignServer(t *testing.T) {
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Enabled", tagCap: "someone-else"}
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		c, s := net.Pipe()
		go s.Close()
		return c, nil
	}
	_, err := d.Probe("flexpostgres", "db", probeSourcePID(), true)
	if err == nil || !strings.Contains(err.Error(), "not ours") {
		t.Fatalf("intrusive probe on a foreign server must refuse, got %v", err)
	}
	if st.putSeen.Load() {
		t.Error("a refused intrusive probe must NOT PUT a scratch server")
	}
}

func TestProbeIntrusiveRefusesSubscriptionMismatch(t *testing.T) {
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Enabled", tagCap: "db"}
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	foreignSub := "11111111-1111-1111-1111-111111111111"
	pid := flexProviderID(foreignSub, "rg1", "pv-pg-src")
	_, err := d.Probe("flexpostgres", "db", pid, true)
	if err == nil || !strings.Contains(err.Error(), "subscription") {
		t.Fatalf("a cross-subscription probe must refuse, got %v", err)
	}
	if st.putSeen.Load() {
		t.Error("a cross-subscription probe must NOT PUT a scratch server")
	}
}

func TestProbeScratchDeleteFailureSurfacedLoudly(t *testing.T) {
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Enabled",
		tagCap: "db", deleteStatus: http.StatusInternalServerError}
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.Now = tickClock(30 * time.Millisecond)
	out, err := d.Probe("flexpostgres", "db", probeSourcePID(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !st.deleteSeen.Load() {
		t.Error("cleanup must be ATTEMPTED even so")
	}
	var loud bool
	for _, f := range out.Failures {
		if f.Path == "recovery.rto" && strings.Contains(f.Reason, "NOT deleted") &&
			strings.Contains(f.Reason, "costs money") {
			loud = true
		}
	}
	if !loud {
		t.Fatalf("a scratch that could not be deleted must be surfaced loudly: %+v", out.Failures)
	}
}

// TestProbeIntrusiveDisabledNoPut pins invariant 4: with allowIntrusive=false the
// probe runs only the non-intrusive exposure read and NEVER PUTs a billed scratch.
func TestProbeIntrusiveDisabledNoPut(t *testing.T) {
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Enabled", tagCap: "db"}
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		c, s := net.Pipe()
		go s.Close()
		return c, nil
	}
	if _, err := d.Probe("flexpostgres", "db", probeSourcePID(), false); err != nil {
		t.Fatal(err)
	}
	if st.putSeen.Load() {
		t.Fatal("allowIntrusive=false must NEVER create a scratch server")
	}
}

// TestProbeRTOTerminalFailedCleansUp: a scratch that lands in a terminal-failed
// state is torn down (cleanup attempted) and reported as a FAILURE, never a fabricated
// recovery.rto measurement.
func TestProbeRTOTerminalFailedCleansUp(t *testing.T) {
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Enabled",
		tagCap: "db", scratchState: "Failed"}
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.Now = tickClock(30 * time.Millisecond)
	out, err := d.Probe("flexpostgres", "db", probeSourcePID(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !st.deleteSeen.Load() {
		t.Error("a failed scratch must still be deleted")
	}
	for _, m := range out.Measurements {
		if m.Path == "recovery.rto" {
			t.Fatalf("a scratch that never became Ready must NOT yield an rto measurement: %+v", m)
		}
	}
	if len(out.Failures) == 0 {
		t.Error("a terminal-failed restore must surface a failure")
	}
}

// TestProbeRTOPollTimeoutCleansUp: a scratch stuck provisioning to the deadline is
// torn down and reported as a failure — never left leaking, never a fabricated value.
func TestProbeRTOPollTimeoutCleansUp(t *testing.T) {
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com", pubAccess: "Enabled",
		tagCap: "db", scratchState: "Creating"} // never reaches Ready
	srv := flexProbeFake(t, st)
	defer srv.Close()
	d := vnetTestDriver(t, srv)
	d.PollInterval = 0
	d.PollTimeout = 150 * time.Millisecond
	d.Now = tickClock(40 * time.Millisecond) // crosses the deadline within a few polls
	out, err := d.Probe("flexpostgres", "db", probeSourcePID(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !st.deleteSeen.Load() {
		t.Error("a scratch stuck provisioning must still be deleted at timeout")
	}
	for _, m := range out.Measurements {
		if m.Path == "recovery.rto" {
			t.Fatalf("a poll timeout must NOT yield an rto measurement: %+v", m)
		}
	}
	if len(out.Failures) == 0 {
		t.Error("a poll timeout must surface a failure")
	}
}
