package aws

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// D461: the intrusive-probe register on AWS. Both probers gate — rds and aurora share
// gateIntrusive — and both refusals have been driven by their own tests since they were
// written. What did not exist is the statement that ALL of them do, or a test that would
// notice a third prober landing without one.
//
// The mutation count is the load-bearing assertion here, more than anywhere else in the
// sweep: an intrusive probe's damage is not a lost resource but a BILLED restore against
// an estate that never agreed to it, and a prober that asks for the restore and then
// errors reads identically to one that refused first.

type intrusiveProbeCase struct {
	svc, cap string
	server   func(t *testing.T) *httptest.Server
	pid      string
	classify certifynet.Classifier
}

func runIntrusiveProbeForeign(t *testing.T, c intrusiveProbeCase) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.IntrusiveProbeProbe{
		Name:          "aws/" + c.svc,
		Classify:      c.classify,
		ForeignServer: func() *httptest.Server { return c.server(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Prober {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000"
			d.RDSBaseURL = happyURL
			return d
		},
		Probe: func(pr provider.Prober) (provider.ProbeOutcome, error) {
			return pr.Probe(c.svc, c.cap, c.pid, true)
		},
	}
	certifynet.CertifyIntrusiveProbeRefusesForeign(t, p)
}

func TestRefusesIntrusiveProbeForeignRDS(t *testing.T) {
	var restore atomic.Bool
	runIntrusiveProbeForeign(t, intrusiveProbeCase{svc: "rds", cap: "db",
		server: func(t *testing.T) *httptest.Server {
			return rdsProbeServer(t, rdsProbeOpts{account: "000000000000",
				capabilityTag: "someone-else", snapshotStatus: "available",
				restoreCalled: &restore})
		},
		pid: "rds:eu-central-1:db-x", classify: rdsQueryRole})
	if restore.Load() {
		t.Fatal("restore was issued against a resource that is not ours")
	}
}

func TestRefusesIntrusiveProbeForeignAurora(t *testing.T) {
	var restore atomic.Bool
	runIntrusiveProbeForeign(t, intrusiveProbeCase{svc: "aurora", cap: "db",
		server: func(t *testing.T) *httptest.Server {
			return auroraProbeServer(t, auroraProbeOpts{account: "000000000000",
				capabilityTag: "someone-else", snapshotStatus: "available",
				restoreCalled: &restore})
		},
		pid: auroraProviderID("eu-central-1", "cluster-x"), classify: rdsQueryRole})
	if restore.Load() {
		t.Fatal("restore was issued against a cluster that is not ours")
	}
}

// D779. The register named two tests for the intrusive-probe consent gate and both drive
// the SAME guard: each fixture serves the acting account with a foreign capability tag, so
// the tag check refuses and the ACCOUNT check never decides anything. A mutant that
// disabled the account branch entirely passed both.
//
// The account branch is the one whose failure means a restore test — a WRITE — executed
// against, and billed to, an account that is not ours. It gets its own case now: a foreign
// account with a MATCHING tag, so only the account guard can refuse.
func TestRefusesIntrusiveProbeForeignAccount(t *testing.T) {
	var restore atomic.Bool
	runIntrusiveProbeForeign(t, intrusiveProbeCase{svc: "rds", cap: "db",
		server: func(t *testing.T) *httptest.Server {
			return rdsProbeServer(t, rdsProbeOpts{
				account:        "999999999999", // NOT the acting account
				capabilityTag:  "db",           // ours by tag — only the account differs
				snapshotStatus: "available",
				restoreCalled:  &restore})
		},
		pid: "rds:eu-central-1:db-x", classify: rdsQueryRole})
	if restore.Load() {
		t.Fatal("a restore was issued against a FOREIGN account — the tag matched, and " +
			"the account guard is the only thing standing between an intrusive probe and " +
			"someone else's data (D779)")
	}
}
