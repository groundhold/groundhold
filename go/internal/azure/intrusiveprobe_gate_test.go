package azure

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// D461: the intrusive-probe register on Azure. One prober (flexpostgres), gated on the
// capability tag before the scratch server is PUT — which matters more here than
// elsewhere, because on Azure the scratch creation is a PUT and a PUT to an occupied
// path overwrites (D254).
func TestRefusesIntrusiveProbeForeignFlexServer(t *testing.T) {
	st := &flexProbeState{fqdn: "src.postgres.database.azure.com",
		pubAccess: "Enabled", tagCap: "someone-else"}
	p := &certifynet.IntrusiveProbeProbe{
		Name:          "azure/flexpostgres",
		Classify:      azReadRole,
		ForeignServer: func() *httptest.Server { return flexProbeFake(t, st) },
		New: func(happyURL string, rt http.RoundTripper) provider.Prober {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
				c, s := net.Pipe()
				go s.Close()
				return c, nil
			}
			return d
		},
		Probe: func(pr provider.Prober) (provider.ProbeOutcome, error) {
			return pr.Probe("flexpostgres", "db", probeSourcePID(), true)
		},
	}
	certifynet.CertifyIntrusiveProbeRefusesForeign(t, p)
	if st.putSeen.Load() {
		t.Fatal("a scratch server was PUT for a resource that is not ours")
	}
}
