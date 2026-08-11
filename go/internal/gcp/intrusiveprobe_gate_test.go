package gcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// D461: the intrusive-probe register on GCP. One prober (cloudsql), gated on the
// capability label before the scratch restore is created. The register exists so the
// second one cannot land without the gate.
func TestRefusesIntrusiveProbeForeignCloudSQL(t *testing.T) {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	p := &certifynet.IntrusiveProbeProbe{
		Name:     "gcp/cloudsql",
		Classify: gcpReadRole,
		ForeignServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if r.Method != http.MethodGet {
						t.Errorf("an intrusive probe on a foreign instance must not %s "+
							"— the gate fires before any billed restore", r.Method)
						w.WriteHeader(400)
						return
					}
					_, _ = w.Write([]byte(`{"databaseVersion":"POSTGRES_16",` +
						`"name":"source-db","region":"europe-central2","settings":{` +
						`"tier":"db-custom-2-8192","edition":"ENTERPRISE",` +
						`"userLabels":{"groundhold-capability":"someone-else"},` +
						`"ipConfiguration":{"ipv4Enabled":true}},` +
						`"ipAddresses":[{"type":"PRIMARY","ipAddress":"10.0.0.5"}]}`))
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Prober {
			d := NewDriver("acme-prod")
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.PollInterval = 0
			d.PollTimeout = 100 * time.Millisecond
			return d
		},
		Probe: func(pr provider.Prober) (provider.ProbeOutcome, error) {
			return pr.Probe("cloudsql", "db", "acme-prod:europe-central2:source-db", true)
		},
	}
	certifynet.CertifyIntrusiveProbeRefusesForeign(t, p)
}
