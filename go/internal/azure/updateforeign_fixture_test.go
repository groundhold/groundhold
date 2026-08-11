package azure

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// D460: the update register on Azure — the cloud where the verb is most dangerous. An
// ARM update is frequently a PUT, and a PUT to an occupied path is an UNCONDITIONAL
// UPSERT (D254): without an ownership check the update does not fail against a stranger's
// resource, it OVERWRITES it, in place, silently.

type azUpdateCase struct {
	svc, cap string
	server   func(t *testing.T) *httptest.Server
	pid      string
	attrs    map[string]any
	impl     map[string]any
	changes  []string
	fromID   bool
}

func runAzForeignUpdate(t *testing.T, c azUpdateCase) {
	t.Helper()
	p := &certifynet.ForeignProbe{
		Name:                 "azure/" + c.svc,
		Classify:             azReadRole,
		OwnershipFromIDAlone: c.fromID,
		ForeignServer:        func() *httptest.Server { return c.server(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(testSub)
			d.HTTP = &http.Client{Transport: rt}
			d.BaseURL = happyURL
			d.token = "test-token"
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Update: func(pr provider.Provider) provider.CreateResult {
			return pr.Update(c.svc, c.cap, "prod", c.pid, c.attrs, c.impl, c.changes, "k")
		},
	}
	certifynet.CertifyUpdateRefusesForeign(t, p)
}

func TestRefusesForeignUpdateAzLogAnalytics(t *testing.T) {
	runAzForeignUpdate(t, azUpdateCase{svc: "loganalytics", cap: "app-logs",
		server: func(t *testing.T) *httptest.Server { return laServer(t, "someone-else", 90) },
		pid:    laProviderID(testSub, "rg1", azResourceName("pv-la", "prod", "app-logs", 1)),
		attrs:  laAttrs(), impl: laImpl(), changes: []string{"retention.days"}})
}

func TestRefusesForeignUpdateAzBackupPolicy(t *testing.T) {
	runAzForeignUpdate(t, azUpdateCase{svc: "backuppolicy", cap: "dr-plan", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			return backupPolicyServer(t, "someone-elses-policy", "westeurope")
		},
		pid:   backupPolicyProviderID(testSub, "rg1", "bv-prod", "someone-elses-policy"),
		attrs: backupPolicyAttrs(), impl: backupPolicyImpl(),
		changes: []string{"schedule.frequency"}})
}

func TestRefusesForeignUpdateAzConsumptionBudget(t *testing.T) {
	runAzForeignUpdate(t, azUpdateCase{svc: "consumptionbudget", cap: "spend-guard",
		fromID: true,
		server: func(t *testing.T) *httptest.Server {
			return consBudgetServer(t, "someone-elses-budget")
		},
		pid:   consBudgetProviderID(testSub, "", "someone-elses-budget"),
		attrs: consBudgetAttrs(), impl: consBudgetImpl(),
		changes: []string{"alert.threshold"}})
}

func TestRefusesForeignUpdateAzServiceBus(t *testing.T) {
	a := sbQueueAttrs()
	a["reliability.deadLetter"] = true
	runAzForeignUpdate(t, azUpdateCase{svc: "servicebusqueue", cap: "orders",
		server: func(t *testing.T) *httptest.Server { return sbArmFake(t, "someone-else") },
		pid: sbProviderID("sbq", testSub, "rg1", serviceBusNamespace("prod", "orders", 1),
			azResourceName("q", "prod", "orders", 1)),
		attrs:   a,
		impl:    map[string]any{"resource_group": "rg1", "max_delivery_count": 9},
		changes: []string{"reliability.deadLetter"}})
}

func TestRefusesForeignUpdateAzAKS(t *testing.T) {
	name := aksPlanName(t)
	runAzForeignUpdate(t, azUpdateCase{svc: "aks", cap: aksCap,
		server: func(t *testing.T) *httptest.Server {
			f := newFakeAKS(testSub, "rg1", name)
			f.exists = true
			f.tags = map[string]string{"team": "someone-else"}
			return httptest.NewServer(f.handler())
		},
		pid:     aksProviderID(testSub, "rg1", name),
		attrs:   map[string]any{"cluster.version": "1.30"},
		changes: []string{"cluster.version"}})
}

// TestRefusesForeignUpdateAzDNSRecord: the repoint. The evidence is the parent ZONE's
// tags — the same boundary AWS and GCP drew independently (D408/D420/D449).
func TestRefusesForeignUpdateAzDNSRecord(t *testing.T) {
	runAzForeignUpdate(t, azUpdateCase{svc: "dnsrecord", cap: azDNSRecordCap,
		server: func(t *testing.T) *httptest.Server { return azDNSRecordServer(t, "someone-else", nil) },
		pid:    azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect"),
		attrs: map[string]any{"dns.type": "CNAME", "dns.target": "new-origin.example.net",
			"service.managed": true},
		impl: azDNSRecordImpl(), changes: []string{"dns.target"}})
}

func TestRefusesForeignUpdateAzACSEmail(t *testing.T) {
	runAzForeignUpdate(t, azUpdateCase{svc: "acsemail", cap: "email",
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						_, _ = w.Write([]byte(`{"location":"westeurope","tags":{` +
							`"groundhold-capability":"someone-else",` +
							`"groundhold-environment":"prod"},` +
							`"properties":{"provisioningState":"Succeeded",` +
							`"dataLocation":"Europe"}}`))
						return
					}
					t.Errorf("update must not %s a foreign-tagged emailService", r.Method)
					w.WriteHeader(400)
				}))
		},
		pid:   acsEmailProviderID(testSub, "rg1", "pvmailsvc"), // the name acsEmailImpl() pins
		attrs: acsEmailAttrs(), impl: acsEmailImpl(),
		changes: []string{"authentication.dkim"}})
}

// TestRefusesForeignUpdateAzActivityLog: the delete's sibling from D458. The update was
// already right — it refuses on a name mismatch, which is what made the delete's silence
// visible in the first place.
func TestRefusesForeignUpdateAzActivityLog(t *testing.T) {
	runAzForeignUpdate(t, azUpdateCase{svc: "activitylog", cap: "audit", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					t.Errorf("update must not %s a setting outside our naming scheme", r.Method)
					w.WriteHeader(400)
				}))
		},
		pid:   activityLogProviderID(testSub, "SecurityTeam-ActivityLog-Archive"),
		attrs: activityLogAttrs(), impl: activityLogImpl(),
		changes: []string{"delivery.assured"}})
}
