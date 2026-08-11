package azure

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// D457: the delete-side register on the third cloud, and the one where the API is least
// forgiving. An ARM DELETE against a resourceId is unconditional — there is no
// "only if it is mine" precondition to send — so the ownership check must happen in the
// driver, before the mutation, every time. D254 built the create-side pre-read for the
// same reason (a PUT to an occupied path OVERWRITES); this is its mirror.
type azForeignCase struct {
	svc, cap string
	server   func(t *testing.T) *httptest.Server
	pid      string
	// fromID: ownership is derivable from the content-addressed providerId, with no
	// estate read possible. Rare on Azure — nearly everything here carries ARM tags.
	fromID bool
}

func runAzForeignDelete(t *testing.T, c azForeignCase) {
	t.Helper()
	p := &certifynet.ForeignProbe{
		Name:          "azure/" + c.svc,
		Classify:      azReadRole,
		ForeignServer: func() *httptest.Server { return c.server(t) },
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
		Delete: func(pr provider.Provider) provider.CreateResult {
			return pr.Delete(c.svc, c.cap, "prod", c.pid, "k")
		},
		OwnershipFromIDAlone: c.fromID,
	}
	certifynet.CertifyDeleteRefusesForeign(t, p)
}

func TestRefusesForeignDeleteAzAzkafka(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "azkafka", cap: "bus",
		server: func(t *testing.T) *httptest.Server { return azKafkaServer(t, "someone-else", false, false) },
		pid:    azKafkaProviderID(testSub, "rg1", azKafkaNamespaceName("prod", "bus", 1))})
}

func TestRefusesForeignDeleteAzRediscache(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "rediscache", cap: "sessions",
		server: func(t *testing.T) *httptest.Server {
			return redisAzServer(t, "someone-else", "Basic", "6.0", "Disabled", false)
		},
		pid: redisAzureProviderID(testSub, "rg1", azResourceName("pv-cache", "prod", "sessions", 1))})
}

func TestRefusesForeignDeleteAzAzurecdn(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "azurecdn", cap: "edge",
		server: func(t *testing.T) *httptest.Server {
			return azCDNServer(t, "someone-else", "origin.example.com", "https-only")
		},
		pid: azureCDNProviderID(testSub, "rg1", azCDNProfileName("prod", "edge", 1), azResourceName("pv-ep", "prod", "edge", 1))})
}

func TestRefusesForeignDeleteAzContainerappsjob(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "containerappsjob", cap: "worker",
		server: func(t *testing.T) *httptest.Server { return cajServer(t, "someone-else", "Manual", "img") },
		pid:    containerAppsJobProviderID(testSub, "rg1", azResourceName("pv-job", "prod", "worker", 1))})
}

func TestRefusesForeignDeleteAzKeyvault(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "keyvault", cap: "dbcreds",
		server: func(t *testing.T) *httptest.Server { return kvServer(t, "someone-else", "Disabled") },
		pid:    keyVaultProviderID(testSub, "rg1", keyVaultName("prod", "dbcreds", 1))})
}

func TestRefusesForeignDeleteAzAzurefiles(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "azurefiles", cap: "shared",
		server: func(t *testing.T) *httptest.Server {
			return azfilesServer(t, "someone-else", "StorageV2", "Standard_LRS", "")
		},
		pid: azFilesProviderID(testSub, "rg1", azStorageName("prod", "shared", 1), azFilesShareName("prod", "shared", 1))})
}

func TestRefusesForeignDeleteAzEventhubs(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "eventhubs", cap: "events",
		server: func(t *testing.T) *httptest.Server { return ehServer(t, "someone-else", false, false, 1) },
		pid:    eventHubsProviderID(testSub, "rg1", eventHubsNamespaceName("prod", "events", 1), azResourceName("pv-hub", "prod", "events", 1))})
}

func TestRefusesForeignDeleteAzCosmos(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "cosmos", cap: "sessions",
		server: func(t *testing.T) *httptest.Server { return cosmosServer(t, "someone-else", "Periodic", "") },
		pid:    cosmosProviderID(testSub, "rg1", cosmosAccountName("prod", "sessions", 1))})
}

func TestRefusesForeignDeleteAzApim(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "apim", cap: "front",
		server: func(t *testing.T) *httptest.Server { return apimServer(t, "someone-else") },
		pid:    apimProviderID(testSub, "rg1", apimServiceName("prod", "front", 1))})
}

func TestRefusesForeignDeleteAzKeyvaultkey(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "keyvaultkey", cap: "datakey",
		server: func(t *testing.T) *httptest.Server { return azKeyServer(t, "someone-else", "RSA", "") },
		pid:    azureKeyProviderID(testSub, "rg1", "eastus", keyVaultName("prod", "datakey", 1), azResourceName("pv-key", "prod", "datakey", 1))})
}

func TestRefusesForeignDeleteAzContainerapps(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "containerapps", cap: "api",
		server: func(t *testing.T) *httptest.Server { return acaArmFake(t, "someone-else") },
		pid:    acaProviderID(testSub, "rg1", containerAppName("prod", "api", 1))})
}

func TestRefusesForeignDeleteAzConsumptionbudget(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "consumptionbudget", cap: "spend-guard", fromID: true, //a consumption budget carries no ARM tags
		server: func(t *testing.T) *httptest.Server { return consBudgetServer(t, "someone-elses-budget") },
		pid:    consBudgetProviderID(testSub, "", "someone-elses-budget")})
}

func TestRefusesForeignDeleteAzAisearch(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "aisearch", cap: "catalog",
		server: func(t *testing.T) *httptest.Server {
			return aiSearchServer(t, "someone-else", "basic", 1, "enabled", "")
		},
		pid: aiSearchProviderID(testSub, "rg1", aiSearchName("prod", "catalog", 1))})
}

func TestRefusesForeignDeleteAzLoganalytics(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "loganalytics", cap: "app-logs",
		server: func(t *testing.T) *httptest.Server { return laServer(t, "someone-else", 90) },
		pid:    laProviderID(testSub, "rg1", azResourceName("pv-la", "prod", "app-logs", 1))})
}

func TestRefusesForeignDeleteAzManagedidentity(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "managedidentity", cap: "runner",
		server: func(t *testing.T) *httptest.Server { return uamiServer(t, "someone-else", "batch runner") },
		pid:    uamiProviderID(testSub, "rg1", azResourceName("id", "prod", "runner", 1))})
}

func TestRefusesForeignDeleteAzServicebusqueue(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "servicebusqueue", cap: "orders",
		server: func(t *testing.T) *httptest.Server { return sbArmFake(t, "someone-else") },
		pid:    sbProviderID("sbq", testSub, "rg1", serviceBusNamespace("prod", "orders", 1), azResourceName("q", "prod", "orders", 1))})
}

func TestRefusesForeignDeleteAzFlexpostgres(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "flexpostgres", cap: "db",
		server: func(t *testing.T) *httptest.Server { return flexArmFake(t, "someone-else") },
		pid:    flexProviderID(testSub, "rg1", flexServerName("prod", "db", 1))})
}

func TestRefusesForeignDeleteAzBlob(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "blob", cap: "assets",
		server: func(t *testing.T) *httptest.Server { return blobArmFake(t, "someone-else") },
		pid:    blobProviderID(testSub, "rg1", azStorageName("prod", "assets", 1), blobContainerName("prod", "assets", 1))})
}

func TestRefusesForeignDeleteAzFrontdoorwaf(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "frontdoorwaf", cap: "edge",
		server: func(t *testing.T) *httptest.Server { return fdWafServer(t, "someone-else", "Detection", false, false) },
		pid:    frontDoorWAFProviderID(testSub, "rg1", frontDoorWAFName("prod", "edge", 1))})
}

func TestRefusesForeignDeleteAzBackuppolicy(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "backuppolicy", cap: "dr-plan", fromID: true, //a backup policy carries no ARM tags
		server: func(t *testing.T) *httptest.Server {
			return backupPolicyServer(t, "someone-elses-policy", "westeurope")
		},
		pid: backupPolicyProviderID(testSub, "rg1", "bv-prod", "someone-elses-policy")})
}
func TestRefusesForeignDeleteAzMetricalert(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "metricalert", cap: "cpu",
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
						`"properties":{"criteria":{"allOf":[{"metricName":"x","operator":"GreaterThan","threshold":1}]}}}`))
					return
				}
				w.WriteHeader(200)
			}))
		},
		pid: "azalert:" + testSub + ":rg1:pv-alert-cpu-prod-abcd1234"})
}

func TestRefusesForeignDeleteAzScheduledquery(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "scheduledquery", cap: "errors",
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
						`"properties":{"displayName":"x","criteria":{"allOf":[{"query":"q"}]}}}`))
					return
				}
				w.WriteHeader(200)
			}))
		},
		pid: "azlm:" + testSub + ":rg1:pv-lm-errors-prod-abcd1234"})
}

func TestRefusesForeignDeleteAzWebtest(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "webtest", cap: "api",
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
						`"properties":{"Frequency":300,"Request":{"RequestUrl":"https://x/y"}}}`))
					return
				}
				w.WriteHeader(200)
			}))
		},
		pid: "azwebtest:" + testSub + ":rg1:pv-webtest-api-prod-abcd1234"})
}

func TestRefusesForeignDeleteAzPortaldash(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "portaldash", cap: "golden",
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"},` +
						`"properties":{"lenses":[]}}`))
					return
				}
				w.WriteHeader(200)
			}))
		},
		pid: "azdash:" + testSub + ":rg1:pv-dash-golden-prod-abcd1234"})
}

func TestRefusesForeignDeleteAzDnszone(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "dnszone", cap: "apex",
		server: func(t *testing.T) *httptest.Server { return azDNSServer(t, "someone-else", nil) },
		pid:    "adns:" + testSub + ":rg1:pub:example.com"})
}

func TestRefusesForeignDeleteAzDnsrecord(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "dnsrecord", cap: azDNSRecordCap,
		server: func(t *testing.T) *httptest.Server { return azDNSRecordServer(t, "someone-else", nil) },
		pid:    azureDNSRecordProviderID(testSub, "rg1", "example.com", "CNAME", "connect")})
}

func TestRefusesForeignDeleteAzAcr(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "acr", cap: "images",
		server: func(t *testing.T) *httptest.Server { return acrServer(t, "someone-else") },
		pid:    "acr:" + testSub + ":rg1:" + acrName("prod", "images", 1)})
}

func TestRefusesForeignDeleteAzVnet(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "vnet", cap: "backbone",
		server: func(t *testing.T) *httptest.Server { return armFake(t, "someone-else") },
		pid:    vnetProviderID(testSub, "rg1", "pv-net-backbone-prod-abcd1234")})
}

func TestRefusesForeignDeleteAzServicebustopic(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "servicebustopic", cap: "orders",
		server: func(t *testing.T) *httptest.Server { return sbArmFake(t, "someone-else") },
		pid:    sbProviderID("sbt", testSub, "rg1", serviceBusNamespace("prod", "orders", 1), azResourceName("t", "prod", "orders", 1))})
}

func TestRefusesForeignDeleteAzBackupvault(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "backupvault", cap: "archive",
		server: func(t *testing.T) *httptest.Server {
			return backupVaultServer(t, "eastus", "Disabled", 0, false,
				map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"})
		},
		pid: backupVaultProviderID(testSub, "rg1", BackupVaultName("prod", "archive", 1))})
}

func TestRefusesForeignDeleteAzAzureopenai(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "azureopenai", cap: aoiCap,
		server: func(t *testing.T) *httptest.Server {
			return func() *httptest.Server {
				f := &fakeAOI{location: "swedencentral", tags: aoiTags("someone-else")}
				return httptest.NewServer(f.handler(t))
			}()
		},
		pid: aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))})
}

func TestRefusesForeignDeleteAzLoadbalancer(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "loadbalancer", cap: "edge",
		server: func(t *testing.T) *httptest.Server {
			return func() *httptest.Server {
				f := &agwProvisionFake{getDoc: `{"location":"eastus","tags":{"groundhold-capability":"someone-else",` +
					`"groundhold-environment":"prod"},"properties":{"provisioningState":"Succeeded",` +
					`"frontendIPConfigurations":[],"httpListeners":[]}}`}
				return f.server(t)
			}()
		},
		pid: agwProviderID(testSub, "rg1", "pv-agw-foreign")})
}

func TestRefusesForeignDeleteAzAks(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "aks", cap: aksCap,
		server: func(t *testing.T) *httptest.Server {
			return func() *httptest.Server {
				f := newFakeAKS(testSub, "rg1", aksPlanName(t))
				f.exists = true
				f.tags = map[string]string{"team": "someone-else"}
				return httptest.NewServer(f.handler())
			}()
		},
		pid: aksProviderID(testSub, "rg1", aksPlanName(t))})
}

// ---- D458: the compute family. A disk holds someone's data; a scale set IS someone's
// fleet; a VM is both. These are the deletes where being wrong costs the most, so they
// are driven through the public dispatch rather than trusted to their unit tests.

func TestRefusesForeignDeleteAzDisk(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "azdisk", cap: "orders-data",
		server: func(t *testing.T) *httptest.Server {
			s := &azDiskServer{getStatus: 200, delStatus: 200,
				getBody: azDiskDoc(t, "someone-elses-database", "Premium_LRS", false)}
			return httptest.NewServer(s.handler())
		},
		pid: azureDiskProviderID(testSub, "rg", "pv-disk-x")})
}

func TestRefusesForeignDeleteAzVmss(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "azvmss", cap: "web-fleet",
		server: func(t *testing.T) *httptest.Server {
			s := vmssHappyServer()
			s.getBody = vmssDoc("someone-elses-fleet", 2, false)
			return httptest.NewServer(s.handler())
		},
		pid: azureVMSSProviderID(testSub, "rg", "pv-vmss-x")})
}

func TestRefusesForeignDeleteAzVm(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "azvm", cap: "web",
		server: func(t *testing.T) *httptest.Server {
			s := &azVMServer{vmStatus: 200, delStatus: 200,
				vmBody: azVMDoc(t, "someone-else", false)}
			return httptest.NewServer(s.handler())
		},
		pid: azureVMProviderID(testSub, "rg", "pv-vm-abc123456789")})
}

// ---- D458: the two name-only objects, and the hole they were hiding.
//
// A subscription-scope diagnostic setting and an EventGrid event subscription carry no
// ARM tags. Both deletes checked only that the providerId's SUBSCRIPTION was ours and
// then issued the DELETE — while their update paths refused on a name mismatch. Same
// shape as the five AWS defects (D444-D449), same asymmetry: the check the other verbs
// carried, the delete did not.

func TestRefusesForeignDeleteAzActivitylog(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "activitylog", cap: "audit", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					t.Errorf("delete must not %s a setting outside our naming scheme", r.Method)
					w.WriteHeader(400)
				}))
		},
		// OUR subscription — the cross-subscription guard does not fire. A stranger's
		// export, which `discover` deliberately surfaces for brownfield onboarding.
		pid: activityLogProviderID(testSub, "SecurityTeam-ActivityLog-Archive")})
}

func TestRefusesForeignDeleteAzChangefeed(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "changefeed", cap: "feed", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					t.Errorf("delete must not %s a subscription outside our naming scheme", r.Method)
					w.WriteHeader(400)
				}))
		},
		pid: changeFeedProviderID(testSub, "finance-audit-feed")})
}

func TestRefusesForeignDeleteAzAcsemail(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "acsemail", cap: "email",
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
					t.Errorf("delete must not %s a foreign-tagged emailService", r.Method)
					w.WriteHeader(400)
				}))
		},
		pid: acsEmailProviderID(testSub, "rg1", acsEmailName("prod", "email", 1))})
}

// ---- D458: the authorization pair, and the worst two holes the sweep has found.
//
// Both deletes took a GUID and issued the DELETE. No subscription guard, no read, no
// ownership check of any kind. A custom role definition's deletion revokes every
// permission it grants from every principal assigned to it; a role assignment's deletion
// takes a principal's access away with no record of what it was. Neither is undoable and
// neither leaves a trace of what was there.
//
// Both are content-addressed, so the check is an EQUALITY rather than a pattern: the
// create derives the GUID from (scope, roleName) or (scope, principal, role), and the
// delete re-derives it. A stranger's role or assignment has a GUID from Azure's own
// generator and cannot match.

func TestRefusesForeignDeleteAzCustomroledef(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "customroledef", cap: "viewer", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					t.Errorf("delete must not %s a role definition we did not mint", r.Method)
					w.WriteHeader(400)
				}))
		},
		// A GUID Azure minted for someone else's role, inside OUR subscription.
		pid: azureCustomRoleProviderID(testSub, "2f0e1b7c-9a3d-4c11-8f65-0d9a7b3e5c21")})
}

func TestRefusesForeignDeleteAzRoleassignment(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "roleassignment", cap: "reader",
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						_, _ = w.Write([]byte(`{"properties":{"roleDefinitionId":` +
							`"/subscriptions/` + testSub + `/providers/Microsoft.Authorization/` +
							`roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7",` +
							`"principalId":"7d3f1a92-5c88-4b1e-9a2d-3e6f0c4b8a51"}}`))
						return
					}
					t.Errorf("delete must not %s a grant we did not mint", r.Method)
					w.WriteHeader(400)
				}))
		},
		pid: azureRoleProviderID(testSub, "b41d2e60-7f3a-4c95-8e21-a0c5d9f7b384")})
}

// TestRefusesForeignDeleteAzAksWorkloadidentity: a federated identity credential is a
// child of a user-assigned managed identity, and the SAME identity can carry credentials
// for uses that are not ours. The ownership evidence is the subject: a credential whose
// subject is not a Kubernetes serviceAccount binding belongs to some other use of this
// UAMI, and deleting it would break that use.
func TestRefusesForeignDeleteAzAksWorkloadidentity(t *testing.T) {
	runAzForeignDelete(t, azForeignCase{svc: "aks-workloadidentity", cap: "runner",
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						_, _ = w.Write([]byte(`{"properties":{"subject":` +
							`"repo:some-org/some-repo:ref:refs/heads/main",` +
							`"issuer":"https://token.actions.githubusercontent.com",` +
							`"audiences":["api://AzureADTokenExchange"]}}`))
						return
					}
					t.Errorf("delete must not %s a credential that is not a k8s binding", r.Method)
					w.WriteHeader(400)
				}))
		},
		pid: aksWIProviderID(testSub, "rg1", "pv-id-runner-prod-abcd1234", "pv-fic-runner-prod-abcd1234")})
}
