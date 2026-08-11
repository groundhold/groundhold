package aws

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"groundhold/internal/provider"
)

// D459: the third verb. The create register asked "does it bind what is already ours?";
// the delete register asked "does it refuse what is not?". The update sits between them
// and has been asked by nobody as a class.
//
// An update on a foreign resource is not the mild case. It is a TAKEOVER: the resource
// keeps running, under someone else's name, with our configuration written into it —
// their retention policy replaced by ours, their encryption flipped, their DNS record
// repointed. A delete at least announces itself by the thing that is gone; this does
// not. That is the argument for a register rather than an assumption that whoever wrote
// the delete's ownership check wrote this one too — an assumption the delete sweep
// disproved nine times.

func upd(svc, cap, pid string, attrs, impl map[string]any,
	changes []string) func(provider.Provider) provider.CreateResult {
	return func(pr provider.Provider) provider.CreateResult {
		return pr.Update(svc, cap, "prod", pid, attrs, impl, changes, "k")
	}
}

func TestRefusesForeignUpdateS3(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "s3", cap: "assets",
		server: func(t *testing.T) *httptest.Server {
			return s3UpdateServer(t, "someone-else", "prod", 0, map[string]bool{})
		},
		base:     func(d *Driver, u string) { d.S3BaseURL = u },
		classify: s3Role,
		update: upd("s3", "assets", "s3:eu-central-1:pv-assets-abcd1234",
			s3Attrs(), nil, []string{"versioning.enabled"})})
}

func TestRefusesForeignUpdateSNS(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "sns", cap: "events",
		server: func(t *testing.T) *httptest.Server {
			return snsUpdateServer(t, "someone-else", "prod", 0, nil)
		},
		base:     func(d *Driver, u string) { d.SNSBaseURL = u },
		classify: snsRole,
		update: upd("sns", "events", "sns:eu-central-1:000000000000:events-x",
			snsAttrs(), nil, []string{"encryption.atRest"})})
}

func TestRefusesForeignUpdateSQS(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "sqs", cap: "orders",
		server: func(t *testing.T) *httptest.Server {
			return sqsUpdateServer(t, "someone-else", "prod", 0, nil)
		},
		base:     func(d *Driver, u string) { d.SQSBaseURL = u },
		classify: sqsRole,
		update: upd("sqs", "orders", "sqs:eu-central-1:000000000000:orders-x",
			sqsRetentionAttrs(), nil, []string{"retention.minimum"})})
}

func TestRefusesForeignUpdateCWLogs(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	runForeignUpdate(t, foreignCase{svc: "cwlogs", cap: "app-logs",
		server: func(t *testing.T) *httptest.Server {
			return cwLogsServer(t, name, "someone-else", 90, "")
		},
		base:     func(d *Driver, u string) { d.LogsBaseURL = u },
		classify: cwLogsRole,
		update: upd("cwlogs", "app-logs", cwLogsProviderID("eu-central-1", name),
			cwLogsAttrs(), nil, []string{"retention.days"})})
}

func TestRefusesForeignUpdateECR(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "ecr", cap: "images",
		server:   func(t *testing.T) *httptest.Server { return ecrServer(t, "someone-else") },
		base:     func(d *Driver, u string) { d.ECRBaseURL = u },
		classify: ecrTargetRole,
		update: upd("ecr", "images", "ecr:eu-central-1:000000000000:pv-images-prod-abcd1234",
			ecrAttrs(), ecrImpl(), []string{"security.scanOnPush"})})
}

// TestRefusesForeignUpdateRoute53Record: the ownership boundary is the parent ZONE, and
// the update at stake is a REPOINT — sending someone else's traffic to our target.
func TestRefusesForeignUpdateRoute53Record(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "route53record", cap: r53RecordCap,
		server:   func(t *testing.T) *httptest.Server { return r53RecordServer(t, "someone-else") },
		base:     func(d *Driver, u string) { d.Route53BaseURL = u },
		classify: r53Role,
		update: upd("route53record", r53RecordCap,
			r53RecordProviderID("Z123ABC", "CNAME", "connect.example.com."),
			r53RecordAttrs(), r53RecordImpl(), []string{"dns.target"})})
}

func TestRefusesForeignUpdateASM(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "secretsmanager", cap: "dbcreds",
		server:   func(t *testing.T) *httptest.Server { return asmFailServer(t, "someone-else", asmFail{}) },
		base:     func(d *Driver, u string) { d.SecretsManagerBaseURL = u },
		classify: asmTargetRole,
		update: upd("secretsmanager", "dbcreds", "asm:eu-central-1:x",
			asmAttrs(), asmImpl(), []string{"network.publicExposure"})})
}

func TestRefusesForeignUpdateRDS(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "rds", cap: "db",
		server: func(t *testing.T) *httptest.Server {
			return rdsUpdateServer(t, "someone-else", "prod", 0, nil)
		},
		base:     func(d *Driver, u string) { d.RDSBaseURL, d.KMSBaseURL = u, u },
		classify: rdsQueryRole,
		update: upd("rds", "db", "rds:eu-central-1:db-x", rdsAttrs(), rdsImpl(),
			[]string{"network.publicExposure"})})
}

func TestRefusesForeignUpdateAurora(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "aurora", cap: "db",
		server: func(t *testing.T) *httptest.Server {
			f := newFakeAurora()
			f.clusterExists = true
			f.tags = map[string]string{
				"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
			return f.handler(t, nil)
		},
		base:     func(d *Driver, u string) { d.RDSBaseURL, d.KMSBaseURL = u, u },
		classify: rdsQueryRole,
		update: upd("aurora", "db", auroraProviderID("eu-central-1", "foreign-db"),
			auroraAttrs(), auroraImpl(), []string{"recovery.rpo"})})
}

func TestRefusesForeignUpdateEKS(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "eks", cap: "cluster",
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					_, _ = w.Write([]byte(`{"cluster":{"status":"ACTIVE","version":"1.29",` +
						`"tags":{"team":"someone-else"}}}`))
				}))
		},
		base:     func(d *Driver, u string) { d.EKSBaseURL = u },
		classify: eksRole,
		update: upd("eks", "cluster", "eks:eu-central-1:acme-prod",
			map[string]any{"cluster.version": "1.30"}, nil, []string{"cluster.version"})})
}

func TestRefusesForeignUpdateAppRunner(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "apprunner", cap: "app",
		server: func(t *testing.T) *httptest.Server {
			return (&apprunnerFake{tagCap: "someone-else"}).handler(t)
		},
		base:     func(d *Driver, u string) { d.AppRunnerBaseURL = u },
		classify: apprunnerRole,
		update: upd("apprunner", "app", apprunnerProviderID("eu-central-1", "app-abcd1234"),
			apprunnerAttrs(), apprunnerImpl(), []string{"replicas.minimum"})})
}

func TestRefusesForeignUpdateSESSending(t *testing.T) {
	attrs, impl := sesCandidate()
	runForeignUpdate(t, foreignCase{svc: "ses-sending", cap: sesCap,
		server: func(t *testing.T) *httptest.Server {
			f := newFakeSES()
			f.identityExists = true
			f.tags = []map[string]string{{"Key": "team", "Value": "someone-else"}}
			return f.handler(t, nil)
		},
		base:     func(d *Driver, u string) { d.SESBaseURL = u },
		classify: sesRESTRole,
		update: upd("ses-sending", sesCap, sesSendingProviderID(sesRegion, sesDomain),
			attrs, impl, []string{"authentication.dkim"})})
}

func TestRefusesForeignUpdateACM(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "acm", cap: "web",
		server: func(t *testing.T) *httptest.Server {
			return acmServer(t, "someone-else", "app.example.com", "INELIGIBLE")
		},
		base:     func(d *Driver, u string) { d.ACMBaseURL = u },
		classify: acmRole,
		update: upd("acm", "web", acmProviderID("eu-central-1", "000000000000",
			"abcd1234-ab12-cd34-ef56-abcdef123456"), acmAttrs(), nil,
			[]string{"auto.renew"})})
}

func TestRefusesForeignUpdateBackupPlan(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "backupplan", cap: "archive",
		server:   func(t *testing.T) *httptest.Server { return bkpServer(t, "someone-else") },
		base:     func(d *Driver, u string) { d.BackupBaseURL = u },
		classify: bkvRole,
		update: upd("backupplan", "archive", "backupplan:eu-central-1:plan-abc",
			bkpAttrs(), bkpImpl(), []string{"retention.duration"})})
}

func TestRefusesForeignUpdateCloudTrail(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "cloudtrail", cap: "audit",
		server: func(t *testing.T) *httptest.Server { return cloudTrailForeignServer(t) },
		base: func(d *Driver, u string) {
			cloudTrailBaseURLOverride = u
			t.Cleanup(func() { cloudTrailBaseURLOverride = "" })
		},
		classify: cloudTrailRole,
		update: upd("cloudtrail", "audit",
			cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1)),
			cloudTrailAttrs(), cloudTrailImpl(),
			[]string{"scope.multiRegion", "delivery.assured"})})
}

func TestRefusesForeignUpdateEKSAddon(t *testing.T) {
	attrs, impl := addonCandidate()
	runForeignUpdate(t, foreignCase{svc: "eks-addon", cap: eksAddonCap,
		server: func(t *testing.T) *httptest.Server {
			f := newFakeAddon()
			f.exists = true
			f.tags = map[string]string{"groundhold-capability": "someone-else"}
			return f.handler(t, nil)
		},
		base:     func(d *Driver, u string) { d.EKSBaseURL, d.EC2BaseURL = u, u },
		classify: eksRole,
		update:   upd("eks-addon", eksAddonCap, addonPID(), attrs, impl, []string{"addon.version"})})
}

func TestRefusesForeignUpdateGuardDuty(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "guardduty", cap: gdCap,
		server: func(t *testing.T) *httptest.Server {
			f := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, status: "ENABLED",
				tags: map[string]string{"groundhold-capability": "someone-else"}}
			return f.handler(t, nil)
		},
		base: func(d *Driver, u string) {
			guarddutyBaseURLOverride = u
			t.Cleanup(func() { guarddutyBaseURLOverride = "" })
		},
		classify: gdRole,
		update: upd("guardduty", gdCap, guardDutyProviderID(gdRegion, gdDetectorID),
			map[string]any{"location.region": gdRegion, "detection.enabled": true,
				"protection.kubernetes": true, "service.managed": true}, nil,
			[]string{"protection.kubernetes"})})
}

func TestRefusesForeignUpdateLambda(t *testing.T) {
	name := ECSName("000000000000", "prod", "api", 1)
	runForeignUpdate(t, foreignCase{svc: "lambda", cap: "api",
		server: func(t *testing.T) *httptest.Server {
			f := &lambdaFake{t: t, readyState: "Active", created: true, capValue: "someone-else"}
			srv := httptest.NewServer(f.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.LambdaBaseURL = u },
		classify: lambdaRESTRole,
		update: upd("lambda", "api",
			lambdaProviderID("eu-central-1", "000000000000", name),
			map[string]any{"location.region": "eu-central-1", "timeout.maximum": "60s"},
			map[string]any{
				"image_uri": "000000000000.dkr.ecr.eu-central-1.amazonaws.com/api:v2",
				"role_arn":  "arn:aws:iam::000000000000:role/api-exec"},
			[]string{"timeout.maximum"})})
}

// ---- The two tagless ones. Their ownership is the NAME, so the refusal is decided from
// the providerId without an estate read — the same declaration the delete register makes
// (D455), and the same five services that produced the delete defects (D444-D449).

func TestRefusesForeignUpdateBudgets(t *testing.T) {
	runForeignUpdate(t, foreignCase{svc: "budgets", cap: "inference", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					t.Error("update must not reach the API for a budget outside our naming scheme")
					w.WriteHeader(400)
				}))
		},
		base: func(d *Driver, u string) {
			budgetsBaseURLOverride = u
			t.Cleanup(func() { budgetsBaseURLOverride = "" })
		},
		classify: cwQueryRole,
		update: upd("budgets", "inference",
			"budgets:"+budgetTestAccount+":finance-team-quarterly",
			budgetAttrs(), budgetImpl(), []string{"budget.limit"})})
}

func TestRefusesForeignUpdateSESInbound(t *testing.T) {
	attrs, impl := sesInbCandidate()
	runForeignUpdate(t, foreignCase{svc: "ses-inbound", cap: "email", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					t.Error("update must not reach the API for a rule outside our naming scheme")
					w.WriteHeader(400)
				}))
		},
		base:     func(d *Driver, u string) { d.SESBaseURL = u },
		classify: sesInbRole,
		update: upd("ses-inbound", "email",
			sesInboundProviderID(sesInbRegion, "finance-inbound-rules", "invoice-router"),
			attrs, impl, []string{"delivery.sink"})})
}
