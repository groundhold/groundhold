package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
	"net/url"
)

// D440: the delete-ownership enrolments share a shape — each driver already HAS a
// foreign-tagged fixture, written for its own per-driver refusal test. Reusing those
// rather than authoring new ones is the D415 rule: derive the estate from what the
// driver's own tests already trust, because a re-authored estate is a second opinion
// about the provider's wire and this sweep has six demonstrations of that opinion being
// wrong.

type foreignCase struct {
	svc, cap  string
	server    func(t *testing.T) *httptest.Server
	base      func(d *Driver, url string)
	pid       string
	classify  certifynet.Classifier
	mutations int
	// fromID: ownership is derivable from the CONTENT-ADDRESSED providerId, with no
	// estate read possible (a CloudWatch dashboard carries no tags at all).
	fromID bool
	// update, when set, drives the UPDATE verb against the same foreign estate instead
	// of the delete (D459). attrs/impl/changes are the candidate an operator would have
	// applied; the point is that they never reach the wire.
	update func(pr provider.Provider) provider.CreateResult
}

// runForeignUpdate is runForeignDelete's sibling on the middle verb. Same fixture, same
// question: does the driver refuse before writing to a resource that is not ours?
// newForeignDriver is the pinned driver both foreign probes build: a fixed account so
// no STS round-trip can leave the fake and count as a mutation (a lesson from D440).
func newForeignDriver(rt http.RoundTripper) *Driver {
	d := NewDriver("eu-central-1")
	d.HTTP = &http.Client{Transport: rt}
	d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func runForeignUpdate(t *testing.T, c foreignCase) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ForeignProbe{
		OwnershipFromIDAlone: c.fromID,
		Name:                 "aws/" + c.svc,
		Classify:             c.classify,
		ForeignServer:        func() *httptest.Server { return c.server(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := newForeignDriver(rt)
			c.base(d, happyURL)
			return d
		},
		Update:           c.update,
		AllowedMutations: c.mutations,
	}
	certifynet.CertifyUpdateRefusesForeign(t, p)
}

func runForeignDelete(t *testing.T, c foreignCase) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ForeignProbe{
		OwnershipFromIDAlone: c.fromID,
		Name:                 "aws/" + c.svc,
		Classify:             c.classify,
		ForeignServer:        func() *httptest.Server { return c.server(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := newForeignDriver(rt)
			c.base(d, happyURL)
			return d
		},
		Delete: func(pr provider.Provider) provider.CreateResult {
			return pr.Delete(c.svc, c.cap, "prod", c.pid, "k")
		},
		AllowedMutations: c.mutations,
	}
	certifynet.CertifyDeleteRefusesForeign(t, p)
}

func TestRefusesForeignDeleteECR(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "ecr", cap: "images",
		server:   func(t *testing.T) *httptest.Server { return ecrServer(t, "someone-else") },
		base:     func(d *Driver, u string) { d.ECRBaseURL = u },
		pid:      "ecr:eu-central-1:000000000000:pv-images-prod-abcd1234",
		classify: ecrTargetRole})
}

func TestRefusesForeignDeleteEFS(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "efs", cap: "shared",
		server:   func(t *testing.T) *httptest.Server { return efsServer(t, "someone-else", "", "") },
		base:     func(d *Driver, u string) { d.EFSBaseURL = u },
		pid:      "efs:eu-central-1:000000000000:fs-0123456789abcdef0",
		classify: efsRESTRole})
}

func TestRefusesForeignDeleteElastiCache(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "elasticache", cap: "sessions",
		server: func(t *testing.T) *httptest.Server {
			return ecServer(t, "someone-else", "true", "false", "disabled", "")
		},
		base:     func(d *Driver, u string) { d.ElastiCacheBaseURL = u },
		pid:      "ecredis:eu-central-1:000000000000:x",
		classify: rdsQueryRole})
}

func TestRefusesForeignDeleteKinesis(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "kinesis", cap: "events",
		server:   func(t *testing.T) *httptest.Server { return kinesisServer(t, "someone-else", 24, false) },
		base:     func(d *Driver, u string) { d.KinesisBaseURL = u },
		pid:      kinesisProviderID("eu-central-1", "000000000000", KinesisStreamName("prod", "events", 1)),
		classify: kinesisRole})
}

func TestRefusesForeignDeleteOpenSearch(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "opensearch", cap: "catalog",
		server:   func(t *testing.T) *httptest.Server { return osServer(t, "someone-else", false, false) },
		base:     func(d *Driver, u string) { d.OpenSearchBaseURL = u },
		pid:      openSearchProviderID("eu-central-1", "000000000000", OpenSearchDomainName("prod", "catalog", 1)),
		classify: osRESTRole})
}

func TestRefusesForeignDeleteCWLogs(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	runForeignDelete(t, foreignCase{svc: "cwlogs", cap: "app-logs",
		server:   func(t *testing.T) *httptest.Server { return cwLogsServer(t, name, "someone-else", 90, "") },
		base:     func(d *Driver, u string) { d.LogsBaseURL = u },
		pid:      cwLogsProviderID("eu-central-1", name),
		classify: cwLogsRole})
}

func TestRefusesForeignDeleteACM(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "acm", cap: "web",
		server: func(t *testing.T) *httptest.Server {
			return acmServer(t, "someone-else", "app.example.com", "INELIGIBLE")
		},
		base: func(d *Driver, u string) { d.ACMBaseURL = u },
		pid: acmProviderID("eu-central-1", "000000000000",
			"abcd1234-ab12-cd34-ef56-abcdef123456"),
		classify: acmRole})
}

func TestRefusesForeignDeleteCloudFront(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "cloudfront", cap: "edge",
		server: func(t *testing.T) *httptest.Server {
			return cfServer(t, "someone-else", "origin.example.com", "https-only", false)
		},
		base:     func(d *Driver, u string) { d.CloudFrontBaseURL = u },
		pid:      cfProviderID("000000000000", "E1234567890ABC"),
		classify: cloudfrontRole})
}

func TestRefusesForeignDeleteBackupPlan(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "backupplan", cap: "archive",
		server:   func(t *testing.T) *httptest.Server { return bkpServer(t, "someone-else") },
		base:     func(d *Driver, u string) { d.BackupBaseURL = u },
		pid:      "backupplan:eu-central-1:plan-abc",
		classify: bkvRole})
}

func TestRefusesForeignDeleteMSK(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "msk", cap: "bus",
		server:   func(t *testing.T) *httptest.Server { return mskServer(t, "someone-else", "3.5.1", false) },
		base:     func(d *Driver, u string) { d.MSKBaseURL = u },
		pid:      mskProviderID("eu-central-1", "000000000000", MSKClusterName("prod", "bus", 1)),
		classify: mskRESTRole})
}

func TestRefusesForeignDeleteWAF(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "waf", cap: "edge",
		server:   func(t *testing.T) *httptest.Server { return wafServer(t, "someone-else", true, false, false) },
		base:     func(d *Driver, u string) { d.WAFBaseURL = u },
		pid:      wafProviderID("000000000000", WAFACLName("prod", "edge", 1)),
		classify: wafRole})
}

func TestRefusesForeignDeleteSecretsManager(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "secretsmanager", cap: "dbcreds",
		server:   func(t *testing.T) *httptest.Server { return asmServer(t, "someone-else", `"\"\""`) },
		base:     func(d *Driver, u string) { d.SecretsManagerBaseURL = u },
		pid:      "asm:eu-central-1:x",
		classify: asmTargetRole})
}

// cloudfrontRole / asmTargetRole: the read/mutate split for two protocols the shared
// classifiers do not cover — CloudFront is REST (GET reads) and Secrets Manager is
// X-Amz-Target JSON.
func cloudfrontRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

func asmTargetRole(req *http.Request, _ []byte) certifynet.Role {
	tgt := req.Header.Get("X-Amz-Target")
	switch tgt[strings.LastIndex(tgt, ".")+1:] {
	case "DescribeSecret", "GetSecretValue", "ListSecrets", "GetResourcePolicy":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// ---- D441: the rest come from the ADOPTION fixtures, flipped foreign by passing a
// capability label that is not ours. Same fake, opposite verdict — which is the cheapest
// honest way to build a foreign estate, because the two cases differ by exactly the thing
// under test.

func TestRefusesForeignDeleteECS(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "ecs", cap: "app",
		server:   func(t *testing.T) *httptest.Server { return ecsServer(t, "other") },
		base:     func(d *Driver, u string) { d.ECSBaseURL = u },
		pid:      "ecs:eu-central-1:app-abcd1234",
		classify: ecsTargetRole})
}

func TestRefusesForeignDeleteSNS(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "sns", cap: "events",
		server: func(t *testing.T) *httptest.Server {
			return foreignTagQueryServer(t, "ListTagsForResource",
				`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>`+
					`<member><Key>groundhold-capability</Key><Value>other</Value></member>`+
					`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`)
		},
		base:     func(d *Driver, u string) { d.SNSBaseURL = u },
		pid:      "sns:eu-central-1:000000000000:events-x",
		classify: snsRole})
}

func TestRefusesForeignDeleteSQS(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "sqs", cap: "orders",
		server: func(t *testing.T) *httptest.Server {
			return foreignTagQueryServer(t, "ListQueueTags",
				`<ListQueueTagsResponse><ListQueueTagsResult>`+
					`<Tag><Key>groundhold-capability</Key><Value>other</Value></Tag>`+
					`</ListQueueTagsResult></ListQueueTagsResponse>`)
		},
		base:     func(d *Driver, u string) { d.SQSBaseURL = u },
		pid:      "sqs:eu-central-1:000000000000:orders-x",
		classify: sqsRole})
}

func TestRefusesForeignDeleteRDS(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "rds", cap: "db",
		server: func(t *testing.T) *httptest.Server {
			return rdsForeignServer(t)
		},
		base:     func(d *Driver, u string) { d.RDSBaseURL = u; d.KMSBaseURL = u },
		pid:      "rds:eu-central-1:db-abcd1234",
		classify: rdsQueryRole})
}

// rdsForeignServer: the stock rdsServer tags every instance as ours, so the foreign case
// needs the tag swapped — one substitution rather than a second fake.
func rdsForeignServer(t *testing.T) *httptest.Server {
	t.Helper()
	inner := rdsServer(t, "", "false")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		inner.Config.Handler.ServeHTTP(rec, r)
		body := strings.ReplaceAll(rec.Body.String(),
			"<Key>groundhold-capability</Key><Value>db</Value>",
			"<Key>groundhold-capability</Key><Value>someone-else</Value>")
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(func() { srv.Close(); inner.Close() })
	return srv
}

// foreignTagQueryServer answers the named AWS query-protocol tag action with a FOREIGN
// owner and nothing else — anything past the ownership read is a mutation the refusal
// must not have sent, and the countRT will say so.
func foreignTagQueryServer(t *testing.T, tagAction, tagXML string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		if queryAction(body) == tagAction {
			_, _ = w.Write([]byte(tagXML))
			return
		}
		_, _ = w.Write([]byte(`<Response></Response>`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---- D442: eight more off the adoption fixtures, each flipped foreign by its own
// tag/label parameter.

func TestRefusesForeignDeleteAppRunner(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "apprunner", cap: "capability.workload.container",
		server: func(t *testing.T) *httptest.Server {
			return (&apprunnerFake{tagCap: "someone-else"}).handler(t)
		},
		base:     func(d *Driver, u string) { d.AppRunnerBaseURL = u },
		pid:      "apprunner:eu-central-1:app-abcd1234",
		classify: apprunnerRole})
}

func TestRefusesForeignDeleteAurora(t *testing.T) {
	clusterID := DBIdentifier("000000000000", "prod", "db", 1)
	runForeignDelete(t, foreignCase{svc: "aurora", cap: "db",
		server: func(t *testing.T) *httptest.Server {
			f := newFakeAurora()
			f.clusterExists = true
			f.tags = map[string]string{
				"groundhold-capability":  "someone-else",
				"groundhold-environment": sanitizeTag("prod"),
			}
			return f.handler(t, nil)
		},
		base:     func(d *Driver, u string) { d.RDSBaseURL = u; d.KMSBaseURL = u },
		pid:      auroraProviderID("eu-central-1", clusterID),
		classify: rdsQueryRole})
}

func TestRefusesForeignDeleteGuardDuty(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "guardduty", cap: gdCap,
		server: func(t *testing.T) *httptest.Server {
			f := &fakeGuardDuty{detectorID: gdDetectorID, exists: true, status: "ENABLED",
				tags: map[string]string{"groundhold-capability": "someone-else"}}
			return f.handler(t, nil)
		},
		base: func(d *Driver, u string) {
			guarddutyBaseURLOverride = u
			t.Cleanup(func() { guarddutyBaseURLOverride = "" })
		},
		pid:      guardDutyProviderID(gdRegion, gdDetectorID),
		classify: gdRole})
}

func TestRefusesForeignDeleteLambda(t *testing.T) {
	name := ECSName("000000000000", "prod", "api", 1)
	runForeignDelete(t, foreignCase{svc: "lambda", cap: "api",
		server: func(t *testing.T) *httptest.Server {
			f := &lambdaFake{t: t, readyState: "Active", created: true, capValue: "someone-else"}
			srv := httptest.NewServer(f.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.LambdaBaseURL = u },
		pid:      lambdaProviderID("eu-central-1", "000000000000", name),
		classify: lambdaRESTRole})
}

func TestRefusesForeignDeleteRoute53(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "route53", cap: "apex",
		server:   func(t *testing.T) *httptest.Server { return r53Server(t, "someone-else", "false") },
		base:     func(d *Driver, u string) { d.Route53BaseURL = u },
		pid:      r53ProviderID("Z123ABC"),
		classify: r53Role})
}

func TestRefusesForeignDeleteElastiCacheServerless(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "elasticache-serverless", cap: "sessions",
		server: func(t *testing.T) *httptest.Server {
			f := &ecslFake{tagCap: "someone-else"}
			return f.handler(t)
		},
		base:     func(d *Driver, u string) { d.ElastiCacheServerlessBaseURL = u },
		pid:      "ecserverless:eu-central-1:000000000000:sessions-prod-abcd1234",
		classify: rdsQueryRole})
}

func TestRefusesForeignDeleteOpenSearchServerless(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "opensearch-serverless", cap: "catalog",
		server: func(t *testing.T) *httptest.Server {
			f := &aossFake{public: true, tagCap: "someone-else"}
			return f.handler(t)
		},
		base:     func(d *Driver, u string) { d.OpenSearchServerlessBaseURL = u },
		pid:      "aoss:eu-central-1:000000000000:col-x",
		classify: aossRole})
}

func TestRefusesForeignDeleteCloudTrail(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "cloudtrail", cap: "audit",
		server: func(t *testing.T) *httptest.Server {
			return cloudTrailForeignServer(t)
		},
		base: func(d *Driver, u string) {
			cloudTrailBaseURLOverride = u
			t.Cleanup(func() { cloudTrailBaseURLOverride = "" })
		},
		pid:      cloudTrailProviderID("eu-central-1", CloudTrailName("prod", "audit", 1)),
		classify: cloudTrailRole})
}

func cloudTrailForeignServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch cloudTrailAction(r) {
		case "ListTags":
			_, _ = w.Write([]byte(`{"ResourceTagList":[{"TagsList":[` +
				`{"Key":"groundhold-capability","Value":"someone-else"}]}]}`))
		case "GetTrail":
			_, _ = w.Write([]byte(`{"Trail":{"Name":"pv-x","TrailARN":"` +
				cloudTrailArn("pv-x") + `"}}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// ---- D444: the two other TAG-LESS services, both found by the D443 diagnostic and both
// carrying the same defect budgets had.

func TestRefusesForeignDeleteCustomPolicy(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "custompolicy", cap: "viewer", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("delete must not reach the API for a policy outside our naming scheme")
				w.WriteHeader(400)
			}))
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.IAMBaseURL = u },
		pid:      "acrole:arn:aws:iam::000000000000:policy/FinanceTeamReadOnly",
		classify: iamQueryRole})
}

func TestRefusesForeignDeleteCWLogFilter(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "cwlogfilter", cap: "errors", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("delete must not reach the API for a filter outside our naming scheme")
				w.WriteHeader(400)
			}))
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.LogsBaseURL = u },
		pid:      "cwlogfilter:eu-central-1:/aws/lambda/app:SecurityTeamErrorRate",
		classify: cwLogsTargetRole})
}

// TestRefusesForeignDeleteRolePolicy (D445): an attachment has no ownership surface of
// its own — no tags, no name, only the pair it joins — which for a while made this look
// like the one delete in the family with nothing to check. The ROLE has tags, and
// detaching a policy MODIFIES that role: it removes a permission the role's workload is
// using. Reversible by re-attaching is a mitigation, not a licence.
func TestRefusesForeignDeleteRolePolicy(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "rolepolicy", cap: "reader",
		server: func(t *testing.T) *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := make([]byte, r.ContentLength)
				_, _ = r.Body.Read(body)
				v, _ := url.ParseQuery(string(body))
				if v.Get("Action") == "GetRole" {
					_, _ = w.Write([]byte(iamRoleXML("GetRole", "someone-else", "prod")))
					return
				}
				t.Errorf("detach must not be issued against a role that is not ours")
				w.WriteHeader(400)
			}))
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.IAMBaseURL = u },
		pid:      "aauth:app-runner:arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",
		classify: iamQueryRole})
}

// TestRefusesForeignDeleteSESInbound (D446): the fourth tag-less service. Its comment
// already said "the NAME is the ownership marker"; it never checked that the name is one
// we would produce. A rule set is where inbound mail is ROUTED, so deleting a stranger's
// rule silently stops delivering their mail.
func TestRefusesForeignDeleteSESInbound(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "ses-inbound", cap: "email", fromID: true,
		// the pre-read SUCCEEDS and describes a real foreign rule — otherwise the gate
		// would pass on an unreadable estate rather than on the name check (D411: a gate
		// that passes for the wrong reason is the same failure as one that never runs).
		server: func(t *testing.T) *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := make([]byte, r.ContentLength)
				_, _ = r.Body.Read(body)
				if queryAction(body) == "DescribeReceiptRule" {
					_, _ = w.Write([]byte(`<DescribeReceiptRuleResponse><DescribeReceiptRuleResult>` +
						`<Rule><Name>invoice-router</Name><Enabled>true</Enabled></Rule>` +
						`</DescribeReceiptRuleResult></DescribeReceiptRuleResponse>`))
					return
				}
				t.Errorf("delete must not reach %s for a rule outside our naming scheme",
					queryAction(body))
				w.WriteHeader(400)
			}))
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.SESBaseURL = u },
		pid:      "ses-inbound:eu-central-1:finance-inbound-rules:invoice-router",
		classify: sesInbRole})
}

// ---- D447: the stateful-compute batch. Each of these already has a per-driver refusal
// test whose fixture describes a READABLE foreign resource — the shape D446 showed is the
// only one that proves anything.

func TestRefusesForeignDeleteEBSVolume(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "ebs", cap: "orders-data",
		server: func(t *testing.T) *httptest.Server {
			foreign := strings.Replace(ebsAvailableXML, "orders-data", "someone-elses-database", 1)
			s := &ebsVolServer{describe: []string{foreign}, deleteStatus: 200}
			srv := httptest.NewServer(s.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.EC2BaseURL = u },
		pid:      ebsPID,
		classify: vpcRole})
}

func TestRefusesForeignDeleteEC2Instance(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "ec2", cap: "web",
		server: func(t *testing.T) *httptest.Server {
			foreign := strings.Replace(ec2RunningXML, "<value>web</value>", "<value>someone-else</value>", 1)
			s := &ec2InstanceServer{describe: []string{foreign}}
			srv := httptest.NewServer(s.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.EC2BaseURL = u },
		pid:      "ec2:eu-central-1:000000000000:i-0123456789abcdef0",
		classify: vpcRole})
}

func TestRefusesForeignDeleteBedrock(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "bedrock", cap: bedrockCap,
		server: func(t *testing.T) *httptest.Server {
			return bedrockForeignServer(t, bedrockAppID)
		},
		base:     func(d *Driver, u string) { d.BedrockBaseURL = u },
		pid:      bedrockProviderID(bedrockRegion, bedrockAppID),
		classify: bedrockRole})
}

// bedrockForeignServer: the profile exists and is READABLE, and its tags are someone
// else's — the only fixture shape that can prove the ownership check is load-bearing.
func bedrockForeignServer(t *testing.T, profID string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"inferenceProfileArn":"arn:aws:bedrock:` + bedrockRegion +
				`:000000000000:inference-profile/` + profID + `","inferenceProfileId":"` + profID +
				`","inferenceProfileName":"someone-elses","type":"APPLICATION","status":"ACTIVE",` +
				`"tags":[{"key":"groundhold-capability","value":"someone-else"}]}`))
			return
		}
		t.Errorf("delete must not %s a profile whose tags are not ours", r.Method)
		w.WriteHeader(400)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRefusesForeignDeleteEventBridgeScheduler(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "eventbridgescheduler", cap: "nightly",
		server:   func(t *testing.T) *httptest.Server { return ebsServer(t, "someone-else", "ENABLED") },
		base:     func(d *Driver, u string) { d.SchedulerBaseURL = u },
		pid:      "ebsched:eu-central-1:" + EBSName("prod", "nightly", 1),
		classify: cloudfrontRole})
}

// ---- D448: four more off their own foreign fixtures.

func TestRefusesForeignDeleteBackupVault(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "backupvault", cap: "archive",
		server:   func(t *testing.T) *httptest.Server { return bkvServer(t, "someone-else", true, 90, 0) },
		base:     func(d *Driver, u string) { d.BackupBaseURL = u },
		pid:      bkvProviderID("eu-central-1", "000000000000", BackupVaultName("prod", "archive", 1)),
		classify: bkvRole})
}

func TestRefusesForeignDeleteIAMRole(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "iam", cap: "runner",
		server:   func(t *testing.T) *httptest.Server { return iamServer(t, "someone-else") },
		base:     func(d *Driver, u string) { d.IAMBaseURL = u },
		pid:      iamRoleProviderID("000000000000", "pv-runner-prod-x"),
		classify: iamQueryRole})
}

func TestRefusesForeignDeleteRedshiftServerless(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "redshiftserverless", cap: "lake",
		server:   func(t *testing.T) *httptest.Server { return rssServer(t, "someone-else", false) },
		base:     func(d *Driver, u string) { d.RedshiftServerlessBaseURL = u },
		pid:      rssProviderID("eu-central-1", "lake-prod-abcd1234"),
		classify: rssRole})
}

// TestRefusesForeignDeleteVpnGateway closes the loop on D409, which found this driver's
// CREATE minting a second billed gateway. Its delete already checked ownership; now the
// class says so.
func TestRefusesForeignDeleteVpnGateway(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "vpngateway", cap: "site",
		server:   func(t *testing.T) *httptest.Server { return vgwServer(t, "someone-else") },
		base:     func(d *Driver, u string) { d.EC2BaseURL = u },
		pid:      vgwProviderID("eu-central-1", "vgw-0abc123"),
		classify: vgwQueryRole})
}

// ---- D449: the fifth tag-less service, plus the ones whose ownership lives one level up.

// TestRefusesForeignDeleteCWDashboard: a CloudWatch dashboard carries no tags, so its
// name is the only evidence. Deleting a stranger's dashboard destroys the view an on-call
// rotation works from, and nothing about that is visible until an incident.
func TestRefusesForeignDeleteCWDashboard(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "cloudwatchdash", cap: "golden", fromID: true,
		server: func(t *testing.T) *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Errorf("delete must not reach the API for a dashboard outside our naming scheme")
				w.WriteHeader(400)
			}))
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.CloudWatchDashBaseURL = u },
		pid:      "cwdash:finance-team-overview",
		classify: cwQueryRole})
}

// TestRefusesForeignDeleteRoute53Record: the ownership evidence is the PARENT ZONE's
// tags, one level up — a record has nowhere to carry a marker (the same design both
// clouds reached independently, D408/D420).
func TestRefusesForeignDeleteRoute53Record(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "route53record", cap: r53RecordCap,
		server:   func(t *testing.T) *httptest.Server { return r53RecordServer(t, "someone-else") },
		base:     func(d *Driver, u string) { d.Route53BaseURL = u },
		pid:      r53RecordProviderID("Z123ABC", "CNAME", "connect.example.com."),
		classify: r53Role})
}

func TestRefusesForeignDeleteRoute53HealthCheck(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "route53health", cap: "api",
		server:   func(t *testing.T) *httptest.Server { return r53hcServer(t, "someone-else") },
		base:     func(d *Driver, u string) { d.Route53BaseURL = u },
		pid:      "r53hc:hc-123",
		classify: r53Role})
}

func TestRefusesForeignDeleteApiGWv2(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "apigateway", cap: "front",
		server:   func(t *testing.T) *httptest.Server { return apigwServer(t, "someone-else", "HTTP") },
		base:     func(d *Driver, u string) { d.APIGatewayBaseURL = u },
		pid:      apigwProviderID("eu-central-1", "000000000000", "a1b2c3d4e5"),
		classify: apigwRESTRole})
}

// ---- D450: the last eight, closing AWS.

func TestRefusesForeignDeleteASG(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "asg", cap: "web-fleet",
		server: func(t *testing.T) *httptest.Server {
			s := asgHappyServer()
			s.describe = strings.Replace(asgGroupXML, "<Value>web-fleet</Value>",
				"<Value>someone-elses-fleet</Value>", 1)
			srv := httptest.NewServer(s.handler())
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.AutoScalingBaseURL = u; d.EC2BaseURL = u },
		pid:      asgPID,
		classify: asgQueryRole})
}

func TestRefusesForeignDeleteChangeFeed(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "changefeed", cap: "changes",
		server: func(t *testing.T) *httptest.Server {
			f := newCFFake()
			f.seedForeign()
			return f.server(t)
		},
		base:     func(d *Driver, u string) { d.EventBridgeBaseURL = u },
		pid:      changefeedProviderID("eu-central-1", "changes-prod-x"),
		classify: chfRole})
}

func TestRefusesForeignDeleteEKSAddon(t *testing.T) {
	attrs, impl := addonCandidate()
	_ = attrs
	_ = impl
	runForeignDelete(t, foreignCase{svc: "eks-addon", cap: eksAddonCap,
		server: func(t *testing.T) *httptest.Server {
			f := newFakeAddon()
			f.exists = true
			f.tags = map[string]string{"groundhold-capability": "someone-else"}
			return f.handler(t, nil)
		},
		base:     func(d *Driver, u string) { d.EKSBaseURL = u; d.EC2BaseURL = u },
		pid:      addonPID(),
		classify: eksRole})
}

func TestRefusesForeignDeleteEKSPodIdentity(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "eks-podidentity", cap: eksPodIDCap,
		server: func(t *testing.T) *httptest.Server {
			f := newFakePodID()
			f.exists = true
			f.tags = map[string]string{"groundhold-capability": "someone-else"}
			return f.handler(t, nil)
		},
		base:     func(d *Driver, u string) { d.EKSBaseURL = u; d.EC2BaseURL = u },
		pid:      podIDPID(),
		classify: eksRole})
}

func TestRefusesForeignDeleteSESSending(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "ses-sending", cap: sesCap,
		server: func(t *testing.T) *httptest.Server {
			f := newFakeSES()
			f.identityExists = true
			f.tags = []map[string]string{{"Key": "groundhold-capability", "Value": "someone-else"}}
			return f.handler(t, nil)
		},
		base:     func(d *Driver, u string) { d.SESBaseURL = u },
		pid:      sesSendingProviderID(sesRegion, sesDomain),
		classify: sesRESTRole})
}

func TestRefusesForeignDeleteCloudWatchAlarm(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "cloudwatch", cap: "cpu",
		server: func(t *testing.T) *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body := make([]byte, r.ContentLength)
				_, _ = r.Body.Read(body)
				v, _ := url.ParseQuery(string(body))
				switch v.Get("Action") {
				case "DescribeAlarms":
					_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms>` +
						`<member><Namespace>AWS/EC2</Namespace><MetricName>CPUUtilization</MetricName>` +
						`</member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))
				case "ListTagsForResource":
					_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
						`<member><Key>groundhold-capability</Key><Value>someone-else</Value></member>` +
						`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
				default:
					t.Errorf("delete must not issue %s against a foreign alarm", v.Get("Action"))
					w.WriteHeader(400)
				}
			}))
			t.Cleanup(srv.Close)
			return srv
		},
		base:     func(d *Driver, u string) { d.CloudWatchBaseURL = u },
		pid:      cwAlarmProviderID("eu-central-1", "000000000000", "pv-cpu-prod-abcd1234"),
		classify: cwQueryRole})
}

func TestRefusesForeignDeleteLoadBalancer(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "loadbalancer", cap: lbCap,
		server: func(t *testing.T) *httptest.Server {
			f := newFakeELB()
			f.lbCreated, f.tgCreated = true, true
			f.tags = map[string]string{
				"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
			return f.handler(t, nil)
		},
		base:     func(d *Driver, u string) { d.ELBv2BaseURL = u },
		pid:      elbv2ProviderID("eu-central-1", lbTestName),
		classify: elbRole})
}

func TestRefusesForeignDeleteEKS(t *testing.T) {
	runForeignDelete(t, foreignCase{svc: "eks", cap: eksCap,
		server: func(t *testing.T) *httptest.Server {
			return newFakeEKSNamed(eksTestName, true, false).handler(t, nil)
		},
		base:     func(d *Driver, u string) { d.EKSBaseURL = u; d.EC2BaseURL = u },
		pid:      eksProviderID("eu-central-1", eksTestName),
		classify: eksRole})
}
