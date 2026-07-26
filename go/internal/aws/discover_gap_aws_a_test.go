package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// gapDiscoverServerA answers the LIST + DESCRIBE calls of every batch-A gap sweep
// (ACM, API Gateway, Backup, CloudFront, CloudWatch dashboards, custom IAM policies,
// EFS, EventBridge Scheduler, Kinesis). Each service surfaces exactly one resource,
// and each response is the minimal shape its observe reverse-map reads — so a sweep
// can be asserted end to end (LIST -> observe -> reverse-mapped observations).
func gapDiscoverServerA(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	const acmArn = "arn:aws:acm:eu-central-1:000000000000:certificate/12345678-1234-1234-1234-123456789012"
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			target := r.Header.Get("X-Amz-Target")
			var body string
			if r.Method == http.MethodPost {
				b, _ := io.ReadAll(r.Body)
				body = string(b)
			}
			if rec != nil {
				rec.record(r, body)
			}
			switch {
			// ---- ACM (JSON protocol) ----
			case strings.HasSuffix(target, ".ListCertificates"):
				_, _ = w.Write([]byte(`{"CertificateSummaryList":[{"CertificateArn":"` + acmArn + `","DomainName":"example.com"}]}`))
			case strings.HasSuffix(target, ".DescribeCertificate"):
				_, _ = w.Write([]byte(`{"Certificate":{"CertificateArn":"` + acmArn + `",` +
					`"DomainName":"example.com","Status":"ISSUED","Type":"AMAZON_ISSUED","RenewalEligibility":"ELIGIBLE"}}`))

			// ---- Kinesis (JSON protocol) ----
			case strings.HasSuffix(target, ".ListStreams"):
				_, _ = w.Write([]byte(`{"StreamNames":["pv-stream-1"]}`))
			case strings.HasSuffix(target, ".DescribeStreamSummary"):
				_, _ = w.Write([]byte(`{"StreamDescriptionSummary":{"StreamStatus":"ACTIVE",` +
					`"StreamARN":"arn:aws:kinesis:eu-central-1:000000000000:stream/pv-stream-1",` +
					`"RetentionPeriodHours":48,"EncryptionType":"KMS","KeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc"}}`))

			// ---- CloudWatch dashboards (Query protocol) ----
			case formAction(body) == "ListDashboards":
				_, _ = w.Write([]byte(`<ListDashboardsResponse><ListDashboardsResult><DashboardEntries>` +
					`<member><DashboardName>pv-dash-1</DashboardName></member>` +
					`</DashboardEntries></ListDashboardsResult></ListDashboardsResponse>`))
			case formAction(body) == "GetDashboard":
				_, _ = w.Write([]byte(`<GetDashboardResponse><GetDashboardResult><DashboardBody>` +
					`{"widgets":[{"type":"metric","properties":{"metrics":[["AWS/ECS","CPUUtilization"]]}}]}` +
					`</DashboardBody></GetDashboardResult></GetDashboardResponse>`))

			// ---- Custom IAM policies (Query protocol, global) ----
			case formAction(body) == "ListPolicies":
				_, _ = w.Write([]byte(`<ListPoliciesResponse><ListPoliciesResult><Policies>` +
					`<member><Arn>arn:aws:iam::000000000000:policy/pv-role-1</Arn></member>` +
					`</Policies></ListPoliciesResult></ListPoliciesResponse>`))
			case formAction(body) == "GetPolicy":
				_, _ = w.Write([]byte(`<GetPolicyResponse><GetPolicyResult><Policy>` +
					`<DefaultVersionId>v1</DefaultVersionId></Policy></GetPolicyResult></GetPolicyResponse>`))
			case formAction(body) == "GetPolicyVersion":
				_, _ = w.Write([]byte(`<GetPolicyVersionResponse><GetPolicyVersionResult><PolicyVersion>` +
					`<Document>` + url.QueryEscape(policyDoc) + `</Document>` +
					`</PolicyVersion></GetPolicyVersionResult></GetPolicyVersionResponse>`))

			// ---- API Gateway v2 (REST-JSON) ----
			case path == "/v2/apis":
				_, _ = w.Write([]byte(`{"Items":[{"ApiId":"abc123def4","Name":"pv-api","ProtocolType":"HTTP"}]}`))
			case strings.HasPrefix(path, "/v2/apis/"):
				_, _ = w.Write([]byte(`{"ApiId":"abc123def4","Name":"pv-api","ProtocolType":"HTTP","Tags":{"groundhold-capability":"api"}}`))

			// ---- AWS Backup (REST-JSON) ----
			case path == "/backup-vaults":
				_, _ = w.Write([]byte(`{"BackupVaultList":[{"BackupVaultName":"pv-vault-1",` +
					`"BackupVaultArn":"arn:aws:backup:eu-central-1:000000000000:backup-vault:pv-vault-1"}]}`))
			case strings.HasPrefix(path, "/backup-vaults/"):
				_, _ = w.Write([]byte(`{"BackupVaultArn":"arn:aws:backup:eu-central-1:000000000000:backup-vault:pv-vault-1",` +
					`"EncryptionKeyArn":"arn:aws:kms:eu-central-1:000000000000:key/xyz","Locked":true,"MinRetentionDays":30}`))

			// ---- CloudFront (REST-XML, global) ----
			case path == "/2020-05-31/distribution":
				_, _ = w.Write([]byte(`<DistributionList><Items><DistributionSummary>` +
					`<Id>E123ABC456</Id>` +
					`<ARN>arn:aws:cloudfront::000000000000:distribution/E123ABC456</ARN>` +
					`</DistributionSummary></Items></DistributionList>`))
			case strings.HasPrefix(path, "/2020-05-31/distribution/"):
				_, _ = w.Write([]byte(`<Distribution><Id>E123ABC456</Id>` +
					`<ARN>arn:aws:cloudfront::000000000000:distribution/E123ABC456</ARN><Status>Deployed</Status>` +
					`<DistributionConfig><Enabled>true</Enabled>` +
					`<Origins><Items><Origin><DomainName>origin.example.com</DomainName></Origin></Items></Origins>` +
					`<DefaultCacheBehavior><ViewerProtocolPolicy>https-only</ViewerProtocolPolicy></DefaultCacheBehavior>` +
					`</DistributionConfig></Distribution>`))

			// ---- EFS (REST-JSON; one payload serves list + describe) ----
			case strings.HasPrefix(path, "/2015-02-01/file-systems"):
				_, _ = w.Write([]byte(`{"FileSystems":[{"FileSystemId":"fs-0123abcd","CreationToken":"tok",` +
					`"LifeCycleState":"available","Encrypted":true}]}`))

			// ---- EventBridge Scheduler (REST-JSON) ----
			case path == "/schedules":
				_, _ = w.Write([]byte(`{"Schedules":[{"Name":"pv-sched-1",` +
					`"Arn":"arn:aws:scheduler:eu-central-1:000000000000:schedule/default/pv-sched-1"}]}`))
			case strings.HasPrefix(path, "/schedules/"):
				_, _ = w.Write([]byte(`{"Name":"pv-sched-1","State":"ENABLED","Description":"groundhold"}`))

			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
}

// gapDriverA points every batch-A service's BaseURL at the fake endpoint (the
// existing BaseURL injection mechanism) and pins the account so STS is skipped.
func gapDriverA(t *testing.T, srv *httptest.Server) *Driver {
	d := s3TestDriver(t, srv) // creds + Account pinned
	d.ACMBaseURL = srv.URL
	d.APIGatewayBaseURL = srv.URL
	d.BackupBaseURL = srv.URL
	d.CloudFrontBaseURL = srv.URL
	d.CloudWatchDashBaseURL = srv.URL
	d.IAMBaseURL = srv.URL
	d.EFSBaseURL = srv.URL
	d.SchedulerBaseURL = srv.URL
	d.KinesisBaseURL = srv.URL
	return d
}

// gapCaseA is one discoverer + the pid and observations it must reverse-map back.
type gapCaseA struct {
	name     string
	sweep    func(*Driver, string) ([]provider.Discovered, []string, error)
	wantType string
	wantID   string
	wantObs  map[string]any
}

func TestDiscoverGapAWS_A(t *testing.T) {
	rec := newCapture()
	srv := gapDiscoverServerA(t, rec)
	defer srv.Close()
	d := gapDriverA(t, srv)

	cases := []gapCaseA{
		{
			name:     "acm",
			sweep:    (*Driver).discoverACM,
			wantType: "capability.certificate.tls",
			wantID:   "acm:eu-central-1:000000000000:12345678-1234-1234-1234-123456789012",
			wantObs:  map[string]any{"domain": "example.com", "auto.renew": true, "service.managed": true},
		},
		{
			name:     "apigateway",
			sweep:    (*Driver).discoverAPIGateway,
			wantType: "capability.apigateway.http",
			wantID:   "apigw:eu-central-1:000000000000:abc123def4",
			wantObs:  map[string]any{"protocol": "http", "service.managed": true},
		},
		{
			name:     "backupvault",
			sweep:    (*Driver).discoverBackupVaults,
			wantType: "capability.backup.vault",
			wantID:   "bkv:eu-central-1:000000000000:pv-vault-1",
			wantObs:  map[string]any{"retention.minimum": "720h", "retention.lockMode": "compliance", "encryption.customerManagedKeys": true},
		},
		{
			name:     "cloudfront",
			sweep:    (*Driver).discoverCloudFront,
			wantType: "capability.cdn.distribution",
			wantID:   "cf:000000000000:E123ABC456",
			wantObs:  map[string]any{"viewer.protocol": "https-only", "origin.domain": "origin.example.com", "service.managed": true},
		},
		{
			name:     "cloudwatchdash",
			sweep:    (*Driver).discoverCloudWatchDashboards,
			wantType: "capability.monitoring.dashboard",
			wantID:   "cwdash:pv-dash-1",
			wantObs:  map[string]any{"dashboard.widgetCount": float64(1), "service.managed": true},
		},
		{
			name:     "custompolicy",
			sweep:    (*Driver).discoverCustomPolicies,
			wantType: "capability.authorization.role",
			wantID:   "acrole:arn:aws:iam::000000000000:policy/pv-role-1",
			wantObs:  map[string]any{"access.mutating": false, "access.privileged": false, "service.managed": true},
		},
		{
			name:     "efs",
			sweep:    (*Driver).discoverEFS,
			wantType: "capability.storage.filesystem",
			wantID:   "efs:eu-central-1:000000000000:fs-0123abcd",
			wantObs:  map[string]any{"encryption.atRest": true, "availability.class": "regional", "service.managed": true},
		},
		{
			name:     "eventbridgescheduler",
			sweep:    (*Driver).discoverEventBridgeSchedulers,
			wantType: "capability.scheduler.cron",
			wantID:   "ebsched:eu-central-1:pv-sched-1",
			wantObs:  map[string]any{"schedule.enabled": true, "service.managed": true},
		},
		{
			name:     "kinesis",
			sweep:    (*Driver).discoverKinesis,
			wantType: "capability.streaming.pipe",
			wantID:   "kinesis:eu-central-1:000000000000:pv-stream-1",
			wantObs:  map[string]any{"retention.window": "48h", "encryption.customerManagedKeys": true, "service.managed": true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			found, diags, err := tc.sweep(d, "eu-central-1")
			if err != nil {
				t.Fatalf("%s sweep errored: %v (diags %v)", tc.name, err, diags)
			}
			if len(found) != 1 {
				t.Fatalf("%s: want exactly 1 discovered resource, got %d: %+v (diags %v)", tc.name, len(found), found, diags)
			}
			got := found[0]
			if got.ResourceType != tc.wantType {
				t.Fatalf("%s: ResourceType = %q, want %q", tc.name, got.ResourceType, tc.wantType)
			}
			if got.ProviderID != tc.wantID {
				t.Fatalf("%s: ProviderID = %q, want %q", tc.name, got.ProviderID, tc.wantID)
			}
			if len(got.Observations) == 0 {
				t.Fatalf("%s: no observations — a discovered resource must carry the reverse-mapped observe output, never all-unknown", tc.name)
			}
			obs := obsMap(got)
			for path, want := range tc.wantObs {
				if obs[path] != want {
					t.Fatalf("%s: observation %s = %v (%T), want %v (%T) — full: %+v", tc.name, path, obs[path], obs[path], want, want, obs)
				}
			}
		})
	}

	// every request the sweeps issued was SigV4-signed.
	if rec.unsign != 0 {
		t.Fatalf("every discovery request must be SigV4-signed; %d were not", rec.unsign)
	}
	// the JSON/Query LIST calls were made (the REST list calls are proven by the
	// resource landing above).
	for _, op := range []string{"ListCertificates", "ListStreams", "ListDashboards", "ListPolicies"} {
		if !rec.saw(op) {
			t.Fatalf("expected the sweep to issue %s", op)
		}
	}
}

// TestDiscoverGapAWS_A_ListErrorIsError proves a non-200 LIST returns an error, never
// a fabricated empty list (the honesty invariant every sweep shares).
func TestDiscoverGapAWS_A_ListErrorIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"__type":"ServerException"}`))
	}))
	defer srv.Close()
	d := gapDriverA(t, srv)

	sweeps := []func(*Driver, string) ([]provider.Discovered, []string, error){
		(*Driver).discoverACM, (*Driver).discoverAPIGateway, (*Driver).discoverBackupVaults,
		(*Driver).discoverCloudFront, (*Driver).discoverCloudWatchDashboards, (*Driver).discoverCustomPolicies,
		(*Driver).discoverEFS, (*Driver).discoverEventBridgeSchedulers, (*Driver).discoverKinesis,
	}
	for _, sweep := range sweeps {
		found, _, err := sweep(d, "eu-central-1")
		if err == nil {
			t.Fatalf("a 500 on LIST must return an error, not a fabricated empty list (got %d resources)", len(found))
		}
		if found != nil {
			t.Fatalf("a failed LIST must return nil resources, got %+v", found)
		}
	}
}
