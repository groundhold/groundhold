package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// gapBServer answers the List + Describe calls of every batch-B discoverer
// (KMS, MSK, OpenSearch, Redshift Serverless, Route 53, Route 53 health checks,
// VPN gateways, WAFv2). Each service surfaces exactly one resource; the Describe
// leg carries the real attributes the SAME observe reverse-map turns into
// observations. GetSecretValue and any key-material read are structurally absent
// (D53) — a discoverer that asked for one would 501.
func gapBServer(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// D765: a CLOUDFRONT-scope WebACL protects something only if a distribution
			// names it; this fake's ACL is associated, so discovery sees a firewall that
			// actually guards its edge.
			if r.Method == "GET" && strings.Contains(r.URL.Path, "/distribution") {
				_, _ = w.Write([]byte(`<DistributionList><Items><DistributionSummary>` +
					`<Id>E1</Id><WebACLId>arn:aws:wafv2:us-east-1:000000000000:global/webacl/cf-waf/id-123` +
					`</WebACLId></DistributionSummary></Items></DistributionList>`))
				return
			}
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
			// ---- KMS (JSON protocol; metadata only, never key material — D53) ----
			case strings.HasSuffix(target, ".ListKeys"):
				_, _ = w.Write([]byte(`{"Keys":[{"KeyId":"1234abcd-12ab-34cd-56ef-1234567890ab"}]}`))
			case strings.HasSuffix(target, ".DescribeKey"):
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyId":"1234abcd-12ab-34cd-56ef-1234567890ab"}}`))
			case strings.HasSuffix(target, ".GetKeyRotationStatus"):
				_, _ = w.Write([]byte(`{"KeyRotationEnabled":true,"RotationPeriodInDays":90}`))

			// ---- Redshift Serverless (JSON protocol) ----
			case strings.HasSuffix(target, ".ListWorkgroups"):
				_, _ = w.Write([]byte(`{"workgroups":[{"workgroupName":"analytics"}]}`))
			case strings.HasSuffix(target, ".GetWorkgroup"):
				_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"analytics","status":"AVAILABLE","publiclyAccessible":false}}`))
			case strings.HasSuffix(target, ".GetNamespace"):
				_, _ = w.Write([]byte(`{"namespace":{"namespaceName":"analytics","kmsKeyId":""}}`))

			// ---- WAFv2 (JSON protocol, CLOUDFRONT scope / global) ----
			case strings.HasSuffix(target, ".ListWebACLs"):
				_, _ = w.Write([]byte(`{"WebACLs":[{"Name":"cf-waf","Id":"id-123","ARN":"arn:aws:wafv2:us-east-1:000000000000:global/webacl/cf-waf/id-123","LockToken":"lt"}]}`))
			case strings.HasSuffix(target, ".GetWebACL"):
				_, _ = w.Write([]byte(`{"WebACL":{"DefaultAction":{"Allow":{}},"Rules":[` +
					`{"Statement":{"ManagedRuleGroupStatement":{"Name":"AWSManagedRulesCommonRuleSet"}},"OverrideAction":{"None":{}}}]}}`))

			// ---- MSK (REST-JSON; ListClustersV2 serves list + observe filter) ----
			case r.Method == http.MethodGet && path == mskPath:
				_, _ = w.Write([]byte(`{"ClusterInfoList":[{"ClusterName":"events-kafka","State":"ACTIVE",` +
					`"Provisioned":{"CurrentBrokerSoftwareInfo":{"KafkaVersion":"3.5.1"},` +
					`"EncryptionInfo":{"EncryptionInTransit":{"ClientBroker":"TLS"},"EncryptionAtRest":{"DataVolumeKMSKeyId":""}}}}]}`))

			// ---- OpenSearch (REST-JSON) ----
			case r.Method == http.MethodGet && path == openSearchAccountPath+"/domain":
				_, _ = w.Write([]byte(`{"DomainNames":[{"DomainName":"logs","EngineType":"OpenSearch"}]}`))
			case r.Method == http.MethodGet && strings.HasPrefix(path, openSearchPath+"/domain/"):
				_, _ = w.Write([]byte(`{"DomainStatus":{"DomainName":"logs",` +
					`"EncryptionAtRestOptions":{"Enabled":true},"DomainEndpointOptions":{"EnforceHTTPS":true},` +
					`"ClusterConfig":{"ZoneAwarenessEnabled":true}}}`))

			// ---- Route 53 (REST-XML, global; ListHostedZones + GetHostedZone) ----
			case r.Method == http.MethodGet && path == route53Path+"/hostedzone":
				_, _ = w.Write([]byte(`<ListHostedZonesResponse><HostedZones>` +
					`<HostedZone><Id>/hostedzone/Z1234ABC</Id><Name>example.com.</Name></HostedZone>` +
					`</HostedZones></ListHostedZonesResponse>`))
			case r.Method == http.MethodGet && strings.HasPrefix(path, route53Path+"/hostedzone/"):
				_, _ = w.Write([]byte(`<GetHostedZoneResponse><HostedZone>` +
					`<Id>/hostedzone/Z1234ABC</Id><Name>example.com.</Name>` +
					`<Config><PrivateZone>false</PrivateZone></Config></HostedZone></GetHostedZoneResponse>`))

			// ---- Route 53 health checks (REST-XML, global) ----
			case r.Method == http.MethodGet && path == "/2013-04-01/healthcheck":
				_, _ = w.Write([]byte(`<ListHealthChecksResponse><HealthChecks>` +
					`<HealthCheck><Id>hc-abc-123</Id></HealthCheck>` +
					`</HealthChecks></ListHealthChecksResponse>`))
			case r.Method == http.MethodGet && strings.HasPrefix(path, "/2013-04-01/healthcheck/"):
				_, _ = w.Write([]byte(`<GetHealthCheckResponse><HealthCheck><HealthCheckConfig>` +
					`<Type>HTTPS</Type><FullyQualifiedDomainName>example.com</FullyQualifiedDomainName>` +
					`<ResourcePath>/health</ResourcePath><RequestInterval>30</RequestInterval>` +
					`</HealthCheckConfig></HealthCheck></GetHealthCheckResponse>`))

			// ---- VPN gateway (EC2 Query; DescribeVpnGateways serves list + observe) ----
			case r.Method == http.MethodPost && strings.Contains(body, "DescribeVpnGateways"):
				_, _ = w.Write([]byte(`<DescribeVpnGatewaysResponse><vpnGatewaySet><item>` +
					`<vpnGatewayId>vgw-0abc123</vpnGatewayId><state>available</state>` +
					`<tagSet><item><key>groundhold-capability</key><value>vpn</value></item></tagSet>` +
					`</item></vpnGatewaySet></DescribeVpnGatewaysResponse>`))

			// D53 tripwire — must never fire.
			case strings.HasSuffix(target, ".GetSecretValue"):
				w.WriteHeader(http.StatusNotImplemented)
			default:
				w.WriteHeader(http.StatusOK)
			}
		}))
}

// gapBDriver wires every batch-B service to the fixture and pins the account so
// no test hits STS.
func gapBDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000" // skip the STS resolve
	d.KMSBaseURL = srv.URL
	d.MSKBaseURL = srv.URL
	d.OpenSearchBaseURL = srv.URL
	d.RedshiftServerlessBaseURL = srv.URL
	d.Route53BaseURL = srv.URL
	d.EC2BaseURL = srv.URL
	d.WAFBaseURL = srv.URL
	d.CloudFrontBaseURL = srv.URL // D765: associations live on the distribution
	return d
}

func TestDiscoverKMSGapB(t *testing.T) {
	rec := newCapture()
	srv := gapBServer(t, rec)
	defer srv.Close()
	d := gapBDriver(t, srv)

	found, diags, err := d.discoverKMS("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 key, got %d (diags %v)", len(found), diags)
	}
	if found[0].ProviderID != "akms:eu-central-1:1234abcd-12ab-34cd-56ef-1234567890ab" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.key.encryption" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	obs := obsMap(found[0])
	if obs["protection.level"] != "hsm" || obs["rotation.period"] != "90d" {
		t.Fatalf("kms observations = %+v", obs)
	}
	if !rec.saw("ListKeys") || !rec.saw("DescribeKey") {
		t.Fatal("expected ListKeys + DescribeKey")
	}
	if rec.unsign != 0 {
		t.Fatalf("every request must be SigV4-signed; %d were not", rec.unsign)
	}
}

func TestDiscoverMSKGapB(t *testing.T) {
	rec := newCapture()
	srv := gapBServer(t, rec)
	defer srv.Close()
	d := gapBDriver(t, srv)

	found, diags, err := d.discoverMSK("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 cluster, got %d (diags %v)", len(found), diags)
	}
	if found[0].ProviderID != "msk:eu-central-1:000000000000:events-kafka" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.messaging.kafka" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	obs := obsMap(found[0])
	if obs["encryption.inTransit"] != true || obs["engine.protocol"] != "kafka/3" {
		t.Fatalf("msk observations = %+v", obs)
	}
	if rec.unsign != 0 {
		t.Fatalf("every request must be SigV4-signed; %d were not", rec.unsign)
	}
}

func TestDiscoverOpenSearchGapB(t *testing.T) {
	rec := newCapture()
	srv := gapBServer(t, rec)
	defer srv.Close()
	d := gapBDriver(t, srv)

	found, diags, err := d.discoverOpenSearch("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 domain, got %d (diags %v)", len(found), diags)
	}
	if found[0].ProviderID != "opensearch:eu-central-1:000000000000:logs" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.search.index" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	obs := obsMap(found[0])
	if obs["encryption.atRest"] != true || obs["encryption.inTransit"] != true ||
		obs["availability.class"] != "regional" {
		t.Fatalf("opensearch observations = %+v", obs)
	}
	if rec.unsign != 0 {
		t.Fatalf("every request must be SigV4-signed; %d were not", rec.unsign)
	}
}

func TestDiscoverRedshiftServerlessGapB(t *testing.T) {
	rec := newCapture()
	srv := gapBServer(t, rec)
	defer srv.Close()
	d := gapBDriver(t, srv)

	found, diags, err := d.discoverRedshiftServerless("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 workgroup, got %d (diags %v)", len(found), diags)
	}
	if found[0].ProviderID != "rss:eu-central-1:analytics" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.warehouse.analytics" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	obs := obsMap(found[0])
	if obs["network.publicExposure"] != false || obs["encryption.atRest"] != true {
		t.Fatalf("rss observations = %+v", obs)
	}
	if !rec.saw("ListWorkgroups") || rec.unsign != 0 {
		t.Fatalf("expected signed ListWorkgroups; unsigned=%d", rec.unsign)
	}
}

func TestDiscoverRoute53GapB(t *testing.T) {
	rec := newCapture()
	srv := gapBServer(t, rec)
	defer srv.Close()
	d := gapBDriver(t, srv)

	found, diags, err := d.discoverRoute53("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 zone, got %d (diags %v)", len(found), diags)
	}
	if found[0].ProviderID != "r53:Z1234ABC" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.dns.zone" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	obs := obsMap(found[0])
	if obs["network.publicExposure"] != true || obs["zone.domain"] != "example.com" {
		t.Fatalf("route53 observations = %+v", obs)
	}
	if rec.unsign != 0 {
		t.Fatalf("every request must be SigV4-signed; %d were not", rec.unsign)
	}
}

func TestDiscoverRoute53HealthGapB(t *testing.T) {
	rec := newCapture()
	srv := gapBServer(t, rec)
	defer srv.Close()
	d := gapBDriver(t, srv)

	found, diags, err := d.discoverRoute53Health("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 health check, got %d (diags %v)", len(found), diags)
	}
	if found[0].ProviderID != "r53hc:hc-abc-123" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.monitoring.uptime" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	obs := obsMap(found[0])
	if obs["check.protocol"] != "https" || obs["check.period"] != "30s" || obs["check.path"] != "/health" {
		t.Fatalf("route53health observations = %+v", obs)
	}
	if rec.unsign != 0 {
		t.Fatalf("every request must be SigV4-signed; %d were not", rec.unsign)
	}
}

func TestDiscoverVpnGatewayGapB(t *testing.T) {
	rec := newCapture()
	srv := gapBServer(t, rec)
	defer srv.Close()
	d := gapBDriver(t, srv)

	found, diags, err := d.discoverVpnGateway("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 gateway, got %d (diags %v)", len(found), diags)
	}
	if found[0].ProviderID != "vgw:eu-central-1:vgw-0abc123" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.vpn.gateway" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	obs := obsMap(found[0])
	if obs["location.region"] != "eu-central-1" || obs["ip.stack"] != "ipv4" {
		t.Fatalf("vpngateway observations = %+v", obs)
	}
	if !rec.saw("DescribeVpnGateways") || rec.unsign != 0 {
		t.Fatalf("expected signed DescribeVpnGateways; unsigned=%d", rec.unsign)
	}
}

func TestDiscoverWAFGapB(t *testing.T) {
	rec := newCapture()
	srv := gapBServer(t, rec)
	defer srv.Close()
	d := gapBDriver(t, srv)

	found, diags, err := d.discoverWAF("us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 WebACL, got %d (diags %v)", len(found), diags)
	}
	if found[0].ProviderID != "waf:000000000000:cf-waf" {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	if found[0].ResourceType != "capability.security.waf" {
		t.Fatalf("resourceType = %q", found[0].ResourceType)
	}
	obs := obsMap(found[0])
	if obs["policy.mode"] != "prevention" || obs["managed.ruleset"] != true {
		t.Fatalf("waf observations = %+v", obs)
	}
	if !rec.saw("ListWebACLs") || !rec.saw("GetWebACL") {
		t.Fatal("expected ListWebACLs + GetWebACL")
	}
	if rec.unsign != 0 {
		t.Fatalf("every request must be SigV4-signed; %d were not", rec.unsign)
	}
}

// TestDiscoverGapBPerResourceIsolation proves an observe that fails for one
// resource is a diagnostic + skip, never a fabricated all-unknown record: a KMS
// DescribeKey that 500s yields no resource but does surface a diagnostic.
func TestDiscoverGapBPerResourceIsolation(t *testing.T) {
	inner := gapBServer(t, nil)
	defer inner.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".DescribeKey") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"__type":"KMSInternalException"}`))
			return
		}
		inner.Config.Handler.ServeHTTP(w, r)
	}))
	defer srv.Close()
	d := gapBDriver(t, srv)

	found, diags, err := d.discoverKMS("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 0 {
		t.Fatalf("a 500 DescribeKey must not yield a resource, got %+v", found)
	}
	if len(diags) == 0 {
		t.Fatal("the failed observe must surface as a diagnostic")
	}
}
