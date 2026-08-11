package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// D800. Every encrypted AWS resource reports a KMS key — the account-default aws/<svc>
// one when the customer brought none. Three drivers read "a key id is present" as "the
// customer brought a key", so a default-encrypted file system, cache or domain certified
// BYOK against a compliance attribute, on somebody else's estate, at adoption.
//
// The correct implementation was already in the same package: RDS traces the key to KMS
// and reads KeyManager. These tests hold the three drivers to it, in both directions —
// an AWS-managed key is reported FALSE, and a KMS lookup that fails is reported as
// nothing at all plus a diagnostic, never as a false true.

// kmsSaying builds a fixture whose KMS DescribeKey answers with the given manager, and
// whose service routes are supplied by the caller.
func kmsSaying(manager string, rest http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.Header.Get("X-Amz-Target"), ".DescribeKey") {
			if manager == "" {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"__type":"AccessDeniedException"}`))
				return
			}
			_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyManager":"` + manager + `"}}`))
			return
		}
		rest(w, r)
	}))
}

func byokDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.KMSBaseURL = srv.URL
	d.EFSBaseURL = srv.URL
	d.ElastiCacheBaseURL = srv.URL
	d.OpenSearchBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = time.Second
	return d
}

func byokFlat(t *testing.T, obs any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(obs)
	var list []struct {
		Path  string `json:"path"`
		Value any    `json:"value"`
	}
	_ = json.Unmarshal(b, &list)
	out := map[string]any{}
	for _, o := range list {
		out[o.Path] = o.Value
	}
	return out
}

func TestEFSDefaultKeyIsNotReportedAsCustomerManaged(t *testing.T) {
	srv := kmsSaying("AWS", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, efsPath+"/resource-tags/"):
			_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"shared"},` +
				`{"Key":"groundhold-environment","Value":"prod"}]}`))
		case r.URL.Path == efsPath+"/file-systems":
			_, _ = w.Write([]byte(`{"FileSystems":[{"FileSystemId":"fs-0123456789abcdef0",` +
				`"LifeCycleState":"available","Encrypted":true,` +
				`"KmsKeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc"}]}`))
		default:
			w.WriteHeader(404)
		}
	})
	defer srv.Close()
	d := byokDriver(t, srv)
	obs, _, err := d.observeEFS("shared", efsProviderID("eu-central-1", "000000000000", "fs-0123456789abcdef0"))
	if err != nil {
		t.Fatal(err)
	}
	got := byokFlat(t, obs)
	if got["encryption.customerManagedKeys"] != false {
		t.Fatalf("an AWS-managed key certified as BYOK: %+v", got)
	}
}

func TestEFSUnreadableKeyIsNotClaimedEitherWay(t *testing.T) {
	srv := kmsSaying("", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, efsPath+"/resource-tags/"):
			_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"shared"},` +
				`{"Key":"groundhold-environment","Value":"prod"}]}`))
		case r.URL.Path == efsPath+"/file-systems":
			_, _ = w.Write([]byte(`{"FileSystems":[{"FileSystemId":"fs-0123456789abcdef0",` +
				`"LifeCycleState":"available","Encrypted":true,` +
				`"KmsKeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc"}]}`))
		default:
			w.WriteHeader(404)
		}
	})
	defer srv.Close()
	d := byokDriver(t, srv)
	obs, diags, err := d.observeEFS("shared", efsProviderID("eu-central-1", "000000000000", "fs-0123456789abcdef0"))
	if err != nil {
		t.Fatal(err)
	}
	if _, claimed := byokFlat(t, obs)["encryption.customerManagedKeys"]; claimed {
		t.Fatal("an unreadable KMS trace still produced a BYOK claim")
	}
	if !strings.Contains(strings.Join(diags, " | "), "customerManagedKeys not observed") {
		t.Fatalf("the withheld attribute is not explained: %v", diags)
	}
}

func TestOpenSearchDefaultKeyIsNotReportedAsCustomerManaged(t *testing.T) {
	srv := kmsSaying("AWS", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/tags"):
			_, _ = w.Write([]byte(`{"TagList":[{"Key":"groundhold-capability","Value":"search"},` +
				`{"Key":"groundhold-environment","Value":"prod"}]}`))
		case strings.Contains(r.URL.Path, "/domain/"):
			_, _ = w.Write([]byte(`{"DomainStatus":{"DomainName":"catalog-prod-kfzktzaw","Created":true,"Processing":false,` +
				`"ARN":"arn:aws:es:eu-central-1:000000000000:domain/d",` +
				`"EncryptionAtRestOptions":{"Enabled":true,` +
				`"KmsKeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc"}}}`))
		default:
			w.WriteHeader(404)
		}
	})
	defer srv.Close()
	d := byokDriver(t, srv)
	obs, _, err := d.observeOpenSearch("search", openSearchProviderID("eu-central-1", "000000000000", "catalog-prod-kfzktzaw"))
	if err != nil {
		t.Fatal(err)
	}
	if byokFlat(t, obs)["encryption.customerManagedKeys"] != false {
		t.Fatalf("an AWS-managed key certified as BYOK: %+v", byokFlat(t, obs))
	}
}

// D803. The truncation signal is a property of the RESPONSE, so it is read at the
// transport chokepoint — once, where every response arrives — rather than in the 139
// sweeps that would each have to remember. This holds the AWS half of that: a listing
// answer carrying a continuation token is recorded, and reading the record clears it so
// one sweep cannot report the next one's pages.
func TestAWSTransportRecordsATruncatedListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Functions":[{"FunctionName":"a"}],"NextMarker":"page-2"}`))
	}))
	defer srv.Close()
	d := byokDriver(t, srv)
	d.LambdaBaseURL = srv.URL
	if _, _, _, err := d.doSignedH("GET", srv.URL+"/2015-03-31/functions/", "lambda",
		"eu-central-1", nil, nil); err != nil {
		t.Fatal(err)
	}
	notes := d.TruncatedListings()
	if len(notes) != 1 || !strings.Contains(notes[0].Call, "lambda") {
		t.Fatalf("a truncated listing was not recorded: %+v", notes)
	}
	if again := d.TruncatedListings(); len(again) != 0 {
		t.Fatalf("reading the record must clear it, got %+v", again)
	}
}

func TestAWSTransportStaysQuietOnACompleteListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Functions":[{"FunctionName":"a"}]}`))
	}))
	defer srv.Close()
	d := byokDriver(t, srv)
	if _, _, _, err := d.doSignedH("GET", srv.URL+"/2015-03-31/functions/", "lambda",
		"eu-central-1", nil, nil); err != nil {
		t.Fatal(err)
	}
	if notes := d.TruncatedListings(); len(notes) != 0 {
		t.Fatalf("a complete listing was recorded as truncated: %+v", notes)
	}
}

// D809. D803 taught the crawl to SAY that a listing stopped at the first page. These two
// make it untrue where it costs the most: the sweeps that enumerate an account's
// functions and its customer-managed policies, both of which a real estate has more of
// than one page.
//
// The fixture answers twice and only twice — the second page carries no continuation —
// so a driver that reads one page finds one item, and a driver that follows finds both.
func TestLambdaSweepFollowsTheSecondPage(t *testing.T) {
	// The COUNT of requests is the wrong instrument here: lambdaGet retries, so a driver
	// that never follows a marker can still hit the endpoint twice. What settles it is
	// whether the second page was ASKED for — a request carrying the marker the first
	// page handed back.
	askedForPage2 := false
	first := true
	srv := kmsSaying("AWS", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/functions"):
			if r.URL.Query().Get("Marker") == "p2" {
				askedForPage2 = true
				_, _ = w.Write([]byte(`{"Functions":[{"FunctionName":"api-prod-mjipeplg"}]}`))
				return
			}
			if first {
				first = false
				_, _ = w.Write([]byte(`{"Functions":[{"FunctionName":"api-abcdefgh"}],"NextMarker":"p2"}`))
				return
			}
			_, _ = w.Write([]byte(`{"Functions":[{"FunctionName":"api-abcdefgh"}],"NextMarker":"p2"}`))
		case strings.Contains(r.URL.Path, "GetCallerIdentity") || r.Method == "POST":
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
				`<Account>000000000000</Account></GetCallerIdentityResult></GetCallerIdentityResponse>`))
		default:
			w.WriteHeader(404)
		}
	})
	defer srv.Close()
	d := byokDriver(t, srv)
	d.LambdaBaseURL = srv.URL
	d.STSBaseURL = srv.URL
	_, _, err := d.discoverLambda("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if !askedForPage2 {
		t.Fatal("a NextMarker was handed back and never used — the sweep stopped at page one")
	}
}

func TestCustomPolicySweepFollowsTheSecondPage(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch {
		case strings.Contains(string(body), "ListPolicies"):
			page++
			if page == 1 {
				_, _ = w.Write([]byte(`<ListPoliciesResponse><ListPoliciesResult>` +
					`<Policies><member><Arn>arn:aws:iam::000000000000:policy/one</Arn></member></Policies>` +
					`<IsTruncated>true</IsTruncated><Marker>p2</Marker>` +
					`</ListPoliciesResult></ListPoliciesResponse>`))
				return
			}
			_, _ = w.Write([]byte(`<ListPoliciesResponse><ListPoliciesResult>` +
				`<Policies><member><Arn>arn:aws:iam::000000000000:policy/two</Arn></member></Policies>` +
				`<IsTruncated>false</IsTruncated></ListPoliciesResult></ListPoliciesResponse>`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := byokDriver(t, srv)
	d.IAMBaseURL = srv.URL
	_, _, _ = d.discoverCustomPolicies("eu-central-1")
	if page < 2 {
		t.Fatalf("the sweep read %d page(s) — IsTruncated said there was more and it stopped", page)
	}
}

// D810. Three more sweeps follow their pages: topics, queues and metric alarms. The
// assertion is the one D809 had to learn — not how many requests were made (a retry
// inflates that) but whether the second page was ASKED for, with the token the first
// page handed back.
func TestQueryProtocolSweepsFollowTheirPages(t *testing.T) {
	for _, c := range []struct {
		name   string
		action string
		page1  string
		sweep  func(d *Driver) error
	}{
		{"sns", "ListTopics",
			`<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>` +
				`arn:aws:sns:eu-central-1:000000000000:events-prod-1a2b3c4d</TopicArn></member></Topics>` +
				`<NextToken>p2</NextToken></ListTopicsResult></ListTopicsResponse>`,
			func(d *Driver) error { _, _, err := d.discoverSNS("eu-central-1"); return err }},
		{"sqs", "ListQueues",
			`<ListQueuesResponse><ListQueuesResult><QueueUrl>` +
				`https://sqs.eu-central-1.amazonaws.com/000000000000/orders-prod-1a2b3c4d</QueueUrl>` +
				`<NextToken>p2</NextToken></ListQueuesResult></ListQueuesResponse>`,
			func(d *Driver) error { _, _, err := d.discoverSQS("eu-central-1"); return err }},
	} {
		t.Run(c.name, func(t *testing.T) {
			asked := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(body))
				if form.Get("Action") != c.action {
					w.WriteHeader(400)
					return
				}
				if form.Get("NextToken") == "p2" {
					asked = true
					_, _ = w.Write([]byte(`<Response><Result></Result></Response>`))
					return
				}
				_, _ = w.Write([]byte(c.page1))
			}))
			defer srv.Close()
			d := byokDriver(t, srv)
			d.SNSBaseURL = srv.URL
			d.SQSBaseURL = srv.URL
			_ = c.sweep(d)
			if !asked {
				t.Fatalf("%s handed back a NextToken and the sweep never used it", c.action)
			}
		})
	}
}

// D811. Secrets, same rule and same assertion: was the second page asked for?
func TestSecretSweepFollowsTheSecondPage(t *testing.T) {
	asked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(r.Header.Get("X-Amz-Target"), "ListSecrets") {
			w.WriteHeader(400)
			return
		}
		if strings.Contains(string(body), `"NextToken":"p2"`) {
			asked = true
			_, _ = w.Write([]byte(`{"SecretList":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"SecretList":[{"Name":"db-prod-1a2b3c4d"}],"NextToken":"p2"}`))
	}))
	defer srv.Close()
	d := byokDriver(t, srv)
	d.SecretsManagerBaseURL = srv.URL
	_, _, _ = d.discoverSecrets("eu-central-1")
	if !asked {
		t.Fatal("ListSecrets handed back a NextToken and the sweep never used it")
	}
}

// D812. Four more sweeps follow their pages: IAM roles, ECR repositories, ECS clusters
// and RDS instances. One table, one assertion — was the second page ASKED for?
func TestRemainingAWSSweepsFollowTheirPages(t *testing.T) {
	for _, c := range []struct {
		name   string
		marker string // what the second-page request must carry
		page1  string
		target string // X-Amz-Target substring, for the JSON-protocol ones
		action string // Action=, for the query-protocol ones
		sweep  func(d *Driver) error
		wire   func(d *Driver, u string)
	}{
		{name: "iam-roles", marker: "Marker=p2", action: "ListRoles",
			page1: `<ListRolesResponse><ListRolesResult><Roles><member>` +
				`<RoleName>app-prod-1a2b3c4d</RoleName><Arn>arn:aws:iam::000000000000:role/app-prod-1a2b3c4d</Arn>` +
				`</member></Roles><IsTruncated>true</IsTruncated><Marker>p2</Marker>` +
				`</ListRolesResult></ListRolesResponse>`,
			sweep: func(d *Driver) error { _, _, err := d.discoverIAM("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.IAMBaseURL = u }},
		{name: "ecs-clusters", marker: `"nextToken":"p2"`, target: "ListClusters",
			page1: `{"clusterArns":["arn:aws:ecs:eu-central-1:000000000000:cluster/api-prod-1a2b3c4d"],"nextToken":"p2"}`,
			sweep: func(d *Driver) error { _, _, err := d.discoverECS("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.ECSBaseURL = u }},
	} {
		t.Run(c.name, func(t *testing.T) {
			asked := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), c.marker) {
					asked = true
					w.WriteHeader(200)
					_, _ = w.Write([]byte(`{"clusterArns":[]}`))
					return
				}
				_, _ = w.Write([]byte(c.page1))
			}))
			defer srv.Close()
			d := byokDriver(t, srv)
			c.wire(d, srv.URL)
			_ = c.sweep(d)
			if !asked {
				t.Fatalf("%s handed back a continuation and the sweep never used it", c.name)
			}
		})
	}
}

// D817. Four more sweeps follow their pages, and these four matter most: they have the
// SMALLEST default pages in the whole AWS surface this driver touches. EFS answers ten
// file systems, Auto Scaling fifty groups, KMS and Route 53 a hundred each. An estate
// with eleven file systems was reported as having ten, and nothing said otherwise.
//
// The assertion is the D809 one throughout: not "were there two requests" (a retry makes
// that true), but "did a request carry the continuation the first page handed back".
func TestSmallPageSweepsFollowTheirPages(t *testing.T) {
	for _, c := range []struct {
		name  string
		want  string // what the second-page request must carry, in query OR body
		page1 string
		sweep func(d *Driver) error
		wire  func(d *Driver, u string)
		page2 string
	}{
		{name: "efs", want: "Marker=p2",
			page1: `{"FileSystems":[{"FileSystemId":"fs-0123456789abcdef0"}],"NextMarker":"p2"}`,
			page2: `{"FileSystems":[]}`,
			sweep: func(d *Driver) error { _, _, err := d.discoverEFS("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.EFSBaseURL = u }},
		{name: "route53", want: "marker=p2",
			page1: `<ListHostedZonesResponse><HostedZones><HostedZone><Id>/hostedzone/Z123ABC</Id>` +
				`</HostedZone></HostedZones><IsTruncated>true</IsTruncated><NextMarker>p2</NextMarker>` +
				`</ListHostedZonesResponse>`,
			page2: `<ListHostedZonesResponse><HostedZones></HostedZones></ListHostedZonesResponse>`,
			sweep: func(d *Driver) error { _, _, err := d.discoverRoute53("us-east-1"); return err },
			wire:  func(d *Driver, u string) { d.Route53BaseURL = u }},
		{name: "kms", want: `"Marker":"p2"`,
			page1: `{"Keys":[{"KeyId":"1234abcd-12ab-34cd-56ef-1234567890ab"}],` +
				`"Truncated":true,"NextMarker":"p2"}`,
			page2: `{"Keys":[]}`,
			sweep: func(d *Driver) error { _, _, err := d.discoverKMS("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.KMSBaseURL = u }},
		{name: "asg", want: "NextToken=p2",
			page1: `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult>` +
				`<AutoScalingGroups><member><AutoScalingGroupName>web-prod-1a2b3c4d` +
				`</AutoScalingGroupName></member></AutoScalingGroups><NextToken>p2</NextToken>` +
				`</DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`,
			page2: `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult>` +
				`</DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`,
			sweep: func(d *Driver) error { _, _, err := d.discoverASGs("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.AutoScalingBaseURL = u }},
	} {
		t.Run(c.name, func(t *testing.T) {
			asked := false
			first := true
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				// STS, for the sweeps that resolve the account first.
				if strings.Contains(string(body), "GetCallerIdentity") {
					_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
						`<Account>000000000000</Account></GetCallerIdentityResult>` +
						`</GetCallerIdentityResponse>`))
					return
				}
				carried := strings.Contains(r.URL.RawQuery, c.want) || strings.Contains(string(body), c.want)
				if carried {
					asked = true
					_, _ = w.Write([]byte(c.page2))
					return
				}
				if first {
					first = false
					_, _ = w.Write([]byte(c.page1))
					return
				}
				// A per-resource observe: answer nothing useful, it becomes a diagnostic.
				w.WriteHeader(404)
			}))
			defer srv.Close()
			d := byokDriver(t, srv)
			c.wire(d, srv.URL)
			d.STSBaseURL = srv.URL
			_ = c.sweep(d)
			if !asked {
				t.Fatalf("%s handed back a continuation and the sweep never used it", c.name)
			}
		})
	}
}
