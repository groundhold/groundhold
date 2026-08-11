package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D818. D803 promised that a sweep reading one page SAYS so: the transport reads every
// response, and a continuation token makes the crawl record the scope as incomplete, which
// makes `posture` publish "at least N" instead of an exact count of what is unmanaged.
//
// The promise held in neither direction. A sweep that FOLLOWS its pages hands the transport
// a truncated response on every page but the last, so all twenty-four paginating sweeps
// reported themselves incomplete. And three sweeps that read one page reported themselves
// COMPLETE, because the signal their service uses was one the detector could not see.
//
// The note is now conditional on the continuation going unused. These two tests pin both
// halves, because a mechanism that only ever says "incomplete" is as useless as one that
// only ever says "complete", and each failure hides the other.
func TestFollowingThePagesClearsTheTruncationNote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form := string(body)
		if !strings.Contains(form, "Action=ListTopics") {
			// GetTopicAttributes and friends: not a listing, nothing to continue.
			_, _ = w.Write([]byte(`<GetTopicAttributesResponse><GetTopicAttributesResult>` +
				`<Attributes></Attributes></GetTopicAttributesResult></GetTopicAttributesResponse>`))
			return
		}
		if strings.Contains(form, "NextToken=p2") {
			_, _ = w.Write([]byte(`<ListTopicsResponse><ListTopicsResult><Topics></Topics>` +
				`</ListTopicsResult></ListTopicsResponse>`))
			return
		}
		_, _ = w.Write([]byte(`<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>` +
			`arn:aws:sns:eu-central-1:000000000000:events-prod-1a2b3c4d</TopicArn></member></Topics>` +
			`<NextToken>p2</NextToken></ListTopicsResult></ListTopicsResponse>`))
	}))
	defer srv.Close()
	d := byokDriver(t, srv)
	d.SNSBaseURL = srv.URL
	_, _, _ = d.discoverSNS("eu-central-1")
	if notes := d.TruncatedListings(); len(notes) != 0 {
		t.Fatalf("a sweep that followed every page reported its listing as truncated: %+v\n"+
			"Every paginating sweep would mark the scope incomplete, so posture would say "+
			"'at least N' about counts it knows exactly (D818).", notes)
	}
}

// TestReadingOnePageLeavesTheTruncationNote is the other half, and its subject is chosen
// for two reasons. DescribeVolumes is one of the thirty-odd sweeps that still read a single
// page (D817), and EC2 is the family where this went most wrong: its model calls the field
// NextToken and the WIRE says `<nextToken>`, so a case-sensitive pattern made truncation
// invisible for every EC2 sweep there is.
//
// The note must also NAME the operation, which for the Query-protocol services means
// reading Action out of the form BODY. Reading only the query string — where EC2's siblings
// never put it — named every one of these truncations "POST /".
func TestReadingOnePageLeavesTheTruncationNote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<DescribeVolumesResponse><volumeSet><item>` +
			`<volumeId>vol-0123456789abcdef0</volumeId></item></volumeSet>` +
			`<nextToken>p2</nextToken></DescribeVolumesResponse>`))
	}))
	defer srv.Close()
	d := byokDriver(t, srv)
	d.EC2BaseURL = srv.URL
	d.STSBaseURL = srv.URL
	_, _, _ = d.discoverEBSVolumes("eu-central-1")
	notes := d.TruncatedListings()
	if len(notes) == 0 {
		t.Fatal("the response said more results exist, nobody fetched them, and the driver " +
			"reported a COMPLETE listing — posture will publish an exact count of what is " +
			"unmanaged, and it will be wrong (D803/D818)")
	}
	if !strings.Contains(notes[0].Call, "DescribeVolumes") {
		t.Fatalf("the note names %q — a truncation that does not name its operation sends "+
			"nobody anywhere (D803)", notes[0].Call)
	}
}

// TestSmallestSweepsFollowTheirPages covers the three D818 found reading one page while
// saying nothing. The assertion is the D809 one: did a request carry the continuation the
// previous page handed back? Never a request COUNT, which a retry makes lie.
func TestSmallestSweepsFollowTheirPages(t *testing.T) {
	for _, c := range []struct {
		name  string
		want  string
		page1 string
		page2 string
		sweep func(d *Driver) error
		wire  func(d *Driver, u string)
	}{
		{name: "dynamodb", want: `"ExclusiveStartTableName":"orders-prod-1a2b3c4d"`,
			page1: `{"TableNames":["orders-prod-1a2b3c4d"],"LastEvaluatedTableName":"orders-prod-1a2b3c4d"}`,
			page2: `{"TableNames":[]}`,
			sweep: func(d *Driver) error { _, _, err := d.discoverDynamoDB("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.DynamoDBBaseURL = u }},
		{name: "kinesis", want: `"NextToken":"p2"`,
			page1: `{"StreamNames":["events-prod-1a2b3c4d"],"HasMoreStreams":true,"NextToken":"p2"}`,
			page2: `{"StreamNames":[],"HasMoreStreams":false}`,
			sweep: func(d *Driver) error { _, _, err := d.discoverKinesis("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.KinesisBaseURL = u }},
		{name: "elasticache", want: "Marker=p2",
			page1: `<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
				`<ReplicationGroups><ReplicationGroup><ReplicationGroupId>cache-prod-1a2b3c4d` +
				`</ReplicationGroupId></ReplicationGroup></ReplicationGroups><Marker>p2</Marker>` +
				`</DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`,
			page2: `<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
				`</DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`,
			sweep: func(d *Driver) error { _, _, err := d.discoverElastiCache("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.ElastiCacheBaseURL = u }},
	} {
		t.Run(c.name, func(t *testing.T) {
			asked := false
			first := true
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), "GetCallerIdentity") {
					_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
						`<Account>000000000000</Account></GetCallerIdentityResult>` +
						`</GetCallerIdentityResponse>`))
					return
				}
				if strings.Contains(string(body), c.want) || strings.Contains(r.URL.RawQuery, c.want) {
					asked = true
					_, _ = w.Write([]byte(c.page2))
					return
				}
				if first {
					first = false
					_, _ = w.Write([]byte(c.page1))
					return
				}
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

// TestPaginatedSweepsWithoutACaseUntilNow closes a gap D818 found by accident: a mutant
// that broke RDS pagination passed the entire AWS suite. D812's own comment claimed to
// cover "IAM roles, ECR repositories, ECS clusters and RDS instances" and its table had
// two entries — a published claim with nothing holding it up, which is the shape this
// repository keeps finding in its own work.
//
// These are the four paginated sweeps that had no case at all. Same assertion as always:
// did a request carry the continuation the previous page handed back?
func TestPaginatedSweepsWithoutACaseUntilNow(t *testing.T) {
	for _, c := range []struct {
		name  string
		want  string
		page1 string
		page2 string
		sweep func(d *Driver) error
		wire  func(d *Driver, u string)
	}{
		{name: "rds", want: "Marker=p2",
			page1: `<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances>` +
				`<DBInstance><DBInstanceIdentifier>db-prod-1a2b3c4d</DBInstanceIdentifier></DBInstance>` +
				`</DBInstances><Marker>p2</Marker></DescribeDBInstancesResult></DescribeDBInstancesResponse>`,
			page2: `<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances>` +
				`</DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`,
			sweep: func(d *Driver) error { _, _, err := d.discoverRDS("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.RDSBaseURL = u }},
		{name: "ecr", want: `"nextToken":"p2"`,
			page1: `{"repositories":[{"repositoryName":"api-prod-1a2b3c4d"}],"nextToken":"p2"}`,
			page2: `{"repositories":[]}`,
			sweep: func(d *Driver) error { _, _, err := d.discoverECR("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.ECRBaseURL = u }},
		{name: "cloudwatch-alarms", want: "NextToken=p2",
			page1: `<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member>` +
				`<AlarmName>cpu-prod-1a2b3c4d</AlarmName></member></MetricAlarms>` +
				`<NextToken>p2</NextToken></DescribeAlarmsResult></DescribeAlarmsResponse>`,
			page2: `<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms>` +
				`</MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`,
			sweep: func(d *Driver) error { _, _, err := d.discoverCloudWatch("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.CloudWatchBaseURL = u }},
		{name: "cwlogs", want: `"nextToken":"p2"`,
			page1: `{"logGroups":[{"logGroupName":"/aws/lambda/api-prod-1a2b3c4d"}],"nextToken":"p2"}`,
			page2: `{"logGroups":[]}`,
			sweep: func(d *Driver) error { _, _, err := d.discoverCWLogs("eu-central-1"); return err },
			wire:  func(d *Driver, u string) { d.LogsBaseURL = u }},
	} {
		t.Run(c.name, func(t *testing.T) {
			asked := false
			first := true
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if strings.Contains(string(body), "GetCallerIdentity") {
					_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
						`<Account>000000000000</Account></GetCallerIdentityResult>` +
						`</GetCallerIdentityResponse>`))
					return
				}
				if strings.Contains(string(body), c.want) || strings.Contains(r.URL.RawQuery, c.want) {
					asked = true
					_, _ = w.Write([]byte(c.page2))
					return
				}
				if first {
					first = false
					_, _ = w.Write([]byte(c.page1))
					return
				}
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

// D820. OpenSearch Service mixes two path prefixes under one API version, and the driver
// used the longer one for all six of its routes. Four were right; the two READS were not,
// and AWS answers those 404 forever — so `discover` reported an estate with no OpenSearch
// domains in it whatever the truth was.
//
// This pins the exact paths, because the thing that went wrong was a constant that looked
// consistent. The fixture answers ONLY the routes AWS actually has (confirmed against the
// provider's model and against live AWS, which returns "Missing Authentication Token" for
// them and <UnknownOperationException/> for the others); anything else is a 404, exactly as
// the real endpoint would.
func TestOpenSearchReadsUseThePrefixAWSHas(t *testing.T) {
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "GetCallerIdentity") {
			_, _ = w.Write([]byte(`<GetCallerIdentityResponse><GetCallerIdentityResult>` +
				`<Account>000000000000</Account></GetCallerIdentityResult>` +
				`</GetCallerIdentityResponse>`))
			return
		}
		asked = append(asked, r.URL.Path)
		switch {
		case r.URL.Path == "/2021-01-01/domain":
			_, _ = w.Write([]byte(`{"DomainNames":[{"DomainName":"catalog-prod-kfzktzaw"}]}`))
		case r.URL.Path == "/2021-01-01/opensearch/domain/catalog-prod-kfzktzaw":
			_, _ = w.Write([]byte(`{"DomainStatus":{"DomainName":"catalog-prod-kfzktzaw"}}`))
		case r.URL.Path == "/2021-01-01/tags/":
			_, _ = w.Write([]byte(`{"TagList":[]}`))
		default:
			w.WriteHeader(404)
			_, _ = w.Write([]byte(`<UnknownOperationException/>`))
		}
	}))
	defer srv.Close()
	d := byokDriver(t, srv)
	d.OpenSearchBaseURL = srv.URL
	d.STSBaseURL = srv.URL

	found, _, err := d.discoverOpenSearch("eu-central-1")
	if err != nil {
		t.Fatalf("the sweep failed against the routes AWS really has: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 domain from a listing that has one, got %d — the sweep is reading "+
			"a path AWS answers 404 to, and an estate with domains reports as empty", len(found))
	}
	if _, err := d.openSearchTags("eu-central-1", "000000000000", "catalog-prod-kfzktzaw"); err != nil {
		t.Fatalf("the tag read failed against the route AWS really has: %v", err)
	}
	for _, p := range asked {
		if strings.HasPrefix(p, "/2021-01-01/opensearch/domain/") || p == "/2021-01-01/domain" ||
			p == "/2021-01-01/tags/" {
			continue
		}
		t.Errorf("the driver asked for %q, which AWS does not serve", p)
	}
}
