package aws

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func sqsAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eu-central-1",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

func TestQueueNameDeterministicAndFIFO(t *testing.T) {
	n := QueueName("000000000000", "prod", "orders", 1, false)
	if !sqsNameOK.MatchString(n) {
		t.Fatalf("queue name not valid: %q", n)
	}
	if n != QueueName("000000000000", "prod", "orders", 1, false) {
		t.Fatal("queue name must be deterministic")
	}
	if g2 := QueueName("000000000000", "prod", "orders", 2, false); g2 == n {
		t.Fatal("a replacement (g2) must not collide with g1")
	}
	fifo := QueueName("000000000000", "prod", "orders", 1, true)
	if !strings.HasSuffix(fifo, ".fifo") {
		t.Fatalf("a FIFO queue name must end in .fifo, got %q", fifo)
	}
	if !sqsNameOK.MatchString(fifo) || len(fifo) > 80 {
		t.Fatalf("FIFO queue name invalid/too long: %q", fifo)
	}
}

// exactly-once OR ordering makes a FIFO queue; exactly-once also enables
// content-based dedup (the mechanism that makes FIFO actually dedupe).
func TestBuildSQSFIFO(t *testing.T) {
	a := sqsAttrs()
	a["delivery.guarantee"] = "exactly-once"
	plan, err := BuildSQSCreate("acct", "prod", "orders", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.FIFO || plan.Attributes["FifoQueue"] != "true" {
		t.Fatalf("exactly-once must make a FIFO queue, got %+v", plan)
	}
	if plan.Attributes["ContentBasedDeduplication"] != "true" {
		t.Fatalf("exactly-once must enable content-based dedup, got %+v", plan.Attributes)
	}
	if !strings.HasSuffix(plan.Name, ".fifo") {
		t.Fatalf("FIFO plan name must end .fifo, got %q", plan.Name)
	}

	a2 := sqsAttrs()
	a2["ordering.enabled"] = true
	plan2, err := BuildSQSCreate("acct", "prod", "orders", a2, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan2.FIFO || plan2.Attributes["ContentBasedDeduplication"] == "true" {
		t.Fatalf("ordering alone makes FIFO WITHOUT content dedup, got %+v", plan2.Attributes)
	}
}

func TestBuildSQSStandardNoFifo(t *testing.T) {
	plan, err := BuildSQSCreate("acct", "prod", "orders", sqsAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.FIFO || plan.Attributes["FifoQueue"] == "true" {
		t.Fatalf("a standard queue must not be FIFO, got %+v", plan)
	}
	if strings.HasSuffix(plan.Name, ".fifo") {
		t.Fatalf("a standard queue name must not end .fifo, got %q", plan.Name)
	}
}

func TestBuildSQSEncryption(t *testing.T) {
	// atRest without CMEK -> SSE-SQS managed key.
	plan, err := BuildSQSCreate("acct", "prod", "orders", sqsAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Attributes["SqsManagedSseEnabled"] != "true" {
		t.Fatalf("atRest without CMEK must enable SSE-SQS, got %+v", plan.Attributes)
	}
	// atRest=false -> no encryption attrs.
	a := sqsAttrs()
	a["encryption.atRest"] = false
	plan, err = BuildSQSCreate("acct", "prod", "orders", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Attributes["SqsManagedSseEnabled"] != "" || plan.Attributes["KmsMasterKeyId"] != "" {
		t.Fatalf("atRest=false must set no encryption, got %+v", plan.Attributes)
	}
	// CMEK -> customer key.
	a = sqsAttrs()
	a["encryption.customerManagedKeys"] = true
	impl := map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
	plan, err = BuildSQSCreate("acct", "prod", "orders", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Attributes["KmsMasterKeyId"] != impl["kms_key_id"] {
		t.Fatalf("CMEK must set the customer key, got %+v", plan.Attributes)
	}
}

func TestBuildSQSRetention(t *testing.T) {
	a := sqsAttrs()
	a["retention.minimum"] = "1h"
	plan, err := BuildSQSCreate("acct", "prod", "orders", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Attributes["MessageRetentionPeriod"] != "3600" {
		t.Fatalf("retention 1h must map to 3600s, got %q", plan.Attributes["MessageRetentionPeriod"])
	}
}

// reliability.deadLetter=true sets RedrivePolicy from the impl operands; the
// posture bool without operands is a loud refusal, never a silent no-DLQ queue.
func TestBuildSQSDeadLetter(t *testing.T) {
	dlqArn := "arn:aws:sqs:eu-central-1:000000000000:orders-dlq"
	a := sqsAttrs()
	a["reliability.deadLetter"] = true
	impl := map[string]any{"dead_letter_target_arn": dlqArn, "max_receive_count": 5}
	plan, err := BuildSQSCreate("acct", "prod", "orders", a, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	rp := plan.Attributes["RedrivePolicy"]
	if rp == "" {
		t.Fatalf("deadLetter must set RedrivePolicy, got %+v", plan.Attributes)
	}
	if !strings.Contains(rp, `"deadLetterTargetArn":"`+dlqArn+`"`) ||
		!strings.Contains(rp, `"maxReceiveCount":5`) {
		t.Fatalf("RedrivePolicy shape wrong: %s", rp)
	}
	// float64 (JSON loader) operand is accepted.
	impl2 := map[string]any{"dead_letter_target_arn": dlqArn, "max_receive_count": float64(3)}
	if _, err := BuildSQSCreate("acct", "prod", "orders", a, impl2, 1); err != nil {
		t.Fatalf("float64 max_receive_count must be accepted: %v", err)
	}
	// deadLetter=false leaves no RedrivePolicy.
	a2 := sqsAttrs()
	a2["reliability.deadLetter"] = false
	plan2, err := BuildSQSCreate("acct", "prod", "orders", a2, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if plan2.Attributes["RedrivePolicy"] != "" {
		t.Fatalf("deadLetter=false must set no RedrivePolicy, got %+v", plan2.Attributes)
	}
}

func TestBuildSQSDeadLetterRefusals(t *testing.T) {
	dlqArn := "arn:aws:sqs:eu-central-1:000000000000:orders-dlq"
	cases := map[string]map[string]any{
		"no operands":       nil,
		"no arn":            {"max_receive_count": 5},
		"no count":          {"dead_letter_target_arn": dlqArn},
		"bad arn":           {"dead_letter_target_arn": "not-an-arn", "max_receive_count": 5},
		"count too low":     {"dead_letter_target_arn": dlqArn, "max_receive_count": 0},
		"count too high":    {"dead_letter_target_arn": dlqArn, "max_receive_count": 1001},
		"count not integer": {"dead_letter_target_arn": dlqArn, "max_receive_count": 2.5},
	}
	for name, impl := range cases {
		t.Run(name, func(t *testing.T) {
			a := sqsAttrs()
			a["reliability.deadLetter"] = true
			if _, err := BuildSQSCreate("acct", "prod", "orders", a, impl, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

// reliability.deadLetter is patchable in place (RedrivePolicy via SetQueueAttributes).
func TestSQSDeadLetterIsMutable(t *testing.T) {
	d := NewDriver("eu-central-1")
	if class, _ := d.ClassifyChange("sqs", "reliability.deadLetter", nil, true, nil); class != "mutable" {
		t.Errorf("reliability.deadLetter must classify mutable, got %q", class)
	}
}

func TestBuildSQSRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(map[string]any)
		impl   map[string]any
	}{
		"cmek without key":    {func(a map[string]any) { a["encryption.customerManagedKeys"] = true }, nil},
		"retention too short": {func(a map[string]any) { a["retention.minimum"] = "30s" }, nil},
		"retention too long":  {func(a map[string]any) { a["retention.minimum"] = "30d" }, nil},
		"bad delivery":        {func(a map[string]any) { a["delivery.guarantee"] = "maybe" }, nil},
		"unmanaged":           {func(a map[string]any) { a["service.managed"] = false }, nil},
		"no region":           {func(a map[string]any) { delete(a, "location.region") }, nil},
		"bad region":          {func(a map[string]any) { a["location.region"] = "not a region" }, nil},
		"unknown attr":        {func(a map[string]any) { a["visibility.timeout"] = "30s" }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := sqsAttrs()
			c.mutate(a)
			if _, err := BuildSQSCreate("acct", "prod", "orders", a, c.impl, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

func TestSQSPublicPolicyIsAnonymous(t *testing.T) {
	pol := sqsPublicPolicy("arn:aws:sqs:eu-central-1:000000000000:orders-x")
	pub, ok := sqsPolicyPublic(pol)
	if !ok || !pub {
		t.Fatalf("the public policy must read back as public, got public=%v parseable=%v", pub, ok)
	}
	owner := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sqs:SendMessage"}]}`
	if pub, _ := sqsPolicyPublic(owner); pub {
		t.Fatal("an owner-only policy must not read as public")
	}
	// D1189: a wildcard principal with a non-who-scoping condition (date) is PUBLIC —
	// the old "any condition => not public" rule false-greened it.
	nonScoped := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Condition":{"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}`
	if pub, ok := sqsPolicyPublic(nonScoped); !ok || !pub {
		t.Fatalf("a wildcard principal with a non-scoping condition must read PUBLIC, got public=%v parseable=%v", pub, ok)
	}
	// a who-scoping condition (aws:SourceAccount) keeps it non-public
	scoped := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:SendMessage","Condition":{"StringEquals":{"aws:SourceAccount":"000000000000"}}}]}`
	if pub, _ := sqsPolicyPublic(scoped); pub {
		t.Error("aws:SourceAccount scopes who may act — must not read public")
	}
}

func TestSplitSQSProviderID(t *testing.T) {
	for _, ok := range []string{
		"sqs:eu-central-1:000000000000:orders-x",
		"sqs:eu-central-1:000000000000:orders-x.fifo",
	} {
		if _, _, _, err := splitSQSProviderID(ok); err != nil {
			t.Errorf("valid id rejected: %q %v", ok, err)
		}
	}
	for _, bad := range []string{
		"sqs:eu-central-1:orders", "sns:eu-central-1:000000000000:orders",
		"sqs:badregion:000000000000:orders", "sqs:eu-central-1:12:orders",
		"sqs:eu-central-1:000000000000:bad/name",
	} {
		if _, _, _, err := splitSQSProviderID(bad); err == nil {
			t.Errorf("accepted malformed sqs id %q", bad)
		}
	}
}

// TestSQSFIFOChangeIsReplacement pins that the FIFO switch is a replacement, not
// a patch (D48): the ".fifo" name is create-time immutable.
func TestSQSFIFOChangeIsReplacement(t *testing.T) {
	d := NewDriver("eu-central-1")
	for _, path := range []string{"delivery.guarantee", "ordering.enabled"} {
		class, _ := d.ClassifyChange("sqs", path, nil, true, nil)
		if class != "immutable" {
			t.Errorf("%s must classify as immutable (replacement), got %q", path, class)
		}
	}
}

// sqsServer answers the SQS Query protocol with OUR ownership tags — used by the
// honesty harness and the happy-path unit tests.
func sqsServer(t *testing.T) *httptest.Server {
	t.Helper()
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch queryAction(body) {
			case "CreateQueue":
				_, _ = w.Write([]byte(`<CreateQueueResponse><CreateQueueResult>` +
					`<QueueUrl>https://sqs.eu-central-1.amazonaws.com/000000000000/q</QueueUrl>` +
					`</CreateQueueResult></CreateQueueResponse>`))
			case "ListQueueTags":
				if deleted {
					// the queue has finished deleting — the delete's poll-to-absence (D982)
					// confirms NonExistentQueue.
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>AWS.SimpleQueueService.NonExistentQueue</Code></Error></ErrorResponse>`))
					return
				}
				_, _ = w.Write([]byte(`<ListQueueTagsResponse><ListQueueTagsResult>` +
					`<Tag><Key>groundhold-capability</Key><Value>orders</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</ListQueueTagsResult></ListQueueTagsResponse>`))
			case "GetQueueAttributes":
				_, _ = w.Write([]byte(`<GetQueueAttributesResponse><GetQueueAttributesResult>` +
					`<Attribute><Name>SqsManagedSseEnabled</Name><Value>true</Value></Attribute>` +
					`</GetQueueAttributesResult></GetQueueAttributesResponse>`))
			case "DeleteQueue":
				deleted = true
				_, _ = w.Write([]byte(`<DeleteQueueResponse></DeleteQueueResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func sqsTestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.SQSBaseURL = srv.URL
	d.Account = "000000000000"
	return d
}

func TestCreateSQSHappyPath(t *testing.T) {
	srv := sqsServer(t)
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.createSQS("eu-central-1", "000000000000", "prod", "orders", sqsAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "sqs:eu-central-1:000000000000:") {
		t.Fatalf("got %+v, want succeeded + sqs-prefixed id", res)
	}
}

// An untagged same-account queue (CreateQueue did not apply our tags) must NOT
// be silently taken over — unknown carrying the deterministic pid (mirrors S3).
func TestCreateSQSUntaggedRefusesToAdopt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch queryAction(body) {
			case "CreateQueue":
				_, _ = w.Write([]byte(`<CreateQueueResponse></CreateQueueResponse>`))
			case "ListQueueTags":
				_, _ = w.Write([]byte(`<ListQueueTagsResponse><ListQueueTagsResult>` +
					`</ListQueueTagsResult></ListQueueTagsResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.createSQS("eu-central-1", "000000000000", "prod", "orders", sqsAttrs(), nil, 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("an untagged queue must be unknown WITH a pid, got %+v", res)
	}
}

func TestCreateSQSForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch queryAction(body) {
			case "CreateQueue":
				_, _ = w.Write([]byte(`<CreateQueueResponse></CreateQueueResponse>`))
			case "ListQueueTags":
				_, _ = w.Write([]byte(`<ListQueueTagsResponse><ListQueueTagsResult>` +
					`<Tag><Key>groundhold-capability</Key><Value>other</Value></Tag>` +
					`</ListQueueTagsResult></ListQueueTagsResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.createSQS("eu-central-1", "000000000000", "prod", "orders", sqsAttrs(), nil, 1)
	if res.Status != "failed" {
		t.Fatalf("a foreign-tagged queue must be refused, got %+v", res)
	}
}

func TestDeleteSQSOurs(t *testing.T) {
	srv := sqsServer(t)
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.deleteSQS("orders", "prod", "sqs:eu-central-1:000000000000:orders-x")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an owned queue must succeed, got %+v", res)
	}
}

func TestDeleteSQSForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if queryAction(body) == "ListQueueTags" {
				_, _ = w.Write([]byte(`<ListQueueTagsResponse><ListQueueTagsResult>` +
					`<Tag><Key>groundhold-capability</Key><Value>other</Value></Tag>` +
					`</ListQueueTagsResult></ListQueueTagsResponse>`))
				return
			}
			t.Errorf("delete must not proceed past the ownership check, saw %s", queryAction(body))
			w.WriteHeader(404)
		}))
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.deleteSQS("orders", "prod", "sqs:eu-central-1:000000000000:orders-x")
	if res.Status != "failed" {
		t.Fatalf("delete of a foreign queue must be refused, got %+v", res)
	}
}

// TestDeleteSQSAsyncNotGoneIsUnknown pins D982: a queue delete the provider ACCEPTS
// but that stays present (DeleteQueue is eventually-consistent, up to ~60s) must
// report unknown — never a terminal "succeeded" that tombstones a queue still live
// with in-flight messages.
func TestDeleteSQSAsyncNotGoneIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			switch queryAction(body) {
			case "ListQueueTags": // never gone — owned, still present
				_, _ = w.Write([]byte(`<ListQueueTagsResponse><ListQueueTagsResult>` +
					`<Tag><Key>groundhold-capability</Key><Value>orders</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</ListQueueTagsResult></ListQueueTagsResponse>`))
			case "DeleteQueue":
				_, _ = w.Write([]byte(`<DeleteQueueResponse></DeleteQueueResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	d.PollInterval = time.Millisecond
	d.PollTimeout = 5 * time.Millisecond // the queue never goes NonExistent → times out fast
	res := d.deleteSQS("orders", "prod", "sqs:eu-central-1:000000000000:orders-x")
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-still-deleting queue must be unknown (keep the handle), got %+v", res)
	}
}

// deadLetter round-trip: create writes RedrivePolicy, observe reverse-maps it to
// reliability.deadLetter=true; a queue without a DLQ observes measured false.
func TestSQSDeadLetterRoundTrip(t *testing.T) {
	srv := metamorphicSQSServer(t)
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	a := sqsAttrs()
	a["reliability.deadLetter"] = true
	impl := map[string]any{
		"dead_letter_target_arn": "arn:aws:sqs:eu-central-1:000000000000:orders-dlq",
		"max_receive_count":      5,
	}
	res := d.createSQS("eu-central-1", "000000000000", "prod", "orders", a, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create failed: %+v", res)
	}
	obs, _, err := d.observeSQS("orders", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["reliability.deadLetter"] != true {
		t.Fatalf("deadLetter round-trip broke: observed %v", got["reliability.deadLetter"])
	}

	// a queue with no RedrivePolicy observes deadLetter=false.
	srv2 := metamorphicSQSServer(t)
	defer srv2.Close()
	d2 := sqsTestDriver(t, srv2)
	res2 := d2.createSQS("eu-central-1", "000000000000", "prod", "orders", sqsAttrs(), nil, 1)
	if res2.Status != "succeeded" {
		t.Fatalf("create failed: %+v", res2)
	}
	obs2, _, err := d2.observeSQS("orders", res2.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs2 {
		if o.Path == "reliability.deadLetter" && o.Value != false {
			t.Fatalf("no-DLQ queue must observe deadLetter=false, got %v", o.Value)
		}
	}
}

// Weapon 2 (D87): the metamorphic write/read round-trip. A stateful fake records
// what CreateQueue WRITES (the Attribute.N map + Policy) and reflects it on
// GetQueueAttributes; the test asserts observeSQS reverse-maps the SAME semantic
// attributes create was given.
func metamorphicSQSServer(t *testing.T) *httptest.Server {
	t.Helper()
	stored := map[string]string{}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(raw))
			switch form.Get("Action") {
			case "CreateQueue":
				for i := 1; ; i++ {
					name := form.Get(fmt.Sprintf("Attribute.%d.Name", i))
					if name == "" {
						break
					}
					stored[name] = form.Get(fmt.Sprintf("Attribute.%d.Value", i))
				}
				_, _ = w.Write([]byte(`<CreateQueueResponse></CreateQueueResponse>`))
			case "ListQueueTags":
				_, _ = w.Write([]byte(`<ListQueueTagsResponse><ListQueueTagsResult>` +
					`<Tag><Key>groundhold-capability</Key><Value>orders</Value></Tag>` +
					`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
					`</ListQueueTagsResult></ListQueueTagsResponse>`))
			case "GetQueueAttributes":
				entries := ""
				for _, k := range sortedStrKeys(stored) {
					entries += `<Attribute><Name>` + k + `</Name><Value>` +
						xmlEsc(stored[k]) + `</Value></Attribute>`
				}
				_, _ = w.Write([]byte(`<GetQueueAttributesResponse><GetQueueAttributesResult>` +
					entries + `</GetQueueAttributesResult></GetQueueAttributesResponse>`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestMetamorphicSQSRoundTrip(t *testing.T) {
	cases := []struct {
		name          string
		public        bool
		atRest        bool
		cmek          bool
		exactlyOnce   bool
		ordering      bool
		retention     string
		wantGuarantee string
		wantOrdering  bool
		wantRetention string // the observed retention.minimum ("" = absent)
	}{
		{"standard-provider-default", false, true, false, false, false, "", "at-least-once", false, ""},
		{"fifo-exactly-once-cmek-public", true, true, true, true, false, "1h", "exactly-once", true, "3600s"},
		{"fifo-ordering-only", false, false, false, false, true, "", "at-least-once", true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicSQSServer(t)
			defer srv.Close()
			d := sqsTestDriver(t, srv)
			attrs := map[string]any{
				"location.region":        "eu-central-1",
				"network.publicExposure": c.public,
				"encryption.atRest":      c.atRest,
				"service.managed":        true,
			}
			if c.exactlyOnce {
				attrs["delivery.guarantee"] = "exactly-once"
			}
			if c.ordering {
				attrs["ordering.enabled"] = true
			}
			if c.retention != "" {
				attrs["retention.minimum"] = c.retention
			}
			var impl map[string]any
			if c.cmek {
				attrs["encryption.customerManagedKeys"] = true
				impl = map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
			}
			res := d.createSQS("eu-central-1", "000000000000", "prod", "orders", attrs, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, _, err := d.observeSQS("orders", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["location.region"] != "eu-central-1" {
				t.Errorf("region round-trip broke: %v", got["location.region"])
			}
			if got["network.publicExposure"] != c.public {
				t.Errorf("public round-trip broke: wrote %v observed %v", c.public, got["network.publicExposure"])
			}
			if got["delivery.guarantee"] != c.wantGuarantee {
				t.Errorf("guarantee round-trip broke: want %v observed %v", c.wantGuarantee, got["delivery.guarantee"])
			}
			if got["ordering.enabled"] != c.wantOrdering {
				t.Errorf("ordering round-trip broke: want %v observed %v", c.wantOrdering, got["ordering.enabled"])
			}
			wantEncrypted := c.atRest || c.cmek
			if got["encryption.atRest"] != wantEncrypted {
				t.Errorf("atRest round-trip broke: want %v observed %v", wantEncrypted, got["encryption.atRest"])
			}
			// retention.minimum: "1h" written -> MessageRetentionPeriod=3600 ->
			// observed "3600s". A drift in the seconds conversion OR the "+s"
			// reverse-map (either side) breaks this equality.
			gotRet, hasRet := got["retention.minimum"]
			if c.wantRetention == "" {
				if hasRet {
					t.Errorf("retention round-trip broke: none written but observed %v", gotRet)
				}
			} else if gotRet != c.wantRetention {
				t.Errorf("retention round-trip broke: want %v observed %v", c.wantRetention, gotRet)
			}
			if got["encryption.customerManagedKeys"] != c.cmek {
				t.Errorf("cmek round-trip broke: want %v observed %v", c.cmek, got["encryption.customerManagedKeys"])
			}
			if c.retention != "" && got["retention.minimum"] != "3600s" {
				t.Errorf("retention round-trip broke: observed %v", got["retention.minimum"])
			}
		})
	}
}

func sqsRole(_ *http.Request, body []byte) certifynet.Role {
	switch queryAction(body) {
	case "ListQueueTags", "GetQueueAttributes", "GetQueueUrl", "ListQueues":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingSQS enrols SQS in the D391 gate — the mirror of SNS. CreateQueue is
// idempotent by NAME, so binding the queue that already exists (and carries our tags) is
// the property; the untagged and foreign cases already have tests, the OURS case did not.
func TestAdoptsExistingSQS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/sqs",
		Classify: sqsRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					switch queryAction(body) {
					case "CreateQueue":
						_, _ = w.Write([]byte(`<CreateQueueResponse></CreateQueueResponse>`))
					case "ListQueueTags":
						_, _ = w.Write([]byte(`<ListQueueTagsResponse><ListQueueTagsResult>` +
							`<Tag><Key>groundhold-capability</Key><Value>orders</Value></Tag>` +
							`<Tag><Key>groundhold-environment</Key><Value>prod</Value></Tag>` +
							`</ListQueueTagsResult></ListQueueTagsResponse>`))
					default:
						_, _ = w.Write([]byte(`<Response></Response>`))
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.SQSBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("sqs", "orders", "prod", sqsAttrs(), nil, "orders", 1)
		},
		AllowedMutations: 4, // name-idempotent CreateQueue + attribute convergence
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D745: a redrive policy NAMES a dead-letter queue. It does not mean the queue exists —
// delete the DLQ and the policy stays behind, over-limit messages are dropped instead of
// captured, and `reliability.deadLetter` reported true. A reliability control naming a
// queue that is not there is the same shape as a firewall protecting nothing.
func TestDeadLetterRequiresTheTargetToExist(t *testing.T) {
	const policy = `{"deadLetterTargetArn":"arn:aws:sqs:eu-central-1:000000000000:jobs-dlq","maxReceiveCount":5}`
	cases := []struct {
		name       string
		policy     string
		targetGone bool
		targetErr  bool
		want       any // nil => withheld
	}{
		{"no redrive policy at all", "", false, false, false},
		{"policy and the target stands", policy, false, false, true},
		{"policy naming a queue that was deleted", policy, true, false, false},
		{"target unreadable — neither answer is earned", policy, false, true, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				body := string(b)
				isTarget := strings.Contains(body, "jobs-dlq")
				switch {
				case isTarget && c.targetErr:
					w.WriteHeader(500)
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InternalError</Code></Error></ErrorResponse>`))
				case isTarget && c.targetGone:
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>AWS.SimpleQueueService.NonExistentQueue</Code></Error></ErrorResponse>`))
				case isTarget:
					_, _ = w.Write([]byte(`<GetQueueAttributesResponse><GetQueueAttributesResult>` +
						`<Attribute><Name>QueueArn</Name><Value>arn:aws:sqs:eu-central-1:000000000000:jobs-dlq</Value></Attribute>` +
						`</GetQueueAttributesResult></GetQueueAttributesResponse>`))
				default:
					attr := ""
					if c.policy != "" {
						attr = `<Attribute><Name>RedrivePolicy</Name><Value>` +
							strings.ReplaceAll(c.policy, `"`, "&quot;") + `</Value></Attribute>`
					}
					_, _ = w.Write([]byte(`<GetQueueAttributesResponse><GetQueueAttributesResult>` +
						`<Attribute><Name>QueueArn</Name><Value>arn:aws:sqs:eu-central-1:000000000000:jobs</Value></Attribute>` +
						attr + `</GetQueueAttributesResult></GetQueueAttributesResponse>`))
				}
			}))
			defer srv.Close()
			t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
			d := NewDriver("eu-central-1")
			d.SQSBaseURL = srv.URL
			d.Account = "000000000000"

			obs, _, err := d.Observe("sqs", "jobs", "sqs:eu-central-1:000000000000:jobs")
			if err != nil {
				t.Fatal(err)
			}
			var got any
			for _, o := range obs {
				if o.Path == "reliability.deadLetter" {
					got = o.Value
				}
			}
			if got != c.want {
				t.Fatalf("reliability.deadLetter = %v, want %v — a policy names a queue; "+
					"it does not make one exist", got, c.want)
			}
		})
	}
}
