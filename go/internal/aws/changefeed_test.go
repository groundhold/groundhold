package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func chfAttrs() map[string]any {
	return map[string]any{
		"feed.target":     "arn:aws:sqs:eu-central-1:000000000000:infra-changes",
		"service.managed": true,
	}
}

func TestBuildChangeFeedHonors(t *testing.T) {
	p, err := BuildChangeFeed("prod", "changes", chfAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !cfRuleNameOK.MatchString(p.RuleName) || !strings.HasPrefix(p.RuleName, "changes-prod-") {
		t.Fatalf("name = %q", p.RuleName)
	}
	if p.Region != "eu-central-1" {
		t.Fatalf("region must be derived from the target ARN, got %q", p.Region)
	}
	rb := p.putRuleBody("changes", "prod")
	if rb["State"] != "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS" {
		t.Fatalf("rule must capture CloudTrail management events, State = %v", rb["State"])
	}
	if !strings.Contains(rb["Description"].(string), "capability=changes") {
		t.Fatalf("ownership marker missing: %v", rb["Description"])
	}
	if rb["EventPattern"] != defaultChangeFeedPattern {
		t.Fatalf("default pattern not applied: %v", rb["EventPattern"])
	}
	tb := p.putTargetsBody()
	tgts := tb["Targets"].([]map[string]any)
	if len(tgts) != 1 || tgts[0]["Arn"] != chfAttrs()["feed.target"] {
		t.Fatalf("target must be the feed.target queue: %v", tgts)
	}
	// no Input payload is ever set (D53).
	if _, has := tgts[0]["Input"]; has {
		t.Fatal("target must not carry an Input payload (D53)")
	}
}

func TestBuildChangeFeedPatternOverride(t *testing.T) {
	p, err := BuildChangeFeed("prod", "changes", chfAttrs(),
		map[string]any{"event_pattern": `{"source":["aws.ec2"]}`}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Pattern != `{"source":["aws.ec2"]}` {
		t.Fatalf("impl.event_pattern override ignored: %v", p.Pattern)
	}
}

func TestBuildChangeFeedRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"no-target":      {"service.managed": true},
		"target-not-arn": {"feed.target": "my-queue", "service.managed": true},
		"target-not-sqs": {"feed.target": "arn:aws:sns:eu-central-1:000000000000:t", "service.managed": true},
		"bad-region":     {"feed.target": "arn:aws:sqs:nope:000000000000:q", "service.managed": true},
		"bad-account":    {"feed.target": "arn:aws:sqs:eu-central-1:0:q", "service.managed": true},
		"unmanaged":      {"feed.target": "arn:aws:sqs:eu-central-1:000000000000:q", "service.managed": false},
		"unknown-attr":   {"feed.target": "arn:aws:sqs:eu-central-1:000000000000:q", "service.managed": true, "feed.coverage": "all"},
	}
	for name, attrs := range cases {
		if _, err := BuildChangeFeed("prod", "changes", attrs, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// cfFake is a stateful EventBridge REST-JSON double: it holds one rule + its targets so a
// full create -> observe -> delete roundtrip runs against a single endpoint. The
// foreignMarker option seeds a pre-existing rule owned by someone else.
type cfFake struct {
	rule    *cfRuleDoc
	targets []cfTarget
	seen    map[string]int // X-Amz-Target action -> call count
}

func newCFFake() *cfFake { return &cfFake{seen: map[string]int{}} }

func (f *cfFake) seedForeign() {
	f.rule = &cfRuleDoc{Name: "changes-prod-x", State: "ENABLED",
		Description: awsOwnerMarker("someone-else", "prod")}
}

func (f *cfFake) server(t *testing.T) *httptest.Server {
	t.Helper()
	notFound := func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"no rule"}`))
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		f.seen[action]++
		if ct := r.Header.Get("Content-Type"); ct != "application/x-amz-json-1.1" {
			t.Errorf("Content-Type = %q, want application/x-amz-json-1.1", ct)
		}
		if r.Header.Get("Authorization") == "" {
			t.Errorf("request %s was not SigV4-signed", action)
		}
		body, _ := io.ReadAll(r.Body)
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		switch action {
		case "AWSEvents.PutRule":
			f.rule = &cfRuleDoc{
				Name:         in["Name"].(string),
				State:        in["State"].(string),
				Description:  in["Description"].(string),
				EventPattern: in["EventPattern"].(string),
				Arn:          "arn:aws:events:eu-central-1:000000000000:rule/" + in["Name"].(string),
			}
			_, _ = w.Write([]byte(`{"RuleArn":"` + f.rule.Arn + `"}`))
		case "AWSEvents.PutTargets":
			for _, raw := range in["Targets"].([]any) {
				tg := raw.(map[string]any)
				f.targets = append(f.targets, cfTarget{Id: tg["Id"].(string), Arn: tg["Arn"].(string)})
			}
			_, _ = w.Write([]byte(`{"FailedEntryCount":0,"FailedEntries":[]}`))
		case "AWSEvents.DescribeRule":
			if f.rule == nil {
				notFound(w)
				return
			}
			out, _ := json.Marshal(f.rule)
			_, _ = w.Write(out)
		case "AWSEvents.ListTargetsByRule":
			if f.rule == nil {
				notFound(w)
				return
			}
			out, _ := json.Marshal(map[string]any{"Targets": f.targets})
			_, _ = w.Write(out)
		case "AWSEvents.RemoveTargets":
			f.targets = nil
			_, _ = w.Write([]byte(`{"FailedEntryCount":0,"FailedEntries":[]}`))
		case "AWSEvents.DeleteRule":
			f.rule = nil
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func chfDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.EventBridgeBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteChangeFeed(t *testing.T) {
	fake := newCFFake()
	srv := fake.server(t)
	defer srv.Close()
	d := chfDriver(t, srv)

	res := d.Create("changefeed", "changes", "prod", chfAttrs(), nil, "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "eventbridge:eu-central-1:") {
		t.Fatalf("create: %+v", res)
	}
	// PutRule then PutTargets both landed.
	if fake.seen["AWSEvents.PutRule"] != 1 || fake.seen["AWSEvents.PutTargets"] != 1 {
		t.Fatalf("expected PutRule+PutTargets, saw %v", fake.seen)
	}

	obs, diags, err := d.observeChangeFeed("changes", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diags: %v", diags)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["feed.target"] != "arn:aws:sqs:eu-central-1:000000000000:infra-changes" {
		t.Fatalf("feed.target not reverse-mapped: %+v", got)
	}
	if got["service.managed"] != true || got["location.region"] != "eu-central-1" {
		t.Fatalf("observe: %+v", got)
	}

	if del := d.Delete("changefeed", "changes", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	// RemoveTargets ran before DeleteRule.
	if fake.seen["AWSEvents.RemoveTargets"] != 1 || fake.seen["AWSEvents.DeleteRule"] != 1 {
		t.Fatalf("delete must RemoveTargets then DeleteRule, saw %v", fake.seen)
	}
	// idempotent: a second delete on the now-absent rule still succeeds.
	if del := d.Delete("changefeed", "changes", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("second delete not idempotent: %+v", del)
	}
	// observing a deleted feed is a clean "nothing to observe".
	obs, diags, err = d.observeChangeFeed("changes", res.ProviderID)
	if err != nil || len(obs) != 0 || len(diags) == 0 {
		t.Fatalf("observe after delete: obs=%v diags=%v err=%v", obs, diags, err)
	}
}

func TestCreateChangeFeedForeignRefused(t *testing.T) {
	fake := newCFFake()
	fake.seedForeign()
	srv := fake.server(t)
	defer srv.Close()
	d := chfDriver(t, srv)

	// the deterministic name collides with a foreign rule — PutRule is an upsert, so
	// create must refuse rather than overwrite it.
	res := d.Create("changefeed", "changes", "prod", chfAttrs(), nil, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign rule must refuse create, got %+v", res)
	}
	if fake.seen["AWSEvents.PutRule"] != 0 {
		t.Fatal("PutRule must not run when the pre-read shows a foreign rule")
	}
}

func TestDeleteChangeFeedForeignRefused(t *testing.T) {
	fake := newCFFake()
	fake.seedForeign()
	srv := fake.server(t)
	defer srv.Close()
	d := chfDriver(t, srv)

	pid := changefeedProviderID("eu-central-1", "changes-prod-x")
	res := d.Delete("changefeed", "changes", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign rule must refuse delete, got %+v", res)
	}
	if fake.seen["AWSEvents.DeleteRule"] != 0 {
		t.Fatal("DeleteRule must not run on a foreign rule")
	}
}

func TestChangeFeedProviderIDRoundTrip(t *testing.T) {
	region, rule, err := splitChangefeedProviderID("eventbridge:us-west-2:changes-prod-abc123")
	if err != nil || region != "us-west-2" || rule != "changes-prod-abc123" {
		t.Fatalf("split: %q %q %v", region, rule, err)
	}
	for _, bad := range []string{"eventbridge:bad:rule", "sched:us-west-2:r", "eventbridge:us-west-2"} {
		if _, _, err := splitChangefeedProviderID(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}
