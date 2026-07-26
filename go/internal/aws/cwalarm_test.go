package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func cwAlertAttrs() map[string]any {
	return map[string]any{
		"alert.metric":     "AWS/EC2/CPUUtilization",
		"alert.threshold":  float64(80),
		"alert.comparison": "greater-than",
		"alert.notify":     true,
		"service.managed":  true,
	}
}

func cwAlertImpl() map[string]any {
	return map[string]any{
		"region":               "eu-central-1",
		"notification_channel": "arn:aws:sns:eu-central-1:000000000000:alerts",
	}
}

func TestBuildCloudWatchAlarmHonors(t *testing.T) {
	p, err := BuildCloudWatchAlarm("000000000000", "prod", "cpu", cwAlertAttrs(), cwAlertImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Namespace != "AWS/EC2" || p.MetricName != "CPUUtilization" ||
		p.ComparisonOperator != "GreaterThanThreshold" || p.Threshold != 80 || !p.Notify || p.TopicArn == "" {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildCloudWatchAlarmRefusals(t *testing.T) {
	cases := map[string]struct {
		extra map[string]any
		impl  map[string]any
	}{
		"notify-no-channel": {map[string]any{"alert.notify": true}, map[string]any{"region": "eu-central-1"}},
		"bad-comparison":    {map[string]any{"alert.comparison": "sideways"}, cwAlertImpl()},
		"no-namespace":      {map[string]any{"alert.metric": "CPUUtilization"}, cwAlertImpl()}, // needs Namespace/MetricName
		"unmanaged":         {map[string]any{"service.managed": false}, cwAlertImpl()},
		"compound-attr":     {map[string]any{"alert.conditions": "a AND b"}, cwAlertImpl()},
	}
	for name, c := range cases {
		a := cwAlertAttrs()
		for k, v := range c.extra {
			a[k] = v
		}
		if _, err := BuildCloudWatchAlarm("000000000000", "prod", "cpu", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	for _, drop := range []string{"alert.metric", "alert.threshold", "alert.comparison"} {
		a := cwAlertAttrs()
		delete(a, drop)
		if _, err := BuildCloudWatchAlarm("000000000000", "prod", "cpu", a, cwAlertImpl(), 1); err == nil {
			t.Errorf("missing %s must refuse", drop)
		}
	}
	// a non-notifying alarm needs no channel
	a := cwAlertAttrs()
	a["alert.notify"] = false
	if _, err := BuildCloudWatchAlarm("000000000000", "prod", "cpu", a, map[string]any{"region": "eu-central-1"}, 1); err != nil {
		t.Errorf("a non-notifying alarm should build without a channel: %v", err)
	}
}

func cwAlarmServer(t *testing.T) *httptest.Server {
	t.Helper()
	created := false
	ns, metric, threshold, cmp, action := "", "", "", "", ""
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			switch r.PostForm.Get("Action") {
			case "PutMetricAlarm":
				created = true
				ns, metric, threshold, cmp = r.PostForm.Get("Namespace"), r.PostForm.Get("MetricName"),
					r.PostForm.Get("Threshold"), r.PostForm.Get("ComparisonOperator")
				action = r.PostForm.Get("AlarmActions.member.1")
				_, _ = w.Write([]byte(`<PutMetricAlarmResponse></PutMetricAlarmResponse>`))
			case "DescribeAlarms":
				if !created {
					_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))
					return
				}
				actionsXML := ""
				if action != "" {
					actionsXML = `<AlarmActions><member>` + action + `</member></AlarmActions>`
				}
				_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member>` +
					`<Namespace>` + ns + `</Namespace><MetricName>` + metric + `</MetricName>` +
					`<Threshold>` + threshold + `</Threshold><ComparisonOperator>` + cmp + `</ComparisonOperator>` +
					actionsXML + `</member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
					`<member><Key>groundhold-capability</Key><Value>cpu</Value></member>` +
					`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
					`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			case "DeleteAlarms":
				_, _ = w.Write([]byte(`<DeleteAlarmsResponse></DeleteAlarmsResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func cwAlarmDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.CloudWatchBaseURL = srv.URL
	d.Account = "000000000000"
	return d
}

func TestCreateObserveDeleteCloudWatchAlarm(t *testing.T) {
	srv := cwAlarmServer(t)
	defer srv.Close()
	d := cwAlarmDriver(t, srv)
	res := d.createCloudWatchAlarm("eu-central-1", "000000000000", "prod", "cpu", cwAlertAttrs(), cwAlertImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "awsalert:eu-central-1:000000000000:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCloudWatchAlarm("cpu", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["alert.metric"] != "AWS/EC2/CPUUtilization" || got["alert.threshold"] != float64(80) ||
		got["alert.comparison"] != "greater-than" || got["alert.notify"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteCloudWatchAlarm("cpu", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteCloudWatchAlarmForeignRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.PostForm.Get("Action") {
		case "DescribeAlarms":
			_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member>` +
				`<Namespace>AWS/EC2</Namespace><MetricName>CPUUtilization</MetricName></member>` +
				`</MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
				`<member><Key>groundhold-capability</Key><Value>someone-else</Value></member>` +
				`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
		default:
			w.WriteHeader(200)
		}
	}))
	defer srv.Close()
	d := cwAlarmDriver(t, srv)
	res := d.deleteCloudWatchAlarm("cpu", "prod", "awsalert:eu-central-1:000000000000:pv-cpu-prod-abcd1234")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign alarm must refuse delete, got %+v", res)
	}
}

// cwAlarmOwnedServer reports the alarm exists + our tags so the harness delete
// baseline reaches DeleteAlarms; create pre-read also sees it as ours.
func cwAlarmOwnedServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.PostForm.Get("Action") {
		case "PutMetricAlarm":
			_, _ = w.Write([]byte(`<PutMetricAlarmResponse></PutMetricAlarmResponse>`))
		case "DescribeAlarms":
			_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member>` +
				`<Namespace>AWS/EC2</Namespace><MetricName>CPUUtilization</MetricName>` +
				`<Threshold>80</Threshold><ComparisonOperator>GreaterThanThreshold</ComparisonOperator>` +
				`<AlarmActions><member>arn:aws:sns:eu-central-1:000000000000:alerts</member></AlarmActions>` +
				`</member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
				`<member><Key>groundhold-capability</Key><Value>cpu</Value></member>` +
				`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
				`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
		case "DeleteAlarms":
			_, _ = w.Write([]byte(`<DeleteAlarmsResponse></DeleteAlarmsResponse>`))
		default:
			w.WriteHeader(400)
		}
	}))
}
