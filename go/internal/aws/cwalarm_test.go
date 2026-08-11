package aws

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
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

// actionsEnabledXML lets a test model an alarm whose actions are switched OFF (D726).
// Empty means the element is absent, which AWS treats as enabled.
var actionsEnabledXML string

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
					actionsXML + actionsEnabledXML +
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

// cwAlarmExistingServer: the alarm is already there (created=true from the start), so a
// converge meets a standing alarm rather than an empty account.
func cwAlarmExistingServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, r.ContentLength)
			_, _ = r.Body.Read(body)
			v, _ := url.ParseQuery(string(body))
			switch v.Get("Action") {
			case "PutMetricAlarm":
				_, _ = w.Write([]byte(`<PutMetricAlarmResponse></PutMetricAlarmResponse>`))
			case "DescribeAlarms":
				_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member>` +
					`<Namespace>AWS/EC2</Namespace><MetricName>CPUUtilization</MetricName>` +
					`<Threshold>80</Threshold><ComparisonOperator>GreaterThanThreshold</ComparisonOperator>` +
					`</member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>` +
					`<member><Key>groundhold-capability</Key><Value>cpu</Value></member>` +
					`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
					`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`))
			default:
				w.WriteHeader(400)
			}
		}))
}

// TestAdoptsExistingCloudWatchAlarm enrols cloudwatch in the D391 gate. PutMetricAlarm
// is an UPSERT keyed by alarm name, so a re-run overwrites rather than duplicating —
// the mutation is the mechanism and the identity is the proof. It is the cheapest shape
// in the family, and it is worth having asserted precisely because it looks too obvious
// to test.
func TestAdoptsExistingCloudWatchAlarm(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/cloudwatch",
		Classify:       cwQueryRole,
		ExistingServer: func() *httptest.Server { return cwAlarmExistingServer(t) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.CloudWatchBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("cloudwatch", "cpu", "prod", cwAlertAttrs(), cwAlertImpl(), "cpu", 1)
		},
		AllowedMutations: 1, // the upsert itself
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

func cwQueryRole(_ *http.Request, body []byte) certifynet.Role {
	v, _ := url.ParseQuery(string(body))
	a := v.Get("Action")
	// D700: `Get*` is a read too. CloudWatch's Query API spells its dashboard read
	// GetDashboard, and this classifier only knew Describe/List — so the one read the
	// dashboard create makes was counted as a MUTATION, and the adopt gate reported
	// both "no read of the estate" and "sent 1 mutation" about a create that read once
	// and wrote nothing. A classifier that mislabels a read accuses the driver of the
	// opposite of what it did.
	if strings.HasPrefix(a, "Describe") || strings.HasPrefix(a, "List") ||
		strings.HasPrefix(a, "Get") {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// D695: the five evaluation operands Acme asked for. Each one changes the request
// CloudWatch receives; the test reads the form off the wire rather than the plan, so
// a plan field that never reaches PutMetricAlarm fails here.
func TestCloudWatchAlarmEvaluationOperandsReachTheRequest(t *testing.T) {
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("Action") == "PutMetricAlarm" {
			form = r.PostForm
			_, _ = w.Write([]byte(`<PutMetricAlarmResponse></PutMetricAlarmResponse>`))
			return
		}
		// no alarm exists yet: the ownership pre-read must find nothing
		_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult>` +
			`<MetricAlarms></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))
	}))
	defer srv.Close()
	d := cwAlarmDriver(t, srv)

	impl := cwAlertImpl()
	impl["statistic"] = "Sum"
	impl["period_seconds"] = 900
	impl["evaluation_periods"] = 3
	impl["treat_missing_data"] = "notBreaching"
	// two dimensions, declared in reverse order: the request must be sorted by name
	impl["dimensions"] = map[string]any{"wynik": "nasza_awaria", "endpoint": "platnosc.webhook"}

	res := d.createCloudWatchAlarm("eu-central-1", "000000000000", "prod", "cpu",
		cwAlertAttrs(), impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	want := map[string]string{
		"Statistic":                 "Sum",
		"Period":                    "900",
		"EvaluationPeriods":         "3",
		"TreatMissingData":          "notBreaching",
		"Dimensions.member.1.Name":  "endpoint",
		"Dimensions.member.1.Value": "platnosc.webhook",
		"Dimensions.member.2.Name":  "wynik",
		"Dimensions.member.2.Value": "nasza_awaria",
	}
	for k, v := range want {
		if got := form.Get(k); got != v {
			t.Errorf("PutMetricAlarm %s = %q, want %q", k, got, v)
		}
	}
}

// A candidate that declares none of them must send exactly what the driver sent
// before D695 — the operands are an addition, not a change of default.
func TestCloudWatchAlarmDefaultsUnchangedWithoutOperands(t *testing.T) {
	p, err := BuildCloudWatchAlarm("000000000000", "prod", "cpu", cwAlertAttrs(), cwAlertImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Statistic != "Average" || p.PeriodSeconds != 300 || p.EvaluationPeriods != 1 ||
		p.TreatMissingData != "" || len(p.Dimensions) != 0 {
		t.Fatalf("defaults drifted: %+v", p)
	}
}

func TestCloudWatchAlarmEvaluationRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"statistic-outside-the-set": {"statistic": "p99"},
		"statistic-not-a-string":    {"statistic": 99},
		"period-not-a-multiple":     {"period_seconds": 45},
		"period-fractional":         {"period_seconds": 60.5},
		"period-as-a-string":        {"period_seconds": "60"},
		"eval-periods-zero":         {"evaluation_periods": 0},
		"eval-periods-negative":     {"evaluation_periods": -1},
		"missing-data-unknown":      {"treat_missing_data": "whatever"},
		"dimensions-not-a-map":      {"dimensions": "wynik=nasza_awaria"},
		"dimensions-empty":          {"dimensions": map[string]any{}},
		"dimension-value-not-text":  {"dimensions": map[string]any{"wynik": 3}},
		"dimension-name-empty":      {"dimensions": map[string]any{"": "x"}},
	}
	for name, extra := range cases {
		impl := cwAlertImpl()
		for k, v := range extra {
			impl[k] = v
		}
		if _, err := BuildCloudWatchAlarm("000000000000", "prod", "cpu", cwAlertAttrs(), impl, 1); err == nil {
			t.Errorf("%s: expected a refusal, got none", name)
		}
	}
}

// The driver reading an operand is half the wiring; the compiler refuses any operand
// the registry does not declare (D530), so a key read here and undeclared there still
// never reaches the driver. This pins both halves against each other.
func TestCloudWatchEvaluationOperandsAreDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, k := range awsConsumedOperands["cloudwatch"] {
		declared[k] = true
	}
	for _, k := range []string{"dimensions", "statistic", "period_seconds",
		"evaluation_periods", "treat_missing_data"} {
		if !declared[k] {
			t.Errorf("cloudwatch reads implementation.%s but the operand registry does not "+
				"declare it — the compiler would refuse the candidate with unknown-operand", k)
		}
	}
}

// D695, the other half: reading the operands back. Without this, a candidate that
// ADDS dimensions to an alarm that already exists produces no action — the operand is
// accepted, the alarm stays dimensionless, and converge reports converged. That is the
// same pretense one level down from the one this entry closes.
func TestCloudWatchAlarmOperandDriftIsVisible(t *testing.T) {
	live := struct{ stat, period, evals, missing, dims string }{
		stat: "Average", period: "300", evals: "1", missing: "missing",
		dims: "", // an alarm created before anyone declared dimensions
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostForm.Get("Action") != "DescribeAlarms" {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write([]byte(`<DescribeAlarmsResponse><DescribeAlarmsResult><MetricAlarms><member>` +
			`<Namespace>AWS/EC2</Namespace><MetricName>CPUUtilization</MetricName>` +
			`<Threshold>80</Threshold><ComparisonOperator>GreaterThanThreshold</ComparisonOperator>` +
			`<Statistic>` + live.stat + `</Statistic><Period>` + live.period + `</Period>` +
			`<EvaluationPeriods>` + live.evals + `</EvaluationPeriods>` +
			`<TreatMissingData>` + live.missing + `</TreatMissingData>` + live.dims +
			`</member></MetricAlarms></DescribeAlarmsResult></DescribeAlarmsResponse>`))
	}))
	defer srv.Close()
	d := cwAlarmDriver(t, srv)

	obs, _, err := d.observeCloudWatchAlarm("cpu", "awsalert:eu-central-1:000000000000:pv-cpu-prod-abcdefgh")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]any{}
	for _, o := range obs {
		seen[o.Path] = o.Value
	}

	// An alarm built before the operands existed must NOT read as drifted against a
	// candidate that declares none of them: the defaults and the live values agree.
	same, err := cloudWatchOperandTargets(cwAlertAttrs(), cwAlertImpl())
	if err != nil {
		t.Fatal(err)
	}
	for _, tgt := range same {
		got, ok := seen[tgt.Path]
		if !ok {
			t.Errorf("%s is declared as an operand target but observe never records it — "+
				"the compiler would demand a re-observation that can never satisfy it", tgt.Path)
			continue
		}
		if fmt.Sprint(got) != fmt.Sprint(tgt.Desired) {
			t.Errorf("%s: observed %v, desired %v — a candidate declaring no evaluation "+
				"operands must not read as drift against an alarm built before they existed",
				tgt.Path, got, tgt.Desired)
		}
	}

	// Declaring dimensions against that same alarm IS drift, in exactly one path.
	impl := cwAlertImpl()
	impl["dimensions"] = map[string]any{"wynik": "nasza_awaria"}
	want, err := cloudWatchOperandTargets(cwAlertAttrs(), impl)
	if err != nil {
		t.Fatal(err)
	}
	drifted := 0
	for _, tgt := range want {
		if fmt.Sprint(seen[tgt.Path]) != fmt.Sprint(tgt.Desired) {
			drifted++
			if tgt.Path != cwDimensionsOperand {
				t.Errorf("unexpected drift on %s", tgt.Path)
			}
		}
	}
	if drifted != 1 {
		t.Errorf("adding dimensions produced %d drifted operands, want exactly 1 — "+
			"if it is 0 the change is a silent no-op, which is the defect", drifted)
	}
}

// D726: an alarm with an action group whose actions are DISABLED enters its alarm state
// and invokes nothing. The create sets ActionsEnabled=true and observe never read it
// back, so `alert.notify` said "this alarm names somewhere to send a notification", not
// "this alarm will send one" — and a contract demanding notification read satisfied on
// an alarm that had been switched off.
func TestAlarmNotifyIsFalseWhenItsActionsAreDisabled(t *testing.T) {
	old := actionsEnabledXML
	actionsEnabledXML = `<ActionsEnabled>false</ActionsEnabled>`
	defer func() { actionsEnabledXML = old }()

	srv := cwAlarmServer(t)
	defer srv.Close()
	d := cwAlarmDriver(t, srv)

	res := d.createCloudWatchAlarm("eu-central-1", "000000000000", "prod", "cpu",
		cwAlertAttrs(), cwAlertImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeCloudWatchAlarm("cpu", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "alert.notify" && o.Value != false {
			t.Fatalf("alert.notify = %v on an alarm whose actions are disabled — it names "+
				"a target and will never invoke it", o.Value)
		}
	}
}
