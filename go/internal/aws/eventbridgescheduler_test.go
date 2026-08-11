package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func ebsAttrs() map[string]any {
	return map[string]any{
		"location.region":  "eu-central-1",
		"schedule.enabled": true,
		"service.managed":  true,
	}
}

func ebsImpl() map[string]any {
	return map[string]any{
		"schedule":   "cron(0 2 * * ? *)",
		"target_arn": "arn:aws:sqs:eu-central-1:000000000000:jobs",
		"role_arn":   "arn:aws:iam::000000000000:role/scheduler",
	}
}

func TestBuildEventBridgeSchedulerHonors(t *testing.T) {
	p, err := BuildEventBridgeScheduler("prod", "nightly", ebsAttrs(), ebsImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !ebsNameOK.MatchString(p.Name) || !strings.HasPrefix(p.Name, "nightly-prod-") {
		t.Fatalf("name = %q", p.Name)
	}
	body := p.createBody("nightly", "prod")
	if body["State"] != "ENABLED" {
		t.Fatalf("state = %v", body["State"])
	}
	if !strings.Contains(body["Description"].(string), "capability=nightly") {
		t.Fatalf("marker missing: %v", body["Description"])
	}
	// no payload/input is ever set (D53).
	tgt := body["Target"].(map[string]any)
	if _, has := tgt["Input"]; has {
		t.Fatal("target must not carry an Input payload (D53)")
	}
}

func TestBuildEventBridgeSchedulerDisabled(t *testing.T) {
	a := ebsAttrs()
	a["schedule.enabled"] = false
	p, err := BuildEventBridgeScheduler("prod", "nightly", a, ebsImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.createBody("nightly", "prod")["State"] != "DISABLED" {
		t.Fatal("schedule.enabled=false must map to State DISABLED")
	}
}

func TestBuildEventBridgeSchedulerRefusals(t *testing.T) {
	type c struct{ attrs, impl map[string]any }
	cases := map[string]c{
		"no-schedule": {ebsAttrs(), map[string]any{"target_arn": "a", "role_arn": "r"}},
		"no-target":   {ebsAttrs(), map[string]any{"schedule": "cron()"}},
		"no-role":     {ebsAttrs(), map[string]any{"schedule": "cron()", "target_arn": "a"}},
		"unmanaged":   {map[string]any{"location.region": "eu-central-1", "service.managed": false}, ebsImpl()},
		"unknown":     {map[string]any{"location.region": "eu-central-1", "trigger.jitter": "5s"}, ebsImpl()},
		"bad-region":  {map[string]any{"location.region": "nope", "service.managed": true}, ebsImpl()},
	}
	for name, tc := range cases {
		if _, err := BuildEventBridgeScheduler("prod", "nightly", tc.attrs, tc.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// TestCreateEBSClientToken pins the Acme finding (same class as F27): CreateSchedule
// must carry a non-empty ClientToken (AWS rejects the raw request without it, HTTP 400
// "ClientToken cannot be empty"), and the token must be DETERMINISTIC (a retry reuses
// it → idempotent, not a duplicate schedule).
func TestCreateEBSClientToken(t *testing.T) {
	var createBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			createBody = string(b)
			_, _ = w.Write([]byte(`{"ScheduleArn":"arn:aws:scheduler:eu-central-1:0:schedule/default/nightly-prod-x"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	d := ebsDriver(t, srv)
	res := d.Create("eventbridgescheduler", "nightly", "prod", ebsAttrs(), ebsImpl(), "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	want := ebsClientToken(EBSName("prod", "nightly", 1))
	if want == "" {
		t.Fatal("ClientToken must be non-empty")
	}
	if !strings.Contains(createBody, `"ClientToken":"`+want+`"`) {
		t.Fatalf("CreateSchedule must carry the deterministic ClientToken %q; body=%s", want, createBody)
	}
	// determinism: recomputing the token yields the same value across builds.
	if ebsClientToken(EBSName("prod", "nightly", 1)) != want {
		t.Fatal("ebsClientToken must be deterministic")
	}
}

// ebsServer is a happy EventBridge Scheduler REST double. GET reflects the marker+state.
// D899: a DELETE with no clientToken query parameter is rejected the way real AWS rejects
// it ("ClientToken cannot be empty"), so a driver that forgets the token fails the delete
// test rather than passing against a double that shrugs it off.
func ebsServer(t *testing.T, capLabel, state string) *httptest.Server {
	t.Helper()
	marker := awsOwnerMarker(capLabel, "prod")
	doc := `{"Name":"nightly-prod-x","Arn":"arn:aws:scheduler:eu-central-1:0:schedule/default/nightly-prod-x",` +
		`"State":"` + state + `","Description":"` + marker + `"}`
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "POST":
				_, _ = w.Write([]byte(`{"ScheduleArn":"arn:aws:scheduler:eu-central-1:0:schedule/default/nightly-prod-x"}`))
			case "GET":
				_, _ = w.Write([]byte(doc))
			case "DELETE":
				if r.URL.Query().Get("clientToken") == "" {
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`{"Message":"ClientToken cannot be empty."}`))
					return
				}
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func ebsDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.SchedulerBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// TestEBSScheduleDriftAndUpdate (D1004): the cron/rate expression is observed as an operand
// and is a DESIRED target, so a change is a detected DRIFT (mutable → UpdateSchedule), not
// silence — the field case where declaring rate(1 minute) over a live rate(1 hour) produced
// zero actions and the contract could stand a schedule up but never keep it.
func TestEBSScheduleDriftAndUpdate(t *testing.T) {
	// classify: the expression + enabled patch in place; region is a replacement.
	if k, _ := classifyEBSChange(ebsScheduleOperand); k != "mutable" {
		t.Fatalf("schedule expression must be mutable, got %q", k)
	}
	if k, _ := classifyEBSChange("location.region"); k != "immutable" {
		t.Fatalf("region must be immutable, got %q", k)
	}

	// observe emits the live expression on the reserved operand path.
	marker := awsOwnerMarker("nightly", "prod")
	var putBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			_, _ = w.Write([]byte(`{"Name":"nightly-prod-x","State":"ENABLED",` +
				`"Description":"` + marker + `","ScheduleExpression":"rate(1 hour)"}`))
		case "PUT":
			b, _ := io.ReadAll(r.Body)
			putBody = string(b)
			_, _ = w.Write([]byte(`{"ScheduleArn":"arn"}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := ebsDriver(t, srv)
	pid := ebsProviderID("eu-central-1", EBSName("prod", "nightly", 1))

	obs, _, err := d.observeEventBridgeScheduler("nightly", pid)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got[ebsScheduleOperand] != "rate(1 hour)" {
		t.Fatalf("observe must emit the live schedule expression, got %+v", got[ebsScheduleOperand])
	}

	// OperandTargets renders the DESIRED expression, so the reconcile can compare.
	targets, err := d.OperandTargets("eventbridgescheduler", ebsAttrs(), ebsImpl())
	if err != nil {
		t.Fatal(err)
	}
	var desired any
	for _, tg := range targets {
		if tg.Path == ebsScheduleOperand {
			desired = tg.Desired
		}
	}
	if desired != "cron(0 2 * * ? *)" {
		t.Fatalf("OperandTargets must render the desired schedule, got %v", desired)
	}

	// update PUTs the new expression via UpdateSchedule (no replacement).
	impl := ebsImpl()
	impl["schedule"] = "rate(1 minute)"
	res := d.updateEventBridgeScheduler("nightly", "prod", pid, ebsAttrs(), impl, []string{ebsScheduleOperand})
	if res.Status != "succeeded" {
		t.Fatalf("schedule update: %+v", res)
	}
	if !strings.Contains(putBody, `"ScheduleExpression":"rate(1 minute)"`) {
		t.Fatalf("UpdateSchedule must PUT the new expression, got %s", putBody)
	}
}

func TestCreateObserveDeleteEventBridgeScheduler(t *testing.T) {
	srv := ebsServer(t, "nightly", "ENABLED")
	defer srv.Close()
	d := ebsDriver(t, srv)
	res := d.Create("eventbridgescheduler", "nightly", "prod", ebsAttrs(), ebsImpl(), "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "ebsched:eu-central-1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeEventBridgeScheduler("nightly", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["schedule.enabled"] != true || got["location.region"] != "eu-central-1" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("eventbridgescheduler", "nightly", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteEventBridgeSchedulerForeignRefused(t *testing.T) {
	srv := ebsServer(t, "someone-else", "ENABLED")
	defer srv.Close()
	d := ebsDriver(t, srv)
	pid := ebsProviderID("eu-central-1", EBSName("prod", "nightly", 1))
	res := d.Delete("eventbridgescheduler", "nightly", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign schedule must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessEventBridgeScheduler(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := ebsProviderID("eu-central-1", EBSName("prod", "nightly", 1))
	p := &certifynet.Probe{
		Name:            "aws/eventbridgescheduler",
		AssertTransient: true,        // D237: create/delete route through provider.MutationResult
		Classify:        restXMLRole, // REST: GET read, POST/DELETE opaque (name deterministic)
		OwnerTagValue:   "nightly",
		DeterministicID: true, // the schedule name is chosen
		// F-LC3 (D520): migrated to the absence property.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("eventbridgescheduler", "nightly", pid)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return ebsServer(t, "nightly", "ENABLED") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("eventbridgescheduler", "nightly", "prod", ebsAttrs(), ebsImpl(), "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return ebsServer(t, "nightly", "ENABLED") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("eventbridgescheduler", "nightly", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestRefusesForeignUpdateEBS (D1004): updateEventBridgeScheduler refuses a schedule whose
// Description marker is a stranger's — a patch must not touch a resource we do not own.
func TestRefusesForeignUpdateEBS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			_, _ = w.Write([]byte(`{"Name":"nightly-prod-x","State":"ENABLED","Description":"someone-elses-marker","ScheduleExpression":"rate(1 hour)"}`))
			return
		}
		w.WriteHeader(400)
	}))
	defer srv.Close()
	d := ebsDriver(t, srv)
	pid := ebsProviderID("eu-central-1", EBSName("prod", "nightly", 1))
	res := d.updateEventBridgeScheduler("nightly", "prod", pid, ebsAttrs(), ebsImpl(), []string{ebsScheduleOperand})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign schedule update must refuse, got %+v", res)
	}
}
