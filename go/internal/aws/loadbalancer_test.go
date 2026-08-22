package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- the pure reverse map: the load-bearing truth table ---

func TestReverseMapLoadBalancer(t *testing.T) {
	https := elbListener{Protocol: "HTTPS"}
	tls := elbListener{Protocol: "TLS"}
	httpPlain := elbListener{Protocol: "HTTP"}
	httpRedirect := elbListener{Protocol: "HTTP", RedirectsToTLS: true}
	cases := []struct {
		name          string
		scheme        string
		listeners     []elbListener
		wantPublic    bool
		wantInTransit bool
	}{
		{"internet-facing HTTPS ALB", "internet-facing", []elbListener{https}, true, true},
		{"internal HTTP ALB", "internal", []elbListener{httpPlain}, false, false},
		{"internet-facing plaintext (public + no TLS)", "internet-facing", []elbListener{httpPlain}, true, false},
		{"internal TLS NLB", "internal", []elbListener{tls}, false, true},
		// D1186: a plaintext HTTP:80 forwarding alongside HTTPS:443 is a cleartext path —
		// inTransit must be FALSE (the old "any TLS listener" rule read this true).
		{"mixed HTTP-forward + HTTPS -> inTransit FALSE", "internet-facing", []elbListener{httpPlain, https}, true, false},
		// an HTTP:80 that only REDIRECTS to HTTPS is not a cleartext data path -> true.
		{"HTTP-redirect + HTTPS -> inTransit true", "internet-facing", []elbListener{httpRedirect, https}, true, true},
		{"no listeners -> inTransit false", "internal", nil, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := map[string]any{}
			for _, o := range reverseMapLoadBalancer(c.scheme, c.listeners) {
				if o.Derivation != "measured" {
					t.Errorf("%s must be measured, got %q", o.Path, o.Derivation)
				}
				m[o.Path] = o.Value
			}
			if m["network.publicExposure"] != c.wantPublic {
				t.Errorf("publicExposure = %v, want %v", m["network.publicExposure"], c.wantPublic)
			}
			if m["encryption.inTransit"] != c.wantInTransit {
				t.Errorf("inTransit = %v, want %v", m["encryption.inTransit"], c.wantInTransit)
			}
			if m["service.managed"] != true {
				t.Errorf("service.managed must always be true, got %v", m["service.managed"])
			}
		})
	}
}

// elbv2Server is a fake ELBv2 endpoint: DescribeLoadBalancers returns one LB with
// the given scheme; DescribeListeners returns one listener with the given protocol.
func elbv2Server(t *testing.T, name, scheme, protocol string, rec *capture) *httptest.Server {
	t.Helper()
	arn := "arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/" + name + "/50dc6c495c0c9188"
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		if rec != nil {
			rec.record(r, body)
		}
		switch formAction(body) {
		case "DescribeLoadBalancers":
			_, _ = w.Write([]byte(`<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>` +
				`<LoadBalancerArn>` + arn + `</LoadBalancerArn>` +
				`<LoadBalancerName>` + name + `</LoadBalancerName>` +
				`<Scheme>` + scheme + `</Scheme>` +
				`<Type>application</Type><VpcId>vpc-0abc123</VpcId>` +
				`<State><Code>active</Code></State>` +
				`</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`))
		case "DescribeListeners":
			_, _ = w.Write([]byte(`<DescribeListenersResponse><DescribeListenersResult><Listeners><member>` +
				`<LoadBalancerArn>` + arn + `</LoadBalancerArn>` +
				`<Protocol>` + protocol + `</Protocol><Port>443</Port>` +
				`<ListenerArn>` + arn + `/f2f7dc8efc522ab2</ListenerArn>` +
				`</member></Listeners></DescribeListenersResult></DescribeListenersResponse>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func elbv2TestDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.ELBv2BaseURL = srv.URL
	d.Account = "000000000000"
	return d
}

// TestObserveLoadBalancerGolden: an internet-facing HTTPS ALB reverse-maps to
// publicExposure=true, inTransit=true — through a SigV4-signed two-call observe.
func TestObserveLoadBalancerGolden(t *testing.T) {
	rec := newCapture()
	srv := elbv2Server(t, "vendor-broker", "internet-facing", "HTTPS", rec)
	defer srv.Close()
	d := elbv2TestDriver(t, srv)

	obs, diags, err := d.observeLoadBalancer("capability.network.loadbalancer", "elbv2:eu-central-1:vendor-broker")
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diags: %v", diags)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["network.publicExposure"] != true || m["encryption.inTransit"] != true || m["service.managed"] != true {
		t.Fatalf("internet-facing HTTPS ALB = %+v, want public+inTransit+managed all true", m)
	}
	// both reads happened AND were SigV4-signed.
	if !rec.saw("DescribeLoadBalancers") || !rec.saw("DescribeListeners") {
		t.Fatalf("observe must call DescribeLoadBalancers + DescribeListeners, saw %+v", rec.ops)
	}
	if rec.unsign != 0 {
		t.Fatalf("every ELBv2 request must be SigV4-signed; %d were not", rec.unsign)
	}
}

// TestObserveLoadBalancerInternalPlaintext: an internal HTTP ALB -> false/false.
func TestObserveLoadBalancerInternalPlaintext(t *testing.T) {
	srv := elbv2Server(t, "internal-svc", "internal", "HTTP", nil)
	defer srv.Close()
	d := elbv2TestDriver(t, srv)

	obs, _, err := d.observeLoadBalancer("capability.network.loadbalancer", "elbv2:eu-central-1:internal-svc")
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["network.publicExposure"] != false || m["encryption.inTransit"] != false {
		t.Fatalf("internal HTTP ALB = %+v, want public=false inTransit=false", m)
	}
}

// TestDiscoverLoadBalancers: the two-step sweep (DescribeLoadBalancers -> per-LB
// DescribeListeners) surfaces the ALB as capability.network.loadbalancer.
func TestDiscoverLoadBalancers(t *testing.T) {
	rec := newCapture()
	srv := elbv2Server(t, "vendor-broker", "internet-facing", "HTTPS", rec)
	defer srv.Close()
	d := elbv2TestDriver(t, srv)

	found, diags, err := d.discoverLoadBalancers("eu-central-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 {
		t.Fatalf("want 1 load balancer, got %d (diags %v)", len(found), diags)
	}
	got := found[0]
	if got.ProviderID != "elbv2:eu-central-1:vendor-broker" {
		t.Fatalf("providerId = %q, want elbv2:eu-central-1:vendor-broker", got.ProviderID)
	}
	if got.ResourceType != "capability.network.loadbalancer" {
		t.Fatalf("resourceType = %q", got.ResourceType)
	}
	m := obsMap(got)
	if m["network.publicExposure"] != true || m["encryption.inTransit"] != true {
		t.Fatalf("discovered ALB observations = %+v, want the public HTTPS posture", m)
	}
	if !rec.saw("DescribeLoadBalancers") || !rec.saw("DescribeListeners") {
		t.Fatalf("the sweep must issue both actions, saw %+v", rec.ops)
	}
	if rec.unsign != 0 {
		t.Fatalf("every sweep request must be SigV4-signed; %d were not", rec.unsign)
	}
}

func TestSplitELBv2ProviderID(t *testing.T) {
	if _, _, err := splitELBv2ProviderID("elbv2:eu-central-1:vendor-broker"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	for _, bad := range []string{"eu:lb", "elbv2:bad:lb", "ecs:eu-central-1:lb", "elbv2:eu-central-1:-bad-"} {
		if _, _, err := splitELBv2ProviderID(bad); err == nil {
			t.Errorf("accepted malformed elbv2 id %q", bad)
		}
	}
}

// --- PROVISIONING: the full create -> observe -> delete composite ---

const lbCap = "capability.network.loadbalancer"

// fakeELB is a stateful fake ELBv2 endpoint for the whole composite lifecycle. It
// records the ORDER of mutating actions, tracks the target group / load balancer /
// listener as they land and are torn down, stores the ownership tags AddTags sets,
// captures the CreateListener body (to assert HTTPS + certificate), and can inject a
// listener failure to exercise the partial-failure -> unknown path.
type fakeELB struct {
	mu sync.Mutex

	name            string // the composite name (deterministic, shared LB + target group)
	tgCreated       bool
	lbCreated       bool
	listenerCreated bool
	tags            map[string]string
	listenerProto   string
	listenerBody    string

	// injection
	listenerStatus int  // if non-zero, CreateListener returns this HTTP status (failure)
	keepLB         bool // async test (D980): DeleteLoadBalancer accepted but LB stays present

	order []string
}

// lbTestName is the deterministic composite name for (capability, environment=prod,
// generation=1) — the fake echoes it so describe/wait paths resolve by name.
var lbTestName = elbCompositeName("prod", lbCap, 1)

func (f *fakeELB) lbArn() string {
	return "arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/" + f.name + "/50dc6c495c0c9188"
}
func (f *fakeELB) tgArn() string {
	return "arn:aws:elasticloadbalancing:eu-central-1:000000000000:targetgroup/" + f.name + "/73e2d6bc24d8a067"
}
func (f *fakeELB) lsnrArn() string { return f.lbArn() + "/listener/f2f7dc8efc522ab2" }

func formValue(body, key string) string {
	for _, kv := range strings.Split(body, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if ok && k == key {
			return v
		}
	}
	return ""
}

func newFakeELB() *fakeELB { return &fakeELB{name: lbTestName, tags: map[string]string{}} }

func (f *fakeELB) handler(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		if rec != nil {
			rec.record(r, body)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		act := formAction(body)
		switch act {
		case "CreateTargetGroup":
			f.order = append(f.order, act)
			f.tgCreated = true
			_, _ = w.Write([]byte(`<CreateTargetGroupResponse><CreateTargetGroupResult><TargetGroups><member>` +
				`<TargetGroupArn>` + f.tgArn() + `</TargetGroupArn><TargetGroupName>` + f.name + `</TargetGroupName>` +
				`</member></TargetGroups></CreateTargetGroupResult></CreateTargetGroupResponse>`))
		case "CreateLoadBalancer":
			f.order = append(f.order, act)
			f.lbCreated = true
			_, _ = w.Write([]byte(`<CreateLoadBalancerResponse><CreateLoadBalancerResult><LoadBalancers><member>` +
				`<LoadBalancerArn>` + f.lbArn() + `</LoadBalancerArn><LoadBalancerName>` + f.name + `</LoadBalancerName>` +
				`<Scheme>internet-facing</Scheme><Type>application</Type><State><Code>provisioning</Code></State>` +
				`</member></LoadBalancers></CreateLoadBalancerResult></CreateLoadBalancerResponse>`))
		case "AddTags":
			f.order = append(f.order, act)
			f.tags["groundhold-capability"] = formValue(body, "Tags.member.1.Value")
			f.tags["groundhold-environment"] = formValue(body, "Tags.member.2.Value")
			_, _ = w.Write([]byte(`<AddTagsResponse><AddTagsResult/></AddTagsResponse>`))
		case "DescribeLoadBalancers":
			if !f.lbCreated {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>LoadBalancerNotFound</Code></Error></ErrorResponse>`))
				return
			}
			_, _ = w.Write([]byte(`<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>` +
				`<LoadBalancerArn>` + f.lbArn() + `</LoadBalancerArn><LoadBalancerName>` + f.name + `</LoadBalancerName>` +
				`<Scheme>internet-facing</Scheme><Type>application</Type><State><Code>active</Code></State>` +
				`</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`))
		case "DescribeTags":
			out := `<DescribeTagsResponse><DescribeTagsResult><TagDescriptions><member><ResourceArn>` + f.lbArn() + `</ResourceArn><Tags>`
			for k, v := range f.tags {
				out += `<member><Key>` + k + `</Key><Value>` + v + `</Value></member>`
			}
			out += `</Tags></member></TagDescriptions></DescribeTagsResult></DescribeTagsResponse>`
			_, _ = w.Write([]byte(out))
		case "CreateListener":
			f.order = append(f.order, act)
			f.listenerBody = body
			if f.listenerStatus != 0 {
				w.WriteHeader(f.listenerStatus)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>ValidationError</Code></Error></ErrorResponse>`))
				return
			}
			f.listenerCreated = true
			f.listenerProto = formValue(body, "Protocol")
			_, _ = w.Write([]byte(`<CreateListenerResponse><CreateListenerResult><Listeners><member>` +
				`<ListenerArn>` + f.lsnrArn() + `</ListenerArn><Protocol>` + f.listenerProto + `</Protocol>` +
				`</member></Listeners></CreateListenerResult></CreateListenerResponse>`))
		case "DescribeListeners":
			out := `<DescribeListenersResponse><DescribeListenersResult><Listeners>`
			if f.listenerCreated {
				proto := f.listenerProto
				if proto == "" {
					proto = "HTTPS"
				}
				out += `<member><ListenerArn>` + f.lsnrArn() + `</ListenerArn><Protocol>` + proto + `</Protocol><Port>443</Port></member>`
			}
			out += `</Listeners></DescribeListenersResult></DescribeListenersResponse>`
			_, _ = w.Write([]byte(out))
		case "DescribeTargetGroups":
			if !f.tgCreated {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>TargetGroupNotFound</Code></Error></ErrorResponse>`))
				return
			}
			_, _ = w.Write([]byte(`<DescribeTargetGroupsResponse><DescribeTargetGroupsResult><TargetGroups><member>` +
				`<TargetGroupArn>` + f.tgArn() + `</TargetGroupArn><TargetGroupName>` + f.name + `</TargetGroupName>` +
				`</member></TargetGroups></DescribeTargetGroupsResult></DescribeTargetGroupsResponse>`))
		case "DeleteListener":
			f.order = append(f.order, act)
			f.listenerCreated = false
			_, _ = w.Write([]byte(`<DeleteListenerResponse><DeleteListenerResult/></DeleteListenerResponse>`))
		case "DeleteLoadBalancer":
			f.order = append(f.order, act)
			if !f.keepLB {
				f.lbCreated = false
			}
			_, _ = w.Write([]byte(`<DeleteLoadBalancerResponse><DeleteLoadBalancerResult/></DeleteLoadBalancerResponse>`))
		case "DeleteTargetGroup":
			f.order = append(f.order, act)
			f.tgCreated = false
			_, _ = w.Write([]byte(`<DeleteTargetGroupResponse><DeleteTargetGroupResult/></DeleteTargetGroupResponse>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
}

func lbProvDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.ELBv2BaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// httpsLBCandidate is an internet-facing HTTPS ALB candidate: publicExposure +
// inTransit drive the SHAPE, the impl block supplies the operands (subnets, SGs,
// certificate ARN, VPC).
func httpsLBCandidate() (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region":        "eu-central-1",
		"network.publicExposure": true,
		"encryption.inTransit":   true,
		"service.managed":        true,
	}
	impl = map[string]any{
		"subnets":         []any{"subnet-aaa", "subnet-bbb"},
		"securityGroups":  []any{"sg-123"},
		"certificateArn":  "arn:aws:acm:eu-central-1:000000000000:certificate/abc-123",
		"vpcId":           "vpc-0abc123",
		"healthCheckPath": "/healthz",
	}
	return
}

// TestLoadBalancerComposite_CreateObserveDelete is the golden lifecycle: a SigV4-
// signed create builds the composite in dependency ORDER (target group -> load
// balancer -> AddTags -> wait active -> HTTPS listener WITH the certificate), observe
// reverse-maps the live posture, and delete tears it down in REVERSE order.
func TestLoadBalancerComposite_CreateObserveDelete(t *testing.T) {
	f := newFakeELB()
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := lbProvDriver(t, srv)
	attrs, impl := httpsLBCandidate()

	// --- CREATE ---
	res := d.Create("loadbalancer", lbCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != elbv2ProviderID("eu-central-1", lbTestName) {
		t.Fatalf("create providerId = %q", res.ProviderID)
	}
	// dependency ORDER: target group first, then the load balancer, ownership tags,
	// then the listener (the DescribeLoadBalancers wait sits between, uncounted here).
	wantOrder := []string{"CreateTargetGroup", "CreateLoadBalancer", "AddTags", "CreateListener"}
	if strings.Join(f.order, ",") != strings.Join(wantOrder, ",") {
		t.Fatalf("create order = %v, want %v", f.order, wantOrder)
	}
	// HTTPS listener WITH the certificate (inTransit=true).
	if p := formValue(f.listenerBody, "Protocol"); p != "HTTPS" {
		t.Fatalf("listener Protocol = %q, want HTTPS", p)
	}
	if formValue(f.listenerBody, "Certificates.member.1.CertificateArn") == "" {
		t.Fatalf("HTTPS listener must carry the certificate ARN; body = %s", f.listenerBody)
	}
	if formValue(f.listenerBody, "DefaultActions.member.1.Type") != "forward" {
		t.Fatalf("listener default action must forward to the target group; body = %s", f.listenerBody)
	}
	if rec.unsign != 0 {
		t.Fatalf("every ELBv2 request must be SigV4-signed; %d were not", rec.unsign)
	}

	// --- OBSERVE ---
	obs, _, err := d.Observe("loadbalancer", lbCap, res.ProviderID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["network.publicExposure"] != true || m["encryption.inTransit"] != true {
		t.Fatalf("observe = %+v, want internet-facing + HTTPS", m)
	}

	// --- DELETE (reverse order) ---
	f.order = nil
	del := d.Delete("loadbalancer", lbCap, "prod", res.ProviderID, "k")
	if del.Status != "succeeded" {
		t.Fatalf("delete status = %q (%s), want succeeded", del.Status, del.Reason)
	}
	wantDel := []string{"DeleteListener", "DeleteLoadBalancer", "DeleteTargetGroup"}
	if strings.Join(f.order, ",") != strings.Join(wantDel, ",") {
		t.Fatalf("delete order = %v, want %v", f.order, wantDel)
	}
}

// TestDeleteLoadBalancerAsyncNotGoneIsUnknown pins D980: a DeleteLoadBalancer the
// provider ACCEPTS but that leaves the LB present (still deleting) must report unknown
// — never a terminal "succeeded" that tombstones an hourly-billable LB still live (and
// still referencing its target group, which cannot be deleted meanwhile).
func TestDeleteLoadBalancerAsyncNotGoneIsUnknown(t *testing.T) {
	f := newFakeELB()
	f.lbCreated = true
	f.keepLB = true // DeleteLoadBalancer accepted, but the LB never leaves the describe
	f.tags["groundhold-capability"] = lbCap
	f.tags["groundhold-environment"] = "prod"
	srv := f.handler(t, nil)
	defer srv.Close()
	d := lbProvDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the LB never goes NotFound → times out fast
	del := d.Delete("loadbalancer", lbCap, "prod", elbv2ProviderID("eu-central-1", lbTestName), "k")
	if del.Status != "unknown" {
		t.Fatalf("an accepted-but-still-deleting load balancer must be unknown (keep the handle), got %+v", del)
	}
	for _, a := range f.order {
		if a == "DeleteTargetGroup" {
			t.Fatal("the target group was deleted while the LB was still present — the poll must gate it")
		}
	}
}

// TestDeleteLoadBalancerGoneLeavesTargetGroupUntouched: when the load balancer is
// ALREADY GONE, its ownership check cannot run, and a target group carries no ownership
// tag of its own (ownership lives on the LB). Deleting a target group at our shared name
// then would risk destroying a FOREIGN one that reused the name — routing breakage. The
// delete must leave the target group for reconcile, never issue DeleteTargetGroup it
// cannot show is ours (the delete-ownership sweep's finding; the GCP/Azure per-companion
// skip, D943). The trade is a leaked target group in this rare partial, not a foreign
// resource deleted.
func TestDeleteLoadBalancerGoneLeavesTargetGroupUntouched(t *testing.T) {
	f := newFakeELB()
	f.lbCreated = false // the LB is gone (DescribeLoadBalancers → LoadBalancerNotFound)
	f.tgCreated = true  // a target group at our name is present (possibly foreign)
	srv := f.handler(t, nil)
	defer srv.Close()
	d := lbProvDriver(t, srv)
	del := d.Delete("loadbalancer", lbCap, "prod", elbv2ProviderID("eu-central-1", lbTestName), "k")
	if del.Status != "succeeded" {
		t.Fatalf("a gone load balancer is idempotent-succeeded, got %+v", del)
	}
	for _, a := range f.order {
		if a == "DeleteTargetGroup" {
			t.Fatal("the target group was deleted while the LB was gone — we cannot prove " +
				"it is ours, so it must be left, never destroyed as a possible foreign resource")
		}
	}
}

// TestLoadBalancerCreate_MissingOperandRefuses: a required operand missing is a
// refuse-BEFORE-mutate — failed, no ELBv2 call, honest reason. Covers both the cert
// (HTTPS with no certificateArn) and the subnets (<2) refusals.
func TestLoadBalancerCreate_MissingOperandRefuses(t *testing.T) {
	f := newFakeELB()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := lbProvDriver(t, srv)

	// inTransit=true but no certificateArn.
	attrs, impl := httpsLBCandidate()
	delete(impl, "certificateArn")
	res := d.Create("loadbalancer", lbCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "certificateArn") {
		t.Fatalf("missing cert must refuse with a cert reason, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("refuse-before-mutate must not call ELBv2; saw %v", f.order)
	}
	// Validate must refuse it too (refuse-before-mutate at the plan gate).
	if err := d.Validate("loadbalancer", lbCap, "prod", attrs, impl, 1); err == nil {
		t.Fatal("Validate must refuse an HTTPS candidate with no certificateArn")
	}

	// fewer than two subnets.
	attrs2, impl2 := httpsLBCandidate()
	impl2["subnets"] = []any{"subnet-only-one"}
	res2 := d.Create("loadbalancer", lbCap, "prod", attrs2, impl2, "k", 1)
	if res2.Status != "failed" || !strings.Contains(res2.Reason, "subnets") {
		t.Fatalf("single subnet must refuse with a subnets reason, got %+v", res2)
	}
}

// TestLoadBalancerCreate_ListenerFailsIsUnknown: the four-valued crux — the load
// balancer LANDS but the listener fails. The result must be unknown WITH the
// providerId (reconcile the target-less front door), never a silent success and
// never a bare failed that hides the standing load balancer.
func TestLoadBalancerCreate_ListenerFailsIsUnknown(t *testing.T) {
	f := newFakeELB()
	f.listenerStatus = http.StatusBadRequest // CreateListener rejects
	srv := f.handler(t, nil)
	defer srv.Close()
	d := lbProvDriver(t, srv)
	attrs, impl := httpsLBCandidate()

	res := d.Create("loadbalancer", lbCap, "prod", attrs, impl, "k", 1)
	if res.Status != "unknown" {
		t.Fatalf("LB up + listener failed must be unknown, got %q (%s)", res.Status, res.Reason)
	}
	if res.ProviderID != elbv2ProviderID("eu-central-1", lbTestName) {
		t.Fatalf("unknown must carry the providerId for reconcile, got %q", res.ProviderID)
	}
	if !f.lbCreated {
		t.Fatal("the load balancer should have landed before the listener failure")
	}
}

// TestLoadBalancerDelete_ForeignOwnershipRefuses: a load balancer at our name whose
// ownership tags are NOT ours must not be deleted — refuse, and issue no delete.
func TestLoadBalancerDelete_ForeignOwnershipRefuses(t *testing.T) {
	f := newFakeELB()
	f.lbCreated = true
	f.tgCreated = true
	f.tags = map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := lbProvDriver(t, srv)

	res := d.Delete("loadbalancer", lbCap, "prod", elbv2ProviderID("eu-central-1", lbTestName), "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign LB delete must refuse, got %+v", res)
	}
	for _, a := range f.order {
		if strings.HasPrefix(a, "Delete") {
			t.Fatalf("no delete may be issued against a foreign LB; saw %v", f.order)
		}
	}
}

// TestLoadBalancerDelete_Idempotent: nothing at our name -> succeeded (idempotent).
func TestLoadBalancerDelete_Idempotent(t *testing.T) {
	f := newFakeELB() // nothing created
	srv := f.handler(t, nil)
	defer srv.Close()
	d := lbProvDriver(t, srv)

	res := d.Delete("loadbalancer", lbCap, "prod", elbv2ProviderID("eu-central-1", lbTestName), "k")
	if res.Status != "succeeded" {
		t.Fatalf("delete of an already-gone LB must be idempotent succeeded, got %+v", res)
	}
}

// TestLoadBalancerClassifyChange: scheme + inTransit are immutable (replacement);
// the health-check path is mutable.
func TestLoadBalancerClassifyChange(t *testing.T) {
	d := NewDriver("eu-central-1")
	for _, tc := range []struct {
		path string
		want string
	}{
		{"network.publicExposure", "immutable"},
		// D832: this pinned "immutable" for a TLS switch. ModifyListener takes Protocol,
		// SslPolicy and Certificates on the existing listener — the old expectation pinned
		// replacing a balancer, and with it the DNS name every client holds.
		{"encryption.inTransit", "unsupported"},
		{"healthCheckPath", "mutable"},
	} {
		got, _ := d.ClassifyChange("loadbalancer", tc.path, nil, nil, nil)
		if got != tc.want {
			t.Errorf("classify %s = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestLoadBalancerUpdateRefuses: in-place update is unsupported (the governed
// attributes route to a replacement) — refuse honestly, never a silent no-op.
func TestLoadBalancerUpdateRefuses(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	pid := elbv2ProviderID("eu-central-1", lbTestName)
	res := d.Update("loadbalancer", lbCap, "prod", pid, map[string]any{}, nil, []string{"encryption.inTransit"}, "k")
	if res.Status != "failed" {
		t.Fatalf("in-place update must refuse, got %+v", res)
	}
}
