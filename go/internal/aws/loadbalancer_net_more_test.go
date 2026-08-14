package aws

import (
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

// This file rounds out loadbalancer_net.go coverage: ensureListener (0%) — the
// idempotent repair path for a load balancer that is ALREADY OURS (a prior
// partial create), reached when createLoadBalancer's ownership pre-read finds
// a matching load balancer already standing at the deterministic name.

// TestCreateLoadBalancer_AlreadyOursNoListenerRepairs: the load balancer + its
// target group already exist and are ours, but no listener was ever attached
// (a prior partial) — create must repair by attaching the listener, not
// re-create the composite from scratch.
func TestCreateLoadBalancer_AlreadyOursNoListenerRepairs(t *testing.T) {
	f := newFakeELB()
	f.lbCreated = true
	f.tgCreated = true
	f.tags = map[string]string{"groundhold-capability": lbCap, "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := lbProvDriver(t, srv)
	attrs, impl := httpsLBCandidate()

	res := d.Create("loadbalancer", lbCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("repair of an already-ours, listener-less LB must succeed, got %+v", res)
	}
	if res.ProviderID != elbv2ProviderID("eu-central-1", lbTestName) {
		t.Fatalf("repair must carry the existing pid, got %q", res.ProviderID)
	}
	// the composite was NOT re-created — no CreateTargetGroup/CreateLoadBalancer,
	// only the listener attach.
	for _, a := range f.order {
		if a == "CreateTargetGroup" || a == "CreateLoadBalancer" {
			t.Fatalf("repair must not re-create the standing composite; order = %v", f.order)
		}
	}
	if !f.listenerCreated {
		t.Fatal("repair must attach the missing listener")
	}
}

// TestCreateLoadBalancer_AlreadyOursWithListenerIsNoop: a load balancer that is
// ours and already has a listener is idempotently complete — no new listener,
// no re-create.
func TestCreateLoadBalancer_AlreadyOursWithListenerIsNoop(t *testing.T) {
	f := newFakeELB()
	f.lbCreated = true
	f.tgCreated = true
	f.listenerCreated = true
	f.listenerProto = "HTTPS"
	f.tags = map[string]string{"groundhold-capability": lbCap, "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := lbProvDriver(t, srv)
	attrs, impl := httpsLBCandidate()

	res := d.Create("loadbalancer", lbCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("an already-complete composite must be idempotent succeeded, got %+v", res)
	}
	for _, a := range f.order {
		if strings.HasPrefix(a, "Create") {
			t.Fatalf("an already-complete composite must issue NO create calls; order = %v", f.order)
		}
	}
}

// TestCreateLoadBalancer_AlreadyOursTargetGroupGoneRebuilds: the load balancer
// is ours but its target group vanished (a prior partial teardown) — repair
// must rebuild the target group before attaching the listener.
func TestCreateLoadBalancer_AlreadyOursTargetGroupGoneRebuilds(t *testing.T) {
	f := newFakeELB()
	f.lbCreated = true
	f.tgCreated = false // gone
	f.tags = map[string]string{"groundhold-capability": lbCap, "groundhold-environment": "prod"}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := lbProvDriver(t, srv)
	attrs, impl := httpsLBCandidate()

	res := d.Create("loadbalancer", lbCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("rebuild of a vanished target group must succeed, got %+v", res)
	}
	if !f.tgCreated {
		t.Fatal("the target group must have been rebuilt")
	}
	if !f.listenerCreated {
		t.Fatal("the listener must be attached once the target group is rebuilt")
	}
	if f.order[0] != "CreateTargetGroup" {
		t.Fatalf("the rebuild must create the target group before the listener; order = %v", f.order)
	}
}

// TestCreateLoadBalancer_AlreadyOursListenersReadUnknown: an unreadable listener
// list on an already-ours LB is ambiguous — unknown WITH the pid, never a
// fabricated repair or a silent success. fakeELB's DescribeListeners always
// succeeds, so this uses a small dedicated stub that fails ONLY that action.
func TestCreateLoadBalancer_AlreadyOursListenersReadUnknown(t *testing.T) {
	lbArn := "arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/" + lbTestName + "/50dc6c495c0c9188"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch formAction(string(b)) {
		case "DescribeLoadBalancers":
			_, _ = w.Write([]byte(`<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>` +
				`<LoadBalancerArn>` + lbArn + `</LoadBalancerArn><LoadBalancerName>` + lbTestName + `</LoadBalancerName>` +
				`<Scheme>internet-facing</Scheme><Type>application</Type><State><Code>active</Code></State>` +
				`</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`))
		case "DescribeTags":
			_, _ = w.Write([]byte(`<DescribeTagsResponse><DescribeTagsResult><TagDescriptions><member><ResourceArn>` + lbArn + `</ResourceArn><Tags>` +
				`<member><Key>groundhold-capability</Key><Value>` + lbCap + `</Value></member>` +
				`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
				`</Tags></member></TagDescriptions></DescribeTagsResult></DescribeTagsResponse>`))
		case "DescribeListeners":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>InternalError</Code></Error></ErrorResponse>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer srv.Close()
	d := lbProvDriver(t, srv)
	attrs, impl := httpsLBCandidate()

	res := d.Create("loadbalancer", lbCap, "prod", attrs, impl, "k", 1)
	if res.Status != "unknown" || res.ProviderID != elbv2ProviderID("eu-central-1", lbTestName) {
		t.Fatalf("an unreadable listener list must be unknown WITH the pid, got %+v", res)
	}
}

// ---- classifyLBChange: the default arm ------------------------------------

func TestClassifyLBChange_DefaultAndProjection(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{"location.region", "unsupported"},
		{"service.managed", "unsupported"},
		{"no.such.path", "unsupported"},
	} {
		got, reason := classifyLBChange(tc.path, nil, nil)
		if got != tc.want {
			t.Errorf("classifyLBChange(%q) = %q, want %q", tc.path, got, tc.want)
		}
		if reason == "" {
			t.Errorf("classifyLBChange(%q) carries no reason", tc.path)
		}
	}
}

func elbRole(_ *http.Request, body []byte) certifynet.Role {
	if v, err := url.ParseQuery(string(body)); err == nil {
		if strings.HasPrefix(v.Get("Action"), "Describe") {
			return certifynet.RoleRead
		}
	}
	return certifynet.RoleMutateOpaque
}

// lbAdoptFixture serves an already-ours, fully-standing load balancer whose exposure
// posture is set by the caller: the Scheme (internet-facing/internal) and the single
// listener's Protocol (HTTPS/HTTP) are the two knobs the D1062 control-completeness
// cases turn. Read-only — DescribeLoadBalancers, DescribeTags, DescribeListeners — so
// adopting it sends no mutation and the check is on the adopt verdict alone.
func lbAdoptFixture(scheme, listenerProto string) func() *httptest.Server {
	return func() *httptest.Server {
		lbArn := "arn:aws:elasticloadbalancing:eu-central-1:000000000000:loadbalancer/app/" + lbTestName + "/50dc6c495c0c9188"
		lisArn := "arn:aws:elasticloadbalancing:eu-central-1:000000000000:listener/app/" + lbTestName + "/50dc6c495c0c9188/abc"
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			switch formAction(string(b)) {
			case "DescribeLoadBalancers":
				_, _ = w.Write([]byte(`<DescribeLoadBalancersResponse><DescribeLoadBalancersResult><LoadBalancers><member>` +
					`<LoadBalancerArn>` + lbArn + `</LoadBalancerArn><LoadBalancerName>` + lbTestName + `</LoadBalancerName>` +
					`<Scheme>` + scheme + `</Scheme><Type>application</Type><State><Code>active</Code></State>` +
					`</member></LoadBalancers></DescribeLoadBalancersResult></DescribeLoadBalancersResponse>`))
			case "DescribeTags":
				_, _ = w.Write([]byte(`<DescribeTagsResponse><DescribeTagsResult><TagDescriptions><member><ResourceArn>` + lbArn + `</ResourceArn><Tags>` +
					`<member><Key>groundhold-capability</Key><Value>` + lbCap + `</Value></member>` +
					`<member><Key>groundhold-environment</Key><Value>prod</Value></member>` +
					`</Tags></member></TagDescriptions></DescribeTagsResult></DescribeTagsResponse>`))
			case "DescribeListeners":
				_, _ = w.Write([]byte(`<DescribeListenersResponse><DescribeListenersResult><Listeners><member>` +
					`<ListenerArn>` + lisArn + `</ListenerArn><Protocol>` + listenerProto + `</Protocol>` +
					`</member></Listeners></DescribeListenersResult></DescribeListenersResponse>`))
			default:
				w.WriteHeader(http.StatusBadRequest)
			}
		}))
	}
}

// TestAdoptsExistingLoadBalancer enrols loadbalancer in the D391 gate. An ALB is a
// COMPOSITE — load balancer plus target group plus listener — so the property here is
// partial: the standing pieces must be bound and only the MISSING piece created. That
// makes a fixed mutation budget the wrong assertion; what the gate pins is the identity
// bound, and the existing per-driver test pins that no CreateLoadBalancer or
// CreateTargetGroup is re-issued.
func TestAdoptsExistingLoadBalancer(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	attrs, impl := httpsLBCandidate()
	p := &certifynet.ExistingProbe{
		Name:     "aws/loadbalancer",
		Classify: elbRole,
		ExistingServer: func() *httptest.Server {
			f := newFakeELB()
			f.lbCreated = true
			f.tgCreated = true
			f.listenerCreated = true // the fully-standing estate: nothing left to do
			f.tags = map[string]string{"groundhold-capability": lbCap, "groundhold-environment": "prod"}
			return f.handler(t, nil)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.ELBv2BaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("loadbalancer", lbCap, "prod", attrs, impl, "k", 1)
		},
		PID:              elbv2ProviderID("eu-central-1", lbTestName),
		AllowedMutations: 2, // tag/attribute convergence onto the standing composite
		// D1062: the exposure posture is set inline at create and never reapplied to a
		// standing LB; both controls are fixed at creation (updateLoadBalancer refuses
		// them in place), so a live LB more exposed than declared FAILS.
		AdoptControls: lbAdoptControls,
		MissingControl: []certifynet.ControlCase{
			// declared INTERNAL over a live internet-facing LB — a public front door we
			// cannot make internal in place.
			{Path: "network.publicExposure", Server: lbAdoptFixture("internet-facing", "HTTPS"),
				Create: func(pr provider.Provider) provider.CreateResult {
					a, im := httpsLBCandidate()
					a["network.publicExposure"] = false
					return pr.Create("loadbalancer", lbCap, "prod", a, im, "k", 1)
				},
				WantStatus: "failed", WantMutations: 0},
			// declared TLS over a live plaintext (HTTP) listener — an unencrypted front
			// door we cannot re-terminate in place.
			{Path: "encryption.inTransit", Server: lbAdoptFixture("internet-facing", "HTTP"),
				WantStatus: "failed", WantMutations: 0},
		},
		// declared public but the live LB is INTERNAL (more secure) and TLS matches —
		// the safe direction must still adopt clean.
		MoreSecure: lbAdoptFixture("internal", "HTTPS"),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
