package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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
