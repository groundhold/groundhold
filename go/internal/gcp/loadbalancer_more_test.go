package gcp

import (
	"strings"
	"testing"
)

// This file extends loadbalancer_test.go, which pins the pure reverse map,
// the golden observe/discover, and the full create/observe/delete composite
// loop. These tests pin the remaining branches of the pure builder helpers:
// lbPortOperand's string/type/range branches, applyBackendServiceOperand's
// map/neg/unsupported-type branches, and classifyLoadBalancerChange's default
// path (exercised directly, not just through the two mutable-immutable cases
// already covered by TestLoadBalancerClassifyChange).

// --- lbPortOperand ---------------------------------------------------------

func TestLbPortOperandBranches(t *testing.T) {
	t.Run("default HTTP 80", func(t *testing.T) {
		p, err := lbPortOperand(nil, false)
		if err != nil || p != 80 {
			t.Fatalf("default HTTP port = %d, %v", p, err)
		}
	})
	t.Run("default HTTPS 443", func(t *testing.T) {
		p, err := lbPortOperand(nil, true)
		if err != nil || p != 443 {
			t.Fatalf("default HTTPS port = %d, %v", p, err)
		}
	})
	t.Run("explicit nil operand falls back to default", func(t *testing.T) {
		p, err := lbPortOperand(map[string]any{"port": nil}, false)
		if err != nil || p != 80 {
			t.Fatalf("nil port operand = %d, %v", p, err)
		}
	})
	t.Run("float64 (JSON number)", func(t *testing.T) {
		p, err := lbPortOperand(map[string]any{"port": float64(8080)}, false)
		if err != nil || p != 8080 {
			t.Fatalf("float64 port = %d, %v", p, err)
		}
	})
	t.Run("int", func(t *testing.T) {
		p, err := lbPortOperand(map[string]any{"port": 8443}, true)
		if err != nil || p != 8443 {
			t.Fatalf("int port = %d, %v", p, err)
		}
	})
	t.Run("numeric string", func(t *testing.T) {
		p, err := lbPortOperand(map[string]any{"port": "9090"}, false)
		if err != nil || p != 9090 {
			t.Fatalf("string port = %d, %v", p, err)
		}
	})
	t.Run("non-numeric string refuses", func(t *testing.T) {
		if _, err := lbPortOperand(map[string]any{"port": "not-a-port"}, false); err == nil {
			t.Fatal("a non-numeric port string must refuse")
		}
	})
	t.Run("unsupported type refuses", func(t *testing.T) {
		if _, err := lbPortOperand(map[string]any{"port": []any{80}}, false); err == nil {
			t.Fatal("an unsupported port operand type must refuse")
		}
	})
	t.Run("out of range low refuses", func(t *testing.T) {
		if _, err := lbPortOperand(map[string]any{"port": 0}, false); err == nil {
			t.Fatal("port 0 must refuse")
		}
	})
	t.Run("out of range high refuses", func(t *testing.T) {
		if _, err := lbPortOperand(map[string]any{"port": 70000}, false); err == nil {
			t.Fatal("port > 65535 must refuse")
		}
	})
}

// --- applyBackendServiceOperand ---------------------------------------

func TestApplyBackendServiceOperandBranches(t *testing.T) {
	t.Run("nil is a no-op (plumbing-only backend)", func(t *testing.T) {
		body := map[string]any{}
		if err := applyBackendServiceOperand(body, nil); err != nil {
			t.Fatal(err)
		}
		if _, has := body["backends"]; has {
			t.Fatalf("nil operand must not set backends, got %+v", body)
		}
	})
	t.Run("empty string is a no-op", func(t *testing.T) {
		body := map[string]any{}
		if err := applyBackendServiceOperand(body, ""); err != nil {
			t.Fatal(err)
		}
		if _, has := body["backends"]; has {
			t.Fatalf("empty string operand must not set backends, got %+v", body)
		}
	})
	t.Run("string attaches a single backend group", func(t *testing.T) {
		body := map[string]any{}
		if err := applyBackendServiceOperand(body, "my-neg"); err != nil {
			t.Fatal(err)
		}
		backends, _ := body["backends"].([]any)
		if len(backends) != 1 {
			t.Fatalf("expected one backend, got %+v", body["backends"])
		}
		grp := backends[0].(map[string]any)
		if grp["group"] != "my-neg" {
			t.Fatalf("expected group=my-neg, got %+v", grp)
		}
	})
	t.Run("map with protocol", func(t *testing.T) {
		body := map[string]any{"protocol": "HTTP"}
		if err := applyBackendServiceOperand(body, map[string]any{"protocol": "HTTP2"}); err != nil {
			t.Fatal(err)
		}
		if body["protocol"] != "HTTP2" {
			t.Fatalf("protocol override not applied, got %v", body["protocol"])
		}
	})
	t.Run("map with verbatim backends", func(t *testing.T) {
		body := map[string]any{}
		verbatim := []any{map[string]any{"group": "g1"}, map[string]any{"group": "g2"}}
		if err := applyBackendServiceOperand(body, map[string]any{"backends": verbatim}); err != nil {
			t.Fatal(err)
		}
		got, _ := body["backends"].([]any)
		if len(got) != 2 {
			t.Fatalf("verbatim backends not applied, got %+v", body["backends"])
		}
	})
	t.Run("map with neg overrides backends", func(t *testing.T) {
		body := map[string]any{"backends": []any{map[string]any{"group": "stale"}}}
		if err := applyBackendServiceOperand(body, map[string]any{"neg": "my-neg-group"}); err != nil {
			t.Fatal(err)
		}
		backends, _ := body["backends"].([]any)
		if len(backends) != 1 || backends[0].(map[string]any)["group"] != "my-neg-group" {
			t.Fatalf("neg must override backends with a single group, got %+v", body["backends"])
		}
	})
	t.Run("empty map is a no-op", func(t *testing.T) {
		body := map[string]any{}
		if err := applyBackendServiceOperand(body, map[string]any{}); err != nil {
			t.Fatal(err)
		}
		if len(body) != 0 {
			t.Fatalf("an empty map operand must set nothing, got %+v", body)
		}
	})
	t.Run("unsupported type refuses", func(t *testing.T) {
		if err := applyBackendServiceOperand(map[string]any{}, 42); err == nil {
			t.Fatal("an unsupported backendService operand type must refuse")
		}
	})
}

// --- classifyLoadBalancerChange default path -----------------------------

func TestClassifyLoadBalancerChangeDirect(t *testing.T) {
	if k, _ := classifyLoadBalancerChange("network.publicExposure"); k != "immutable" {
		t.Errorf("publicExposure = %q", k)
	}
	if k, _ := classifyLoadBalancerChange("encryption.inTransit"); k != "immutable" {
		t.Errorf("inTransit = %q", k)
	}
	if k, reason := classifyLoadBalancerChange("service.managed"); k != "unsupported" || !strings.Contains(reason, "nothing to patch") {
		t.Errorf("service.managed = %q, %q", k, reason)
	}
	if k, reason := classifyLoadBalancerChange("whatever.else"); k != "unsupported" || !strings.Contains(reason, "no load-balancer in-place mapping") {
		t.Errorf("default path = %q, %q", k, reason)
	}
}

// --- targetProxyKind edge cases -------------------------------------------

func TestTargetProxyKindEdgeCases(t *testing.T) {
	if got := targetProxyKind(""); got != "" {
		t.Errorf("empty target = %q", got)
	}
	if got := targetProxyKind(".../regions/us-central1/targetPools/legacy-pool"); got != "targetPools" {
		t.Errorf("targetPools should be recognized as a target* segment, got %q", got)
	}
	if got := targetProxyKind(".../regions/us-central1/backendServices/db-lb"); got != "" {
		t.Errorf("a bare backendService target has no target* segment, got %q", got)
	}
}

// --- BuildLoadBalancerPlan additional refusal branches --------------------

func TestBuildLoadBalancerPlanUnknownAttributeRefuses(t *testing.T) {
	attrs := map[string]any{"network.publicExposure": true, "service.managed": true,
		"cost.monthly": 10}
	if _, err := BuildLoadBalancerPlan("acme-prod", "prod", "capability.network.loadbalancer", attrs, nil, 1); err == nil {
		t.Fatal("an unmapped attribute must refuse")
	}
}

func TestBuildLoadBalancerPlanServiceManagedFalseRefuses(t *testing.T) {
	attrs := map[string]any{"network.publicExposure": true, "service.managed": false}
	if _, err := BuildLoadBalancerPlan("acme-prod", "prod", "capability.network.loadbalancer", attrs, nil, 1); err == nil {
		t.Fatal("service.managed=false must refuse (a GCP LB is always managed)")
	}
}

func TestBuildLoadBalancerPlanCertWithoutInTransitRefuses(t *testing.T) {
	attrs := map[string]any{"network.publicExposure": true, "service.managed": true}
	impl := map[string]any{"sslCertificate": "my-cert"}
	_, err := BuildLoadBalancerPlan("acme-prod", "prod", "capability.network.loadbalancer", attrs, impl, 1)
	if err == nil || !strings.Contains(err.Error(), "contradiction") {
		t.Fatalf("a cert without inTransit must refuse as a contradiction, got %v", err)
	}
}

func TestBuildLoadBalancerPlanBadCertNameRefuses(t *testing.T) {
	attrs := map[string]any{"network.publicExposure": true, "encryption.inTransit": true, "service.managed": true}
	impl := map[string]any{"sslCertificate": "not a valid name!"}
	_, err := BuildLoadBalancerPlan("acme-prod", "prod", "capability.network.loadbalancer", attrs, impl, 1)
	if err == nil || !strings.Contains(err.Error(), "not a valid compute resource name") {
		t.Fatalf("a malformed cert name must refuse, got %v", err)
	}
}

func TestBuildLoadBalancerPlanCertAsFullURL(t *testing.T) {
	// a cert operand containing "/" is treated as an existing full self-link, not
	// a bare name — no gcpName validation applies to it.
	attrs := map[string]any{"network.publicExposure": true, "encryption.inTransit": true, "service.managed": true}
	impl := map[string]any{"sslCertificate": "projects/other-proj/global/sslCertificates/shared-cert"}
	plan, err := BuildLoadBalancerPlan("acme-prod", "prod", "capability.network.loadbalancer", attrs, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.HTTPS {
		t.Fatal("an HTTPS plan must be marked HTTPS")
	}
}
