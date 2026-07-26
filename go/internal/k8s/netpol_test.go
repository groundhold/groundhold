package k8s

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func netpolServer(t *testing.T, ns, name string, spec map[string]any, ann map[string]string) *httptest.Server {
	t.Helper()
	want := netpolPath(ns, name)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != want {
			http.Error(w, "nf", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"metadata": map[string]any{"name": name, "namespace": ns, "annotations": ann},
			"spec":     spec,
		})
	}))
}

func TestProbeNetpolReachableIsMeasuredViolation(t *testing.T) {
	spec := map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}, "ingress": []any{}}
	srv := netpolServer(t, "ns", "np", spec, map[string]string{probeTargetAnnotation: "svc.ns.svc:8080"})
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	// inject a dial that SUCCEEDS -> a path exists
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	out, err := d.Probe("netpol", "np", netpolProviderID("ns", "np"), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Measurements) != 1 || out.Measurements[0].Path != "ingress.public" || out.Measurements[0].Value != true {
		t.Fatalf("a successful handshake must measure ingress.public=true, got %+v", out)
	}
}

func TestProbeNetpolUnreachableCannotConclude(t *testing.T) {
	spec := map[string]any{"policyTypes": []any{"Ingress"}, "ingress": []any{}}
	srv := netpolServer(t, "ns", "np", spec, map[string]string{probeTargetAnnotation: "10.0.0.1:8080"})
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	d.Dial = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("i/o timeout")
	}
	out, _ := d.Probe("netpol", "np", netpolProviderID("ns", "np"), false)
	if len(out.Measurements) != 0 || len(out.Failures) != 1 {
		t.Fatalf("a non-connect must be a probe FAILURE (unknown), never a measured 'private', got %+v", out)
	}
	if !strings.Contains(out.Failures[0].Reason, "cannot be proven by one dial") {
		t.Fatalf("failure must state absence cannot be proven, got %q", out.Failures[0].Reason)
	}
}

func TestProbeNetpolNoTargetIsHonestFailure(t *testing.T) {
	spec := map[string]any{"policyTypes": []any{"Ingress"}, "ingress": []any{}}
	srv := netpolServer(t, "ns", "np", spec, nil) // no annotation
	defer srv.Close()
	d := NewDriver(srv.URL, "tok")
	out, _ := d.Probe("netpol", "np", netpolProviderID("ns", "np"), false)
	if len(out.Measurements) != 0 || len(out.Failures) != 1 {
		t.Fatalf("no probe target must be a failure, not a measurement, got %+v", out)
	}
	if !strings.Contains(out.Failures[0].Reason, "enforcement of this policy is unproven") {
		t.Fatalf("failure must name the unproven enforcement, got %q", out.Failures[0].Reason)
	}
}
