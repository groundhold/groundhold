// k8s NetworkPolicy -> capability.network.private (D60 vocab), the archetype the
// pre-implementation reviews deferred BEHIND a Prober — and why. A NetworkPolicy
// object is accepted and stored by every API server, but only ENFORCED if the
// cluster's CNI implements it (older EKS, kindnet, etc. silently ignore it). So a
// static read is at most CONFIG-INTENT: the config SAYS ingress is denied, but
// whether a packet is actually dropped is unproven. observe therefore tags
// ingress.public / egress.restricted `config-intent` (never `measured`), and the
// Prober measures the real outcome by dialing a declared target: a successful
// handshake PROVES a path exists (ingress.public=true, a violation). Absence of a
// path cannot be proven by one dial from one vantage (filtered/dropped/down are
// indistinguishable), so a non-connect is an honest probe FAILURE, never a
// fabricated "private" — exactly the vocab's static-intent vs measured-outcome line.
package k8s

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"groundhold/internal/provider"
)

var _ provider.Prober = (*Driver)(nil)

const (
	netGroup   = "networking.k8s.io"
	netVersion = "v1"
	// probeTargetAnnotation names the endpoint (host:port) the reachability probe
	// dials — the vantage-specified target a default-deny policy should make
	// unreachable. Absent, the probe cannot measure enforcement (honest failure).
	probeTargetAnnotation = "groundhold.dev/probe-target"
)

type netpolDoc struct {
	Metadata objectMeta `json:"metadata"`
	Spec     struct {
		PodSelector map[string]any `json:"podSelector"`
		PolicyTypes []string       `json:"policyTypes"`
		Ingress     []any          `json:"ingress"`
		Egress      []any          `json:"egress"`
	} `json:"spec"`
}

func netpolPath(namespace, name string) string {
	return fmt.Sprintf("/apis/%s/%s/namespaces/%s/networkpolicies/%s", netGroup, netVersion, namespace, name)
}

func netpolProviderID(namespace, name string) string {
	return rbacProviderID(netGroup, netVersion, "NetworkPolicy", namespace, name)
}

func (d *Driver) getNetpol(namespace, name string) (netpolDoc, bool, bool) {
	st, body, err := d.call("GET", netpolPath(namespace, name), nil)
	if err != nil {
		return netpolDoc{}, false, false
	}
	if st == http.StatusNotFound {
		return netpolDoc{}, false, true
	}
	if st != http.StatusOK {
		return netpolDoc{}, false, false
	}
	var doc netpolDoc
	if json.Unmarshal(body, &doc) != nil {
		return netpolDoc{}, false, false
	}
	return doc, true, true
}

func hasType(types []string, want string) bool {
	for _, t := range types {
		if t == want {
			return true
		}
	}
	return false
}

// The NetworkPolicy observe/build/create/update/delete twin was DELETED once the
// generic engine + the k8s.netpol.defaultDenyIngress read/write lens reproduced
// it: the service "netpol" now routes through mappings/k8s.networkpolicy.yaml.
// getNetpol / netpolDoc / netpolApplyResult remain (the Prober and the generic
// apply-result helper use them).

func netpolApplyResult(pid string, st int, b []byte, e error) provider.CreateResult {
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("apply outcome unknown: %v", e)}
	case st == http.StatusOK || st == http.StatusCreated:
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	case st == http.StatusConflict:
		return provider.CreateResult{ProviderID: pid, Status: "failed", Reason: "field ownership conflict — another manager owns fields (release it first)"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown", Reason: fmt.Sprintf("apply HTTP %d (server error) — reconcile", st)}
	default:
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("apply HTTP %d: %s", st, mutDetail(b))}
	}
}

// Probe implements provider.Prober (D59) for NetworkPolicy reachability. It dials
// the target declared in the probe-target annotation. A successful handshake is a
// MEASURED ingress.public=true — a path demonstrably exists (the strong, honest
// signal that a "private" contract is violated). A non-connect cannot prove the
// path is absent from one vantage, so it is a probe FAILURE (unknown), never a
// fabricated "private". No intrusive path (a dial mutates nothing).
func (d *Driver) Probe(service, capability, providerID string, allowIntrusive bool) (provider.ProbeOutcome, error) {
	if err := d.requireService(service); err != nil {
		return provider.ProbeOutcome{}, err
	}
	if service != "netpol" {
		return provider.ProbeOutcome{}, fmt.Errorf("k8s driver: probes for service %q are not wired", service)
	}
	_, _, ns, name, err := splitRBACProviderID(providerID, "NetworkPolicy")
	if err != nil {
		return provider.ProbeOutcome{}, err
	}
	doc, found, readable := d.getNetpol(ns, name)
	if !readable {
		return provider.ProbeOutcome{}, fmt.Errorf("networkpolicies.get: unreadable")
	}
	var out provider.ProbeOutcome
	if !found {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "ingress.public", Method: "tcp-connect",
			Reason: "networkpolicy no longer exists — nothing to probe", Retryable: false})
		return out, nil
	}
	target := doc.Metadata.Annotations[probeTargetAnnotation]
	if target == "" {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "ingress.public", Method: "tcp-connect",
			Reason:    "no " + probeTargetAnnotation + " annotation — the CNI enforcement of this policy is unproven; declare a host:port a default-deny policy should make unreachable",
			Retryable: false})
		return out, nil
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		out.Failures = append(out.Failures, provider.ProbeFailure{
			Path: "ingress.public", Method: "tcp-connect",
			Reason: fmt.Sprintf("%s=%q is not host:port: %v", probeTargetAnnotation, target, err), Retryable: false})
		return out, nil
	}
	dial := d.Dial
	if dial == nil {
		dial = net.DialTimeout
	}
	conn, err := dial("tcp", target, 5*time.Second)
	if err == nil {
		_ = conn.Close()
		out.Measurements = append(out.Measurements, provider.ProbeMeasurement{
			Path: "ingress.public", Value: true, Method: "tcp-connect",
			Evidence: fmt.Sprintf("TCP handshake to %s succeeded — a path exists (the policy is not enforced, or an allow-path admits it)", target)})
		return out, nil
	}
	// a non-connect cannot distinguish policy-drop from filtered/down — the path
	// MAY still exist under other conditions, so we cannot conclude absence.
	out.Failures = append(out.Failures, provider.ProbeFailure{
		Path: "ingress.public", Method: "tcp-connect",
		Reason:    fmt.Sprintf("no path from this vantage to %s (%v) — filtered, dropped by the policy, or down are indistinguishable; absence of a path cannot be proven by one dial", target, err),
		Retryable: true})
	return out, nil
}
