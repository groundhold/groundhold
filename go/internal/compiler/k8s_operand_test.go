package compiler

import (
	"strings"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/k8s"
	"groundhold/internal/provider"
)

// D563. The silent-ignore guard skips any driver that does not declare a consumed
// set, and its comment says why: "A driver that declares no consumed set (the Fake
// double, which reads no operands) is exempt; the guard binds the real cloud
// drivers."
//
// The k8s driver is a real driver that reads operands — `namespace`, `name`,
// `issuerRef`, `secretName` — and declares none of them, so it is exempt by
// accident. Every k8s candidate can carry any misspelled operand and the guard
// waves it through, which is exactly the failure the pilot reported (D530): the
// operand is accepted, ignored, and the deployment is wrong in the direction the
// operator specifically tried to prevent.
//
// The exemption was written for a test double and silently acquired a production
// driver — the same shape as D561, where "every provider the drivers serve" meant
// the ones that happened to implement an interface.
func TestK8sOperandsAreNotSilentlyIgnored(t *testing.T) {
	cand := &contract.Candidate{Extras: map[string]map[string]any{
		"cert": {
			"provider": "k8s", "service": "certmanager-cert",
			"implementation": map[string]any{
				"namespace":  "default",
				"name":       "web",
				"secretName": "web-tls",
				"sercetName": "typo-tls", // the driver reads no such operand
			},
		},
	}}
	in := Inputs{
		Providers:        map[string]provider.Provider{"k8s": k8s.NewDriver("https://example.invalid", "t")},
		Bindings:         map[string]string{"cert": "cert-manager.io/v1/Certificate/default/web"},
		BindingProviders: map[string]string{"cert": "k8s"},
		BindingServices:  map[string]string{"cert": "certmanager-cert"},
	}
	err := refuseUnknownOperands(nil, cand, in)
	if err == nil {
		t.Fatal("a misspelled k8s operand was accepted — the guard's exemption was " +
			"written for the Fake double and quietly covers a production driver")
	}
	if !strings.Contains(err.Error(), "sercetName") {
		t.Errorf("the refusal does not name the operand: %v", err)
	}
}

// And the converse, or the guard is unusable: every operand the driver DOES read
// must pass, on every mapped service.
func TestK8sKnownOperandsStayQuiet(t *testing.T) {
	d := k8s.NewDriver("https://example.invalid", "t")
	for _, svc := range []struct {
		service, providerID string
		impl                map[string]any
	}{
		{"certmanager-cert", "cert-manager.io/v1/Certificate/default/web",
			map[string]any{"namespace": "default", "name": "web", "secretName": "web-tls",
				"issuerRef": map[string]any{"name": "letsencrypt", "kind": "ClusterIssuer"}}},
		{"rbac-role", "rbac.authorization.k8s.io/v1/Role/default/reader",
			map[string]any{"namespace": "default", "name": "reader"}},
		{"namespace", "core/v1/Namespace/team-a",
			map[string]any{"name": "team-a"}},
	} {
		cand := &contract.Candidate{Extras: map[string]map[string]any{
			"c": {"provider": "k8s", "service": svc.service, "implementation": svc.impl},
		}}
		in := Inputs{
			Providers:        map[string]provider.Provider{"k8s": d},
			Bindings:         map[string]string{"c": svc.providerID},
			BindingProviders: map[string]string{"c": "k8s"},
			BindingServices:  map[string]string{"c": svc.service},
		}
		if err := refuseUnknownOperands(nil, cand, in); err != nil {
			t.Errorf("%s: an operand the driver reads was refused: %v", svc.service, err)
		}
	}
}
