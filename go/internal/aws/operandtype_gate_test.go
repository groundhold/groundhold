package aws

import (
	"strings"
	"testing"
)

// D674. The canonical form renders every number as a string (NUMSTR), so `port: 8443`
// and `port: "8443"` are ONE canonical value and two candidates differing only in
// that hash identically. That is tolerable only if the two BUILD the same resource.
// They did not:
//
//	operand port=8443    -> listener Port=8443  TargetPort=8080   err=<nil>
//	operand port="8443"  -> listener Port=80    TargetPort=8080   err=<nil>
//
// `implInt` returned (0,false) for a present-but-unreadable value exactly as for an
// absent one, and the caller's default took over. `preflight` said `{"ready": true}`
// for both. One sealed identity, two different public front doors.
func TestAnUnreadableOperandRefusesRatherThanDefaulting(t *testing.T) {
	attrs := map[string]any{
		"network.publicExposure": true,
		"encryption.inTransit":   true,
	}
	base := map[string]any{
		"subnets":        []any{"subnet-1", "subnet-2"},
		"securityGroups": []any{"sg-1"},
		"certificateArn": "arn:aws:acm:eu-central-1:000000000000:certificate/abc",
		"targetPort":     8080,
		"vpcId":          "vpc-1",
	}
	with := func(port any) map[string]any {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		if port != nil {
			m["port"] = port
		}
		return m
	}

	good, err := BuildLoadBalancer("test", "lb", attrs, with(8443), 1)
	if err != nil {
		t.Fatalf("a well-typed operand was refused: %v", err)
	}
	if good.Port != 8443 {
		t.Fatalf("the fixture is wrong: port = %d", good.Port)
	}

	_, err = BuildLoadBalancer("test", "lb", attrs, with("8443"), 1)
	if err == nil {
		t.Fatal("a string operand built a listener silently on the DEFAULT port — " +
			"the two candidates hash identically, so the ledger cannot tell which " +
			"front door was built")
	}
	if !strings.Contains(err.Error(), "port") {
		t.Errorf("the refusal does not name the operand: %v", err)
	}

	// The control: an ABSENT operand must still take the default, or every
	// candidate that omits an optional operand starts failing.
	def, err := BuildLoadBalancer("test", "lb", attrs, with(nil), 1)
	if err != nil {
		t.Fatalf("an absent operand must keep its default: %v", err)
	}
	if def.Port != 443 {
		t.Errorf("the HTTPS default moved: port = %d, want 443", def.Port)
	}
}
