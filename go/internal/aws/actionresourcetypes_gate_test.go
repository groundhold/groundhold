package aws

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// D886. The resource preflight judges an action's implicitDeny authoritatively against a
// resource ARN ONLY when the ARN's type is in that action's resource-type set
// (awsActionResourceTypes). The one way that map can HARM is a FALSE match — a type the
// action does NOT actually support, kept authoritative, re-introducing the cross-type
// false refusal. So this gate confronts every (action, type) the runtime map ASSERTS with
// AWS's own authority, the Service Reference, captured in aws_action_resourcetypes.verified
// (scripts/refresh-aws-action-resourcetypes.sh, fetched without credentials). It does NOT
// require the map to be COMPLETE — an omitted action yields no match and routes to the safe
// account "*" check — only that it never claims a scoping AWS does not publish.
func TestEveryAWSActionResourceTypeIsOnePublished(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("..", "provider", "testdata", "aws_action_resourcetypes.verified"))
	if err != nil {
		t.Fatalf("read verified action resource-types: %v — refresh with "+
			"scripts/refresh-aws-action-resourcetypes.sh", err)
	}
	have := map[string]map[string]bool{}
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) < 2 {
			t.Fatalf("verified line is not service<TAB>action<TAB>types: %q", line)
		}
		action := parts[0] + ":" + parts[1]
		set := map[string]bool{}
		if len(parts) == 3 {
			for _, ty := range strings.Fields(parts[2]) {
				set[ty] = true
			}
		}
		have[action] = set
	}

	// D328: assert the subject before reporting a clean sweep over nothing.
	if len(have) < 200 {
		t.Fatalf("only %d actions in the verified file — the Service-Reference fetch went thin; "+
			"refresh with scripts/refresh-aws-action-resourcetypes.sh", len(have))
	}
	if len(awsActionResourceTypes) < 20 {
		t.Fatalf("only %d actions in awsActionResourceTypes — the runtime map went thin", len(awsActionResourceTypes))
	}

	var falseMatch, unlisted []string
	for action, types := range awsActionResourceTypes {
		published, ok := have[action]
		if !ok {
			unlisted = append(unlisted, action)
			continue
		}
		for _, ty := range types {
			if !published[ty] {
				falseMatch = append(falseMatch, action+" -> "+ty)
			}
		}
	}
	if len(falseMatch) > 0 {
		t.Errorf("%d action/type pair(s) the runtime map asserts that AWS does not publish "+
			"(a false match keeps a cross-type action authoritative and re-opens the D886 false "+
			"refusal): %v", len(falseMatch), falseMatch)
	}
	if len(unlisted) > 0 {
		t.Errorf("%d action(s) in the runtime map are not in the Service-Reference file at all: %v "+
			"— an action that authorizes a real mutation must exist in AWS's published set", len(unlisted), unlisted)
	}
}
