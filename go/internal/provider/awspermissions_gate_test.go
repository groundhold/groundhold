package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestEveryAWSPermissionDeclaredIsOneAWSPublishes confronts the permission tables with
// AWS's own machine-readable Service Reference (D846).
//
// These strings are not internal. They are sealed into the plan as `requiredPermissions`,
// they are what an operator writes an IAM policy FROM, and apply SIMULATES them through
// iam:SimulatePrincipalPolicy before taking the lease. A name that is not an action cannot
// be granted, so the operator either cannot satisfy the preflight or grants a string that
// authorizes nothing and is denied mid-apply.
//
// The tables were written by naming each service's API operation, which is right for
// almost every AWS service. It is wrong for the ones whose IAM model is not
// operation-named: API Gateway authorizes by HTTP VERB (`apigateway:GET`, `apigateway:PUT`),
// so `apigateway:TagResource` sat in the claim table looking exactly like `sqs:TagQueue`
// and `ecr:TagResource` on either side of it.
func TestEveryAWSPermissionDeclaredIsOneAWSPublishes(t *testing.T) {
	root := repoRoot(t)

	// Exceptions carry a reason, and a stale one fails: an exemption nobody needs covers
	// the next permission that lands on it (the D803 allowlist did exactly that).
	exempt := map[string]string{}

	have := map[string]map[string]bool{}
	blob, err := os.ReadFile(filepath.Join("testdata", "aws_iam_actions.verified"))
	if err != nil {
		t.Fatalf("read verified actions: %v", err)
	}
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			t.Fatalf("verified action line is not service|actions: %q", line)
		}
		set := map[string]bool{}
		for _, a := range strings.Fields(parts[1]) {
			set[a] = true
		}
		have[parts[0]] = set
	}

	src, err := os.ReadFile(filepath.Join(root, "go", "internal", "provider", "provider.go"))
	if err != nil {
		t.Fatalf("read provider.go: %v", err)
	}
	// The AWS permission shape is `service:Action`. GCP (`cloudsql.instances.get`) and
	// Azure (`Microsoft.Sql/servers/read`) cannot match it, so one pass is enough.
	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([a-z0-9-]{2,20}):([A-Z][A-Za-z0-9]{2,60})"`).
		FindAllStringSubmatch(string(src), -1) {
		declared[m[1]+":"+m[2]] = true
	}

	// D328: assert the subject before reporting on it. Either side going thin would make
	// this print a clean sweep over nothing.
	if len(have) < 35 {
		t.Fatalf("only %d services in the verified file — the action index went thin; refresh "+
			"it with scripts/refresh-aws-actions.sh", len(have))
	}
	if len(declared) < 300 {
		t.Fatalf("only %d AWS permissions found in provider.go — the extraction stopped "+
			"matching its subject", len(declared))
	}

	var bad, unlisted []string
	for p := range declared {
		if _, ok := exempt[p]; ok {
			continue
		}
		service, action, _ := strings.Cut(p, ":")
		set, ok := have[service]
		if !ok {
			unlisted = append(unlisted, p)
			continue
		}
		if !set[action] {
			bad = append(bad, p)
		}
	}
	sort.Strings(bad)
	sort.Strings(unlisted)

	if len(bad) > 0 {
		t.Errorf("%d declared permission(s) are not actions AWS publishes:\n  %s\n\n"+
			"A name that is not an action cannot be granted: the operator writes the policy "+
			"this list dictates and is denied anyway. Check the service's action list in "+
			"testdata/aws_iam_actions.verified — some services (API Gateway) authorize by "+
			"HTTP verb rather than by operation name (D846).",
			len(bad), strings.Join(bad, "\n  "))
	}
	if len(unlisted) > 0 {
		t.Errorf("%d permission(s) name a service with no verified action list:\n  %s\n\n"+
			"Run scripts/refresh-aws-actions.sh so the new service is covered — an "+
			"unverified service is an unchecked claim.",
			len(unlisted), strings.Join(unlisted, "\n  "))
	}
	for p, reason := range exempt {
		if !declared[p] {
			t.Errorf("exception %q (%s) covers a permission nothing declares any more — drop it", p, reason)
		}
	}
}
