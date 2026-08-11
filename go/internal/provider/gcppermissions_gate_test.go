package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D889. A GCP compute IAM permission is `compute.<resource>.create`, even though the REST
// method that creates the resource is `insert`. The vpngateway driver declared
// `compute.vpnGateways.insert` — the REST method name, which is NOT an IAM permission — so
// projects.testIamPermissions 400'd "not valid for this resource", poisoned the WHOLE
// preflight call, and converge refused `preflight-inconclusive`: the gateway could never be
// created. No machine-readable GCP permission index is fetched (unlike the AWS Service
// Reference), so this gate pins the one mechanical rule that catches the whole class from
// the source: no declared compute permission may end in `.insert`.
func TestNoGCPComputePermissionUsesTheRESTInsertName(t *testing.T) {
	root := repoRoot(t)
	src, err := os.ReadFile(filepath.Join(root, "go", "internal", "provider", "provider.go"))
	if err != nil {
		t.Fatalf("read provider.go: %v", err)
	}
	// Every compute permission literal the file declares.
	perms := regexp.MustCompile(`"compute\.[a-zA-Z]+\.[a-zA-Z]+"`).
		FindAllString(string(src), -1)
	if len(perms) < 20 {
		t.Fatalf("only %d compute permission literals found — the extraction stopped matching "+
			"its subject", len(perms))
	}
	var bad []string
	for _, p := range perms {
		if strings.HasSuffix(strings.Trim(p, `"`), ".insert") {
			bad = append(bad, p)
		}
	}
	if len(bad) > 0 {
		t.Errorf("%d GCP compute permission(s) use the REST method name `.insert` instead of the "+
			"IAM permission `.create`: %v — projects.testIamPermissions 400s on these and poisons "+
			"the whole preflight, so converge refuses preflight-inconclusive and the resource can "+
			"never be created (D889)", len(bad), bad)
	}
}
