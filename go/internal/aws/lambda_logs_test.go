package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D381. The conformance case pins the compile-time WIRING (the declared output
// exists, the reference type-checks). It cannot pin the VALUE — gutting the
// resolver leaves it green, which I confirmed by doing exactly that. So the value
// is pinned here, where it can be.
//
// The stakes are the reason: this string is what a retention guarantee lands on.
// A wrong one silently sets 365-day retention on a group nobody writes to, while
// the group that holds the logs keeps them forever — which is what a field
// partner shipped, believing the contract.
func TestLambdaLogGroupNameIsTheGroupAWSCreates(t *testing.T) {
	// AWS fixes this shape; it is not a groundhold naming choice.
	if got := lambdaLogGroupName("pv-api-prod-1a2b3c4d"); got != "/aws/lambda/pv-api-prod-1a2b3c4d" {
		t.Errorf("lambdaLogGroupName = %q, want the /aws/lambda/<fn> group AWS creates", got)
	}
}

// D1031. observeLambda witnesses the retention on the function's DEFAULT log group
// (/aws/lambda/<fn>) — the group the function's own logs land in. A real retention
// reads MEASURED; a never-expires group and a not-yet-created group both stay
// UNMEASURED (a hard constraint blocks as unknown, never a false satisfied over the
// group that actually holds the data — the field GDPR finding). The never-expires
// case mirrors observeCWLogs exactly (a witness cannot fake a finite duration for
// unbounded retention), so the compute witness and a bound monitoring.logs never
// disagree.
func TestObserveLambdaDefaultLogGroupRetention(t *testing.T) {
	cases := []struct {
		name     string
		logsResp string // DescribeLogGroups body
		wantVal  any    // nil = expect NO defaultLogGroup.retention observation
		wantDiag string // required diagnostic substring when unmeasured
	}{
		{"retention set is measured",
			`{"logGroups":[{"logGroupName":"/aws/lambda/api-abcdefgh","retentionInDays":30}]}`,
			"720h", ""},
		{"never-expires is unknown, not a faked duration",
			`{"logGroups":[{"logGroupName":"/aws/lambda/api-abcdefgh"}]}`,
			nil, "never-expires"},
		{"group not created yet is unknown",
			`{"logGroups":[]}`,
			nil, "does not exist yet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &lambdaFake{t: t, readyState: "Active", created: true}
			srv := httptest.NewServer(f.handler())
			defer srv.Close()
			logsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.logsResp))
			}))
			defer logsSrv.Close()
			d := lambdaDriver(t, srv)
			d.LogsBaseURL = logsSrv.URL // the case's own retention response

			pid := lambdaProviderID("eu-central-1", "000000000000", "api-abcdefgh")
			obs, diags, err := d.observeLambda("api", pid)
			if err != nil {
				t.Fatal(err)
			}
			var got any
			for _, o := range obs {
				if o.Path == "defaultLogGroup.retention" {
					got = o.Value
				}
			}
			if tc.wantVal == nil {
				if got != nil {
					t.Fatalf("unbounded/absent retention must NOT emit a duration, got %v", got)
				}
				if !strings.Contains(strings.Join(diags, " "), tc.wantDiag) {
					t.Fatalf("expected a diagnostic mentioning %q, got %v", tc.wantDiag, diags)
				}
			} else {
				if got != tc.wantVal {
					t.Fatalf("defaultLogGroup.retention = %v, want %v", got, tc.wantVal)
				}
			}
		})
	}
}
