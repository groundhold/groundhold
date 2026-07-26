package aws

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/apireq"
)

// apireq_guard_test.go is the durable regression guard for the apireq registry's
// AWS entry (D329). Where cdn_oac_test.go pins the whole CloudFront+OAC edge flow,
// this test binds the ONE catalogued requirement — a post-~2025-10 Function URL
// needs BOTH lambda:InvokeFunctionUrl AND lambda:InvokeFunction — straight to the
// driver seam that must honour it, grantCloudFrontInvoke. Dropping InvokeFunction
// (or the cloudfront principal, or the SourceArn scope) fails HERE, and the
// failure cites the registry entry so an operator knows it is a known AWS
// requirement, not an arbitrary assertion.
func TestApireqGuardCloudFrontOACDualInvoke(t *testing.T) {
	req, ok := apireq.Get(apireq.GuardCloudFrontOACDualInvoke)
	if !ok {
		t.Fatalf("apireq registry is missing entry %q — the guard has nothing to enforce",
			apireq.GuardCloudFrontOACDualInvoke)
	}
	cite := func(format string, args ...any) string {
		return "apireq guard " + req.GuardID + " (known " + req.Provider + " requirement since " +
			req.SinceDate + ", see " + strings.Join(req.SourceURL, " , ") + "): " +
			fmt.Sprintf(format, args...)
	}

	const (
		lambdaARN = "arn:aws:lambda:eu-central-1:000000000000:function:pv-api-prod-1a2b3c4d"
		distID    = "E1234567890ABC"
		sourceArn = "arn:aws:cloudfront::000000000000:distribution/E1234567890ABC"
	)

	var grants []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/policy") {
			b, _ := io.ReadAll(r.Body)
			g := map[string]any{}
			_ = json.Unmarshal(b, &g)
			grants = append(grants, g)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Statement":"{}"}`))
			return
		}
		t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("us-east-1")
	d.Account = "000000000000"
	d.LambdaBaseURL = srv.URL
	d.Now = time.Now

	if res := d.grantCloudFrontInvoke(lambdaARN, distID, sourceArn, "pid"); res != nil {
		t.Fatal(cite("grantCloudFrontInvoke did not succeed: %+v", res))
	}

	// Both actions must have been granted.
	byAction := map[string]map[string]any{}
	for _, g := range grants {
		action, _ := g["Action"].(string)
		byAction[action] = g
		if g["Principal"] != "cloudfront.amazonaws.com" {
			t.Error(cite("grant for %s has principal %v, want cloudfront.amazonaws.com", action, g["Principal"]))
		}
		if g["SourceArn"] != sourceArn {
			t.Error(cite("grant for %s has SourceArn %v, want %s (least-privilege scope)", action, g["SourceArn"], sourceArn))
		}
	}
	if _, has := byAction["lambda:InvokeFunctionUrl"]; !has {
		t.Error(cite("grant is missing lambda:InvokeFunctionUrl; emitted actions: %v", actionsOf(grants)))
	}
	if _, has := byAction["lambda:InvokeFunction"]; !has {
		// THE regression this guard exists to catch: the requirement says BOTH.
		t.Error(cite("grant is missing lambda:InvokeFunction — a post-~2025-10 Function URL "+
			"refuses CloudFront with InvokeFunctionUrl alone; emitted actions: %v", actionsOf(grants)))
	}
}

func actionsOf(grants []map[string]any) []string {
	var out []string
	for _, g := range grants {
		if a, ok := g["Action"].(string); ok {
			out = append(out, a)
		}
	}
	return out
}
