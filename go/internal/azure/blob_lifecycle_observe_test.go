package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D471: retention.maximum was written by createBlob and never read back, while the S3
// twin has always read its lifecycle Expiration rule.

func lifecycleServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "managementPolicies") {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func lifecycleDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	return d
}

const ourLifecycle = `{"properties":{"policy":{"rules":[{"name":"groundhold-retention-maximum",` +
	`"enabled":true,"type":"Lifecycle","definition":{"filters":{"prefixMatch":["assets/"]},` +
	`"actions":{"baseBlob":{"delete":{"daysAfterModificationGreaterThan":365}}}}}]}}}`

func TestObserveBlobLifecycleMeasuresRetentionMaximum(t *testing.T) {
	d := lifecycleDriver(t, lifecycleServer(t, 200, ourLifecycle))
	obs, diags := d.observeBlobLifecycle("rg1", "acct", "assets")
	if len(obs) != 1 || obs[0].Path != "retention.maximum" || obs[0].Value != "365d" {
		t.Fatalf("want retention.maximum=365d measured, got %+v (diags %v)", obs, diags)
	}
	if obs[0].Derivation != "measured" {
		t.Errorf("a value read off the estate is measured, got %q", obs[0].Derivation)
	}
}

// A rule that is not ours must not be attributed to this capability: an account-level
// policy can carry rules nobody here wrote, and measuring the wrong thing is worse than
// measuring nothing.
func TestObserveBlobLifecycleIgnoresForeignRules(t *testing.T) {
	foreign := strings.Replace(ourLifecycle, "groundhold-retention-maximum", "finance-archive", 1)
	d := lifecycleDriver(t, lifecycleServer(t, 200, foreign))
	if obs, _ := d.observeBlobLifecycle("rg1", "acct", "assets"); len(obs) != 0 {
		t.Fatalf("a foreign lifecycle rule must not become our observation: %+v", obs)
	}
}

// Our rule name on ANOTHER container's prefix is equally not ours.
func TestObserveBlobLifecycleIgnoresOtherContainers(t *testing.T) {
	other := strings.Replace(ourLifecycle, `"assets/"`, `"logs/"`, 1)
	d := lifecycleDriver(t, lifecycleServer(t, 200, other))
	if obs, _ := d.observeBlobLifecycle("rg1", "acct", "assets"); len(obs) != 0 {
		t.Fatalf("a rule filtered on another container must not be ours: %+v", obs)
	}
}

func TestObserveBlobLifecycleAbsentIsNotAnError(t *testing.T) {
	d := lifecycleDriver(t, lifecycleServer(t, 404, `{"error":{"code":"NotFound"}}`))
	obs, diags := d.observeBlobLifecycle("rg1", "acct", "assets")
	if len(obs) != 0 || len(diags) != 0 {
		t.Fatalf("no policy means the path is simply absent: obs=%+v diags=%v", obs, diags)
	}
}

func TestObserveBlobLifecycleUnreadableNamesItsCause(t *testing.T) {
	d := lifecycleDriver(t, lifecycleServer(t, 500, `{"error":{"code":"InternalError"}}`))
	_, diags := d.observeBlobLifecycle("rg1", "acct", "assets")
	if len(diags) != 1 || !strings.Contains(diags[0], "managementPolicies.get") {
		t.Fatalf("an unreadable policy must name its cause (D306): %v", diags)
	}
}
