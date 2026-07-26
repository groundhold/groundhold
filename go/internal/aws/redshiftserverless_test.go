package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func rssAttrs() map[string]any {
	return map[string]any{
		"location.region":        "eu-central-1",
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

// rssAction returns the JSON-protocol action from the X-Amz-Target header.
func rssAction(r *http.Request) string {
	t := r.Header.Get("X-Amz-Target")
	return t[strings.LastIndex(t, ".")+1:]
}

func TestBuildRedshiftServerlessHonors(t *testing.T) {
	p, err := BuildRedshiftServerless("prod", "lake", rssAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !rssNameOK.MatchString(p.Name) || !strings.HasPrefix(p.Name, "lake-prod-") {
		t.Fatalf("name = %q", p.Name)
	}
	// no admin credentials must ever appear in the create bodies (D53).
	nb := p.namespaceBody("lake", "prod")
	if _, has := nb["adminUsername"]; has {
		t.Fatal("namespace body must not carry admin credentials (D53)")
	}
	if _, has := nb["adminUserPassword"]; has {
		t.Fatal("namespace body must not carry an admin password (D53)")
	}
	wb := p.workgroupBody("lake", "prod")
	if wb["publiclyAccessible"] != false {
		t.Fatalf("workgroup body = %+v", wb)
	}
}

func TestBuildRedshiftServerlessCMKRequiresKey(t *testing.T) {
	a := rssAttrs()
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildRedshiftServerless("prod", "lake", a, nil, 1); err == nil {
		t.Fatal("cmk without impl.kms_key_id must refuse")
	}
	p, err := BuildRedshiftServerless("prod", "lake", a, map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:0:key/k"}, 1)
	if err != nil || p.KmsKeyID == "" {
		t.Fatalf("cmk with key: %+v err=%v", p, err)
	}
}

func TestBuildRedshiftServerlessRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"no-at-rest":   {"encryption.atRest": false},
		"unmanaged":    {"service.managed": false},
		"unknown-attr": {"warehouse.tier": "x"},
		"bad-region":   {"location.region": "not-a-region"},
	}
	for name, extra := range cases {
		a := rssAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildRedshiftServerless("prod", "lake", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

// rssServer is a happy JSON-protocol double. GetWorkgroup reports AVAILABLE so create
// polls once and succeeds; ListTagsForResource reflects the owner tags.
func rssServer(t *testing.T, capLabel string, public bool) *httptest.Server {
	t.Helper()
	pub := "false"
	if public {
		pub = "true"
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch rssAction(r) {
			case "CreateNamespace":
				_, _ = w.Write([]byte(`{"namespace":{"namespaceName":"n","namespaceArn":"arn:ns","status":"AVAILABLE"}}`))
			case "CreateWorkgroup":
				_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"w","workgroupArn":"arn:wg","status":"CREATING","publiclyAccessible":` + pub + `}}`))
			case "GetWorkgroup":
				_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"w","workgroupArn":"arn:wg","namespaceName":"n","status":"AVAILABLE","publiclyAccessible":` + pub + `}}`))
			case "GetNamespace":
				_, _ = w.Write([]byte(`{"namespace":{"namespaceName":"n","namespaceArn":"arn:ns","status":"AVAILABLE","kmsKeyId":"AWS_OWNED_KMS_KEY"}}`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":[{"key":"groundhold-capability","value":"` + capLabel +
					`"},{"key":"groundhold-environment","value":"prod"}]}`))
			case "DeleteWorkgroup", "DeleteNamespace":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func rssDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.RedshiftServerlessBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteRedshiftServerless(t *testing.T) {
	srv := rssServer(t, "lake", false)
	defer srv.Close()
	d := rssDriver(t, srv)
	res := d.Create("redshiftserverless", "lake", "prod", rssAttrs(), nil, "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "rss:eu-central-1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeRedshiftServerless("lake", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["network.publicExposure"] != false || got["encryption.atRest"] != true ||
		got["service.managed"] != true || got["location.region"] != "eu-central-1" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("redshiftserverless", "lake", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteRedshiftServerlessForeignRefused(t *testing.T) {
	srv := rssServer(t, "someone-else", false)
	defer srv.Close()
	d := rssDriver(t, srv)
	pid := rssProviderID("eu-central-1", RSSName("prod", "lake", 1))
	res := d.Delete("redshiftserverless", "lake", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign workgroup must refuse delete, got %+v", res)
	}
}

func TestHonestyHarnessRedshiftServerless(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := rssProviderID("eu-central-1", RSSName("prod", "lake", 1))
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "aws/redshiftserverless",
		AssertTransient: true,           // D237: create/delete route through provider.MutationResult
		Classify:        jsonTargetRole, // Create*/Delete* opaque; Get*/List* reads
		OwnerTagValue:   "lake",
		DeterministicID: true, // the namespace/workgroup names are chosen
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return rssServer(t, "lake", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("redshiftserverless", "lake", "prod", rssAttrs(), nil, "k", 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return rssServer(t, "lake", false) },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("redshiftserverless", "lake", "prod", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}
