package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// lambdaClaimFake is a stateful stub for the adopt->claim->use loop (the Acme field
// gap: a brownfield function that could neither be updated nor have its resource
// policy touched until claim was wired). It serves GetFunction (with a MUTABLE tag
// map so a claim's RGT stamp becomes visible to a subsequent update), the additive
// Resource Groups Tagging API TagResources, UpdateFunctionConfiguration and the
// CloudFront-invoke AddPermission. arn is the identity GetFunction reports (drive the
// foreign-function guard by returning a mismatching one).
type lambdaClaimFake struct {
	arn        string
	notFound   bool
	mu         sync.Mutex
	tags       map[string]string // current ownership tags (RGT stamp merges into this)
	rgtBody    string            // last RGT TagResources body (empty => never called)
	sawAddPerm bool
}

func (f *lambdaClaimFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = io.ReadFull(r.Body, body)
		// Resource Groups Tagging API (the additive ownership stamp) — routed by target.
		if strings.Contains(r.Header.Get("X-Amz-Target"), "TagResources") {
			var req struct {
				ARNs []string          `json:"ResourceARNList"`
				Tags map[string]string `json:"Tags"`
			}
			_ = json.Unmarshal(body, &req)
			f.mu.Lock()
			f.rgtBody = string(body)
			for k, v := range req.Tags {
				f.tags[k] = v // additive merge, exactly like the real RGT
			}
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"FailedResourcesMap":{}}`))
			return
		}
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/2015-03-31/functions/"):
			if f.notFound {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"Message":"Function not found"}`))
				return
			}
			f.mu.Lock()
			tags, _ := json.Marshal(f.tags)
			f.mu.Unlock()
			_, _ = w.Write([]byte(`{"Configuration":{"State":"Active","Timeout":300,` +
				`"LastUpdateStatus":"Successful","FunctionArn":"` + f.arn + `"},"Tags":` + string(tags) + `}`))
		case r.Method == "PUT" && strings.HasSuffix(r.URL.Path, "/configuration"):
			_, _ = w.Write([]byte(`{"LastUpdateStatus":"Successful"}`)) // UpdateFunctionConfiguration
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/policy"):
			f.mu.Lock()
			f.sawAddPerm = true
			f.mu.Unlock()
			w.WriteHeader(http.StatusCreated) // AddPermission (the CDN/OAC invoke grant)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func lambdaClaimDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.Account = "000000000000"
	d.LambdaBaseURL = srv.URL
	d.RGTBaseURL = srv.URL // both surfaces answered by the one stateful stub
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

const claimLambdaName = "web-prod-xxx"

func claimLambdaPID() string {
	return lambdaProviderID("eu-central-1", "000000000000", claimLambdaName)
}
func claimLambdaARN() string { return lambdaArn("eu-central-1", "000000000000", claimLambdaName) }

// TestClaimLambdaStampsOwnershipThenUpdatable proves the full field loop: an adopted
// function (an operator tag, NO groundhold tags — the realistic pre-claim state) is
// claimed by STAMPING the ownership tags via the additive RGT path, flips to owned,
// and a SUBSEQUENT update-in-place + AddPermission then succeed on the claimed
// function (no delete+recreate). Before the fix, converge died on the unwired claim.
func TestClaimLambdaStampsOwnershipThenUpdatable(t *testing.T) {
	f := &lambdaClaimFake{arn: claimLambdaARN(),
		tags: map[string]string{"team": "ops"}} // adopted: operator tag only
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaClaimDriver(t, srv)

	pid := claimLambdaPID()
	cr := d.Claim("lambda", "web", "prod", pid)
	if cr.Status != "succeeded" {
		t.Fatalf("lambda claim must succeed, got %+v", cr)
	}
	if cr.ProviderID != pid {
		t.Fatalf("claim must carry the providerId, got %q", cr.ProviderID)
	}
	if f.rgtBody == "" {
		t.Fatal("claim must issue an RGT TagResources request")
	}
	for _, want := range []string{
		`"groundhold-capability":"web"`, `"groundhold-environment":"prod"`,
		"ResourceARNList", claimLambdaARN(),
	} {
		if !strings.Contains(f.rgtBody, want) {
			t.Errorf("RGT tag body missing %q\nbody: %s", want, f.rgtBody)
		}
	}
	// the operator's tag survives the additive stamp
	if f.tags["team"] != "ops" {
		t.Errorf("claim clobbered the operator's tags: %v", f.tags)
	}
	// takeover is real: a now-owned function accepts an update-in-place (was refused
	// "not ours" before the claim stamped the tags).
	ur := d.updateLambda("web", "prod", pid,
		map[string]any{"location.region": "eu-central-1", "timeout.maximum": "60s"},
		map[string]any{"image_uri": "111111111111.dkr.ecr.eu-central-1.amazonaws.com/web:v2",
			"role_arn": "arn:aws:iam::000000000000:role/web-exec"},
		[]string{"timeout.maximum"})
	if ur.Status != "succeeded" {
		t.Fatalf("update on the claimed function must succeed, got %+v", ur)
	}
	// and the CDN/OAC invoke grant (AddPermission) lands on the claimed function.
	if r := d.grantCloudFrontInvoke(claimLambdaARN(), "E123", "arn:aws:cloudfront::000000000000:distribution/E123", pid); r != nil {
		t.Fatalf("AddPermission on the claimed function must succeed, got %+v", *r)
	}
	if !f.sawAddPerm {
		t.Fatal("the invoke grant must reach AddPermission")
	}
}

// TestClaimLambdaAlreadyOwnedIdempotent: a function already carrying groundhold's tags
// is an idempotent success with NO re-write (Claim is idempotent by contract).
func TestClaimLambdaAlreadyOwnedIdempotent(t *testing.T) {
	f := &lambdaClaimFake{arn: claimLambdaARN(),
		tags: map[string]string{"groundhold-capability": "web", "groundhold-environment": "prod"}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaClaimDriver(t, srv)

	cr := d.Claim("lambda", "web", "prod", claimLambdaPID())
	if cr.Status != "succeeded" || cr.ProviderID != claimLambdaPID() {
		t.Fatalf("an already-owned function must be an idempotent success, got %+v", cr)
	}
	if f.rgtBody != "" {
		t.Fatalf("an already-owned function must not be re-tagged: %s", f.rgtBody)
	}
}

// TestClaimLambdaForeignFunctionRefuses: the name resolves to a DIFFERENT function
// (a foreign resource in the acting account) — the identity guard refuses (failed)
// and never stamps ownership onto someone else's function.
func TestClaimLambdaForeignFunctionRefuses(t *testing.T) {
	f := &lambdaClaimFake{
		arn:  "arn:aws:lambda:eu-central-1:999999999999:function:" + claimLambdaName, // foreign account
		tags: map[string]string{"team": "ops"}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaClaimDriver(t, srv)

	cr := d.Claim("lambda", "web", "prod", claimLambdaPID())
	if cr.Status != "failed" {
		t.Fatalf("a foreign function must refuse the claim, got %+v", cr)
	}
	if !strings.Contains(cr.Reason, "foreign function") {
		t.Fatalf("the refusal must name the identity mismatch: %q", cr.Reason)
	}
	if f.rgtBody != "" {
		t.Fatalf("a foreign function must not be tagged: %s", f.rgtBody)
	}
}

// TestClaimLambdaVanishedFails: a claim on a function that is gone fails cleanly and
// never issues a tag request (never a fabricated success).
func TestClaimLambdaVanishedFails(t *testing.T) {
	f := &lambdaClaimFake{notFound: true, tags: map[string]string{}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	d := lambdaClaimDriver(t, srv)

	cr := d.Claim("lambda", "web", "prod", claimLambdaPID())
	if cr.Status != "failed" {
		t.Fatalf("a vanished function must fail the claim, got %+v", cr)
	}
	if f.rgtBody != "" {
		t.Fatalf("a vanished function must not be tagged: %s", f.rgtBody)
	}
}
