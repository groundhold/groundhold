package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// D749, from the field. `network.publicExposure` was MEASURED under the vocabulary's
// definition ("invokable over public HTTPS by ANYONE" — AuthType NONE plus an anonymous
// invoke grant, both or private) and VALIDATED under another one ("has a Function URL").
// The edge pattern sits exactly between them: a Function URL with AuthType AWS_IAM,
// reachable only by a SigV4-signed CloudFront OAC, is NOT public exposure.
//
// The reporter's measurement: declaring the truth (`false`) had the capability REFUSED
// and dropped from the plan, and the only declaration that passed validation (`true`)
// made every plan want to change false -> true — that is, to ADD an anonymous invoke
// grant to a function deliberately protected by IAM, asking for --allow-exposure. Their
// words: "nie ma deklaracji, przy której ta zdolność się zbiega".
//
// These tests assert the CALLS the driver makes, not the shape of the plan struct: the
// question is whether an anonymous grant reaches AWS, and only the request log answers
// that. D726's lesson — a test that re-computes the driver's own expression is green by
// construction.
type urlCallLog struct {
	mu        sync.Mutex
	authTypes []string // AuthType of each CreateFunctionUrlConfig
	grants    int      // POSTs to .../policy — the anonymous invoke grant
}

func (l *urlCallLog) fake(t *testing.T) *httptest.Server {
	t.Helper()
	created := false
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "POST" && strings.HasSuffix(p, "/url"):
			body, _ := io.ReadAll(r.Body)
			var doc struct{ AuthType string }
			_ = json.Unmarshal(body, &doc)
			l.mu.Lock()
			l.authTypes = append(l.authTypes, doc.AuthType)
			l.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"FunctionUrl":"https://abc.lambda-url.eu-central-1.on.aws/","AuthType":"` +
				doc.AuthType + `"}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/policy"):
			l.mu.Lock()
			l.grants++
			l.mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Statement":"{}"}`))
		case r.Method == "POST" && strings.HasSuffix(p, "/functions"):
			created = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"FunctionName":"fn","State":"Pending"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/policy"):
			_, _ = w.Write([]byte(`{"Policy":"{\"Version\":\"2012-10-17\",\"Statement\":[]}"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/url"):
			_, _ = w.Write([]byte(`{"AuthType":"AWS_IAM","FunctionUrl":"https://abc.lambda-url.eu-central-1.on.aws/"}`))
		case r.Method == "GET" && strings.Contains(p, "/functions/"):
			if !created {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Function not found"}`))
				return
			}
			_, _ = w.Write([]byte(`{"Configuration":{"State":"Active","Timeout":300},` +
				`"Tags":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// The reporter's exact case: an edge function, declared honestly.
func TestEdgeFunctionURLIsBuiltWithoutAnAnonymousGrant(t *testing.T) {
	log := &urlCallLog{}
	srv := log.fake(t)
	defer srv.Close()
	d := lambdaDriver(t, srv)

	attrs := lambdaAttrs()
	attrs["network.publicExposure"] = false // the truth: nobody can call it unsigned
	impl := lambdaImpl()
	impl["url_auth"] = "iam"

	res := d.createLambda("eu-central-1", "000000000000", "prod", "api", attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("an AWS_IAM Function URL on a non-public function must be buildable, got %+v — "+
			"this is the declaration the field could not make (D749)", res)
	}
	if len(log.authTypes) != 1 || log.authTypes[0] != "AWS_IAM" {
		t.Fatalf("CreateFunctionUrlConfig AuthTypes = %v, want exactly one AWS_IAM", log.authTypes)
	}
	if log.grants != 0 {
		t.Fatalf("%d anonymous invoke grant(s) were added to an edge function — the whole "+
			"point of AWS_IAM is that CloudFront signs the request and nothing is granted "+
			"to principal * (D749)", log.grants)
	}
}

// Each accepted declaration converges, and each refusal names a real contradiction
// rather than a difference of definition.
func TestFunctionURLDeclarationsThatContradictAreRefused(t *testing.T) {
	cases := []struct {
		name     string
		exposure bool
		urlAuth  any // nil => the operand is absent
		wantErr  string
	}{
		{"iam with public exposure cannot converge", true, "iam",
			"carries no anonymous invoke grant"},
		{"an explicit anonymous URL on a private function", false, "none",
			"is anonymous by definition"},
		{"iam on a private function is the edge pattern", false, "iam", ""},
		{"an anonymous URL on a public function", true, "none", ""},
		{"no url_auth, public", true, nil, ""},
		{"no url_auth, private — silence is not a contradiction", false, nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			attrs := lambdaAttrs()
			attrs["network.publicExposure"] = c.exposure
			impl := lambdaImpl()
			if c.urlAuth != nil {
				impl["url_auth"] = c.urlAuth
			}
			p, err := BuildLambda("000000000000", "prod", "api", attrs, impl, 1)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("refused a declaration that describes a real, reachable state: %v", err)
			case c.wantErr != "" && err == nil:
				t.Fatalf("accepted url_auth=%v with publicExposure=%v — one of the two is "+
					"false about the estate and the capability can never converge", c.urlAuth, c.exposure)
			case c.wantErr != "" && !strings.Contains(err.Error(), c.wantErr):
				t.Fatalf("refusal must name the contradiction (%q), got: %v", c.wantErr, err)
			}
			if err == nil {
				// A URL exists whenever either declaration calls for one.
				want := c.exposure || c.urlAuth == "iam"
				if p.wantsFunctionURL() != want {
					t.Fatalf("wantsFunctionURL = %v, want %v", p.wantsFunctionURL(), want)
				}
			}
		})
	}
}

// A private function with no url_auth gets NO Function URL — the operand's absence is
// silence, and silence must not conjure an endpoint.
func TestPrivateFunctionGetsNoURLAtAll(t *testing.T) {
	log := &urlCallLog{}
	srv := log.fake(t)
	defer srv.Close()
	d := lambdaDriver(t, srv)

	attrs := lambdaAttrs()
	attrs["network.publicExposure"] = false

	res := d.createLambda("eu-central-1", "000000000000", "prod", "api", attrs, lambdaImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if len(log.authTypes) != 0 || log.grants != 0 {
		t.Fatalf("a private function got %d Function URL(s) and %d grant(s)", len(log.authTypes), log.grants)
	}
}

// D774, from the field, marked BLOKADA: four ZIP-packaged functions — bound, converged,
// untouched by the plan — blocked the plan of 43 capabilities, 39 of them nothing to do
// with Lambda. The operand-drift step derives the DESIRED shape through BuildLambda, and
// BuildLambda refuses without `image_uri` because a CREATE needs one.
//
// A create requirement is not a drift requirement.
func TestOperandTargetsDoNotDemandACreateOperand(t *testing.T) {
	d := NewDriver("eu-central-1") // OperandTargets is pure — no server needed
	zip := map[string]any{"role_arn": "arn:aws:iam::123456789012:role/fn-exec"}

	targets, err := d.OperandTargets("lambda", lambdaAttrs(), zip)
	if err != nil {
		t.Fatalf("a bound function with no image_uri must still yield drift targets: %v — "+
			"this refusal blocked 43 capabilities in the field (D774)", err)
	}
	got := map[string]bool{}
	for _, tg := range targets {
		got[tg.Path] = true
	}
	if got[lambdaPkgOperand] {
		t.Error("a package target was derived from a placeholder image — the driver cannot " +
			"state a desired package it was never given, and inventing one would drift " +
			"against the real image forever")
	}
	for _, want := range []string{lambdaEnvOperand, lambdaRoleOperand, lambdaVpcOperand} {
		if !got[want] {
			t.Errorf("%s target dropped — the operands the driver DOES govern must keep "+
				"drifting-detection alive", want)
		}
	}

	// The control: with an image, the package target is still derived.
	full := map[string]any{"role_arn": "arn:aws:iam::123456789012:role/fn-exec",
		"image_uri": "123456789012.dkr.ecr.eu-central-1.amazonaws.com/fn:sha"}
	targets, err = d.OperandTargets("lambda", lambdaAttrs(), full)
	if err != nil {
		t.Fatal(err)
	}
	pkg := false
	for _, tg := range targets {
		if tg.Path == lambdaPkgOperand {
			pkg = true
		}
	}
	if !pkg {
		t.Fatal("an image-packaged function must still drift on its package")
	}
}
