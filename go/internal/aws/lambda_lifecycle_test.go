package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

// lambdaOperandFake serves GetFunction with a full operand set (VpcConfig,
// Environment, Code.ImageUri). getState selects the GetFunction outcome: "ok"
// (200 + operands), "gone" (404, a readable absence) or "err" (500, a read
// error). The Function URL is 404 (private) throughout.
type lambdaOperandFake struct {
	getState string
}

func (f *lambdaOperandFake) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "GET" && strings.HasSuffix(p, "/url"):
			w.WriteHeader(http.StatusNotFound)
		case r.Method == "GET" && strings.Contains(p, "/functions/"):
			switch f.getState {
			case "gone":
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Function not found"}`))
			case "err":
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"boom"}`))
			default:
				_, _ = w.Write([]byte(`{"Configuration":{"State":"Active","Timeout":300,` +
					`"VpcConfig":{"SubnetIds":["subnet-b","subnet-a"],"SecurityGroupIds":["sg-1"]},` +
					`"Environment":{"Variables":{"FOO":"bar","DB":"host"}}},` +
					`"Code":{"ImageUri":"img:sha1"},` +
					`"Tags":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func operandDriver(t *testing.T, state string) (*Driver, func()) {
	t.Helper()
	srv := httptest.NewServer((&lambdaOperandFake{getState: state}).handler())
	d := NewDriver("eu-central-1")
	d.creds = Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret"}
	d.Account = "000000000000"
	d.LambdaBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d, srv.Close
}

const operandPID = "lambda:eu-central-1:000000000000:apifn"

// TestObserveLambdaOperands (F-LC3 part 1): observe reads back the live
// VpcConfig, Environment and container image, canonicalized exactly as
// OperandTargets renders the DECLARED operands — so the compiler's operand-drift
// step compares like for like. The golden through observe -> classify.
func TestObserveLambdaOperands(t *testing.T) {
	d, done := operandDriver(t, "ok")
	defer done()

	obs, _, err := d.observeLambda("api", operandPID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got[provider.ResourceAbsentPath] != false {
		t.Fatalf("a present function must observe resource.absent=false, got %v", got[provider.ResourceAbsentPath])
	}
	if got[lambdaVpcOperand] != "subnets=subnet-a,subnet-b;sgs=sg-1" {
		t.Fatalf("vpcConfig canon = %q", got[lambdaVpcOperand])
	}
	if got[lambdaEnvOperand] != "DB=host;FOO=bar" {
		t.Fatalf("environment canon = %q", got[lambdaEnvOperand])
	}
	if got[lambdaPkgOperand] != "img:sha1" {
		t.Fatalf("package canon = %q", got[lambdaPkgOperand])
	}

	// observe -> classify: the DECLARED operands (a DIFFERENT image + subnets)
	// must produce OperandTargets whose values differ from the observed ones, and
	// classifyLambdaChange must route each operand path to a mutable in-place patch.
	attrs := lambdaAttrs()
	impl := map[string]any{
		"image_uri":       "img:sha2", // changed
		"role_arn":        "arn:aws:iam::000000000000:role/fn-exec",
		"subnets":         []any{"subnet-a"}, // changed
		"security_groups": []any{"sg-1"},
		"environment":     map[string]any{"FOO": "bar", "DB": "host"},
	}
	targets, terr := d.OperandTargets("lambda", attrs, impl)
	if terr != nil {
		t.Fatal(terr)
	}
	desired := map[string]any{}
	for _, tg := range targets {
		desired[tg.Path] = tg.Desired
	}
	if desired[lambdaPkgOperand] == got[lambdaPkgOperand] {
		t.Fatal("declared image differs from observed — targets must reflect the drift")
	}
	if desired[lambdaEnvOperand] != got[lambdaEnvOperand] {
		t.Fatalf("environment is unchanged — must NOT drift: desired %q observed %q",
			desired[lambdaEnvOperand], got[lambdaEnvOperand])
	}
	for _, path := range []string{lambdaVpcOperand, lambdaEnvOperand, lambdaPkgOperand} {
		if class, _ := classifyLambdaChange(path); class != "mutable" {
			t.Fatalf("%s must classify mutable (in-place), got %q", path, class)
		}
	}
}

// TestObserveLambdaAbsence (F-LC3 part 2): a bound function that GetFunction
// authoritatively 404s emits resource.absent=true with a NIL error — a readable
// absence the compiler turns into a re-create. A read ERROR (5xx) is a returned
// error (unknown), never an absence — the four-valued split.
func TestObserveLambdaAbsence(t *testing.T) {
	dGone, doneGone := operandDriver(t, "gone")
	defer doneGone()
	obs, _, err := dGone.observeLambda("api", operandPID)
	if err != nil {
		t.Fatalf("a readable 404 must be a nil-error absence, got err=%v", err)
	}
	if !observedAbsent(obs) {
		t.Fatalf("a gone function must observe resource.absent=true, got %v", obs)
	}

	dErr, doneErr := operandDriver(t, "err")
	defer doneErr()
	obs2, _, err2 := dErr.observeLambda("api", operandPID)
	if err2 == nil {
		t.Fatalf("a read ERROR must return an error (unknown), never an absence; obs=%v", obs2)
	}
	if observedAbsent(obs2) {
		t.Fatal("a read error must NOT be reported as an absence (no spurious recreate)")
	}
}
