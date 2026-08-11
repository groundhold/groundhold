package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D852. The operand exists to replace a hand-written `Principal: "*"` invoke grant.
// An operand that accepted a wildcard of its own would have been decoration.
func TestAServicePrincipalWithoutASourceArnIsRefused(t *testing.T) {
	impl := lambdaImpl()
	impl["invokers"] = []any{
		map[string]any{"service": "scheduler.amazonaws.com"},
	}
	_, err := BuildLambda("000000000000", "prod", "api", lambdaAttrs(), impl, 1)
	if err == nil {
		t.Fatal("a service principal with no source_arn authorises that service in EVERY " +
			"AWS account — it must be refused, not written")
	}
	if !strings.Contains(err.Error(), "source_arn") {
		t.Fatalf("the refusal must name what to add, got: %v", err)
	}
}

func TestAnInvokerEntryNamesOneCaller(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry map[string]any
		want  string
	}{
		{"both", map[string]any{"principal": "arn:aws:iam::000000000000:role/r",
			"service": "scheduler.amazonaws.com", "source_arn": "arn:aws:scheduler:eu-central-1:000000000000:schedule/default/s"}, "both"},
		{"neither", map[string]any{"source_arn": "arn:aws:scheduler:eu-central-1:000000000000:schedule/default/s"}, "neither"},
		{"principal not an arn", map[string]any{"principal": "some-role"}, "not an ARN"},
		{"unknown key", map[string]any{"principal": "arn:aws:iam::000000000000:role/r", "conditon": "typo"}, "unknown key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			impl := lambdaImpl()
			impl["invokers"] = []any{tc.entry}
			_, err := BuildLambda("000000000000", "prod", "api", lambdaAttrs(), impl, 1)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a refusal mentioning %q, got %v", tc.want, err)
			}
		})
	}
}

// TestDeclaredInvokersAreGrantedWithTheirCondition is the positive half: the grant
// AWS receives carries the principal AND the SourceArn that narrows it.
func TestDeclaredInvokersAreGrantedWithTheirCondition(t *testing.T) {
	var added []map[string]any
	created := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "POST" && strings.HasSuffix(p, "/policy"):
			b, _ := io.ReadAll(r.Body)
			var body map[string]any
			_ = json.Unmarshal(b, &body)
			added = append(added, body)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Statement":"{}"}`))
		case r.Method == "GET" && strings.HasSuffix(p, "/policy"):
			w.WriteHeader(http.StatusNotFound) // no policy yet
		case r.Method == "POST" && strings.HasSuffix(p, "/functions"):
			created = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"FunctionName":"fn","State":"Pending"}`))
		case r.Method == "GET" && strings.Contains(p, "/functions/"):
			if !created {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"Configuration":{"State":"Active","Timeout":300},` +
				`"Tags":{"groundhold-capability":"api","groundhold-environment":"prod"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	d := lambdaDriver(t, srv)

	attrs := lambdaAttrs()
	attrs["network.publicExposure"] = false
	impl := lambdaImpl()
	impl["invokers"] = []any{
		map[string]any{
			"service":    "scheduler.amazonaws.com",
			"source_arn": "arn:aws:scheduler:eu-central-1:000000000000:schedule/default/sync",
		},
	}
	if res := d.createLambda("eu-central-1", "000000000000", "prod", "api", attrs, impl, 1); res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if len(added) != 1 {
		t.Fatalf("want exactly one AddPermission, got %d: %+v", len(added), added)
	}
	g := added[0]
	if g["Principal"] != "scheduler.amazonaws.com" {
		t.Fatalf("principal = %v", g["Principal"])
	}
	if g["SourceArn"] != "arn:aws:scheduler:eu-central-1:000000000000:schedule/default/sync" {
		t.Fatalf("the grant went out WITHOUT its narrowing condition: %+v", g)
	}
	if g["Action"] != "lambda:InvokeFunction" {
		t.Fatalf("action = %v", g["Action"])
	}
	sid, _ := g["StatementId"].(string)
	if !strings.HasPrefix(sid, lambdaInvokerSidPrefix) {
		t.Fatalf("statement id %q is not ours — reconciliation recognises its own work by "+
			"this prefix and would orphan the grant", sid)
	}
}

// TestAnUnreadablePolicyDoesNotReportAReconciledSet: the reconcile READS before it
// writes, and a read that fails must not be treated as "we own nothing" — that would
// withdraw nothing while reporting success, and on the next run add duplicates under
// ids nobody checked (the D847 shape, in a write path).
func TestAnUnreadablePolicyDoesNotReportAReconciledSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/policy") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"not authorized to perform: lambda:GetPolicy"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := lambdaDriver(t, srv)

	res := d.ensureLambdaInvokers("eu-central-1", "lambda:eu-central-1:000000000000:fn", "fn",
		[]LambdaInvoker{{Principal: "arn:aws:iam::000000000000:role/r"}})
	if res == nil {
		t.Fatal("a denied GetPolicy reported a reconciled grant set")
	}
	if res.Status != "unknown" {
		t.Fatalf("status = %q, want unknown (the outcome is not established)", res.Status)
	}
}

// TestAGrantDroppedFromTheCandidateIsWithdrawn: the whole reason the reconcile reads
// the live policy. Without this, removing an invoker from the contract would leave the
// caller granted forever, and the estate would keep a caller the contract had dropped.
func TestAGrantDroppedFromTheCandidateIsWithdrawn(t *testing.T) {
	stale := LambdaInvoker{Principal: "arn:aws:iam::000000000000:role/old"}
	keep := LambdaInvoker{Principal: "arn:aws:iam::000000000000:role/new"}
	var removed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		switch {
		case r.Method == "GET" && strings.HasSuffix(p, "/policy"):
			doc := `{"Statement":[{"Sid":"` + stale.StatementID() + `"},{"Sid":"someone-elses"}]}`
			b, _ := json.Marshal(map[string]string{"Policy": doc})
			_, _ = w.Write(b)
		case r.Method == "POST" && strings.HasSuffix(p, "/policy"):
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"Statement":"{}"}`))
		case r.Method == "DELETE" && strings.Contains(p, "/policy/"):
			removed = append(removed, p[strings.LastIndex(p, "/")+1:])
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	d := lambdaDriver(t, srv)

	if res := d.ensureLambdaInvokers("eu-central-1", "lambda:eu-central-1:000000000000:fn", "fn",
		[]LambdaInvoker{keep}); res != nil {
		t.Fatalf("reconcile: %+v", res)
	}
	if len(removed) != 1 || removed[0] != stale.StatementID() {
		t.Fatalf("want the dropped grant withdrawn exactly once, got %v", removed)
	}
	for _, r := range removed {
		if !strings.HasPrefix(r, lambdaInvokerSidPrefix) {
			t.Fatalf("withdrew %q, which is not ours to withdraw", r)
		}
	}
}

// TestObservedInvokersCarryTheirCondition serves the condition shape a live policy
// uses, so the branch that reads it is exercised in BOTH directions rather than
// allowlisted as unreachable. The observed rendering must equal the declared one —
// two spellings of the same grant would report permanent drift on a converged
// function, which is its own kind of lie (the D530 lesson).
func TestObservedInvokersCarryTheirCondition(t *testing.T) {
	want := LambdaInvoker{
		Principal: "scheduler.amazonaws.com",
		SourceArn: "arn:aws:scheduler:eu-central-1:000000000000:schedule/default/sync",
	}
	policy := `{"Statement":[` +
		`{"Sid":"` + want.StatementID() + `","Principal":{"Service":"scheduler.amazonaws.com"},` +
		`"Condition":{"ArnLike":{"AWS:SourceArn":"` + want.SourceArn + `"}}},` +
		`{"Sid":"someone-elses","Principal":{"AWS":"*"}}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/policy") {
			b, _ := json.Marshal(map[string]string{"Policy": policy})
			_, _ = w.Write(b)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := lambdaDriver(t, srv)

	got, ok := d.observedLambdaInvokers("eu-central-1", "fn")
	if !ok {
		t.Fatal("a readable policy reported unreadable")
	}
	if got != CanonLambdaInvokers([]LambdaInvoker{want}) {
		t.Fatalf("observed %q, declared %q — the two sides render differently, so a "+
			"converged function would show permanent drift", got, CanonLambdaInvokers([]LambdaInvoker{want}))
	}
	if strings.Contains(got, "someone-elses") || strings.Contains(got, "*") {
		t.Fatalf("a statement that is not ours leaked into the operand: %q", got)
	}
}
