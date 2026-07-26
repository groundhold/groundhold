package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// This file rounds out secretsmanager_net.go coverage: classifyASMChange,
// asmDeletePolicy and updateASM were all previously untested (0% each).

// ---- classifyASMChange: PURE, table-driven over every path -----------------

func TestClassifyASMChange(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"location.region", "immutable"},
		{"network.publicExposure", "mutable"},
		{"encryption.customerManagedKeys", "mutable"},
		{"encryption.atRest", "unsupported"},
		{"service.managed", "unsupported"},
		{"no.such.path", "unsupported"},
	}
	for _, c := range cases {
		got, reason := classifyASMChange(c.path, nil, nil)
		if got != c.want {
			t.Errorf("classifyASMChange(%q) = %q, want %q", c.path, got, c.want)
		}
		// mutable paths carry no extra reason (the transition is unremarkable);
		// immutable/unsupported paths must explain themselves.
		if reason == "" && got != "mutable" {
			t.Errorf("classifyASMChange(%q) = %q with no reason", c.path, got)
		}
	}
}

// asmFailServer extends the asmServer shape with per-action HTTP overrides so the
// transport/5xx/4xx branches of asmPutPolicy/asmDeletePolicy/updateASM (otherwise
// only reachable on a real AWS error) can be exercised directly.
type asmFail struct {
	action string // the X-Amz-Target action to fail
	status int
	errTyp string // secretsmanager error __type, e.g. "InternalServiceError"
}

func asmFailServer(t *testing.T, tagCap string, fail asmFail) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		action = action[strings.LastIndex(action, ".")+1:]
		if fail.action != "" && action == fail.action {
			w.WriteHeader(fail.status)
			_, _ = w.Write([]byte(`{"__type":"` + fail.errTyp + `"}`))
			return
		}
		switch action {
		case "CreateSecret":
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x"}`))
		case "DescribeSecret":
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf",` +
				`"Name":"x","KmsKeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc",` +
				`"Tags":[{"Key":"groundhold-capability","Value":"` + tagCap + `"},` +
				`{"Key":"groundhold-environment","Value":"prod"}]}`))
		case "GetResourcePolicy":
			_, _ = w.Write([]byte(`{"Name":"x"}`))
		case "PutResourcePolicy", "DeleteResourcePolicy", "DeleteSecret", "UpdateSecret", "TagResource":
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x"}`))
		default:
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"UnknownOperationException"}`))
		}
	}))
}

// ---- asmDeletePolicy --------------------------------------------------------

func TestAsmDeletePolicy_Succeeds(t *testing.T) {
	srv := asmFailServer(t, "dbcreds", asmFail{})
	defer srv.Close()
	d := asmDriver(t, srv)
	if r := d.asmDeletePolicy("eu-central-1", "x", "asm:eu-central-1:x"); r != nil {
		t.Fatalf("a successful DeleteResourcePolicy must be nil (keep going), got %+v", r)
	}
}

func TestAsmDeletePolicy_TransportErrorIsUnknown(t *testing.T) {
	d := NewDriver("eu-central-1")
	d.SecretsManagerBaseURL = "http://127.0.0.1:1"
	r := d.asmDeletePolicy("eu-central-1", "x", "asm:eu-central-1:x")
	if r == nil || r.Status != "unknown" || r.ProviderID != "asm:eu-central-1:x" {
		t.Fatalf("a transport error must be unknown WITH the pid, got %+v", r)
	}
}

func TestAsmDeletePolicy_5xxIsUnknown(t *testing.T) {
	srv := asmFailServer(t, "dbcreds", asmFail{action: "DeleteResourcePolicy", status: 500, errTyp: "InternalServiceError"})
	defer srv.Close()
	d := asmDriver(t, srv)
	r := d.asmDeletePolicy("eu-central-1", "x", "asm:eu-central-1:x")
	if r == nil || r.Status != "unknown" {
		t.Fatalf("a 500 must be unknown, got %+v", r)
	}
}

func TestAsmDeletePolicy_4xxIsFailed(t *testing.T) {
	srv := asmFailServer(t, "dbcreds", asmFail{action: "DeleteResourcePolicy", status: 400, errTyp: "ResourceNotFoundException"})
	defer srv.Close()
	d := asmDriver(t, srv)
	r := d.asmDeletePolicy("eu-central-1", "x", "asm:eu-central-1:x")
	if r == nil || r.Status != "failed" {
		t.Fatalf("a 4xx must be failed, got %+v", r)
	}
}

// ---- asmPutPolicy (round out the 5xx/4xx branches) --------------------------

func TestAsmPutPolicy_5xxIsUnknown(t *testing.T) {
	srv := asmFailServer(t, "dbcreds", asmFail{action: "PutResourcePolicy", status: 503, errTyp: "InternalServiceError"})
	defer srv.Close()
	d := asmDriver(t, srv)
	r := d.asmPutPolicy("eu-central-1", "x", "", "asm:eu-central-1:x")
	if r == nil || r.Status != "unknown" {
		t.Fatalf("a 503 must be unknown, got %+v", r)
	}
}

func TestAsmPutPolicy_4xxIsFailed(t *testing.T) {
	srv := asmFailServer(t, "dbcreds", asmFail{action: "PutResourcePolicy", status: 400, errTyp: "MalformedPolicyDocumentException"})
	defer srv.Close()
	d := asmDriver(t, srv)
	r := d.asmPutPolicy("eu-central-1", "x", "", "asm:eu-central-1:x")
	if r == nil || r.Status != "failed" {
		t.Fatalf("a 400 must be failed, got %+v", r)
	}
}

// ---- updateASM ---------------------------------------------------------------

func TestUpdateASM_CMEKPatch(t *testing.T) {
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		action = action[strings.LastIndex(action, ".")+1:]
		if action == "UpdateSecret" {
			b, _ := io.ReadAll(r.Body)
			captured = string(b)
		}
		switch action {
		case "DescribeSecret":
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf",` +
				`"Name":"x","Tags":[{"Key":"groundhold-capability","Value":"dbcreds"},{"Key":"groundhold-environment","Value":"prod"}]}`))
		default:
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x"}`))
		}
	}))
	defer srv.Close()
	d := asmDriver(t, srv)

	res := d.updateASM("dbcreds", "prod", "asm:eu-central-1:x", asmAttrs(), asmImpl(),
		[]string{"encryption.customerManagedKeys"})
	if res.Status != "succeeded" {
		t.Fatalf("CMEK update: %+v", res)
	}
	if !strings.Contains(captured, "arn:aws:kms:eu-central-1:000000000000:key/abc") {
		t.Fatalf("UpdateSecret must carry the plan's kms key, got %s", captured)
	}
}

func TestUpdateASM_CMEKRevertToDefault(t *testing.T) {
	var captured string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		action = action[strings.LastIndex(action, ".")+1:]
		if action == "UpdateSecret" {
			b, _ := io.ReadAll(r.Body)
			captured = string(b)
		}
		switch action {
		case "DescribeSecret":
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf",` +
				`"Name":"x","Tags":[{"Key":"groundhold-capability","Value":"dbcreds"},{"Key":"groundhold-environment","Value":"prod"}]}`))
		default:
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x"}`))
		}
	}))
	defer srv.Close()
	d := asmDriver(t, srv)

	a := asmAttrs()
	a["encryption.customerManagedKeys"] = false
	res := d.updateASM("dbcreds", "prod", "asm:eu-central-1:x", a, map[string]any{},
		[]string{"encryption.customerManagedKeys"})
	if res.Status != "succeeded" {
		t.Fatalf("CMEK revert: %+v", res)
	}
	if !strings.Contains(captured, asmDefaultKeyAlias) {
		t.Fatalf("UpdateSecret must revert to the AWS-managed alias, got %s", captured)
	}
}

func TestUpdateASM_PublicExposureTrueCallsPutPolicy(t *testing.T) {
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		action = action[strings.LastIndex(action, ".")+1:]
		order = append(order, action)
		switch action {
		case "DescribeSecret":
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf",` +
				`"Name":"x","Tags":[{"Key":"groundhold-capability","Value":"dbcreds"},{"Key":"groundhold-environment","Value":"prod"}]}`))
		default:
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x"}`))
		}
	}))
	defer srv.Close()
	d := asmDriver(t, srv)

	a := asmAttrs()
	a["network.publicExposure"] = true
	delete(a, "encryption.customerManagedKeys")
	res := d.updateASM("dbcreds", "prod", "asm:eu-central-1:x", a, map[string]any{}, []string{"network.publicExposure"})
	if res.Status != "succeeded" {
		t.Fatalf("publicExposure=true update: %+v", res)
	}
	sawPut := false
	for _, o := range order {
		if o == "PutResourcePolicy" {
			sawPut = true
		}
		if o == "DeleteResourcePolicy" {
			t.Fatalf("publicExposure=true must not call DeleteResourcePolicy: %v", order)
		}
	}
	if !sawPut {
		t.Fatalf("publicExposure=true must call PutResourcePolicy: %v", order)
	}
}

func TestUpdateASM_PublicExposureFalseCallsDeletePolicy(t *testing.T) {
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		action = action[strings.LastIndex(action, ".")+1:]
		order = append(order, action)
		switch action {
		case "DescribeSecret":
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf",` +
				`"Name":"x","Tags":[{"Key":"groundhold-capability","Value":"dbcreds"},{"Key":"groundhold-environment","Value":"prod"}]}`))
		default:
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x"}`))
		}
	}))
	defer srv.Close()
	d := asmDriver(t, srv)

	a := asmAttrs() // network.publicExposure: false
	delete(a, "encryption.customerManagedKeys")
	res := d.updateASM("dbcreds", "prod", "asm:eu-central-1:x", a, map[string]any{}, []string{"network.publicExposure"})
	if res.Status != "succeeded" {
		t.Fatalf("publicExposure=false update: %+v", res)
	}
	sawDelete := false
	for _, o := range order {
		if o == "DeleteResourcePolicy" {
			sawDelete = true
		}
	}
	if !sawDelete {
		t.Fatalf("publicExposure=false must call DeleteResourcePolicy: %v", order)
	}
}

func TestUpdateASM_UnmappedPathRefuses(t *testing.T) {
	srv := asmFailServer(t, "dbcreds", asmFail{})
	defer srv.Close()
	d := asmDriver(t, srv)
	res := d.updateASM("dbcreds", "prod", "asm:eu-central-1:x", asmAttrs(), asmImpl(), []string{"no.such.path"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not patchable") {
		t.Fatalf("an unmapped path must refuse, got %+v", res)
	}
}

func TestUpdateASM_NotFoundFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		action = action[strings.LastIndex(action, ".")+1:]
		if action == "DescribeSecret" {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException"}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	d := asmDriver(t, srv)
	res := d.updateASM("dbcreds", "prod", "asm:eu-central-1:x", asmAttrs(), asmImpl(), []string{"network.publicExposure"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "no longer exists") {
		t.Fatalf("a vanished secret must refuse update, got %+v", res)
	}
}

func TestUpdateASM_ForeignTagsFails(t *testing.T) {
	srv := asmFailServer(t, "someone-else", asmFail{})
	defer srv.Close()
	d := asmDriver(t, srv)
	res := d.updateASM("dbcreds", "prod", "asm:eu-central-1:x", asmAttrs(), asmImpl(), []string{"network.publicExposure"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign secret must refuse update, got %+v", res)
	}
}

func TestUpdateASM_InvalidPIDFails(t *testing.T) {
	d := NewDriver("eu-central-1")
	res := d.updateASM("dbcreds", "prod", "not-a-pid", asmAttrs(), asmImpl(), []string{"network.publicExposure"})
	if res.Status != "failed" {
		t.Fatalf("a malformed pid must refuse, got %+v", res)
	}
}

func TestUpdateASM_PreReadTransportErrorIsUnknown(t *testing.T) {
	d := NewDriver("eu-central-1")
	d.SecretsManagerBaseURL = "http://127.0.0.1:1"
	res := d.updateASM("dbcreds", "prod", "asm:eu-central-1:x", asmAttrs(), asmImpl(), []string{"network.publicExposure"})
	if res.Status != "unknown" {
		t.Fatalf("an unreadable pre-update read must be unknown, got %+v", res)
	}
}
