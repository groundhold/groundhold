package aws

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// This file rounds out cwlogs_net.go coverage: mustJSON was untested (0%),
// cwLogsPatchOutcome's error/5xx branches were only reached via the success path,
// and createCWLogs's AlreadyExists/failure branches (foreign name conflict,
// CreateLogGroup/PutRetentionPolicy/AssociateKmsKey failures) were all untested.

func TestMustJSON(t *testing.T) {
	b := mustJSON(map[string]any{"logGroupName": "x"})
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("mustJSON did not produce valid JSON: %v (%s)", err, b)
	}
	if got["logGroupName"] != "x" {
		t.Fatalf("mustJSON = %s, want logGroupName=x", b)
	}
}

func TestClassifyCWLogsChange_RemainingPaths(t *testing.T) {
	if k, reason := classifyCWLogsChange("service.managed"); k != "unsupported" || reason == "" {
		t.Fatalf("service.managed = %q (%q), want unsupported with a reason", k, reason)
	}
	if k, reason := classifyCWLogsChange("no.such.path"); k != "unsupported" || reason == "" {
		t.Fatalf("default path = %q (%q), want unsupported with a reason", k, reason)
	}
	if k, reason := classifyCWLogsChange("location.region"); k != "immutable" || reason == "" {
		t.Fatalf("location.region = %q (%q), want immutable with a reason", k, reason)
	}
}

// cwLogsFailServer extends cwLogsServer with per-action HTTP overrides.
type cwLogsFail struct {
	action string
	status int
}

func cwLogsFailServer(t *testing.T, name, capLabel string, retentionDays int, kmsKeyId string, fail cwLogsFail) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			if fail.action != "" && action == fail.action {
				w.WriteHeader(fail.status)
				_, _ = w.Write([]byte(`{"__type":"SomeException","message":"boom"}`))
				return
			}
			switch action {
			case "DescribeLogGroups":
				arn := "arn:aws:logs:eu-central-1:000000000000:log-group:" + name + ":*"
				grp := map[string]any{"logGroupName": name, "arn": arn}
				if retentionDays > 0 {
					grp["retentionInDays"] = retentionDays
				}
				if kmsKeyId != "" {
					grp["kmsKeyId"] = kmsKeyId
				}
				out, _ := json.Marshal(map[string]any{"logGroups": []any{grp}})
				_, _ = w.Write(out)
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + capLabel +
					`","groundhold-environment":"prod"}}`))
			case "CreateLogGroup", "PutRetentionPolicy", "AssociateKmsKey",
				"DisassociateKmsKey", "DeleteLogGroup":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func cwLogsFailAlreadyExistsServer(t *testing.T, name, capLabel string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			switch action {
			case "CreateLogGroup":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"ResourceAlreadyExistsException","message":"exists"}`))
			case "DescribeLogGroups":
				arn := "arn:aws:logs:eu-central-1:000000000000:log-group:" + name + ":*"
				out, _ := json.Marshal(map[string]any{"logGroups": []any{
					map[string]any{"logGroupName": name, "arn": arn}}})
				_, _ = w.Write(out)
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"` + capLabel +
					`","groundhold-environment":"prod"}}`))
			case "PutRetentionPolicy", "AssociateKmsKey":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func TestCreateCWLogs_AlreadyExistsOursRepairs(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsFailAlreadyExistsServer(t, name, "app-logs")
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.createCWLogs("eu-central-1", "prod", "app-logs", cwLogsAttrs(), nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("an already-existing OWNED group must repair to succeeded, got %+v", res)
	}
}

func TestCreateCWLogs_AlreadyExistsForeignFails(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsFailAlreadyExistsServer(t, name, "someone-else")
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.createCWLogs("eu-central-1", "prod", "app-logs", cwLogsAttrs(), nil, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign group at our name must refuse, got %+v", res)
	}
}

// D1036: WITH the sealed emission-adopt grant a group the provider created (untagged
// by us) is GOVERNED — createCWLogs sets retention on it instead of refusing. The
// same foreign group that TestCreateCWLogs_AlreadyExistsForeignFails refuses is now
// adopted, because the grant authorised taking over exactly this providerId.
func TestCreateCWLogs_EmissionAdoptGoverns(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsFailAlreadyExistsServer(t, name, "someone-else")
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	d.SetEmissionAdopt(true) // the sealed D1034 grant the executor sets per action
	res := d.createCWLogs("eu-central-1", "prod", "app-logs", cwLogsAttrs(), nil, 1)
	if res.Status != "succeeded" {
		t.Fatalf("with the emission-adopt grant a provider-created group is governed "+
			"(retention set), not refused, got %+v", res)
	}
}

// D1036 / FM-3: the grant lets the create ADOPT, but retention is still enforced
// WITHIN the same action — if PutRetentionPolicy fails on the adopted group the create
// does NOT succeed, so converge cannot read green over a group left at its old (None)
// retention. Governance is not "adopted", it is "adopted AND retention set".
func TestCreateCWLogs_EmissionAdoptRetentionFailureIsNotGreen(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			switch target[strings.LastIndex(target, ".")+1:] {
			case "CreateLogGroup":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"ResourceAlreadyExistsException","message":"exists"}`))
			case "DescribeLogGroups":
				arn := "arn:aws:logs:eu-central-1:000000000000:log-group:" + name + ":*"
				out, _ := json.Marshal(map[string]any{"logGroups": []any{
					map[string]any{"logGroupName": name, "arn": arn}}})
				_, _ = w.Write(out)
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"someone-else","groundhold-environment":"prod"}}`))
			case "PutRetentionPolicy":
				w.WriteHeader(400) // the whole point: retention does NOT land
				_, _ = w.Write([]byte(`{"__type":"SomeException","message":"boom"}`))
			default:
				_, _ = w.Write([]byte(`{}`))
			}
		}))
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	d.SetEmissionAdopt(true)
	res := d.createCWLogs("eu-central-1", "prod", "app-logs", cwLogsAttrs(), nil, 1)
	if res.Status == "succeeded" {
		t.Fatalf("an adopt whose retention did NOT land must not succeed (FM-3), got %+v", res)
	}
}

func TestCreateCWLogs_CreateLogGroup5xxIsUnknown(t *testing.T) {
	srv := cwLogsFailServer(t, "x", "app-logs", 0, "", cwLogsFail{action: "CreateLogGroup", status: 500})
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.createCWLogs("eu-central-1", "prod", "app-logs", cwLogsAttrs(), nil, 1)
	if res.Status != "unknown" {
		t.Fatalf("a 500 CreateLogGroup must be unknown, got %+v", res)
	}
}

func TestCreateCWLogs_CreateLogGroup4xxIsFailed(t *testing.T) {
	srv := cwLogsFailServer(t, "x", "app-logs", 0, "", cwLogsFail{action: "CreateLogGroup", status: 400})
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.createCWLogs("eu-central-1", "prod", "app-logs", cwLogsAttrs(), nil, 1)
	if res.Status != "failed" {
		t.Fatalf("a plain 400 CreateLogGroup must be failed, got %+v", res)
	}
}

func TestCreateCWLogs_RetentionFailurePaths(t *testing.T) {
	t.Run("5xx unknown", func(t *testing.T) {
		srv := cwLogsFailServer(t, "x", "app-logs", 0, "", cwLogsFail{action: "PutRetentionPolicy", status: 503})
		defer srv.Close()
		d := cwLogsDriver(t, srv)
		res := d.createCWLogs("eu-central-1", "prod", "app-logs", cwLogsAttrs(), nil, 1)
		if res.Status != "unknown" || res.ProviderID == "" {
			t.Fatalf("a 503 PutRetentionPolicy must be unknown WITH the pid, got %+v", res)
		}
	})
	t.Run("4xx failed", func(t *testing.T) {
		srv := cwLogsFailServer(t, "x", "app-logs", 0, "", cwLogsFail{action: "PutRetentionPolicy", status: 400})
		defer srv.Close()
		d := cwLogsDriver(t, srv)
		res := d.createCWLogs("eu-central-1", "prod", "app-logs", cwLogsAttrs(), nil, 1)
		if res.Status != "failed" || !strings.Contains(res.Reason, "NOT enforced") {
			t.Fatalf("a 400 PutRetentionPolicy must be a clean failed, got %+v", res)
		}
	})
}

func TestCreateCWLogs_CMKAssociateFailurePaths(t *testing.T) {
	a := cwLogsAttrs()
	a["encryption.customerManagedKeys"] = true
	impl := map[string]any{"kmsKeyArn": "arn:aws:kms:eu-central-1:0:key/k"}

	t.Run("5xx unknown", func(t *testing.T) {
		srv := cwLogsFailServer(t, "x", "app-logs", 0, "", cwLogsFail{action: "AssociateKmsKey", status: 500})
		defer srv.Close()
		d := cwLogsDriver(t, srv)
		res := d.createCWLogs("eu-central-1", "prod", "app-logs", a, impl, 1)
		if res.Status != "unknown" || res.ProviderID == "" {
			t.Fatalf("a 500 AssociateKmsKey must be unknown WITH the pid, got %+v", res)
		}
	})
	t.Run("4xx failed", func(t *testing.T) {
		srv := cwLogsFailServer(t, "x", "app-logs", 0, "", cwLogsFail{action: "AssociateKmsKey", status: 400})
		defer srv.Close()
		d := cwLogsDriver(t, srv)
		res := d.createCWLogs("eu-central-1", "prod", "app-logs", a, impl, 1)
		if res.Status != "failed" || !strings.Contains(res.Reason, "NOT associated") {
			t.Fatalf("a 400 AssociateKmsKey must be a clean failed, got %+v", res)
		}
	})
	t.Run("succeeds", func(t *testing.T) {
		srv := cwLogsFailServer(t, "x", "app-logs", 0, "", cwLogsFail{})
		defer srv.Close()
		d := cwLogsDriver(t, srv)
		res := d.createCWLogs("eu-central-1", "prod", "app-logs", a, impl, 1)
		if res.Status != "succeeded" {
			t.Fatalf("CMK associate success: %+v", res)
		}
	})
}

func TestUpdateCWLogs_CMKAssociateDisassociate(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	t.Run("turn on", func(t *testing.T) {
		var order []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			order = append(order, action)
			switch action {
			case "DescribeLogGroups":
				arn := "arn:aws:logs:eu-central-1:000000000000:log-group:" + name + ":*"
				out, _ := json.Marshal(map[string]any{"logGroups": []any{
					map[string]any{"logGroupName": name, "arn": arn}}})
				_, _ = w.Write(out)
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"app-logs","groundhold-environment":"prod"}}`))
			default:
				_, _ = w.Write([]byte(`{}`))
			}
		}))
		defer srv.Close()
		d := cwLogsDriver(t, srv)
		a := cwLogsAttrs()
		a["encryption.customerManagedKeys"] = true
		res := d.updateCWLogs("app-logs", "prod", cwLogsProviderID("eu-central-1", name), a,
			map[string]any{"kmsKeyArn": "arn:aws:kms:eu-central-1:0:key/k"}, []string{"encryption.customerManagedKeys"})
		if res.Status != "succeeded" {
			t.Fatalf("CMK-on update: %+v", res)
		}
		sawAssociate := false
		for _, o := range order {
			if o == "AssociateKmsKey" {
				sawAssociate = true
			}
			if o == "DisassociateKmsKey" {
				t.Fatalf("turning CMK on must not disassociate: %v", order)
			}
		}
		if !sawAssociate {
			t.Fatalf("turning CMK on must call AssociateKmsKey: %v", order)
		}
	})
	t.Run("turn off", func(t *testing.T) {
		var order []string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			order = append(order, action)
			switch action {
			case "DescribeLogGroups":
				arn := "arn:aws:logs:eu-central-1:000000000000:log-group:" + name + ":*"
				out, _ := json.Marshal(map[string]any{"logGroups": []any{
					map[string]any{"logGroupName": name, "arn": arn}}})
				_, _ = w.Write(out)
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":{"groundhold-capability":"app-logs","groundhold-environment":"prod"}}`))
			default:
				_, _ = w.Write([]byte(`{}`))
			}
		}))
		defer srv.Close()
		d := cwLogsDriver(t, srv)
		a := cwLogsAttrs() // no CMK
		res := d.updateCWLogs("app-logs", "prod", cwLogsProviderID("eu-central-1", name), a,
			nil, []string{"encryption.customerManagedKeys"})
		if res.Status != "succeeded" {
			t.Fatalf("CMK-off update: %+v", res)
		}
		sawDisassociate := false
		for _, o := range order {
			if o == "DisassociateKmsKey" {
				sawDisassociate = true
			}
		}
		if !sawDisassociate {
			t.Fatalf("turning CMK off must call DisassociateKmsKey: %v", order)
		}
	})
}

func TestUpdateCWLogs_UnmappedPathFails(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsServer(t, name, "app-logs", 90, "")
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.updateCWLogs("app-logs", "prod", cwLogsProviderID("eu-central-1", name),
		cwLogsAttrs(), nil, []string{"no.such.path"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "does not honor") {
		t.Fatalf("an unmapped path must refuse, got %+v", res)
	}
}

func TestUpdateCWLogs_NotFoundFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		action := target[strings.LastIndex(target, ".")+1:]
		if action == "DescribeLogGroups" {
			_, _ = w.Write([]byte(`{"logGroups":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.updateCWLogs("app-logs", "prod", cwLogsProviderID("eu-central-1", "gone"), cwLogsAttrs(), nil,
		[]string{"retention.days"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "no longer exists") {
		t.Fatalf("a vanished group must refuse update, got %+v", res)
	}
}

func TestUpdateCWLogs_ForeignFails(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsServer(t, name, "someone-else", 90, "")
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.updateCWLogs("app-logs", "prod", cwLogsProviderID("eu-central-1", name),
		cwLogsAttrs(), nil, []string{"retention.days"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign group must refuse update, got %+v", res)
	}
}

func TestUpdateCWLogs_InvalidPIDFails(t *testing.T) {
	d := NewDriver("eu-central-1")
	res := d.updateCWLogs("app-logs", "prod", "not-a-pid", cwLogsAttrs(), nil, []string{"retention.days"})
	if res.Status != "failed" {
		t.Fatalf("a malformed pid must refuse, got %+v", res)
	}
}

func TestUpdateCWLogs_RetentionPatch5xxIsUnknown(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsFailServer(t, name, "app-logs", 90, "", cwLogsFail{action: "PutRetentionPolicy", status: 500})
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.updateCWLogs("app-logs", "prod", cwLogsProviderID("eu-central-1", name),
		cwLogsAttrs(), nil, []string{"retention.days"})
	if res.Status != "unknown" {
		t.Fatalf("a 500 PutRetentionPolicy patch must be unknown, got %+v", res)
	}
}

func TestUpdateCWLogs_RetentionPatch4xxIsFailed(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	srv := cwLogsFailServer(t, name, "app-logs", 90, "", cwLogsFail{action: "PutRetentionPolicy", status: 400})
	defer srv.Close()
	d := cwLogsDriver(t, srv)
	res := d.updateCWLogs("app-logs", "prod", cwLogsProviderID("eu-central-1", name),
		cwLogsAttrs(), nil, []string{"retention.days"})
	if res.Status != "failed" {
		t.Fatalf("a 400 PutRetentionPolicy patch must be a clean failed, got %+v", res)
	}
}

func TestCwLogsPatchOutcome_TransportErrorIsUnknown(t *testing.T) {
	r := cwLogsPatchOutcome("set retention", "cwlogs:eu-central-1:x", 0, nil, errTransport("boom"))
	if r == nil || r.Status != "unknown" || r.ProviderID != "cwlogs:eu-central-1:x" {
		t.Fatalf("a transport error must be unknown WITH the pid, got %+v", r)
	}
}

func cwLogsRole(req *http.Request, _ []byte) certifynet.Role {
	tgt := req.Header.Get("X-Amz-Target")
	switch tgt[strings.LastIndex(tgt, ".")+1:] {
	case "DescribeLogGroups", "ListTagsForResource":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingCWLogs enrols CloudWatch Logs in the D391 gate. It adopts
// REACTIVELY: CreateLogGroup answers ResourceAlreadyExistsException, and the driver
// then reads the group's tags and repairs onto it. The refused create and the retention
// write are the mechanism; the proof is that it binds the group that already exists.
func TestAdoptsExistingCWLogs(t *testing.T) {
	name := CWLogGroupName("prod", "app-logs", 1)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/cwlogs",
		Classify: cwLogsRole,
		ExistingServer: func() *httptest.Server {
			return cwLogsFailAlreadyExistsServer(t, name, "app-logs")
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.LogsBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("cwlogs", "app-logs", "prod", cwLogsAttrs(), nil, "app-logs", 1)
		},
		AllowedMutations: 3, // the refused CreateLogGroup + the retention repair
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}
