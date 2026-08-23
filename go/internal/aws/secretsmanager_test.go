package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func asmAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func asmImpl() map[string]any {
	return map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
}

func TestBuildASMHonors(t *testing.T) {
	p, err := BuildSecretsManagerCreate("prod", "dbcreds", asmAttrs(), asmImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "eu-central-1" || p.KmsKeyID == "" || p.Public {
		t.Fatalf("plan = %+v", p)
	}
	if !asmNameOK.MatchString(p.Name) {
		t.Fatalf("generated name is invalid: %q", p.Name)
	}
}

func TestBuildASMRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "eu-central-1", "encryption.atRest": true, "service.managed": true}
	}
	cases := map[string]map[string]any{
		"atRest-false": {"encryption.atRest": false},
		"unmanaged":    {"service.managed": false},
		"rotation":     {"rotation.enabled": true}, // unknown attr — producer's job
		"expiry":       {"expiry.after": "30d"},
		"value":        {"value": "hunter2"}, // the value is data, never a declared attr
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildSecretsManagerCreate("prod", "dbcreds", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// CMK without key
	cmk := base()
	cmk["encryption.customerManagedKeys"] = true
	if _, err := BuildSecretsManagerCreate("prod", "dbcreds", cmk, nil, 1); err == nil {
		t.Error("CMK without kms_key_id must refuse")
	}
	// CMK naming the AWS-managed key does not satisfy customer-managed
	cmk["encryption.customerManagedKeys"] = true
	if _, err := BuildSecretsManagerCreate("prod", "dbcreds", cmk,
		map[string]any{"kms_key_id": "alias/aws/secretsmanager"}, 1); err == nil {
		t.Error("kms_key_id=alias/aws/secretsmanager must refuse (not a customer key)")
	}
	// missing region
	if _, err := BuildSecretsManagerCreate("prod", "dbcreds",
		map[string]any{"encryption.atRest": true, "service.managed": true}, nil, 1); err == nil {
		t.Error("missing region must refuse")
	}
}

// asmDeletedDate is the DeletedDate DescribeSecret reports, as a JSON fragment. The
// fixture never carried one, so the field was decoded and never read for as long as it
// existed (D756).
var asmDeletedDate = ""

// asmServer is a fake Secrets Manager endpoint dispatching on X-Amz-Target.
func asmServer(t *testing.T, tagCap string, policy string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			action := r.Header.Get("X-Amz-Target")
			action = action[strings.LastIndex(action, ".")+1:]
			switch action {
			case "CreateSecret":
				_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x","VersionId":"v1"}`))
			case "DescribeSecret":
				_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf",` +
					`"Name":"x","KmsKeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc"` +
					asmDeletedDate + `,` +
					`"Tags":[{"Key":"groundhold-capability","Value":"` + tagCap + `"},` +
					`{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "GetResourcePolicy":
				// policy == "" means no resource policy (private); otherwise it is
				// the policy DOCUMENT, carried in the ResourcePolicy field as a JSON
				// string (exactly as real Secrets Manager returns it).
				if policy == "" {
					_, _ = w.Write([]byte(`{"Name":"x"}`))
				} else {
					enc, _ := json.Marshal(policy)
					_, _ = w.Write([]byte(`{"Name":"x","ResourcePolicy":` + string(enc) + `}`))
				}
			case "PutResourcePolicy", "DeleteResourcePolicy", "DeleteSecret", "UpdateSecret", "TagResource":
				_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x"}`))
			default:
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"UnknownOperationException"}`))
			}
		}))
}

func asmDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.SecretsManagerBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteASM(t *testing.T) {
	srv := asmServer(t, "dbcreds", "") // no resource policy -> private
	defer srv.Close()
	d := asmDriver(t, srv)
	res := d.createASM("eu-central-1", "prod", "dbcreds", asmAttrs(), asmImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "asm:eu-central-1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeASM("dbcreds", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" || got["encryption.customerManagedKeys"] != true ||
		got["encryption.atRest"] != true || got["network.publicExposure"] != false {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteASM("dbcreds", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestObserveASMPublicPolicy(t *testing.T) {
	// a wildcard-principal Allow -> publicExposure true
	srv := asmServer(t, "dbcreds", asmPublicPolicy(""))
	defer srv.Close()
	d := asmDriver(t, srv)
	obs, diags, err := d.observeASM("dbcreds", "asm:eu-central-1:x")
	if err != nil {
		t.Fatalf("observe err: %v (%v)", err, diags)
	}
	var public any
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			public = o.Value
		}
	}
	if public != true {
		t.Fatalf("expected publicExposure true, obs=%+v diags=%v", obs, diags)
	}
}

func TestDeleteASMForeignRefused(t *testing.T) {
	srv := asmServer(t, "someone-else", `"\"\""`)
	defer srv.Close()
	d := asmDriver(t, srv)
	res := d.deleteASM("dbcreds", "prod", "asm:eu-central-1:x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign secret must refuse delete, got %+v", res)
	}
}

// TestCreateASMClientRequestToken pins F27: CreateSecret must carry a ClientRequestToken
// (AWS rejects the request without it when KMS/tags are present, HTTP 400), and the
// token must be DETERMINISTIC (a retry reuses it → idempotent, not a duplicate).
func TestCreateASMClientRequestToken(t *testing.T) {
	var createBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		action = action[strings.LastIndex(action, ".")+1:]
		if action == "CreateSecret" {
			b, _ := io.ReadAll(r.Body)
			createBody = string(b)
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:eu-central-1:000000000000:secret:x-AbCdEf","Name":"x",` +
			`"Tags":[{"Key":"groundhold-capability","Value":"dbcreds"},{"Key":"groundhold-environment","Value":"prod"}]}`))
	}))
	defer srv.Close()
	d := asmDriver(t, srv)
	if res := d.createASM("eu-central-1", "prod", "dbcreds", asmAttrs(), asmImpl(), 1); res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	want := asmRequestToken(ASMSecretName("prod", "dbcreds", 1))
	if !strings.Contains(createBody, `"ClientRequestToken":"`+want+`"`) {
		t.Fatalf("CreateSecret must carry the deterministic ClientRequestToken %q (F27); body=%s", want, createBody)
	}
	// determinism: recomputing the token yields the same value.
	if asmRequestToken(ASMSecretName("prod", "dbcreds", 1)) != want {
		t.Fatal("asmRequestToken must be deterministic")
	}
}

// D756. A secret scheduled for deletion still answers DescribeSecret, so every
// observation this driver emits stays TRUE — and nothing said that GetSecretValue already
// refuses it. converge reported converged, posture green, and whatever reads the secret
// was already broken. The field that says so was decoded and never read; the
// fixture-coverage gate is what found it.
func TestASMSaysWhenASecretIsScheduledForDeletion(t *testing.T) {
	for _, c := range []struct {
		name    string
		deleted string
		wantSay bool
	}{
		{"a live secret says nothing about deletion", "", false},
		{"scheduled for deletion", `,"DeletedDate":1.7e9`, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			old := asmDeletedDate
			asmDeletedDate = c.deleted
			defer func() { asmDeletedDate = old }()

			srv := asmServer(t, "app-secret", "")
			defer srv.Close()
			d := asmDriver(t, srv)

			obs, diags, err := d.observeASM("app-secret",
				"asm:eu-central-1:app-secret-prod-x")
			if err != nil {
				t.Fatal(err)
			}
			// The resource is NOT absent: it exists, and a re-create under the same name
			// is refused by AWS while the recovery window runs.
			for _, o := range obs {
				if o.Path == "resource.absent" && o.Value == true {
					t.Fatal("a secret scheduled for deletion is not GONE — marking it absent " +
						"makes the compiler plan a create AWS refuses for the whole window")
				}
			}
			said := false
			for _, dg := range diags {
				if strings.Contains(dg, "SCHEDULED FOR DELETION") {
					said = true
				}
			}
			if said != c.wantSay {
				t.Fatalf("diagnostics = %v, want a deletion warning: %v — every attribute "+
					"stays true while the secret is unreadable, so the warning is the only "+
					"thing that carries it (D756)", diags, c.wantSay)
			}
		})
	}
}

// D1241. The delete asks for a 7-day recovery window, so the secret is RESTORABLE and
// only permanently deleted at the window's end — AWS's own model says so. The result
// reported a bare "succeeded", which tells a reader (often an agent deciding what to do
// next) that the secret is gone.
//
// The codebase already discloses this for the twins — KMS's pending window, GCP's
// custom-role undelete window, Azure's key-vault soft delete. This was the outlier.
func TestDeletingASecretSaysItIsStillRestorable(t *testing.T) {
	srv := asmServer(t, sanitizeTag("dbcreds"), "")
	defer srv.Close()
	d := asmDriver(t, srv)
	res := d.createASM("eu-central-1", "prod", "dbcreds", asmAttrs(), asmImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	del := d.deleteASM("dbcreds", "prod", res.ProviderID)
	if del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
	for _, must := range []string{"RESTORABLE", "7-day recovery window"} {
		if !strings.Contains(del.Reason, must) {
			t.Fatalf("a recoverable delete must say the resource is still there and for how "+
				"long — missing %q in %q", must, del.Reason)
		}
	}
}

// The idempotent "already gone" success is a DIFFERENT thing and must stay bare: there
// is no recovery window to disclose, and a caveat on every case distinguishes none
// (D1227).
func TestAnAlreadyGoneSecretReportsAPlainSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException"}`))
	}))
	defer srv.Close()
	d := asmDriver(t, srv)
	del := d.deleteASM("dbcreds", "prod", "asm:eu-central-1:gh-dbcreds")
	if del.Status != "succeeded" {
		t.Fatalf("a secret that is already gone is an idempotent success: %+v", del)
	}
	if strings.Contains(del.Reason, "RESTORABLE") {
		t.Fatalf("nothing was deleted here, so there is no recovery window to disclose: %q",
			del.Reason)
	}
}
