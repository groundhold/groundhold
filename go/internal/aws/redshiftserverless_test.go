package aws

import (
	"encoding/json"
	"io"
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
	// D887: no VPC operands given → no subnet/security-group keys (an account with a
	// default VPC still works). With them, the workgroup body carries the lists.
	if _, has := wb["subnetIds"]; has {
		t.Fatalf("workgroup body must omit subnetIds when none given: %+v", wb)
	}
	pv, err := BuildRedshiftServerless("prod", "lake", rssAttrs(),
		map[string]any{"subnetIds": []any{"subnet-1", "subnet-2"}, "securityGroupIds": []any{"sg-1"}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	wbv := pv.workgroupBody("lake", "prod")
	if sn, _ := wbv["subnetIds"].([]string); len(sn) != 2 {
		t.Fatalf("VPC placement not in workgroup body: %+v", wbv)
	}
	if sg, _ := wbv["securityGroupIds"].([]string); len(sg) != 1 {
		t.Fatalf("security groups not in workgroup body: %+v", wbv)
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

// rssServer is a STATEFUL JSON-protocol double. GetWorkgroup reports AVAILABLE so create
// polls once and succeeds; ListTagsForResource reflects the owner tags. D888: after a
// DeleteWorkgroup, GetWorkgroup returns ResourceNotFound, exactly as the real cloud does
// — so the delete's poll for the workgroup to disappear terminates. A fixture that kept
// reporting the workgroup AVAILABLE after its delete would never let the poll break, and
// hid that the namespace delete was firing while the workgroup still existed.
func rssServer(t *testing.T, capLabel string, public bool) *httptest.Server {
	t.Helper()
	pub := "false"
	if public {
		pub = "true"
	}
	wgDeleted := false
	nsDeleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch rssAction(r) {
			case "CreateNamespace":
				_, _ = w.Write([]byte(`{"namespace":{"namespaceName":"n","namespaceArn":"arn:ns","status":"AVAILABLE"}}`))
			case "CreateWorkgroup":
				_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"w","workgroupArn":"arn:wg","status":"CREATING","publiclyAccessible":` + pub + `}}`))
			case "GetWorkgroup":
				if wgDeleted {
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"workgroup not found"}`))
					return
				}
				_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"w","workgroupArn":"arn:wg","namespaceName":"n","status":"AVAILABLE","publiclyAccessible":` + pub + `}}`))
			case "GetNamespace":
				if nsDeleted {
					// the namespace has finished deleting — the delete's poll-to-absence (D983)
					// confirms gone, as the workgroup leg already did (D888).
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"namespace not found"}`))
					return
				}
				_, _ = w.Write([]byte(`{"namespace":{"namespaceName":"n","namespaceArn":"arn:ns","status":"AVAILABLE","kmsKeyId":"AWS_OWNED_KMS_KEY"}}`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":[{"key":"groundhold-capability","value":"` + capLabel +
					`"},{"key":"groundhold-environment","value":"prod"}]}`))
			case "DeleteWorkgroup":
				wgDeleted = true // the workgroup is gone from the next GetWorkgroup on
				_, _ = w.Write([]byte(`{}`))
			case "DeleteNamespace":
				nsDeleted = true // the namespace is gone from the next GetNamespace on
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

// TestDeleteRedshiftServerlessWaitsForWorkgroup (D888) models the real cloud: the
// workgroup lingers for one GetWorkgroup poll after DeleteWorkgroup, and DeleteNamespace
// 409s while ANY workgroup still references the namespace. The baseline delete must still
// succeed — proof the driver POLLS for the workgroup to vanish before deleting the
// namespace. A driver that skips the poll fires DeleteNamespace against the lingering
// workgroup and fails, orphaning the namespace (the field defect this fixes).
func TestDeleteRedshiftServerlessWaitsForWorkgroup(t *testing.T) {
	getsSinceDelete := -1 // -1 until DeleteWorkgroup; then counts GetWorkgroup calls
	namespaceDeleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch rssAction(r) {
		case "GetWorkgroup":
			if getsSinceDelete >= 0 {
				getsSinceDelete++
				if getsSinceDelete >= 2 { // gone from the SECOND poll — it lingered once
					w.WriteHeader(404)
					_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"gone"}`))
					return
				}
			}
			_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"w","namespaceName":"n","status":"AVAILABLE","publiclyAccessible":false}}`))
		case "GetNamespace":
			// the namespace poll (D983) after DeleteNamespace: gone once it fired.
			if namespaceDeleted {
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"gone"}`))
				return
			}
			_, _ = w.Write([]byte(`{"namespace":{"namespaceName":"n","namespaceArn":"arn:ns","status":"AVAILABLE","kmsKeyId":"AWS_OWNED_KMS_KEY"}}`))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`{"tags":[{"key":"groundhold-capability","value":"lake"},{"key":"groundhold-environment","value":"prod"}]}`))
		case "DeleteWorkgroup":
			getsSinceDelete = 0
			_, _ = w.Write([]byte(`{}`))
		case "DeleteNamespace":
			if getsSinceDelete < 2 { // workgroup still visible → the real cloud 409s
				w.WriteHeader(409)
				_, _ = w.Write([]byte(`{"__type":"ConflictException","message":"a workgroup still references this namespace"}`))
				return
			}
			namespaceDeleted = true
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := rssDriver(t, srv)
	pid := rssProviderID("eu-central-1", RSSName("prod", "lake", 1))
	res := d.Delete("redshiftserverless", "lake", "prod", pid, "k")
	if res.Status != "succeeded" {
		t.Fatalf("delete must wait for the workgroup then succeed, got %+v", res)
	}
	if !namespaceDeleted {
		t.Fatal("DeleteNamespace never fired after the workgroup vanished")
	}
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

// TestDeleteRedshiftServerlessNamespaceAsyncNotGoneIsUnknown pins D983: the workgroup
// leg polls to gone (D888), but the NAMESPACE — the data half — did not. A DeleteNamespace
// the provider ACCEPTS while the namespace stays present (still deleting) must report
// unknown, never a terminal "succeeded" that tombstones data still being torn down.
func TestDeleteRedshiftServerlessNamespaceAsyncNotGoneIsUnknown(t *testing.T) {
	wgDeleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch rssAction(r) {
		case "GetWorkgroup":
			if wgDeleted { // workgroup vanishes so the delete reaches the namespace leg
				w.WriteHeader(404)
				_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"gone"}`))
				return
			}
			_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"w","namespaceName":"n","status":"AVAILABLE","publiclyAccessible":false}}`))
		case "GetNamespace": // never gone — the namespace stays "deleting"
			_, _ = w.Write([]byte(`{"namespace":{"namespaceName":"n","namespaceArn":"arn:ns","status":"AVAILABLE","kmsKeyId":"AWS_OWNED_KMS_KEY"}}`))
		case "ListTagsForResource":
			_, _ = w.Write([]byte(`{"tags":[{"key":"groundhold-capability","value":"lake"},{"key":"groundhold-environment","value":"prod"}]}`))
		case "DeleteWorkgroup":
			wgDeleted = true
			_, _ = w.Write([]byte(`{}`))
		case "DeleteNamespace":
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := rssDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the namespace never goes gone → times out fast
	pid := rssProviderID("eu-central-1", RSSName("prod", "lake", 1))
	res := d.Delete("redshiftserverless", "lake", "prod", pid, "k")
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-still-deleting namespace must be unknown (keep the handle), got %+v", res)
	}
}

func TestHonestyHarnessRedshiftServerless(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := rssProviderID("eu-central-1", RSSName("prod", "lake", 1))
	p := &certifynet.Probe{
		Name:            "aws/redshiftserverless",
		AssertTransient: true,           // D237: create/delete route through provider.MutationResult
		Classify:        jsonTargetRole, // Create*/Delete* opaque; Get*/List* reads
		OwnerTagValue:   "lake",
		DeterministicID: true, // the namespace/workgroup names are chosen
		// F-LC3 (D521): protocol-aware gone estate.
		ObserveAbsent: func(pr provider.Provider) ([]provider.Observation, []string, error) {
			return pr.Observe("redshiftserverless", "lake", pid)
		},
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

func rssRole(req *http.Request, _ []byte) certifynet.Role {
	switch rssAction(req) {
	case "GetWorkgroup", "GetNamespace", "ListTagsForResource", "ListWorkgroups", "ListNamespaces":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingRedshiftServerless enrols redshiftserverless in the D391 gate. It is
// a COMPOSITE (namespace plus workgroup) where BOTH halves answer ConflictException on a
// re-run, so the adoption has to hold twice in one create — the only two-step adoption
// in the AWS family.
func TestAdoptsExistingRedshiftServerless(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/redshiftserverless",
		Classify: rssRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch rssAction(r) {
					case "CreateNamespace", "CreateWorkgroup":
						w.WriteHeader(409)
						_, _ = w.Write([]byte(`{"__type":"ConflictException","message":"already exists"}`))
					case "GetWorkgroup":
						_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"w","workgroupArn":"arn:wg",` +
							`"namespaceName":"n","status":"AVAILABLE","publiclyAccessible":false}}`))
					case "GetNamespace":
						_, _ = w.Write([]byte(`{"namespace":{"namespaceName":"n","namespaceArn":"arn:ns",` +
							`"status":"AVAILABLE","kmsKeyId":"AWS_OWNED_KMS_KEY"}}`))
					case "ListTagsForResource":
						_, _ = w.Write([]byte(`{"tags":[{"key":"groundhold-capability","value":"lake"},` +
							`{"key":"groundhold-environment","value":"prod"}]}`))
					default:
						w.WriteHeader(400)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.RedshiftServerlessBaseURL = happyURL
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("redshiftserverless", "lake", "prod", rssAttrs(), nil, "lake", 1)
		},
		AllowedMutations: 2, // the two refused creates — namespace and workgroup
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D1208: updateRedshiftServerless remediates network.publicExposure in place — an
// UpdateWorkgroup that flips publiclyAccessible, so a public warehouse is made private WITHOUT
// replacing the workgroup (which would tear down its endpoint address). Ownership re-checked by
// tags; foreign refused with no UpdateWorkgroup.
func TestUpdateRedshiftServerlessPublicExposure(t *testing.T) {
	name := RSSName("prod", "lake", 1)
	newSrv := func(capLabel string, seen *[]bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch rssAction(r) {
			case "GetWorkgroup":
				_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"` + name + `","workgroupArn":"arn:wg",` +
					`"namespaceName":"n","status":"AVAILABLE","publiclyAccessible":true}}`))
			case "ListTagsForResource":
				_, _ = w.Write([]byte(`{"tags":[{"key":"groundhold-capability","value":"` + capLabel +
					`"},{"key":"groundhold-environment","value":"prod"}]}`))
			case "UpdateWorkgroup":
				body, _ := io.ReadAll(r.Body)
				var d struct {
					PubliclyAccessible bool `json:"publiclyAccessible"`
				}
				_ = json.Unmarshal(body, &d)
				*seen = append(*seen, d.PubliclyAccessible)
				_, _ = w.Write([]byte(`{"workgroup":{"workgroupName":"` + name + `","status":"MODIFYING","publiclyAccessible":false}}`))
			default:
				t.Errorf("unexpected action %q", rssAction(r))
				w.WriteHeader(400)
			}
		}))
	}

	t.Run("remediate public->private (UpdateWorkgroup publiclyAccessible=false)", func(t *testing.T) {
		var seen []bool
		srv := newSrv("lake", &seen)
		defer srv.Close()
		d := rssDriver(t, srv)
		pid := rssProviderID("eu-central-1", name)
		res := d.updateRedshiftServerless("lake", "prod", pid,
			map[string]any{"network.publicExposure": false}, nil, []string{"network.publicExposure"})
		if res.Status != "succeeded" {
			t.Fatalf("update: %+v", res)
		}
		if len(seen) != 1 || seen[0] != false {
			t.Fatalf("must UpdateWorkgroup publiclyAccessible=false, got %+v", seen)
		}
	})

	t.Run("foreign workgroup refused, no UpdateWorkgroup", func(t *testing.T) {
		var seen []bool
		srv := newSrv("someone-else", &seen)
		defer srv.Close()
		d := rssDriver(t, srv)
		pid := rssProviderID("eu-central-1", name)
		res := d.updateRedshiftServerless("lake", "prod", pid,
			map[string]any{"network.publicExposure": false}, nil, []string{"network.publicExposure"})
		if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
			t.Fatalf("a foreign workgroup must be refused, got %+v", res)
		}
		if len(seen) != 0 {
			t.Fatalf("a refused update must issue NO UpdateWorkgroup, got %+v", seen)
		}
	})
}

func TestClassifyRedshiftServerlessChange(t *testing.T) {
	if got, _ := classifyRedshiftServerlessChange("network.publicExposure"); got != "mutable" {
		t.Fatalf("network.publicExposure must be mutable (in-place), got %q", got)
	}
	for _, p := range []string{"location.region", "encryption.customerManagedKeys", "capacity.baseRPU"} {
		if got, _ := classifyRedshiftServerlessChange(p); got != "immutable" {
			t.Fatalf("%s must be immutable (replacement), got %q", p, got)
		}
	}
}
