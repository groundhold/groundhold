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

func dynamoAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"availability.class":             "regional",
		"encryption.customerManagedKeys": true,
		"backup.pointInTimeRecovery":     true,
		"deletion.protection":            false,
		"service.managed":                true,
	}
}

func dynamoImpl() map[string]any {
	return map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
}

func TestBuildDynamoDBHonors(t *testing.T) {
	a := dynamoAttrs()
	a["deletion.protection"] = true
	p, err := BuildDynamoDB("prod", "sessions", a, dynamoImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.CMEK || p.KmsKeyId == "" || !p.PITR || !p.DeletionProtection {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("sessions", "prod")
	if body["SSESpecification"] == nil || body["DeletionProtectionEnabled"] != true {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildDynamoDBRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"multi-regional": {"availability.class": "multi-regional"}, // global tables refused v0
		"bad-avail":      {"availability.class": "planetary"},
		"unmanaged":      {"service.managed": false},
		"unknown-attr":   {"nosql.tier": "x"},
	}
	for name, extra := range cases {
		a := dynamoAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildDynamoDB("prod", "sessions", a, dynamoImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := dynamoAttrs()
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildDynamoDB("prod", "sessions", a, nil, 1); err == nil {
		t.Error("cmek without impl.kms_key_id must refuse")
	}
}

// dynamoServer is a happy JSON server: create ok, describe ACTIVE with the given
// flags, tags report ownership, continuous-backups reflects PITR, delete ok.
func dynamoServer(t *testing.T, capLabel string, pitr, delProt, cmek bool) *httptest.Server {
	t.Helper()
	target := func(r *http.Request) string {
		full := r.Header.Get("X-Amz-Target")
		return full[strings.LastIndex(full, ".")+1:]
	}
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// once deleted, the table is GONE — the delete's poll-to-absence (D968
			// class) must be able to confirm a ResourceNotFound, or a delete could
			// never conclude.
			if deleted && target(r) == "DescribeTable" {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"com.amazonaws.dynamodb.v20120810#ResourceNotFoundException"}`))
				return
			}
			switch target(r) {
			case "CreateTable":
				_, _ = w.Write([]byte(`{"TableDescription":{"TableStatus":"CREATING"}}`))
			case "DescribeTable":
				sse := ""
				if cmek {
					sse = `,"SSEDescription":{"Status":"ENABLED","SSEType":"KMS","KMSMasterKeyArn":"arn:aws:kms:eu-central-1:000000000000:key/abc"}`
				}
				dp := "false"
				if delProt {
					dp = "true"
				}
				_, _ = w.Write([]byte(`{"Table":{"TableStatus":"ACTIVE","TableArn":"arn:aws:dynamodb:eu-central-1:000000000000:table/t","DeletionProtectionEnabled":` + dp + sse + `}}`))
			case "ListTagsOfResource":
				_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"` + capLabel + `"},{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "UpdateContinuousBackups":
				_, _ = w.Write([]byte(`{"ContinuousBackupsDescription":{"ContinuousBackupsStatus":"ENABLED"}}`))
			case "DescribeContinuousBackups":
				st := "DISABLED"
				if pitr {
					st = "ENABLED"
				}
				_, _ = w.Write([]byte(`{"ContinuousBackupsDescription":{"PointInTimeRecoveryDescription":{"PointInTimeRecoveryStatus":"` + st + `"}}}`))
			case "DeleteTable":
				deleted = true
				_, _ = w.Write([]byte(`{"TableDescription":{"TableStatus":"DELETING"}}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func dynamoDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.DynamoDBBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

// TestClassifyDynamoDBChange (D1004): PITR + deletion.protection patch in place (mutable);
// region + schema are a replacement (immutable). Before this, dynamodb had no explicit
// classification, so disabling PITR read as a destructive stateful replacement.
func TestClassifyDynamoDBChange(t *testing.T) {
	for _, p := range []string{"backup.pointInTimeRecovery", "deletion.protection"} {
		if k, _ := classifyDynamoDBChange(p); k != "mutable" {
			t.Errorf("%s should be mutable (in-place patch), got %q", p, k)
		}
	}
	for _, p := range []string{"location.region", "availability.class"} {
		if k, _ := classifyDynamoDBChange(p); k != "immutable" {
			t.Errorf("%s should be immutable (replacement), got %q", p, k)
		}
	}
}

// TestDynamoDBUpdateInPlace (D1004): a PITR change patches via UpdateContinuousBackups and a
// deletion.protection change via UpdateTable — on the LIVE table, no replacement. The bodies
// carry the DECLARED values (disable is expressible, not just enable).
func TestDynamoDBUpdateInPlace(t *testing.T) {
	var pitrBody, updTableBody string
	deleted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch t := r.Header.Get("X-Amz-Target"); {
		case strings.HasSuffix(t, "DescribeTable"):
			_, _ = w.Write([]byte(`{"Table":{"TableStatus":"ACTIVE","TableArn":"arn:aws:dynamodb:eu-central-1:000000000000:table/t","DeletionProtectionEnabled":false}}`))
		case strings.HasSuffix(t, "ListTagsOfResource"):
			_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"sessions"},{"Key":"groundhold-environment","Value":"prod"}]}`))
		case strings.HasSuffix(t, "UpdateContinuousBackups"):
			pitrBody = string(b)
			_, _ = w.Write([]byte(`{"ContinuousBackupsDescription":{"ContinuousBackupsStatus":"ENABLED"}}`))
		case strings.HasSuffix(t, "UpdateTable"):
			updTableBody = string(b)
			_, _ = w.Write([]byte(`{"TableDescription":{"TableStatus":"ACTIVE"}}`))
		default:
			_ = deleted
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := dynamoDriver(t, srv)
	pid := dynamoProviderID("eu-central-1", "000000000000", "sessions")

	// disable PITR — must be UpdateContinuousBackups with Enabled:false, NOT a replacement.
	a := dynamoAttrs()
	a["backup.pointInTimeRecovery"] = false
	res := d.updateDynamoDB("sessions", "prod", pid, a, dynamoImpl(), []string{"backup.pointInTimeRecovery"})
	if res.Status != "succeeded" {
		t.Fatalf("PITR update: %+v", res)
	}
	if !strings.Contains(pitrBody, `"PointInTimeRecoveryEnabled":false`) {
		t.Fatalf("PITR disable must send Enabled:false, got %s", pitrBody)
	}

	// enable deletion protection — UpdateTable with DeletionProtectionEnabled:true.
	a2 := dynamoAttrs()
	a2["deletion.protection"] = true
	res = d.updateDynamoDB("sessions", "prod", pid, a2, dynamoImpl(), []string{"deletion.protection"})
	if res.Status != "succeeded" {
		t.Fatalf("deletion.protection update: %+v", res)
	}
	if !strings.Contains(updTableBody, `"DeletionProtectionEnabled":true`) {
		t.Fatalf("deletion.protection must send UpdateTable DeletionProtectionEnabled:true, got %s", updTableBody)
	}
}

func TestCreateObserveDeleteDynamoDB(t *testing.T) {
	srv := dynamoServer(t, "sessions", true, false, true)
	defer srv.Close()
	d := dynamoDriver(t, srv)
	res := d.createDynamoDB("eu-central-1", "000000000000", "prod", "sessions", dynamoAttrs(), dynamoImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "dynamodb:eu-central-1:000000000000:pv-") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeDynamoDB("sessions", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" ||
		got["backup.pointInTimeRecovery"] != true || got["deletion.protection"] != false {
		t.Fatalf("observe: %+v", got)
	}
	// customerManagedKeys is unobservable via DescribeTable (managed vs customer
	// KMS key is indistinguishable by ARN, the RDS case) — never fabricated.
	if _, has := got["encryption.customerManagedKeys"]; has {
		t.Fatalf("cmek must not be observed, got %v", got["encryption.customerManagedKeys"])
	}
	if del := d.deleteDynamoDB("sessions", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

// TestDeleteDynamoDBAsyncNotGoneIsUnknown pins D968-class for DynamoDB: a delete
// the provider ACCEPTS but that leaves the table DELETING (not gone) must report
// unknown, never a terminal "succeeded" that tombstones a table still live.
func TestDeleteDynamoDBAsyncNotGoneIsUnknown(t *testing.T) {
	target := func(r *http.Request) string {
		full := r.Header.Get("X-Amz-Target")
		return full[strings.LastIndex(full, ".")+1:]
	}
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch target(r) {
			case "DescribeTable": // never gone — stays ACTIVE
				_, _ = w.Write([]byte(`{"Table":{"TableStatus":"ACTIVE","TableArn":"arn:aws:dynamodb:eu-central-1:000000000000:table/t","DeletionProtectionEnabled":false}}`))
			case "ListTagsOfResource":
				_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"sessions"},{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "DeleteTable":
				_, _ = w.Write([]byte(`{"TableDescription":{"TableStatus":"DELETING"}}`))
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := dynamoDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the table never leaves DELETING → times out fast
	pid := dynamoProviderID("eu-central-1", "000000000000", DynamoTableName("prod", "sessions", 1))
	res := d.deleteDynamoDB("sessions", "prod", pid)
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-still-DELETING table must be unknown (keep the handle), "+
			"got %+v — reporting succeeded tombstones a table still live and billing", res)
	}
}

func TestDeleteDynamoDBProtectedRefused(t *testing.T) {
	srv := dynamoServer(t, "sessions", false, true, false) // deletion protection ON
	defer srv.Close()
	d := dynamoDriver(t, srv)
	pid := dynamoProviderID("eu-central-1", "000000000000", DynamoTableName("prod", "sessions", 1))
	res := d.deleteDynamoDB("sessions", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "deletion protection") {
		t.Fatalf("protected table must refuse delete, got %+v", res)
	}
}

func TestDeleteDynamoDBForeignRefused(t *testing.T) {
	srv := dynamoServer(t, "someone-else", false, false, false)
	defer srv.Close()
	d := dynamoDriver(t, srv)
	pid := dynamoProviderID("eu-central-1", "000000000000", DynamoTableName("prod", "sessions", 1))
	res := d.deleteDynamoDB("sessions", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign table must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.database.nosql on AWS DynamoDB. A STATEFUL fake records the
// DeletionProtectionEnabled and SSE flags CreateTable writes and the PITR flag
// UpdateContinuousBackups writes, and reflects them on the reads; the test varies
// (deletion.protection, cmek, pitr) and asserts observe reverse-maps them.
func TestMetamorphicDynamoDBRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		delProt bool
		cmek    bool
		pitr    bool
	}{
		{"bare", false, false, false},
		{"full", true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := func(r *http.Request) string {
				full := r.Header.Get("X-Amz-Target")
				return full[strings.LastIndex(full, ".")+1:]
			}
			var delProt, cmek, pitr bool
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch target(r) {
					case "CreateTable":
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							DeletionProtectionEnabled bool `json:"DeletionProtectionEnabled"`
							SSESpecification          *struct {
								SSEType string `json:"SSEType"`
							} `json:"SSESpecification"`
						}
						_ = json.Unmarshal(body, &doc)
						delProt = doc.DeletionProtectionEnabled
						cmek = doc.SSESpecification != nil && doc.SSESpecification.SSEType == "KMS"
						_, _ = w.Write([]byte(`{"TableDescription":{"TableStatus":"CREATING"}}`))
					case "DescribeTable":
						sse := ""
						if cmek {
							sse = `,"SSEDescription":{"SSEType":"KMS","KMSMasterKeyArn":"arn:aws:kms:x:y:key/z"}`
						}
						dp := "false"
						if delProt {
							dp = "true"
						}
						_, _ = w.Write([]byte(`{"Table":{"TableStatus":"ACTIVE","DeletionProtectionEnabled":` + dp + sse + `}}`))
					case "UpdateContinuousBackups":
						pitr = true
						_, _ = w.Write([]byte(`{}`))
					case "DescribeContinuousBackups":
						st := "DISABLED"
						if pitr {
							st = "ENABLED"
						}
						_, _ = w.Write([]byte(`{"ContinuousBackupsDescription":{"PointInTimeRecoveryDescription":{"PointInTimeRecoveryStatus":"` + st + `"}}}`))
					default:
						_, _ = w.Write([]byte(`{}`))
					}
				}))
			defer srv.Close()
			d := dynamoDriver(t, srv)
			a := dynamoAttrs()
			a["deletion.protection"] = c.delProt
			a["backup.pointInTimeRecovery"] = c.pitr
			impl := map[string]any{}
			if c.cmek {
				a["encryption.customerManagedKeys"] = true
				impl["kms_key_id"] = "arn:aws:kms:x:y:key/z"
			} else {
				a["encryption.customerManagedKeys"] = false
			}
			res := d.createDynamoDB("eu-central-1", "000000000000", "prod", "sessions", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, diags, err := d.observeDynamoDB("sessions", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["deletion.protection"] != c.delProt {
				t.Errorf("delProt round-trip: want %v got %v", c.delProt, got["deletion.protection"])
			}
			if got["backup.pointInTimeRecovery"] != c.pitr {
				t.Errorf("pitr round-trip: want %v got %v", c.pitr, got["backup.pointInTimeRecovery"])
			}
			// customerManagedKeys is NOT observable from DescribeTable: SSEType=KMS
			// covers BOTH the AWS-managed aws/dynamodb key and a customer key, whose
			// ARNs are indistinguishable without a KMS DescribeKey lookup (the RDS
			// case). So observe never reports it — even for a table groundhold created
			// with a customer key — and emits a diagnostic when a KMS key is set.
			if _, has := got["encryption.customerManagedKeys"]; has {
				t.Errorf("cmek must be unobservable via DescribeTable, got %v (fabricated)",
					got["encryption.customerManagedKeys"])
			}
			hasDiag := false
			for _, dg := range diags {
				if strings.Contains(dg, "customerManagedKeys not observed") {
					hasDiag = true
				}
			}
			if c.cmek && !hasDiag {
				t.Errorf("a KMS-key table must emit a customerManagedKeys diagnostic, got %v", diags)
			}
		})
	}
}

func ddbRole(req *http.Request, _ []byte) certifynet.Role {
	full := req.Header.Get("X-Amz-Target")
	switch full[strings.LastIndex(full, ".")+1:] {
	case "DescribeTable", "ListTagsOfResource", "DescribeContinuousBackups", "ListTables":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingDynamoDB enrols dynamodb in the D391 gate. The table name is
// deterministic, a second CreateTable is answered ResourceInUseException, and the tags
// decide. A duplicated table would be the data-loss shape of this class: the new one is
// empty and the application writes to it.
func TestAdoptsExistingDynamoDB(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/dynamodb",
		Classify: ddbRole,
		ExistingServer: func() *httptest.Server {
			target := func(r *http.Request) string {
				full := r.Header.Get("X-Amz-Target")
				return full[strings.LastIndex(full, ".")+1:]
			}
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch target(r) {
					case "CreateTable":
						w.WriteHeader(400)
						_, _ = w.Write([]byte(`{"__type":"ResourceInUseException","message":"exists"}`))
					case "DescribeTable":
						_, _ = w.Write([]byte(`{"Table":{"TableStatus":"ACTIVE",` +
							`"TableArn":"arn:aws:dynamodb:eu-central-1:000000000000:table/t",` +
							`"DeletionProtectionEnabled":true,` +
							`"SSEDescription":{"Status":"ENABLED","SSEType":"KMS",` +
							`"KMSMasterKeyArn":"arn:aws:kms:eu-central-1:000000000000:key/abc"}}}`))
					case "ListTagsOfResource":
						_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"sessions"},` +
							`{"Key":"groundhold-environment","Value":"prod"}]}`))
					case "DescribeContinuousBackups":
						_, _ = w.Write([]byte(`{"ContinuousBackupsDescription":` +
							`{"PointInTimeRecoveryDescription":{"PointInTimeRecoveryStatus":"ENABLED"}}}`))
					case "UpdateContinuousBackups", "UpdateTable", "TagResource":
						_, _ = w.Write([]byte(`{}`))
					default:
						w.WriteHeader(400)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.DynamoDBBaseURL = happyURL
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("dynamodb", "sessions", "prod", dynamoAttrs(), dynamoImpl(), "sessions", 1)
		},
		AllowedMutations: 3, // the refused create + backup/protection convergence
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// TestRefusesForeignDeleteDynamoDB enrols dynamodb in the D439 gate. A table delete takes
// the DATA with it — this is the delete-side counterpart of D405's observation that a
// duplicated table is the data-loss variant of duplication.
func TestRefusesForeignDeleteDynamoDB(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ForeignProbe{
		Name:     "aws/dynamodb",
		Classify: ddbRole,
		ForeignServer: func() *httptest.Server {
			return dynamoServer(t, "someone-else", false, false, false)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.DynamoDBBaseURL = happyURL
			d.Now = time.Now
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Delete: func(pr provider.Provider) provider.CreateResult {
			return pr.Delete("dynamodb", "sessions", "prod",
				dynamoProviderID("eu-central-1", "000000000000", DynamoTableName("prod", "sessions", 1)), "k")
		},
	}
	certifynet.CertifyDeleteRefusesForeign(t, p)
}

// D799. "Regional" was written as a platform invariant — a claim that a DynamoDB table
// cannot be anything else. Global Tables are exactly that something else, and the driver
// never read the field that says so, so a table replicating its rows into three regions
// satisfied an EU-only residency contract.
func TestDynamoGlobalTableIsNotCalledRegional(t *testing.T) {
	var desc dynamoTableDesc
	if err := json.Unmarshal([]byte(
		`{"TableStatus":"ACTIVE","Replicas":[{"RegionName":"us-east-1"},{"RegionName":"ap-south-1"}]}`),
		&desc); err != nil {
		t.Fatal(err)
	}
	if got := dynamoAvailability(desc); got != "multi-regional" {
		t.Fatalf("a global table reported as %q", got)
	}
	if got := dynamoReplicaRegions(desc); len(got) != 2 || got[0] != "ap-south-1" {
		t.Fatalf("replica regions not read: %v", got)
	}
}

func TestDynamoPlainTableStaysRegional(t *testing.T) {
	var desc dynamoTableDesc
	if err := json.Unmarshal([]byte(`{"TableStatus":"ACTIVE"}`), &desc); err != nil {
		t.Fatal(err)
	}
	if got := dynamoAvailability(desc); got != "regional" {
		t.Fatalf("a single-region table reported as %q", got)
	}
}

// TestRefusesForeignUpdateDynamoDB (D1004): updateDynamoDB refuses a table whose tags are a
// stranger's — a patch must not touch a resource groundhold does not own.
func TestRefusesForeignUpdateDynamoDB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch t := r.Header.Get("X-Amz-Target"); {
		case strings.HasSuffix(t, "DescribeTable"):
			_, _ = w.Write([]byte(`{"Table":{"TableStatus":"ACTIVE","TableArn":"arn:aws:dynamodb:eu-central-1:000000000000:table/t","DeletionProtectionEnabled":false}}`))
		case strings.HasSuffix(t, "ListTagsOfResource"):
			_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"someone-else"},{"Key":"groundhold-environment","Value":"prod"}]}`))
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	d := dynamoDriver(t, srv)
	pid := dynamoProviderID("eu-central-1", "000000000000", "sessions")
	res := d.updateDynamoDB("sessions", "prod", pid, dynamoAttrs(), dynamoImpl(), []string{"deletion.protection"})
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign table update must refuse, got %+v", res)
	}
}
