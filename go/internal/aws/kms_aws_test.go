package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

const testKeyID = "12345678-90ab-cdef-1234-567890abcdef"

func awsKMSAttrs() map[string]any {
	return map[string]any{
		"location.region":  "eu-central-1",
		"rotation.period":  "90d", // AWS KMS minimum automatic rotation
		"protection.level": "hsm",
		"service.managed":  true,
	}
}

func TestBuildAWSKMSHonors(t *testing.T) {
	p, err := BuildAWSKMSKey("prod", "datakey", awsKMSAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Region != "eu-central-1" || p.RotationDays != 90 {
		t.Fatalf("plan = %+v", p)
	}
	j := p.createJSON("datakey", "prod")
	if !strings.Contains(j, `"KeyUsage":"ENCRYPT_DECRYPT"`) ||
		!strings.Contains(j, `"TagValue":"datakey"`) {
		t.Fatalf("json = %s", j)
	}
}

func TestBuildAWSKMSRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "eu-central-1", "protection.level": "hsm", "service.managed": true}
	}
	cases := map[string]map[string]any{
		"software-gap":      {"protection.level": "software"}, // AWS is always HSM
		"rotation-too-fast": {"rotation.period": "30d"},       // below 90 days
		"rotation-too-slow": {"rotation.period": "3000d"},     // above 2560 days
		"unmanaged":         {"service.managed": false},
		"unknown-attr":      {"key.material": "AAAA"},
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildAWSKMSKey("prod", "datakey", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing region
	if _, err := BuildAWSKMSKey("prod", "datakey",
		map[string]any{"protection.level": "hsm", "service.managed": true}, nil, 1); err == nil {
		t.Error("missing location.region must refuse")
	}
	// a key with no rotation (manual) is fine
	if _, err := BuildAWSKMSKey("prod", "datakey", base(), nil, 1); err != nil {
		t.Errorf("a key without rotation should build: %v", err)
	}
}

func awsKMSServer(t *testing.T, tagCap string, rotationEnabled bool, rotationDays int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			action := r.Header.Get("X-Amz-Target")
			action = action[strings.LastIndex(action, ".")+1:]
			switch action {
			case "ListKeys":
				// D253 create-adoption scan: the create Op's happy path has no
				// pre-existing key, so the scan finds none and a genuine create runs.
				_, _ = w.Write([]byte(`{"Keys":[]}`))
			case "CreateKey":
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyId":"` + testKeyID + `","KeyState":"Enabled"}}`))
			case "EnableKeyRotation", "ScheduleKeyDeletion":
				_, _ = w.Write([]byte(`{"KeyId":"` + testKeyID + `"}`))
			case "DescribeKey":
				_, _ = w.Write([]byte(`{"KeyMetadata":{"KeyId":"` + testKeyID + `","KeyState":"Enabled","Origin":"AWS_KMS"}}`))
			case "GetKeyRotationStatus":
				if rotationEnabled {
					_, _ = w.Write([]byte(`{"KeyRotationEnabled":true,"RotationPeriodInDays":` + itoaKMS(rotationDays) + `}`))
				} else {
					_, _ = w.Write([]byte(`{"KeyRotationEnabled":false}`))
				}
			case "ListResourceTags":
				_, _ = w.Write([]byte(`{"Tags":[` +
					`{"TagKey":"groundhold-capability","TagValue":"` + tagCap + `"},` +
					`{"TagKey":"groundhold-environment","TagValue":"prod"}]}`))
			default:
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"UnknownOperationException"}`))
			}
		}))
}

func itoaKMS(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func awsKMSDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.KMSBaseURL = srv.URL
	return d
}

func TestCreateObserveDeleteAWSKMS(t *testing.T) {
	srv := awsKMSServer(t, "datakey", true, 90)
	defer srv.Close()
	d := awsKMSDriver(t, srv)
	res := d.createAWSKMS("eu-central-1", "prod", "datakey", awsKMSAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != "akms:eu-central-1:"+testKeyID {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeAWSKMS("datakey", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" || got["protection.level"] != "hsm" ||
		got["rotation.period"] != "90d" {
		t.Fatalf("observe: %+v", got)
	}
	del := d.deleteAWSKMS("datakey", "prod", res.ProviderID)
	if del.Status != "succeeded" || !strings.Contains(del.Reason, "recovery window") {
		t.Fatalf("delete must succeed + note the recovery window: %+v", del)
	}
}

func TestDeleteAWSKMSForeignRefused(t *testing.T) {
	srv := awsKMSServer(t, "someone-else", false, 0)
	defer srv.Close()
	d := awsKMSDriver(t, srv)
	res := d.deleteAWSKMS("datakey", "prod", "akms:eu-central-1:"+testKeyID)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign key must refuse delete, got %+v", res)
	}
}

// kmsScanServer serves ListKeys (one key) + ListResourceTags (the given tags) —
// the create-adoption scan fixture (D253). Any mutation is a test failure.
func kmsScanServer(t *testing.T, keyID, capTag, envTag string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		action := r.Header.Get("X-Amz-Target")
		action = action[strings.LastIndex(action, ".")+1:]
		switch action {
		case "ListKeys":
			_, _ = w.Write([]byte(`{"Keys":[{"KeyId":"` + keyID + `"}]}`))
		case "ListResourceTags":
			_, _ = w.Write([]byte(`{"Tags":[` +
				`{"TagKey":"groundhold-capability","TagValue":"` + capTag + `"},` +
				`{"TagKey":"groundhold-environment","TagValue":"` + envTag + `"}]}`))
		default:
			t.Errorf("create-adoption must not call %s — bind the existing key, never create", action)
			w.WriteHeader(400)
		}
	}))
}

// TestFindKMSKeyByTags_VerifiesOwnership (D253): a key counts as ours only when its
// tags match; a FOREIGN-tagged key is never counted (never adopted).
func TestFindKMSKeyByTags_VerifiesOwnership(t *testing.T) {
	srv := kmsScanServer(t, testKeyID, "datakey", "prod")
	d := awsKMSDriver(t, srv)
	if id, n, ok := d.findKMSKeyByTags("eu-central-1", "datakey", "prod"); !ok || n != 1 || id != testKeyID {
		t.Fatalf("our-tagged key must count as 1 ours, got id=%q n=%d ok=%v", id, n, ok)
	}
	srv.Close()
	srv2 := kmsScanServer(t, testKeyID, "someone-else", "prod")
	d2 := awsKMSDriver(t, srv2)
	if id, n, ok := d2.findKMSKeyByTags("eu-central-1", "datakey", "prod"); !ok || n != 0 || id != "" {
		t.Fatalf("a FOREIGN-tagged key must never be counted as ours, got id=%q n=%d ok=%v", id, n, ok)
	}
	srv2.Close()
}

// TestCreateAWSKMS_AdoptsExistingOwned (D253): a create whose tag-scan finds our
// existing key BINDS it (succeeded + pid) and issues NO CreateKey.
func TestCreateAWSKMS_AdoptsExistingOwned(t *testing.T) {
	srv := kmsScanServer(t, testKeyID, "datakey", "prod") // default -> t.Errorf on any mutation
	defer srv.Close()
	d := awsKMSDriver(t, srv)
	res := d.createAWSKMS("eu-central-1", "prod", "datakey", awsKMSAttrs(), nil, 1)
	if res.Status != "succeeded" || res.ProviderID != awsKMSProviderID("eu-central-1", testKeyID) {
		t.Fatalf("must adopt the existing owned key (no CreateKey), got %+v", res)
	}
}

// kmsTarget classifies the X-Amz-Target JSON protocol, where every call is a POST and
// the method tells you nothing — reads are the list/describe family, everything else
// changes the world.
func kmsRole(req *http.Request, _ []byte) certifynet.Role {
	tgt := req.Header.Get("X-Amz-Target")
	tgt = tgt[strings.LastIndex(tgt, ".")+1:]
	switch tgt {
	case "ListKeys", "ListResourceTags", "DescribeKey", "GetKeyRotationStatus", "ListAliases":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingKMS enrolls KMS in the D391 create-time-adoption gate. KMS is
// D253's own example of the damage: a KeyId is server-assigned with no idempotency
// token, so a create that does not adopt mints a SECOND PAID KEY and leaves it out of
// the ledger. TestCreateAWSKMS_AdoptsExistingOwned pins the same property for this one
// driver; this enrolls it as a CLASS, through the public Create dispatch, with the
// mutation count as the proof.
func TestAdoptsExistingKMS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:           "aws/kms",
		Classify:       kmsRole,
		ExistingServer: func() *httptest.Server { return kmsScanServer(t, testKeyID, "datakey", "prod") },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.KMSBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("kms", "datakey", "prod",
				awsKMSAttrs(), nil, "datakey", 1)
		},
		PID: awsKMSProviderID("eu-central-1", testKeyID),
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// TestRefusesForeignDeleteKMS enrols KMS in the D439 delete-ownership gate, through the
// PUBLIC Delete dispatch and counting the wire. Its per-driver twin above calls
// deleteAWSKMS directly; this asserts the same refusal as a CLASS, and adds what the
// direct call cannot see — that no mutation went out before the refusal.
func TestRefusesForeignDeleteKMS(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ForeignProbe{
		Name:          "aws/kms",
		Classify:      kmsRole,
		ForeignServer: func() *httptest.Server { return awsKMSServer(t, "someone-else", false, 0) },
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.KMSBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			return d
		},
		Delete: func(pr provider.Provider) provider.CreateResult {
			return pr.Delete("kms", "datakey", "prod", "akms:eu-central-1:"+testKeyID, "k")
		},
	}
	certifynet.CertifyDeleteRefusesForeign(t, p)
}
