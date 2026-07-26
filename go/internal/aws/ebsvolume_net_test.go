package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ebsVolServer routes on the EC2 Query Action, so a test states what the API
// answers rather than how the driver phrases the question.
type ebsVolServer struct {
	createStatus int
	createBody   string
	describe     []string // successive DescribeVolumes bodies; the last repeats
	describeErr  int      // non-zero: DescribeVolumes answers with this status
	deleteStatus int
	deleteBody   string
	calls        []string
	bodies       []string
	n            int
}

func (s *ebsVolServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		action := ""
		for _, kv := range strings.Split(string(body), "&") {
			if strings.HasPrefix(kv, "Action=") {
				action = strings.TrimPrefix(kv, "Action=")
			}
		}
		s.calls = append(s.calls, action)
		s.bodies = append(s.bodies, string(body))
		switch action {
		case "CreateVolume":
			w.WriteHeader(s.createStatus)
			_, _ = w.Write([]byte(s.createBody))
		case "DescribeVolumes":
			if s.describeErr != 0 {
				w.WriteHeader(s.describeErr)
				_, _ = w.Write([]byte(`<Response><Errors><Error><Code>InternalError</Code></Error></Errors></Response>`))
				return
			}
			i := s.n
			if i >= len(s.describe) {
				i = len(s.describe) - 1
			}
			s.n++
			_, _ = w.Write([]byte(s.describe[i]))
		case "DeleteVolume":
			w.WriteHeader(s.deleteStatus)
			_, _ = w.Write([]byte(s.deleteBody))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func ebsVolTestDriver(t *testing.T, s *ebsVolServer) (*Driver, func()) {
	t.Helper()
	// The driver refuses to sign without credentials — correct behaviour, and the
	// reason every test here injects a fake pair rather than relying on ambient ones.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET")
	srv := httptest.NewServer(s.handler())
	d := NewDriver("eu-central-1")
	d.EC2BaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	d.PollTimeout = 50 * time.Millisecond
	return d, srv.Close
}

const ebsCreateOKXML = `<CreateVolumeResponse><volumeId>vol-0123456789abcdef0</volumeId><status>creating</status></CreateVolumeResponse>`

const ebsAvailableXML = `<DescribeVolumesResponse><volumeSet><item>
<volumeId>vol-0123456789abcdef0</volumeId>
<status>available</status>
<availabilityZone>eu-central-1a</availabilityZone>
<encrypted>true</encrypted>
<kmsKeyId>arn:aws:kms:eu-central-1:000000000000:key/abc-123</kmsKeyId>
<tagSet><item><key>groundhold-capability</key><value>orders-data</value></item>
<item><key>groundhold-environment</key><value>production</value></item></tagSet>
</item></volumeSet></DescribeVolumesResponse>`

const ebsEmptyXML = `<DescribeVolumesResponse><volumeSet/></DescribeVolumesResponse>`

const ebsPID = "ebs:eu-central-1:000000000000:vol-0123456789abcdef0"

func TestCreateEBSVolumeHappyPath(t *testing.T) {
	s := &ebsVolServer{createStatus: 200, createBody: ebsCreateOKXML,
		describe: []string{ebsAvailableXML}}
	d, done := ebsVolTestDriver(t, s)
	defer done()

	got := d.createEBSVolume("eu-central-1", "000000000000", "production", "orders-data",
		ebsVolAttrs(), ebsVolImpl(), 0)
	if got.Status != "succeeded" {
		t.Fatalf("status = %q (%s), want succeeded", got.Status, got.Reason)
	}
	if got.ProviderID != ebsPID {
		t.Errorf("providerId = %q, want %q", got.ProviderID, ebsPID)
	}
}

// The mutation-honesty battery (D29). For a STATEFUL capability these verdicts
// carry more than usual: a create wrongly reported `failed` invites a retry, and
// a retry that is not deduplicated splits the data across two volumes.
func TestCreateEBSVolumeMutationHonesty(t *testing.T) {
	t.Run("5xx is unknown, never failed", func(t *testing.T) {
		s := &ebsVolServer{createStatus: 502, createBody: `<Response/>`}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.createEBSVolume("eu-central-1", "000000000000", "production", "orders-data",
			ebsVolAttrs(), ebsVolImpl(), 0)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown (a 502 can front a volume that exists)", got.Status)
		}
		if !strings.Contains(got.Reason, "ClientToken") {
			t.Errorf("reason %q does not say how to reconcile", got.Reason)
		}
	})
	t.Run("2xx with no volume id is unknown", func(t *testing.T) {
		s := &ebsVolServer{createStatus: 200, createBody: `<CreateVolumeResponse/>`}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.createEBSVolume("eu-central-1", "000000000000", "production", "orders-data",
			ebsVolAttrs(), ebsVolImpl(), 0)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown (a truncated body is not a successful create)", got.Status)
		}
	})
	t.Run("a definitive 4xx is failed", func(t *testing.T) {
		s := &ebsVolServer{createStatus: 400,
			createBody: `<Response><Errors><Error><Code>InvalidParameterValue</Code></Error></Errors></Response>`}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.createEBSVolume("eu-central-1", "000000000000", "production", "orders-data",
			ebsVolAttrs(), ebsVolImpl(), 0)
		if got.Status != "failed" {
			t.Errorf("status = %q, want failed", got.Status)
		}
	})
	t.Run("an idempotency mismatch refuses to bind", func(t *testing.T) {
		s := &ebsVolServer{createStatus: 400,
			createBody: `<Response><Errors><Error><Code>IdempotentParameterMismatch</Code></Error></Errors></Response>`}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.createEBSVolume("eu-central-1", "000000000000", "production", "orders-data",
			ebsVolAttrs(), ebsVolImpl(), 0)
		if got.Status != "failed" {
			t.Errorf("status = %q, want failed", got.Status)
		}
		if got.ProviderID != "" {
			t.Errorf("bound providerId %q on a token collision — that is the wrong disk, "+
				"and for a stateful capability the wrong data", got.ProviderID)
		}
	})
	t.Run("still creating at the deadline is unknown, never assumed good", func(t *testing.T) {
		creating := strings.Replace(ebsAvailableXML, "<status>available</status>", "<status>creating</status>", 1)
		s := &ebsVolServer{createStatus: 200, createBody: ebsCreateOKXML, describe: []string{creating}}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.createEBSVolume("eu-central-1", "000000000000", "production", "orders-data",
			ebsVolAttrs(), ebsVolImpl(), 0)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
		if got.ProviderID != ebsPID {
			t.Errorf("providerId = %q — an unknown create must still name what to reconcile", got.ProviderID)
		}
	})
	t.Run("state error is failed", func(t *testing.T) {
		bad := strings.Replace(ebsAvailableXML, "<status>available</status>", "<status>error</status>", 1)
		s := &ebsVolServer{createStatus: 200, createBody: ebsCreateOKXML, describe: []string{bad}}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.createEBSVolume("eu-central-1", "000000000000", "production", "orders-data",
			ebsVolAttrs(), ebsVolImpl(), 0)
		if got.Status != "failed" {
			t.Errorf("status = %q, want failed", got.Status)
		}
	})
}

func TestObserveEBSVolume(t *testing.T) {
	s := &ebsVolServer{describe: []string{ebsAvailableXML}}
	d, done := ebsVolTestDriver(t, s)
	defer done()

	obs, unread, err := d.observeEBSVolume("orders-data", ebsPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(unread) != 0 {
		t.Errorf("unread = %v on a fully readable volume", unread)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
		if o.Derivation != "measured" {
			t.Errorf("%s derivation = %q, want measured", o.Path, o.Derivation)
		}
	}
	want := map[string]any{
		"location.region":                "eu-central-1",
		"availability.class":             "zonal",
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

// The AWS-managed default key is the trap: it IS a KMS key, so a driver that
// checks only "is there a key id" certifies a BYOK control the customer cannot
// revoke.
func TestObserveEBSVolumeDoesNotCallTheAWSDefaultKeyCustomerManaged(t *testing.T) {
	body := strings.Replace(ebsAvailableXML,
		"arn:aws:kms:eu-central-1:000000000000:key/abc-123",
		"arn:aws:kms:eu-central-1:000000000000:alias/aws/ebs", 1)
	s := &ebsVolServer{describe: []string{body}}
	d, done := ebsVolTestDriver(t, s)
	defer done()

	obs, _, err := d.observeEBSVolume("orders-data", ebsPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "encryption.customerManagedKeys" && o.Value != false {
			t.Errorf("the aws/ebs default key was reported as customer-managed (%v)", o.Value)
		}
	}
}

// A read that fails must not become an observation. Defaulting an unreadable
// encryption state either way decides a constraint on evidence nobody has.
func TestObserveEBSVolumeReportsAnUnreadableStateRatherThanDefaultingIt(t *testing.T) {
	s := &ebsVolServer{describeErr: 500}
	d, done := ebsVolTestDriver(t, s)
	defer done()

	obs, _, err := d.observeEBSVolume("orders-data", ebsPID)
	if err == nil {
		t.Fatal("a 500 on the only read produced no error — the caller cannot tell " +
			"an unreadable volume from an unencrypted one")
	}
	if len(obs) != 0 {
		t.Errorf("observations %v were emitted despite the failed read", obs)
	}
	if !strings.Contains(err.Error(), "DescribeVolumes") {
		t.Errorf("diagnostic %q does not name the call that failed", err)
	}
}

func TestObserveEBSVolumeMissingIsNotAnError(t *testing.T) {
	s := &ebsVolServer{describe: []string{ebsEmptyXML}}
	d, done := ebsVolTestDriver(t, s)
	defer done()

	obs, unread, err := d.observeEBSVolume("orders-data", ebsPID)
	if err != nil {
		t.Fatalf("a volume that is simply absent produced an error: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("observations %v for a volume that does not exist", obs)
	}
	if len(unread) == 0 {
		t.Error("no diagnostic — the caller cannot tell an absent volume from a silent one")
	}
}

func TestDeleteEBSVolume(t *testing.T) {
	t.Run("deletes what it owns", func(t *testing.T) {
		s := &ebsVolServer{describe: []string{ebsAvailableXML}, deleteStatus: 200,
			deleteBody: `<DeleteVolumeResponse><return>true</return></DeleteVolumeResponse>`}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.deleteEBSVolume("orders-data", "production", ebsPID)
		if got.Status != "succeeded" {
			t.Fatalf("status = %q (%s)", got.Status, got.Reason)
		}
		var deleted bool
		for _, b := range s.bodies {
			if strings.Contains(b, "Action=DeleteVolume") && strings.Contains(b, "vol-0123456789abcdef0") {
				deleted = true
			}
		}
		if !deleted {
			t.Errorf("no DeleteVolume naming the pinned volume; calls = %v", s.calls)
		}
	})

	// The check that matters most on a stateful capability: someone else's volume
	// holds someone else's data, and a tag mismatch is the only thing standing
	// between a mis-pinned providerId and destroying it.
	t.Run("refuses a volume that is not ours", func(t *testing.T) {
		foreign := strings.Replace(ebsAvailableXML, "orders-data", "someone-elses-database", 1)
		s := &ebsVolServer{describe: []string{foreign}, deleteStatus: 200}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.deleteEBSVolume("orders-data", "production", ebsPID)
		if got.Status != "failed" {
			t.Fatalf("status = %q, want failed", got.Status)
		}
		for _, c := range s.calls {
			if c == "DeleteVolume" {
				t.Fatal("DeleteVolume was issued against a volume with foreign tags")
			}
		}
	})

	t.Run("an absent volume is already deleted", func(t *testing.T) {
		s := &ebsVolServer{describe: []string{ebsEmptyXML}}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		if got := d.deleteEBSVolume("orders-data", "production", ebsPID); got.Status != "succeeded" {
			t.Errorf("status = %q, want succeeded (idempotent)", got.Status)
		}
	})

	t.Run("an unreadable pre-delete read is unknown, never a delete", func(t *testing.T) {
		s := &ebsVolServer{describeErr: 500}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.deleteEBSVolume("orders-data", "production", ebsPID)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
		for _, c := range s.calls {
			if c == "DeleteVolume" {
				t.Fatal("DeleteVolume was issued without a successful ownership read")
			}
		}
	})

	t.Run("5xx on the delete is unknown", func(t *testing.T) {
		s := &ebsVolServer{describe: []string{ebsAvailableXML}, deleteStatus: 503, deleteBody: `<Response/>`}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		if got := d.deleteEBSVolume("orders-data", "production", ebsPID); got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
	})
}

func TestDiscoverEBSVolumes(t *testing.T) {
	s := &ebsVolServer{describe: []string{ebsAvailableXML}}
	d, done := ebsVolTestDriver(t, s)
	defer done()

	got, _, err := d.discoverEBSVolumes("eu-central-1")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("discovered %d volumes, want 1", len(got))
	}
	if got[0].ResourceType != "capability.storage.block" {
		t.Errorf("resourceType = %q", got[0].ResourceType)
	}
	if got[0].ProviderID != ebsPID {
		t.Errorf("providerId = %q", got[0].ProviderID)
	}
	if len(got[0].Observations) == 0 {
		t.Error("a discovered volume with no observations cannot be adopted")
	}
}

// A deleted volume lingering in discovery is something to adopt that no longer
// exists — and DescribeVolumes keeps reporting them for a while.
func TestDiscoverEBSVolumesSkipsDeleted(t *testing.T) {
	body := strings.Replace(ebsAvailableXML, "<status>available</status>", "<status>deleted</status>", 1)
	s := &ebsVolServer{describe: []string{body}}
	d, done := ebsVolTestDriver(t, s)
	defer done()

	got, _, err := d.discoverEBSVolumes("eu-central-1")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("discovered %d deleted volumes, want 0", len(got))
	}
}

func TestSplitEBSVolProviderID(t *testing.T) {
	region, account, id, err := splitEBSVolProviderID(ebsPID)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if region != "eu-central-1" || account != "000000000000" || id != "vol-0123456789abcdef0" {
		t.Errorf("split = %q/%q/%q", region, account, id)
	}
	for _, bad := range []string{
		"ec2:eu-central-1:000000000000:vol-0123456789abcdef0", // another service's id
		"ebs:eu-central-1:000000000000:i-0123456789abcdef0",   // an instance, not a volume
		"ebs::000000000000:vol-0123456789abcdef0",             // no region
		"ebs:eu-central-1:000000000000",                       // truncated
		"ebs:eu-central-1:000000000000:vol-../../etc/passwd",  // a path, not an id
	} {
		if _, _, _, err := splitEBSVolProviderID(bad); err == nil {
			t.Errorf("%q was accepted as an EBS providerId", bad)
		}
	}
}

// A create that never reaches the network still owes the caller a refusal, and a
// refusal is `failed` — nothing happened, so there is nothing to reconcile.
func TestCreateEBSVolumeRefusesBeforeTheNetwork(t *testing.T) {
	s := &ebsVolServer{createStatus: 200, createBody: ebsCreateOKXML}
	d, done := ebsVolTestDriver(t, s)
	defer done()

	impl := ebsVolImpl()
	delete(impl, "size_gb")
	got := d.createEBSVolume("eu-central-1", "000000000000", "production", "orders-data",
		ebsVolAttrs(), impl, 0)
	if got.Status != "failed" {
		t.Errorf("status = %q, want failed", got.Status)
	}
	if len(s.calls) != 0 {
		t.Errorf("the driver called %v before refusing — a refusal must happen before any mutation", s.calls)
	}
}
