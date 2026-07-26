package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

// ec2InstanceServer routes on the EC2 Query Action, so a test states what the API
// answers rather than how the driver phrases the question.
type ec2InstanceServer struct {
	runStatus   int
	runBody     string
	describe    []string // successive DescribeInstances bodies; the last repeats
	describeErr int      // non-zero: DescribeInstances answers with this status
	volumeBody  string
	volumeErr   int
	termStatus  int
	termBody    string
	calls       []string
	n           int
}

func (s *ec2InstanceServer) handler() http.HandlerFunc {
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
		switch action {
		case "RunInstances":
			w.WriteHeader(s.runStatus)
			_, _ = w.Write([]byte(s.runBody))
		case "DescribeInstances":
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
		case "DescribeVolumes":
			if s.volumeErr != 0 {
				w.WriteHeader(s.volumeErr)
				_, _ = w.Write([]byte(`<Response><Errors><Error><Code>InternalError</Code></Error></Errors></Response>`))
				return
			}
			_, _ = w.Write([]byte(s.volumeBody))
		case "TerminateInstances":
			w.WriteHeader(s.termStatus)
			_, _ = w.Write([]byte(s.termBody))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func ec2TestDriver(t *testing.T, s *ec2InstanceServer) (*Driver, func()) {
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

const ec2RunningXML = `<DescribeInstancesResponse><reservationSet><item><instancesSet><item>
<instanceId>i-0123456789abcdef0</instanceId>
<instanceState><name>running</name></instanceState>
<subnetId>subnet-0abc123456789def0</subnetId>
<blockDeviceMapping><item><ebs><volumeId>vol-0123456789abcdef0</volumeId></ebs></item></blockDeviceMapping>
<tagSet><item><key>groundhold-capability</key><value>web</value></item>
<item><key>groundhold-environment</key><value>production</value></item></tagSet>
</item></instancesSet></item></reservationSet></DescribeInstancesResponse>`

const ec2RunOKXML = `<RunInstancesResponse><instancesSet><item><instanceId>i-0123456789abcdef0</instanceId></item></instancesSet></RunInstancesResponse>`

func TestCreateEC2InstanceHappyPath(t *testing.T) {
	s := &ec2InstanceServer{runStatus: 200, runBody: ec2RunOKXML, describe: []string{ec2RunningXML}}
	d, done := ec2TestDriver(t, s)
	defer done()

	got := d.createEC2Instance("eu-central-1", "000000000000", "production", "web",
		ec2Attrs(), ec2Impl(), 0)
	if got.Status != "succeeded" {
		t.Fatalf("status = %q (%s), want succeeded", got.Status, got.Reason)
	}
	if got.ProviderID != "ec2:eu-central-1:000000000000:i-0123456789abcdef0" {
		t.Errorf("providerId = %q", got.ProviderID)
	}
}

// The mutation-honesty battery (D29): the executor trusts these verdicts, so each
// branch is pinned rather than assumed.
func TestCreateEC2InstanceMutationHonesty(t *testing.T) {
	t.Run("5xx is unknown, never failed", func(t *testing.T) {
		s := &ec2InstanceServer{runStatus: 502, runBody: `<Response/>`}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.createEC2Instance("eu-central-1", "000000000000", "production", "web", ec2Attrs(), ec2Impl(), 0)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown — a 502 can front an instance that started", got.Status)
		}
	})

	t.Run("2xx with no instance id is unknown", func(t *testing.T) {
		s := &ec2InstanceServer{runStatus: 200, runBody: `<RunInstancesResponse></RunInstancesResponse>`}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.createEC2Instance("eu-central-1", "000000000000", "production", "web", ec2Attrs(), ec2Impl(), 0)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown — a truncated body is not a successful create", got.Status)
		}
	})

	t.Run("transport error is unknown", func(t *testing.T) {
		s := &ec2InstanceServer{runStatus: 200, runBody: ec2RunOKXML}
		d, done := ec2TestDriver(t, s)
		done() // close the server first: the call cannot reach it
		got := d.createEC2Instance("eu-central-1", "000000000000", "production", "web", ec2Attrs(), ec2Impl(), 0)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown — the request may still have landed", got.Status)
		}
	})

	t.Run("idempotency mismatch is failed, not a silent bind", func(t *testing.T) {
		s := &ec2InstanceServer{runStatus: 400,
			runBody: `<Response><Errors><Error><Code>IdempotentParameterMismatch</Code></Error></Errors></Response>`}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.createEC2Instance("eu-central-1", "000000000000", "production", "web", ec2Attrs(), ec2Impl(), 0)
		if got.Status != "failed" || !strings.Contains(got.Reason, "refusing to bind") {
			t.Errorf("status = %q (%s), want failed with a refusal to bind", got.Status, got.Reason)
		}
	})
}

func TestPollEC2InstanceOutcomes(t *testing.T) {
	terminated := strings.Replace(ec2RunningXML, "<name>running</name>", "<name>shutting-down</name>", 1)

	t.Run("a machine that never runs is failed", func(t *testing.T) {
		s := &ec2InstanceServer{runStatus: 200, runBody: ec2RunOKXML, describe: []string{terminated}}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.createEC2Instance("eu-central-1", "000000000000", "production", "web", ec2Attrs(), ec2Impl(), 0)
		if got.Status != "failed" {
			t.Errorf("status = %q, want failed", got.Status)
		}
	})

	t.Run("still pending at the deadline is unknown", func(t *testing.T) {
		pending := strings.Replace(ec2RunningXML, "<name>running</name>", "<name>pending</name>", 1)
		s := &ec2InstanceServer{runStatus: 200, runBody: ec2RunOKXML, describe: []string{pending}}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.createEC2Instance("eu-central-1", "000000000000", "production", "web", ec2Attrs(), ec2Impl(), 0)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown — a slow start is not a failure", got.Status)
		}
	})
}

func TestObserveEC2Instance(t *testing.T) {
	const encryptedCMK = `<DescribeVolumesResponse><volumeSet><item>
<encrypted>true</encrypted><kmsKeyId>arn:aws:kms:eu-central-1:000000000000:key/abc</kmsKeyId>
</item></volumeSet></DescribeVolumesResponse>`

	s := &ec2InstanceServer{describe: []string{ec2RunningXML}, volumeBody: encryptedCMK}
	d, done := ec2TestDriver(t, s)
	defer done()

	obs, unread, err := d.observeEC2Instance("web", "ec2:eu-central-1:000000000000:i-0123456789abcdef0")
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(unread) != 0 {
		t.Errorf("unexpected unread notes: %v", unread)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	for path, want := range map[string]any{
		"location.region":                "eu-central-1",
		"availability.class":             "zonal",
		"network.publicExposure":         false, // no publicIpAddress in the fixture
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	} {
		if got[path] != want {
			t.Errorf("%s = %v, want %v", path, got[path], want)
		}
	}
}

// An AWS-managed default key is NOT customer-managed: reporting true would
// certify a BYOK control the customer cannot revoke.
func TestObserveEC2InstanceDefaultKeyIsNotCustomerManaged(t *testing.T) {
	const defaultKey = `<DescribeVolumesResponse><volumeSet><item>
<encrypted>true</encrypted><kmsKeyId>alias/aws/ebs</kmsKeyId>
</item></volumeSet></DescribeVolumesResponse>`

	s := &ec2InstanceServer{describe: []string{ec2RunningXML}, volumeBody: defaultKey}
	d, done := ec2TestDriver(t, s)
	defer done()

	obs, _, err := d.observeEC2Instance("web", "ec2:eu-central-1:000000000000:i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range obs {
		if o.Path == "encryption.customerManagedKeys" && o.Value != false {
			t.Error("the account default EBS key was reported as customer-managed — " +
				"that certifies a revocable-key control the customer does not have")
		}
	}
}

// An unreadable disk must be REPORTED as unread, never defaulted: false would fail
// a CMK constraint reality satisfies, true would pass one reality violates.
func TestObserveEC2InstanceUnreadableVolumeIsNotDefaulted(t *testing.T) {
	s := &ec2InstanceServer{describe: []string{ec2RunningXML}, volumeErr: 500}
	d, done := ec2TestDriver(t, s)
	defer done()

	obs, unread, err := d.observeEC2Instance("web", "ec2:eu-central-1:000000000000:i-0123456789abcdef0")
	if err != nil {
		t.Fatal(err)
	}
	if len(unread) == 0 {
		t.Fatal("an unreadable volume produced no unread note")
	}
	for _, o := range obs {
		if o.Path == "encryption.atRest" || o.Path == "encryption.customerManagedKeys" {
			t.Errorf("%s was reported as %v although the volume could not be read", o.Path, o.Value)
		}
	}
}

func TestDeleteEC2Instance(t *testing.T) {
	t.Run("terminates our own machine", func(t *testing.T) {
		s := &ec2InstanceServer{describe: []string{ec2RunningXML}, termStatus: 200, termBody: `<TerminateInstancesResponse/>`}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.deleteEC2Instance("web", "production", "ec2:eu-central-1:000000000000:i-0123456789abcdef0")
		if got.Status != "succeeded" {
			t.Errorf("status = %q (%s), want succeeded", got.Status, got.Reason)
		}
	})

	t.Run("refuses a machine that is not ours", func(t *testing.T) {
		foreign := strings.Replace(ec2RunningXML, "<value>web</value>", "<value>someone-else</value>", 1)
		s := &ec2InstanceServer{describe: []string{foreign}}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.deleteEC2Instance("web", "production", "ec2:eu-central-1:000000000000:i-0123456789abcdef0")
		if got.Status != "failed" || !strings.Contains(got.Reason, "not ours") {
			t.Errorf("status = %q (%s), want a refusal to terminate someone else's machine", got.Status, got.Reason)
		}
		for _, c := range s.calls {
			if c == "TerminateInstances" {
				t.Fatal("a foreign machine was terminated — the ownership check is the only thing between us and someone else's production")
			}
		}
	})

	t.Run("an already-gone machine is idempotently succeeded", func(t *testing.T) {
		s := &ec2InstanceServer{describe: []string{`<DescribeInstancesResponse><reservationSet/></DescribeInstancesResponse>`}}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.deleteEC2Instance("web", "production", "ec2:eu-central-1:000000000000:i-0123456789abcdef0")
		if got.Status != "succeeded" {
			t.Errorf("status = %q, want succeeded (delete is idempotent)", got.Status)
		}
	})

	t.Run("an unreadable pre-delete state is unknown, never a delete", func(t *testing.T) {
		s := &ec2InstanceServer{describeErr: 500}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.deleteEC2Instance("web", "production", "ec2:eu-central-1:000000000000:i-0123456789abcdef0")
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown — we do not terminate what we could not read", got.Status)
		}
		for _, c := range s.calls {
			if c == "TerminateInstances" {
				t.Fatal("terminated a machine whose ownership was never established")
			}
		}
	})

	t.Run("a 5xx on terminate is unknown", func(t *testing.T) {
		s := &ec2InstanceServer{describe: []string{ec2RunningXML}, termStatus: 503, termBody: `<Response/>`}
		d, done := ec2TestDriver(t, s)
		defer done()
		got := d.deleteEC2Instance("web", "production", "ec2:eu-central-1:000000000000:i-0123456789abcdef0")
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown — the terminate may have landed", got.Status)
		}
	})
}

func TestSplitEC2InstanceProviderID(t *testing.T) {
	for _, bad := range []string{
		"ec2:eu-central-1:000000000000:not-an-instance",
		"ec2:eu-central-1:000000000000",
		"rds:eu-central-1:000000000000:i-0123456789abcdef0",
		"ec2::000000000000:i-0123456789abcdef0",
	} {
		if _, _, _, err := splitEC2InstanceProviderID(bad); err == nil {
			t.Errorf("%q was accepted as a provider id", bad)
		}
	}
	region, account, id, err := splitEC2InstanceProviderID("ec2:eu-central-1:000000000000:i-0123456789abcdef0")
	if err != nil || region != "eu-central-1" || account != "000000000000" || id != "i-0123456789abcdef0" {
		t.Errorf("round trip failed: %q %q %q %v", region, account, id, err)
	}
}

// Layer 5 (D87): the adversarial honesty harness injects transport faults, 5xx,
// truncated bodies and mid-flight failures into every mutating call, and asserts
// the driver never reports a verdict stronger than the evidence.
//
// A machine is the sharpest case for this. A create reported `failed` that
// actually landed leaves an instance running and unbound — billed, unmanaged and
// invisible to the contract that was supposed to govern it.
func TestEC2InstanceHonestyNet(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET")

	pid := "ec2:eu-central-1:000000000000:i-0123456789abcdef0"
	happy := func() *httptest.Server {
		s := &ec2InstanceServer{
			runStatus: 200, runBody: ec2RunOKXML,
			describe:   []string{ec2RunningXML},
			volumeBody: `<DescribeVolumesResponse><volumeSet><item><encrypted>true</encrypted></item></volumeSet></DescribeVolumesResponse>`,
			termStatus: 200, termBody: `<TerminateInstancesResponse/>`,
		}
		return httptest.NewServer(s.handler())
	}

	p := &certifynet.Probe{
		Name:            "aws/ec2",
		AssertTransient: true,         // D237: create/delete route through provider.MutationResult
		Classify:        queryXMLRole, // Query-XML: RunInstances is parsed for its instanceId
		OwnerTagValue:   "web",
		DeterministicID: false, // the instance id is server-assigned; ClientToken recovers it
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: happy,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Create("ec2", "web", "production", ec2Attrs(), ec2Impl(), "k", 0)
				},
			},
			{
				Name:  "delete",
				Happy: happy,
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.Delete("ec2", "web", "production", pid, "k")
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}
