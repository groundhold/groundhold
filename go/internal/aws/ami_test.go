package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/provider"
)

type amiServer struct {
	images     string
	imagesErr  int
	snapshot   string
	snapshotEr int
	calls      []string
	bodies     []string
}

func (s *amiServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		s.bodies = append(s.bodies, string(body))
		action := actionOf(string(body))
		s.calls = append(s.calls, action)
		switch action {
		case "DescribeImages":
			if s.imagesErr != 0 {
				w.WriteHeader(s.imagesErr)
				_, _ = w.Write([]byte(`<Response><Errors><Error><Code>InternalError</Code></Error></Errors></Response>`))
				return
			}
			_, _ = w.Write([]byte(s.images))
		case "DescribeSnapshots":
			if s.snapshotEr != 0 {
				w.WriteHeader(s.snapshotEr)
				_, _ = w.Write([]byte(`<Response><Errors><Error><Code>InternalError</Code></Error></Errors></Response>`))
				return
			}
			_, _ = w.Write([]byte(s.snapshot))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func amiTestDriver(t *testing.T, s *amiServer) (*Driver, func()) {
	t.Helper()
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

const amiPrivateXML = `<DescribeImagesResponse><imagesSet><item>
<imageId>ami-0123456789abcdef0</imageId>
<isPublic>false</isPublic>
<blockDeviceMapping><item><ebs><snapshotId>snap-0123456789abcdef0</snapshotId></ebs></item></blockDeviceMapping>
</item></imagesSet></DescribeImagesResponse>`

const amiSnapCMKXML = `<DescribeSnapshotsResponse><snapshotSet><item>
<encrypted>true</encrypted>
<kmsKeyId>arn:aws:kms:eu-central-1:000000000000:key/abc-123</kmsKeyId>
</item></snapshotSet></DescribeSnapshotsResponse>`

const amiPID = "ami:eu-central-1:000000000000:ami-0123456789abcdef0"

// The witness predicate is the design decision this driver exists to make, and
// BOTH halves matter. A predicate that returned true for the whole provider would
// silently stop groundhold creating anything on AWS at all.
func TestAWSWitnessPredicateIsPerServiceAndNarrow(t *testing.T) {
	if provider.CanAuthor("aws", "ami") {
		t.Error("aws/ami reports as authorable — the compiler would emit a create the " +
			"driver refuses, which is the exact lie D177 exists to prevent")
	}
	for _, svc := range []string{"ec2", "ebs", "s3", "rds", "lambda", "eks"} {
		if !provider.CanAuthor("aws", svc) {
			t.Errorf("aws/%s stopped being authorable — the witness predicate is too broad "+
				"and groundhold would silently create nothing", svc)
		}
	}
}

func TestObserveAMI(t *testing.T) {
	s := &amiServer{images: amiPrivateXML, snapshot: amiSnapCMKXML}
	d, done := amiTestDriver(t, s)
	defer done()

	obs, unread, err := d.observeAMI("base-image", amiPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
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
		"network.publicExposure":         false,
		"encryption.atRest":              true,
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	// The whole point of the type: this question is answerable.
	if _, ok := got["network.publicExposure"]; !ok {
		t.Error("public exposure was not observed — the question the type exists to answer")
	}
	if len(unread) == 0 {
		t.Error("no diagnostic for sourceProvenance")
	}
}

// The EC2 API has no build-attestation field. Emitting `false` would state as
// measured fact that the image has no provenance, when the truth is that this
// driver cannot see one — so the attribute is left unobserved and a hard
// constraint on it blocks the plan.
func TestObserveAMINeverFabricatesSourceProvenance(t *testing.T) {
	s := &amiServer{images: amiPrivateXML, snapshot: amiSnapCMKXML}
	d, done := amiTestDriver(t, s)
	defer done()

	obs, unread, err := d.observeAMI("base-image", amiPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "sourceProvenance" {
			t.Fatalf("sourceProvenance was observed as %v — the EC2 API has no such field, "+
				"so any value here is invented", o.Value)
		}
	}
	var said bool
	for _, u := range unread {
		if strings.Contains(u, "sourceProvenance") {
			said = true
		}
	}
	if !said {
		t.Error("sourceProvenance is neither observed nor reported unread — it vanished, " +
			"and a silently absent attribute looks like an attribute nobody asked about")
	}
}

func TestObserveAMIPublicImage(t *testing.T) {
	s := &amiServer{
		images:   strings.Replace(amiPrivateXML, "<isPublic>false</isPublic>", "<isPublic>true</isPublic>", 1),
		snapshot: amiSnapCMKXML,
	}
	d, done := amiTestDriver(t, s)
	defer done()

	obs, _, err := d.observeAMI("base-image", amiPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" && o.Value != true {
			t.Errorf("a public AMI was observed as %v", o.Value)
		}
	}
}

// An image is copied and shared far more readily than the disk it came from, so
// certifying a revocable key that is not revocable matters more here.
func TestObserveAMIDoesNotCallTheAWSDefaultKeyCustomerManaged(t *testing.T) {
	s := &amiServer{images: amiPrivateXML,
		snapshot: strings.Replace(amiSnapCMKXML,
			"arn:aws:kms:eu-central-1:000000000000:key/abc-123",
			"arn:aws:kms:eu-central-1:000000000000:alias/aws/ebs", 1)}
	d, done := amiTestDriver(t, s)
	defer done()

	obs, _, err := d.observeAMI("base-image", amiPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "encryption.customerManagedKeys" && o.Value != false {
			t.Errorf("the aws/ebs default key was reported as customer-managed (%v)", o.Value)
		}
	}
}

func TestObserveAMIUnreadableSnapshotIsUnreadNotFalse(t *testing.T) {
	s := &amiServer{images: amiPrivateXML, snapshotEr: 500}
	d, done := amiTestDriver(t, s)
	defer done()

	obs, unread, err := d.observeAMI("base-image", amiPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if strings.HasPrefix(o.Path, "encryption.") {
			t.Errorf("%s was observed as %v from an unreadable snapshot", o.Path, o.Value)
		}
	}
	var said bool
	for _, u := range unread {
		if strings.Contains(u, "encryption unread") && strings.Contains(u, "DescribeSnapshots") {
			said = true
		}
	}
	if !said {
		t.Errorf("diagnostics %v do not name the failed call", unread)
	}
}

func TestObserveAMIMissingIsNotAnError(t *testing.T) {
	s := &amiServer{images: `<DescribeImagesResponse><imagesSet/></DescribeImagesResponse>`}
	d, done := amiTestDriver(t, s)
	defer done()

	obs, unread, err := d.observeAMI("base-image", amiPID)
	if err != nil {
		t.Fatalf("an image that is simply absent produced an error: %v", err)
	}
	if len(obs) != 0 {
		t.Errorf("observations %v for an image that does not exist", obs)
	}
	if len(unread) == 0 {
		t.Error("no diagnostic — the caller cannot tell an absent image from a silent one")
	}
}

func TestObserveAMIUnreadableIsAnError(t *testing.T) {
	s := &amiServer{imagesErr: 500}
	d, done := amiTestDriver(t, s)
	defer done()

	obs, _, err := d.observeAMI("base-image", amiPID)
	if err == nil {
		t.Fatal("a 500 on the only read produced no error")
	}
	if len(obs) != 0 {
		t.Errorf("observations %v were emitted despite the failed read", obs)
	}
	if !strings.Contains(err.Error(), "DescribeImages") {
		t.Errorf("diagnostic %q does not name the call that failed", err)
	}
}

// Owner=self is load-bearing: without it DescribeImages returns every public AMI
// on the internet, which is not an estate anybody is accountable for.
func TestDiscoverAMIsOnlyEnumeratesOurOwn(t *testing.T) {
	s := &amiServer{images: amiPrivateXML, snapshot: amiSnapCMKXML}
	d, done := amiTestDriver(t, s)
	defer done()

	got, _, err := d.discoverAMIs("eu-central-1")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("discovered %d images, want 1", len(got))
	}
	if got[0].ResourceType != "capability.compute.image" {
		t.Errorf("resourceType = %q", got[0].ResourceType)
	}
	if got[0].ProviderID != amiPID {
		t.Errorf("providerId = %q", got[0].ProviderID)
	}
	var scoped bool
	for _, b := range s.bodies {
		if strings.Contains(b, "DescribeImages") && strings.Contains(b, "Owner.1=self") {
			scoped = true
		}
	}
	if !scoped {
		t.Errorf("DescribeImages was not scoped to Owner=self; bodies = %v — an unscoped "+
			"call enumerates every public AMI in the region as if it were ours", s.bodies)
	}
}

// Every author-shaped entry point must refuse, and each must say WHY — an
// operator who hits one of them will not hit the others.
func TestAMIRefusesEveryAuthoringPath(t *testing.T) {
	s := &amiServer{images: amiPrivateXML}
	d, done := amiTestDriver(t, s)
	defer done()

	if err := d.Validate("ami", "base-image", "production", nil, nil, 1); err == nil {
		t.Error("Validate accepted a create for a witness service")
	} else if !strings.Contains(err.Error(), "WITNESS") {
		t.Errorf("Validate refusal = %q, want it to name the reason", err)
	}
	create := d.Create("ami", "base-image", "production", nil, nil, "k", 1)
	if create.Status != "failed" || !strings.Contains(create.Reason, "WITNESS") {
		t.Errorf("Create = %q/%q, want a failed witness refusal", create.Status, create.Reason)
	}
	del := d.Delete("ami", "base-image", "production", amiPID, "k")
	if del.Status != "failed" || !strings.Contains(del.Reason, "WITNESS") {
		t.Errorf("Delete = %q/%q, want a failed witness refusal", del.Status, del.Reason)
	}
	// And nothing was called: a refusal must happen before any request.
	for _, c := range s.calls {
		if c != "" && c != "DescribeImages" {
			t.Errorf("an authoring path issued %q", c)
		}
	}
}

// `unsupported` rather than `immutable`: immutable would imply groundhold could
// have created the image differently, and it never creates one at all.
func TestClassifyAMIChange(t *testing.T) {
	for _, path := range []string{
		"location.region", "network.publicExposure", "encryption.atRest",
		"encryption.customerManagedKeys", "sourceProvenance", "service.managed",
	} {
		class, why := classifyAMIChange(path)
		if class != "unsupported" {
			t.Errorf("%s classified %q, want unsupported", path, class)
		}
		if !strings.Contains(why, "witnessed") {
			t.Errorf("%s reason = %q, want it to say the image is witnessed", path, why)
		}
	}
	if class, why := classifyAMIChange("something.invented"); class != "" || why != "" {
		t.Errorf("an unknown path classified %q/%q, want the empty answer", class, why)
	}
}

func TestSplitAMIProviderID(t *testing.T) {
	region, account, id, err := splitAMIProviderID(amiPID)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if region != "eu-central-1" || account != "000000000000" || id != "ami-0123456789abcdef0" {
		t.Errorf("split = %q/%q/%q", region, account, id)
	}
	for _, bad := range []string{
		"ec2:eu-central-1:000000000000:ami-0123456789abcdef0", // another service's id
		"ami:eu-central-1:000000000000:i-0123456789abcdef0",   // an instance, not an image
		"ami::000000000000:ami-0123456789abcdef0",             // no region
		"ami:eu-central-1:000000000000",                       // truncated
		"ami:eu-central-1:000000000000:ami-../../etc/passwd",  // a path, not an id
	} {
		if _, _, _, err := splitAMIProviderID(bad); err == nil {
			t.Errorf("%q was accepted as an AMI providerId", bad)
		}
	}
}
