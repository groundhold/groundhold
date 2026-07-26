package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// asgServer routes on the Query Action across BOTH services this driver uses:
// autoscaling for the group and the policy, ec2 for the two preflight reads.
type asgServer struct {
	createStatus int
	createBody   string
	policyStatus int
	describe     string
	describeErr  int
	policies     string
	policiesErr  int
	subnets      string
	subnetsErr   int
	template     string
	templateErr  int
	deleteStatus int
	calls        []string
	bodies       []string
}

func (s *asgServer) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(body)
		s.bodies = append(s.bodies, string(body))
		action := actionOf(string(body))
		s.calls = append(s.calls, action)
		fail := func(code int) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`<Response><Errors><Error><Code>InternalError</Code></Error></Errors></Response>`))
		}
		switch action {
		case "CreateAutoScalingGroup":
			w.WriteHeader(s.createStatus)
			_, _ = w.Write([]byte(s.createBody))
		case "PutScalingPolicy":
			w.WriteHeader(s.policyStatus)
			_, _ = w.Write([]byte(`<PutScalingPolicyResponse/>`))
		case "DescribeAutoScalingGroups":
			if s.describeErr != 0 {
				fail(s.describeErr)
				return
			}
			_, _ = w.Write([]byte(s.describe))
		case "DescribePolicies":
			if s.policiesErr != 0 {
				fail(s.policiesErr)
				return
			}
			_, _ = w.Write([]byte(s.policies))
		case "DescribeSubnets":
			if s.subnetsErr != 0 {
				fail(s.subnetsErr)
				return
			}
			_, _ = w.Write([]byte(s.subnets))
		case "DescribeLaunchTemplateVersions":
			if s.templateErr != 0 {
				fail(s.templateErr)
				return
			}
			_, _ = w.Write([]byte(s.template))
		case "DeleteAutoScalingGroup":
			w.WriteHeader(s.deleteStatus)
			_, _ = w.Write([]byte(`<DeleteAutoScalingGroupResponse/>`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func asgTestDriver(t *testing.T, s *asgServer) (*Driver, func()) {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "SECRET")
	srv := httptest.NewServer(s.handler())
	d := NewDriver("eu-central-1")
	d.AutoScalingBaseURL = srv.URL
	d.EC2BaseURL = srv.URL
	d.Account = "000000000000"
	d.PollInterval = time.Millisecond
	d.PollTimeout = 50 * time.Millisecond
	return d, srv.Close
}

const asgGroupXML = `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups>
<member><AutoScalingGroupName>groundhold-web-fleet-production</AutoScalingGroupName>
<MinSize>2</MinSize><MaxSize>10</MaxSize>
<AvailabilityZones><member>eu-central-1a</member><member>eu-central-1b</member></AvailabilityZones>
<LaunchTemplate><LaunchTemplateId>lt-0123456789abcdef0</LaunchTemplateId></LaunchTemplate>
<Tags><member><Key>groundhold-capability</Key><Value>web-fleet</Value></member>
<member><Key>groundhold-environment</Key><Value>production</Value></member></Tags>
</member></AutoScalingGroups></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`

const asgTwoZonesXML = `<DescribeSubnetsResponse><subnetSet>
<item><subnetId>subnet-0abc123456789def0</subnetId><availabilityZone>eu-central-1a</availabilityZone></item>
<item><subnetId>subnet-0fed987654321cba0</subnetId><availabilityZone>eu-central-1b</availabilityZone></item>
</subnetSet></DescribeSubnetsResponse>`

const asgOneZoneXML = `<DescribeSubnetsResponse><subnetSet>
<item><subnetId>subnet-0abc123456789def0</subnetId><availabilityZone>eu-central-1a</availabilityZone></item>
<item><subnetId>subnet-0fed987654321cba0</subnetId><availabilityZone>eu-central-1a</availabilityZone></item>
</subnetSet></DescribeSubnetsResponse>`

const asgPrivateTemplateXML = `<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet><item>
<launchTemplateData><networkInterfaceSet><item><associatePublicIpAddress>false</associatePublicIpAddress></item></networkInterfaceSet></launchTemplateData>
</item></launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`

const asgPublicTemplateXML = `<DescribeLaunchTemplateVersionsResponse><launchTemplateVersionSet><item>
<launchTemplateData><networkInterfaceSet><item><associatePublicIpAddress>true</associatePublicIpAddress></item></networkInterfaceSet></launchTemplateData>
</item></launchTemplateVersionSet></DescribeLaunchTemplateVersionsResponse>`

const asgHasPolicyXML = `<DescribePoliciesResponse><DescribePoliciesResult><ScalingPolicies>
<member><PolicyName>groundhold-web-fleet-production-cpu</PolicyName></member>
</ScalingPolicies></DescribePoliciesResult></DescribePoliciesResponse>`

const asgPID = "asg:eu-central-1:000000000000:groundhold-web-fleet-production"

func asgHappyServer() *asgServer {
	return &asgServer{
		createStatus: 200, createBody: `<CreateAutoScalingGroupResponse/>`, policyStatus: 200,
		describe: asgGroupXML, policies: asgHasPolicyXML,
		subnets: asgTwoZonesXML, template: asgPrivateTemplateXML, deleteStatus: 200,
	}
}

func TestCreateASGHappyPath(t *testing.T) {
	s := asgHappyServer()
	d, done := asgTestDriver(t, s)
	defer done()

	got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
		asgAttrs(), asgImpl(), 0)
	if got.Status != "succeeded" {
		t.Fatalf("status = %q (%s)", got.Status, got.Reason)
	}
	// Both preflights must have run BEFORE the create.
	var order []string
	for _, c := range s.calls {
		switch c {
		case "DescribeSubnets", "DescribeLaunchTemplateVersions", "CreateAutoScalingGroup", "PutScalingPolicy":
			order = append(order, c)
		}
	}
	if len(order) < 4 || order[len(order)-2] != "CreateAutoScalingGroup" || order[len(order)-1] != "PutScalingPolicy" {
		t.Errorf("call order = %v; want both preflights, then the group, then the policy", order)
	}
}

// The check the pure core cannot make: two subnets in ONE zone would create a
// group that looks spread and survives nothing.
func TestCreateASGRefusesRegionalOverOneZone(t *testing.T) {
	s := asgHappyServer()
	s.subnets = asgOneZoneXML
	d, done := asgTestDriver(t, s)
	defer done()

	got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
		asgAttrs(), asgImpl(), 0)
	if got.Status != "failed" {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !strings.Contains(got.Reason, "same availability zone") {
		t.Errorf("reason = %q", got.Reason)
	}
	for _, c := range s.calls {
		if c == "CreateAutoScalingGroup" {
			t.Fatal("the group was created despite a zone spread that does not exist")
		}
	}
}

// An unreadable zone lookup cannot prove the claim, and creating anyway would
// certify survivability nobody checked.
func TestCreateASGRefusesWhenZonesAreUnreadable(t *testing.T) {
	s := asgHappyServer()
	s.subnetsErr = 500
	d, done := asgTestDriver(t, s)
	defer done()

	got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
		asgAttrs(), asgImpl(), 0)
	if got.Status != "failed" {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	// D296: a read that produced nothing must name its cause, so an operator can
	// tell a throttle from a permission gap.
	if !strings.Contains(got.Reason, "DescribeSubnets") {
		t.Errorf("reason %q does not name the call that failed", got.Reason)
	}
	if !strings.Contains(got.Reason, "nobody has checked") {
		t.Errorf("reason %q does not say why the create was refused", got.Reason)
	}
}

// The group cannot set addressing: it inherits the template's. Accepting the
// declared value without looking would report a contract satisfied by a fleet
// that violates it.
func TestCreateASGRefusesWhenTheTemplateContradictsExposure(t *testing.T) {
	s := asgHappyServer()
	s.template = asgPublicTemplateXML // contract says publicExposure: false
	d, done := asgTestDriver(t, s)
	defer done()

	got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
		asgAttrs(), asgImpl(), 0)
	if got.Status != "failed" {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if !strings.Contains(got.Reason, "cannot override it") {
		t.Errorf("reason = %q", got.Reason)
	}
	for _, c := range s.calls {
		if c == "CreateAutoScalingGroup" {
			t.Fatal("the group was created against a contradicting launch template")
		}
	}
}

func TestCreateASGMutationHonesty(t *testing.T) {
	t.Run("5xx is unknown, never failed", func(t *testing.T) {
		s := asgHappyServer()
		s.createStatus, s.createBody = 503, `<Response/>`
		d, done := asgTestDriver(t, s)
		defer done()
		got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
			asgAttrs(), asgImpl(), 0)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
		if got.ProviderID != asgPID {
			t.Errorf("providerId = %q — the name is deterministic, so an unknown create "+
				"must still name what to reconcile", got.ProviderID)
		}
	})
	t.Run("a definitive 4xx is failed", func(t *testing.T) {
		s := asgHappyServer()
		s.createStatus = 400
		s.createBody = `<ErrorResponse><Error><Type>Sender</Type><Code>ValidationError</Code></Error></ErrorResponse>`
		d, done := asgTestDriver(t, s)
		defer done()
		if got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
			asgAttrs(), asgImpl(), 0); got.Status != "failed" {
			t.Errorf("status = %q, want failed", got.Status)
		}
	})
	t.Run("a name conflict with our tags is the create succeeding twice", func(t *testing.T) {
		s := asgHappyServer()
		s.createStatus = 400
		s.createBody = `<ErrorResponse><Error><Type>Sender</Type><Code>AlreadyExists</Code></Error></ErrorResponse>`
		d, done := asgTestDriver(t, s)
		defer done()
		if got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
			asgAttrs(), asgImpl(), 0); got.Status != "succeeded" {
			t.Errorf("status = %q (%s), want succeeded", got.Status, got.Reason)
		}
	})
	t.Run("a name conflict with foreign tags refuses to bind", func(t *testing.T) {
		s := asgHappyServer()
		s.createStatus = 400
		s.createBody = `<ErrorResponse><Error><Type>Sender</Type><Code>AlreadyExists</Code></Error></ErrorResponse>`
		s.describe = strings.Replace(asgGroupXML, "<Value>web-fleet</Value>",
			"<Value>someone-elses-fleet</Value>", 1)
		d, done := asgTestDriver(t, s)
		defer done()
		got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
			asgAttrs(), asgImpl(), 0)
		if got.Status != "failed" || got.ProviderID != "" {
			t.Errorf("status = %q providerId = %q — binding a stranger's fleet", got.Status, got.ProviderID)
		}
	})
	// The group EXISTS and holds its floor; only the policy is uncertain. Reporting
	// `failed` would invite a retry of the whole create.
	t.Run("a lost policy leaves the group unknown, not failed", func(t *testing.T) {
		s := asgHappyServer()
		s.policyStatus = 503
		d, done := asgTestDriver(t, s)
		defer done()
		got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
			asgAttrs(), asgImpl(), 0)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
		if !strings.Contains(got.Reason, "holds its floor") {
			t.Errorf("reason = %q does not say what state the fleet is in", got.Reason)
		}
	})
	t.Run("a refused policy is failed, and says the contract is unmet", func(t *testing.T) {
		s := asgHappyServer()
		s.policyStatus = 400
		d, done := asgTestDriver(t, s)
		defer done()
		got := d.createASG("eu-central-1", "000000000000", "production", "web-fleet",
			asgAttrs(), asgImpl(), 0)
		if got.Status != "failed" || !strings.Contains(got.Reason, "autoscaling.enabled is not satisfied") {
			t.Errorf("status = %q reason = %q", got.Status, got.Reason)
		}
	})
}

func TestObserveASG(t *testing.T) {
	s := asgHappyServer()
	d, done := asgTestDriver(t, s)
	defer done()

	obs, unread, err := d.observeASG("web-fleet", asgPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(unread) != 0 {
		t.Errorf("unread = %v on a fully readable group", unread)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	want := map[string]any{
		"location.region":        "eu-central-1",
		"availability.class":     "regional",
		"replicas.minimum":       2,
		"replicas.maximum":       10,
		"autoscaling.enabled":    true,
		"network.publicExposure": false,
		"service.managed":        true,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v (%T), want %v", k, got[k], got[k], v)
		}
	}
}

// The class is MEASURED from the zones the group reports, never inferred from
// what was asked for — the create-time check exists because the two can differ.
func TestObserveASGReadsTheClassFromTheZones(t *testing.T) {
	s := asgHappyServer()
	s.describe = strings.Replace(asgGroupXML,
		"<member>eu-central-1a</member><member>eu-central-1b</member>",
		"<member>eu-central-1a</member>", 1)
	d, done := asgTestDriver(t, s)
	defer done()

	obs, _, err := d.observeASG("web-fleet", asgPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "availability.class" && o.Value != "zonal" {
			t.Errorf("a single-zone group was observed as %v", o.Value)
		}
	}
}

// A silent false would report a scaling fleet as fixed-size; a silent true the
// reverse. Neither is a reading.
func TestObserveASGReportsAnUnreadablePolicyRatherThanDefaultingIt(t *testing.T) {
	s := asgHappyServer()
	s.policiesErr = 500
	d, done := asgTestDriver(t, s)
	defer done()

	obs, unread, err := d.observeASG("web-fleet", asgPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "autoscaling.enabled" {
			t.Errorf("autoscaling.enabled was observed as %v from an unreadable policy list", o.Value)
		}
	}
	var said bool
	for _, u := range unread {
		if strings.Contains(u, "autoscaling.enabled unread") {
			said = true
		}
	}
	if !said {
		t.Errorf("diagnostics %v do not report the attribute unread", unread)
	}
}

func TestObserveASGReportsAnUnreadableTemplateRatherThanDefaultingIt(t *testing.T) {
	s := asgHappyServer()
	s.templateErr = 500
	d, done := asgTestDriver(t, s)
	defer done()

	obs, unread, err := d.observeASG("web-fleet", asgPID)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "network.publicExposure" {
			t.Errorf("publicExposure was observed as %v from an unreadable template", o.Value)
		}
	}
	var said bool
	for _, u := range unread {
		if strings.Contains(u, "network.publicExposure unread") {
			said = true
		}
	}
	if !said {
		t.Errorf("diagnostics %v do not report the attribute unread", unread)
	}
}

func TestDeleteASG(t *testing.T) {
	t.Run("retires the fleet it owns", func(t *testing.T) {
		s := asgHappyServer()
		d, done := asgTestDriver(t, s)
		defer done()
		if got := d.deleteASG("web-fleet", "production", asgPID); got.Status != "succeeded" {
			t.Fatalf("status = %q (%s)", got.Status, got.Reason)
		}
		// Retiring a group retires its fleet — that is what the type means (D363),
		// and a delete that failed on a non-empty group would strand every real one.
		var forced bool
		for _, b := range s.bodies {
			if strings.Contains(b, "Action=DeleteAutoScalingGroup") && strings.Contains(b, "ForceDelete=true") {
				forced = true
			}
		}
		if !forced {
			t.Errorf("DeleteAutoScalingGroup did not force — a non-empty group would strand")
		}
	})
	t.Run("refuses a fleet that is not ours", func(t *testing.T) {
		s := asgHappyServer()
		s.describe = strings.Replace(asgGroupXML, "<Value>web-fleet</Value>",
			"<Value>someone-elses-fleet</Value>", 1)
		d, done := asgTestDriver(t, s)
		defer done()
		if got := d.deleteASG("web-fleet", "production", asgPID); got.Status != "failed" {
			t.Fatalf("status = %q, want failed", got.Status)
		}
		for _, c := range s.calls {
			if c == "DeleteAutoScalingGroup" {
				t.Fatal("a foreign fleet was terminated")
			}
		}
	})
	t.Run("an absent group is already deleted", func(t *testing.T) {
		s := asgHappyServer()
		s.describe = `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups/></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`
		d, done := asgTestDriver(t, s)
		defer done()
		if got := d.deleteASG("web-fleet", "production", asgPID); got.Status != "succeeded" {
			t.Errorf("status = %q, want succeeded (idempotent)", got.Status)
		}
	})
	t.Run("an unreadable pre-delete read is unknown, never a delete", func(t *testing.T) {
		s := asgHappyServer()
		s.describeErr = 500
		d, done := asgTestDriver(t, s)
		defer done()
		got := d.deleteASG("web-fleet", "production", asgPID)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
		for _, c := range s.calls {
			if c == "DeleteAutoScalingGroup" {
				t.Fatal("a fleet was terminated without a successful ownership read")
			}
		}
	})
}

func TestDiscoverASGs(t *testing.T) {
	s := asgHappyServer()
	d, done := asgTestDriver(t, s)
	defer done()

	got, _, err := d.discoverASGs("eu-central-1")
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("discovered %d groups, want 1", len(got))
	}
	if got[0].ResourceType != "capability.compute.autoscaling" || got[0].ProviderID != asgPID {
		t.Errorf("discovered %+v", got[0])
	}
}

func TestSplitASGProviderID(t *testing.T) {
	region, account, name, err := splitASGProviderID(asgPID)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if region != "eu-central-1" || account != "000000000000" || name != "groundhold-web-fleet-production" {
		t.Errorf("split = %q/%q/%q", region, account, name)
	}
	for _, bad := range []string{
		"ec2:eu-central-1:000000000000:groundhold-web-fleet-production",
		"asg::000000000000:g",
		"asg:eu-central-1:000000000000:",
		"asg:eu-central-1:000000000000",
		"asg:eu-central-1:000000000000:../../etc/passwd",
	} {
		if _, _, _, err := splitASGProviderID(bad); err == nil {
			t.Errorf("%q was accepted as an ASG providerId", bad)
		}
	}
}
