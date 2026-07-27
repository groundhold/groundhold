package aws

import (
	"strings"
	"testing"
)

// The ClientToken does the second half of the job it exists for: it made the
// create idempotent, and it makes the resulting instance findable without its
// server-assigned id.
func TestReconcileEC2InstanceFindsByClientToken(t *testing.T) {
	// reuse the EC2 query server: it routes DescribeInstances by Action
	es := &ec2InstanceServer{describe: []string{ec2RunningXML}}
	d, done := ec2TestDriver(t, es)
	defer done()

	got := d.reconcileEC2Instance("web", "production", 1)
	if got.Status != "succeeded" {
		t.Fatalf("status = %q (%s), want succeeded", got.Status, got.Reason)
	}
	if !strings.HasPrefix(got.ProviderID, "ec2:eu-central-1:") {
		t.Errorf("providerId = %q", got.ProviderID)
	}
	var filtered bool
	for _, b := range es.calls {
		if b == "DescribeInstances" {
			filtered = true
		}
	}
	if !filtered {
		t.Errorf("DescribeInstances was not called; calls = %v", es.calls)
	}
}

func TestReconcileEC2InstanceVerdicts(t *testing.T) {
	t.Run("absent means the create did not land", func(t *testing.T) {
		es := &ec2InstanceServer{describe: []string{
			`<DescribeInstancesResponse><reservationSet/></DescribeInstancesResponse>`}}
		d, done := ec2TestDriver(t, es)
		defer done()
		if got := d.reconcileEC2Instance("web", "production", 1); got.Status != "failed" {
			t.Errorf("status = %q, want failed", got.Status)
		}
	})
	t.Run("a read that gave no answer is unknown, never a conclusion", func(t *testing.T) {
		es := &ec2InstanceServer{describeErr: 500}
		d, done := ec2TestDriver(t, es)
		defer done()
		if got := d.reconcileEC2Instance("web", "production", 1); got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
	})
	// Found-but-not-ours is unknown, never a takeover: the token collided or the
	// tags were changed, and either way this contract may not claim the machine.
	t.Run("foreign tags are unknown, never succeeded", func(t *testing.T) {
		foreign := strings.Replace(ec2RunningXML, "<value>web</value>", "<value>someone-else</value>", 1)
		es := &ec2InstanceServer{describe: []string{foreign}}
		d, done := ec2TestDriver(t, es)
		defer done()
		got := d.reconcileEC2Instance("web", "production", 1)
		if got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
		if !strings.Contains(got.Reason, "not ours") {
			t.Errorf("reason = %q", got.Reason)
		}
	})
	t.Run("a terminated machine is a failed create", func(t *testing.T) {
		// describeEC2Instances skips terminated instances entirely, so the reconcile
		// sees an absence — which is the same verdict, reached honestly.
		gone := strings.Replace(ec2RunningXML, "<name>running</name>", "<name>terminated</name>", 1)
		es := &ec2InstanceServer{describe: []string{gone}}
		d, done := ec2TestDriver(t, es)
		defer done()
		if got := d.reconcileEC2Instance("web", "production", 1); got.Status != "failed" {
			t.Errorf("status = %q, want failed", got.Status)
		}
	})
}

// The safety argument for the stateful capability, stated as a test: without a
// pinned id there is NO honest handle, and the tempting shortcut (search by
// ownership tags) would match a previous generation's disk.
func TestReconcileEBSVolumeRefusesToGuessWithoutAPinnedID(t *testing.T) {
	d := NewDriver("eu-central-1")
	got := d.reconcileEBSVolume("orders-data", "production", "")
	if got.Status != "unknown" {
		t.Fatalf("status = %q, want unknown", got.Status)
	}
	for _, want := range []string{"assigned by the API", "previous generation"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("reason %q does not mention %q", got.Reason, want)
		}
	}
}

func TestReconcileEBSVolumeFromAPinnedID(t *testing.T) {
	t.Run("ours and available is succeeded", func(t *testing.T) {
		s := &ebsVolServer{describe: []string{ebsAvailableXML}}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		got := d.reconcileEBSVolume("orders-data", "production", ebsPID)
		if got.Status != "succeeded" || got.ProviderID != ebsPID {
			t.Errorf("status = %q providerId = %q (%s)", got.Status, got.ProviderID, got.Reason)
		}
	})
	t.Run("foreign is unknown, never a takeover", func(t *testing.T) {
		foreign := strings.Replace(ebsAvailableXML, "orders-data", "someone-elses-database", 1)
		s := &ebsVolServer{describe: []string{foreign}}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		if got := d.reconcileEBSVolume("orders-data", "production", ebsPID); got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
	})
	t.Run("absent means the create did not land", func(t *testing.T) {
		s := &ebsVolServer{describe: []string{ebsEmptyXML}}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		if got := d.reconcileEBSVolume("orders-data", "production", ebsPID); got.Status != "failed" {
			t.Errorf("status = %q, want failed", got.Status)
		}
	})
	t.Run("an unreadable volume is unknown", func(t *testing.T) {
		s := &ebsVolServer{describeErr: 500}
		d, done := ebsVolTestDriver(t, s)
		defer done()
		if got := d.reconcileEBSVolume("orders-data", "production", ebsPID); got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
	})
}

func TestReconcileASG(t *testing.T) {
	t.Run("ours is succeeded", func(t *testing.T) {
		s := asgHappyServer()
		d, done := asgTestDriver(t, s)
		defer done()
		got := d.reconcileASG("web-fleet", "production", 1)
		if got.Status != "succeeded" {
			t.Fatalf("status = %q (%s)", got.Status, got.Reason)
		}
		if !strings.HasPrefix(got.ProviderID, "asg:eu-central-1:") {
			t.Errorf("providerId = %q", got.ProviderID)
		}
	})
	t.Run("foreign is unknown, never a takeover", func(t *testing.T) {
		s := asgHappyServer()
		s.describe = strings.Replace(asgGroupXML, "<Value>web-fleet</Value>",
			"<Value>someone-elses-fleet</Value>", 1)
		d, done := asgTestDriver(t, s)
		defer done()
		if got := d.reconcileASG("web-fleet", "production", 1); got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
	})
	t.Run("absent means the create did not land", func(t *testing.T) {
		s := asgHappyServer()
		s.describe = `<DescribeAutoScalingGroupsResponse><DescribeAutoScalingGroupsResult><AutoScalingGroups/></DescribeAutoScalingGroupsResult></DescribeAutoScalingGroupsResponse>`
		d, done := asgTestDriver(t, s)
		defer done()
		if got := d.reconcileASG("web-fleet", "production", 1); got.Status != "failed" {
			t.Errorf("status = %q, want failed", got.Status)
		}
	})
	t.Run("an unreadable group is unknown", func(t *testing.T) {
		s := asgHappyServer()
		s.describeErr = 500
		d, done := asgTestDriver(t, s)
		defer done()
		if got := d.reconcileASG("web-fleet", "production", 1); got.Status != "unknown" {
			t.Errorf("status = %q, want unknown", got.Status)
		}
	})
}

// A record's identity is attribute-derived, so the pinned id is the only handle.
func TestReconcileRoute53RecordRefusesWithoutAPinnedID(t *testing.T) {
	d := NewDriver("eu-central-1")
	got := d.reconcileRoute53Record("dns", "production", "")
	if got.Status != "unknown" {
		t.Fatalf("status = %q, want unknown", got.Status)
	}
	if !strings.Contains(got.Reason, "attribute-derived") {
		t.Errorf("reason = %q", got.Reason)
	}
}
