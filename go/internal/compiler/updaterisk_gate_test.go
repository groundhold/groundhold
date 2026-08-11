package compiler

import "testing"

// D628. `updateRisk()` took no arguments and returned a constant. Every update, on
// every provider, for every change-set, was:
//
//	R1 / dataLoss none / downtime possible / securityExposure none / identityReplacement false
//
// So one sealed action that turns `encryption.atRest` OFF **and** `network.publicExposure`
// ON reported `securityExposure: none` — in the plan a human reads before consenting —
// and an update cutting a log retention from 3653d to 7d reported `dataLoss: none`.
// `converge`'s consent gate reads exactly `dataLoss == "certain" || identityReplacement`,
// so the only thing between a user and a silent encryption-disable was a field
// hardcoded to the safest value.
//
// What is derivable here is the DIRECTION of a change the compiler can already see.
// Where it is not derivable the answer is "possible" — the compiler has established
// nothing, and `none` is a claim.
func TestUpdateRiskIsDerivedFromTheChangeSet(t *testing.T) {
	t.Run("a security attribute weakened is certain exposure", func(t *testing.T) {
		r := updateRisk([]Change{
			{Path: "encryption.atRest", From: true, To: false},
		})
		if r.SecurityExposure != "certain" {
			t.Errorf("turning encryption at rest OFF reports securityExposure=%q",
				r.SecurityExposure)
		}
	})

	t.Run("public exposure switched on is certain exposure", func(t *testing.T) {
		r := updateRisk([]Change{
			{Path: "network.publicExposure", From: false, To: true},
		})
		if r.SecurityExposure != "certain" {
			t.Errorf("exposing a resource publicly reports securityExposure=%q",
				r.SecurityExposure)
		}
	})

	t.Run("a retention cut is certain data loss", func(t *testing.T) {
		r := updateRisk([]Change{
			{Path: "retention.days", From: "3653d", To: "7d"},
		})
		if r.DataLoss != "certain" {
			t.Errorf("cutting retention from ten years to a week reports dataLoss=%q",
				r.DataLoss)
		}
	})

	t.Run("strengthening is not an exposure", func(t *testing.T) {
		r := updateRisk([]Change{
			{Path: "encryption.atRest", From: false, To: true},
			{Path: "network.publicExposure", From: true, To: false},
		})
		if r.SecurityExposure == "certain" {
			t.Error("turning encryption ON and exposure OFF was reported as certain " +
				"exposure — the direction is readable and it is the safe one")
		}
	})

	t.Run("growing retention is not data loss", func(t *testing.T) {
		r := updateRisk([]Change{{Path: "retention.days", From: "7d", To: "30d"}})
		if r.DataLoss == "certain" {
			t.Error("extending retention was reported as certain data loss")
		}
	})

	// The load-bearing half: an unclassifiable change must not read as safe.
	t.Run("an undetermined change is possible, never none", func(t *testing.T) {
		r := updateRisk([]Change{{Path: "service.tier", From: "small", To: "large"}})
		if r.DataLoss == "none" || r.SecurityExposure == "none" {
			t.Errorf("a change whose direction the compiler cannot read reported "+
				"dataLoss=%q securityExposure=%q — `none` is a claim, and nothing "+
				"here established it", r.DataLoss, r.SecurityExposure)
		}
	})

	t.Run("an empty change set is still not none", func(t *testing.T) {
		r := updateRisk(nil)
		if r.DataLoss == "none" || r.SecurityExposure == "none" {
			t.Error("an update with no readable changes claimed no risk")
		}
	})

	// D945: network.apiExposure is a STRING enum, not a bool, and not under network.public* —
	// the bool-only allow-list missed a private→public flip that opens a K8s control plane.
	t.Run("opening the API server private->public is certain exposure", func(t *testing.T) {
		for _, to := range []string{"public", "mixed"} {
			r := updateRisk([]Change{{Path: "network.apiExposure", From: "private", To: to}})
			if r.SecurityExposure != "certain" {
				t.Errorf("apiExposure private->%s reported securityExposure=%q — the K8s API "+
					"endpoint is opened and no exposure consent would be required", to, r.SecurityExposure)
			}
		}
	})
	t.Run("closing the API server public->private is not exposure", func(t *testing.T) {
		r := updateRisk([]Change{{Path: "network.apiExposure", From: "public", To: "private"}})
		if r.SecurityExposure == "certain" {
			t.Error("apiExposure public->private (de-escalating) was reported as certain exposure")
		}
	})
	// D945: turning a threat-detection posture control OFF via an in-place update — the
	// protection-lift gate (D698) only binds on delete, so this update path was ungated.
	t.Run("disabling a threat-detection control is certain exposure", func(t *testing.T) {
		for _, p := range []string{"detection.enabled", "protection.kubernetes", "protection.malware"} {
			r := updateRisk([]Change{{Path: p, From: true, To: false}})
			if r.SecurityExposure != "certain" {
				t.Errorf("%s true->false (turning a security control OFF) reported "+
					"securityExposure=%q", p, r.SecurityExposure)
			}
		}
	})
	t.Run("enabling a threat-detection control is not exposure", func(t *testing.T) {
		r := updateRisk([]Change{{Path: "protection.malware", From: false, To: true}})
		if r.SecurityExposure == "certain" {
			t.Error("protection.malware false->true (turning protection ON) was reported as exposure")
		}
	})
}
