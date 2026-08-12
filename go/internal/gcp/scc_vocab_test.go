package gcp

import "testing"

// D1010. The securityCenterServices `{service}` id is a CLOSED set the API documents
// (securitycentermanagement v1, googleapis proto SecurityCenterService.name): exactly
// container-threat-detection, event-threat-detection, security-health-analytics,
// vm-threat-detection, web-security-scanner. A driver id outside it 404s on GET, and the
// driver maps 404 -> found=false: `observeSCC` then reports the control OFF even when the
// live module is ENABLED, and `deleteSCC` skips it as "nothing to disable" while it stays
// live and returns succeeded. `virtual-machine-threat-detection` was exactly that wrong id
// (the real one is `vm-threat-detection`) — a live security control read as absent, and a
// teardown that claims it gone. This pins the ids the driver actually sends to the API's set.
func TestSCCModuleIdsAreDocumentedServices(t *testing.T) {
	valid := map[string]bool{
		"container-threat-detection": true,
		"event-threat-detection":     true,
		"security-health-analytics":  true,
		"vm-threat-detection":        true,
		"web-security-scanner":       true,
	}
	ids := []string{sccModuleEventThreat, sccModuleContainerThreat, sccModuleVMThreat}
	for _, id := range ids {
		if !valid[id] {
			t.Errorf("scc module id %q is not a documented securityCenterServices {service} — a "+
				"GET on it 404s and the live control reads as absent/off, delete claims it gone "+
				"while it stays live (D1010)", id)
		}
	}
	// The subject is three named consts referenced directly — it cannot go empty (D328),
	// but assert the driver still targets all three capability modules it claims to manage.
	if len(ids) != 3 {
		t.Fatalf("expected 3 scc capability modules, found %d", len(ids))
	}
}
