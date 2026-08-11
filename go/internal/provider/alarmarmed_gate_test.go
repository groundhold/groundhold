package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D726. An alarm is a control whose whole job is to fire. All three clouds carry an
// arming switch separate from the list of things to notify, all three creates SET it,
// and no observe read it back — so `alert.notify` was "this alarm names somewhere to
// send a notification", not "this alarm will send one". An alarm switched off enters
// its alarm state and invokes nothing, while the contract reads satisfied.
//
// This gate is over the SOURCE rather than a fixture, deliberately: the defect was
// three drivers making the same omission independently, and the thing worth preventing
// is a fourth. Whatever expression produces `alert.notify`, it must consult more than
// the length of the action list.
func TestAlertNotifyConsultsTheArmingSwitch(t *testing.T) {
	root := repoRoot(t)
	sites := map[string]struct{ file, armed string }{
		"aws":   {"go/internal/aws/cwalarm_net.go", "ActionsEnabled"},
		"gcp":   {"go/internal/gcp/alertpolicy_net.go", "Enabled"},
		"azure": {"go/internal/azure/azalert_net.go", "Enabled"},
	}
	// The emission line, whatever it computes from.
	notify := regexp.MustCompile(`(?s)Path: "alert\.notify", Value: (.*?), Derivation`)

	checked := 0
	for cloud, site := range sites {
		raw, err := os.ReadFile(filepath.Join(root, site.file))
		if err != nil {
			t.Fatalf("%s: %v", cloud, err)
		}
		m := notify.FindSubmatch(raw)
		if m == nil {
			t.Errorf("%s: no alert.notify emission found in %s — this gate has lost its "+
				"subject and would pass over a driver that never emits the attribute at all",
				cloud, site.file)
			continue
		}
		checked++
		expr := string(m[1])
		if !strings.Contains(expr, site.armed) {
			t.Errorf("%s: alert.notify is computed as %q, which never consults %s — an "+
				"alarm that is switched off names its action group and invokes nothing, "+
				"and the contract reads satisfied (D726)", cloud, strings.TrimSpace(expr), site.armed)
		}
	}
	// D328: assert the subject. A refactor that renames these files must break this
	// gate loudly rather than let it report a clean sweep over nothing.
	if checked != len(sites) {
		t.Fatalf("only %d of %d alarm drivers were examined", checked, len(sites))
	}
}
