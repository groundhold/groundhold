package provider_test

import (
	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D517: the F-LC3 absence property — a BOUND resource the API authoritatively 404s
// emits `resource.absent`, so the compile re-creates it instead of reporting a world
// that no longer contains it — migrated service by service.
//
// The debt this measures is the largest known in the system (D513): of the services
// certified across the drivers, ONE (aws/lambda) emitted the marker, and every other
// bound resource deleted out of band produced silence, which converge renders as
// converged. It cannot be fixed in one commit and it must not be claimed in one
// either.
//
// Tracked the way D237's transient invariant was, with one deliberate improvement.
// D237 used `AssertTransient: true`, a boolean, and eighteen files ended up carrying
// a stale TODO comment above an already-migrated flag — the debt read as eighteen
// when it was one (D507). Here the readiness signal is the CLOSURE itself: a probe
// asserts the property by handing the harness something it can actually run against
// a 404-everything server. A nil `ObserveAbsent` is un-migrated and counted; there is
// no way to write a flag that claims coverage the harness cannot exercise.
const absenceUnmigratedBaseline = 0 // every honesty probe asserts F-LC3 (D523)

// D625: the comment above used to end with "COMPLETE", and it was measuring the wrong
// subject. This ratchet counts PROBES — 102 of them, all migrated — while D513
// published the debt in SERVICES: "of roughly 145 certified services across AWS, GCP
// and Azure, one emits the marker". Those are different numbers, and the smaller one
// was being reported as if it closed the larger.
//
// Measured by walking each driver's own ServiceCapabilities() against the probe names:
//
//	aws    54 certified   17 with no absence probe
//	gcp    46 certified   13
//	azure  45 certified   14
//	                      44 of 145, of which 40 have no test naming the marker at all
//
// (k8s is excluded: its ten mapped services prove the property through the shared
// observeMapped unit tests rather than through certifynet probes, which a
// probe-name scan reads as ten gaps. Counting it would have published a number that
// is wrong in the honest direction — I made that mistake first and caught it by
// checking a sample by hand.)
//
// The emission is broadly IMPLEMENTED — roughly 136 driver files reference the marker
// — so this is a proof gap rather than a behaviour gap. D317 is the reason that
// distinction matters: a static scrape of driver sources gave four different wrong
// answers about those drivers, which is why "the code appears to emit it" is not the
// claim being ratcheted here.
const absenceUnprobedServicesBaseline = 44

func TestAbsencePropertyRatchet(t *testing.T) {
	root := repoRoot(t)
	probe := regexp.MustCompile(`(?s)certifynet\.Probe\{(.*?)\n\t\}`)
	name := regexp.MustCompile(`Name:\s*"([^"]+)"`)

	var total int
	var unmigrated, migrated []string
	for _, dir := range []string{"aws", "gcp", "azure", "k8s"} {
		files, err := filepath.Glob(filepath.Join(root, "go", "internal", dir, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range probe.FindAllStringSubmatch(string(raw), -1) {
				body := m[1]
				total++
				who := "(unnamed)"
				if n := name.FindStringSubmatch(body); n != nil {
					who = n[1]
				}
				if strings.Contains(body, "ObserveAbsent:") {
					migrated = append(migrated, who)
				} else {
					unmigrated = append(unmigrated, who)
				}
			}
		}
	}

	if total < 50 {
		t.Fatalf("only %d honesty probes found; the scan is not reaching them and this "+
			"ratchet would pass on anything", total)
	}
	sort.Strings(unmigrated)
	sort.Strings(migrated)

	if len(unmigrated) > absenceUnmigratedBaseline {
		t.Errorf("the absence debt GREW: %d services do not assert F-LC3, baseline is %d.\n"+
			"A new service may not arrive without answering whether it reports its own "+
			"disappearance — that silence is what makes converge agree with a world the "+
			"resource has left.\n  %v",
			len(unmigrated), absenceUnmigratedBaseline, unmigrated)
	}
	if len(unmigrated) < absenceUnmigratedBaseline {
		t.Errorf("the absence debt is now %d (migrated: %v) but the baseline still says %d — "+
			"lower the constant so the ratchet cannot slip back",
			len(unmigrated), migrated, absenceUnmigratedBaseline)
	}
	if len(migrated) == 0 {
		t.Error("no service asserts the property at all — the harness proves nothing")
	}
}

// TestAbsenceProbeCoverageByService is the ratchet on the number D513 actually
// published (D625). The one above proves every PROBE asserts the property; this one
// counts how many certified SERVICES have a probe at all. It may only go down.
func TestAbsenceProbeCoverageByService(t *testing.T) {
	root := repoRoot(t)

	certified := map[string][]string{}
	for cloud, m := range map[string]map[string]string{
		"aws":   aws.NewDriver("eu-central-1").ServiceCapabilities(),
		"gcp":   gcp.NewDriver("acme-prod").ServiceCapabilities(),
		"azure": azure.NewDriver("00000000-0000-0000-0000-000000000001").ServiceCapabilities(),
	} {
		for s := range m {
			certified[cloud] = append(certified[cloud], s)
		}
	}
	total := 0
	for _, v := range certified {
		total += len(v)
	}
	if total < 100 {
		t.Fatalf("only %d certified services found across the three clouds — the "+
			"scan broke and this ratchet would pass on anything (D328)", total)
	}

	probe := regexp.MustCompile(`(?s)certifynet\.Probe\{(.*?)\n\t\}`)
	nameRe := regexp.MustCompile(`Name:\s*"([^"]+)"`)
	withAbsent := map[string]bool{}
	for _, dir := range []string{"aws", "gcp", "azure"} {
		files, err := filepath.Glob(filepath.Join(root, "go", "internal", dir, "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range probe.FindAllStringSubmatch(string(raw), -1) {
				if n := nameRe.FindStringSubmatch(m[1]); n != nil &&
					strings.Contains(m[1], "ObserveAbsent:") {
					withAbsent[n[1]] = true
				}
			}
		}
	}
	if len(withAbsent) == 0 {
		t.Fatal("no absence probes found — the scan broke (D328)")
	}

	var unprobed []string
	for cloud, svcs := range certified {
		sort.Strings(svcs)
		for _, s := range svcs {
			if !withAbsent[cloud+"/"+s] {
				unprobed = append(unprobed, cloud+"/"+s)
			}
		}
	}
	sort.Strings(unprobed)

	if len(unprobed) > absenceUnprobedServicesBaseline {
		t.Errorf("the absence PROOF gap grew: %d of %d certified services have no probe "+
			"asserting F-LC3, baseline is %d.\n"+
			"A service with no probe never answers whether it reports its own "+
			"disappearance — and that silence is what made converge agree with a world "+
			"the resource had left (D513).\n  %v",
			len(unprobed), total, absenceUnprobedServicesBaseline, unprobed)
	}
	if len(unprobed) < absenceUnprobedServicesBaseline {
		t.Errorf("the gap is now %d of %d and the baseline still says %d — lower the "+
			"constant so it cannot slip back", len(unprobed), total,
			absenceUnprobedServicesBaseline)
	}
}
