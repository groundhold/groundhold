package azure

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// serviceCases extracts the service tokens dispatched in a `func (d *Driver)
// <method>(` body (see the AWS twin for the rationale — source-parsing the flat
// service switch, body ends at the first column-0 "}").
func serviceCases(t *testing.T, src, method string) map[string]bool {
	t.Helper()
	lines := strings.Split(src, "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "func (d *Driver) "+method+"(") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("method %s not found in source", method)
	}

	caseLine := regexp.MustCompile(`^\s*case .*:\s*$`)
	token := regexp.MustCompile(`"([a-z0-9-]+)"`)
	out := map[string]bool{}
	for i := start + 1; i < len(lines); i++ {
		if lines[i] == "}" {
			break
		}
		if caseLine.MatchString(lines[i]) {
			for _, m := range token.FindAllStringSubmatch(lines[i], -1) {
				out[m[1]] = true
			}
		}
	}
	// D328: a gate that finds nothing PASSES while checking nothing, which is worse

	// than no gate — it reads as a guarantee. A dispatch that parses to an EMPTY set

	// means the source shape changed (a switch rewritten as if-chains, a renamed

	// helper), not that the driver has no services.

	if len(out) == 0 {

		t.Fatalf("%s parsed to ZERO service cases — the dispatch shape changed and "+

			"every completeness gate built on it just went vacuous", method)

	}

	return out
}

// azureClassifyAllowlist: Azure services that can be CREATED but deliberately have
// NO ClassifyChange (create-only, in-place update not wired) — the visible
// burn-down of the F15 class on Azure (D210), not a green light. Reconciling a
// bound resource of one of these still errors; wiring ClassifyChange removes it.
var azureClassifyAllowlist = map[string]bool{
	"apim": true, "azkafka": true, "azurecdn": true, "azurefiles": true,
	"changefeed": true, "containerapps": true, "containerappsjob": true, "cosmos": true,
	"customroledef": true, "dnszone": true, "eventhubs": true,
	"backupvault":  true, // retention/lock/CMK/region are baked at create — a change is a replacement (D215 default)
	"frontdoorwaf": true, "keyvault": true, "keyvaultkey": true, "managedidentity": true,
	"metricalert": true, "portaldash": true, "roleassignment": true,
	"scheduledquery": true, "servicebustopic": true, "vnet": true, "webtest": true,
}

// TestClassifyChangeCompleteness pins the F15 invariant for Azure (D210): every
// create service must have ClassifyChange or be on the allowlist. A new create
// service without ClassifyChange fails CI; wiring an allowlisted one without
// removing it fails too.
func TestClassifyChangeCompleteness(t *testing.T) {
	src, err := os.ReadFile("azure_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	create := serviceCases(t, string(src), "createService") // Create is a thin D284 outputs wrapper
	classify := serviceCases(t, string(src), "ClassifyChange")

	var missing []string
	for svc := range create {
		if !classify[svc] && !azureClassifyAllowlist[svc] {
			missing = append(missing, svc)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("azure create services with NO ClassifyChange and NOT allowlisted: %v\n"+
			"wire ClassifyChange only if a path is mutable in place (else the D215 default replaces on drift) "+
			"or add them to azureClassifyAllowlist with a reason", missing)
	}

	var stale []string
	for svc := range azureClassifyAllowlist {
		if classify[svc] {
			stale = append(stale, svc)
		} else if !create[svc] {
			stale = append(stale, svc+" (not a create service)")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("azureClassifyAllowlist is stale — these no longer belong: %v", stale)
	}
}

// TestObserveCompleteness (D317) pins the sibling of the ClassifyChange gate: every
// service that can be CREATED must also be OBSERVABLE.
//
// The asymmetry it closes was real — create->ClassifyChange has been gated since
// D210 while create->observe never was, even though observe is the more
// fundamental half: without it a bound capability can never be reconciled against
// reality, D249 marks every declared attribute unverified, and converge reports
// inconclusive forever. The property holds today (measured, both directions
// empty); this keeps a new create service from shipping blind.
//
// There is deliberately NO allowlist. A create with no observe is not a
// burn-down class like an unwired ClassifyChange (where the D215 default still
// replaces on drift, honestly): it is a capability the runtime can build and then
// never check. If one is ever genuinely unobservable, that belongs in the
// vocabulary as an evidence class (D311), not as an exception here.
func TestObserveCompleteness(t *testing.T) {
	raw, err := os.ReadFile("azure_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	create := serviceCases(t, string(raw), "createService")
	observe := serviceCases(t, string(raw), "observeDispatch")

	var blind []string
	for svc := range create {
		if !observe[svc] {
			blind = append(blind, svc)
		}
	}
	sort.Strings(blind)
	if len(blind) > 0 {
		t.Errorf("%s services that can be CREATED but have no observe dispatch: %v\n"+
			"a capability the runtime builds and can never read back is never verified "+
			"against reality — wire observe, or declare the attributes' evidence class "+
			"in the vocabulary (D311)", "azure", blind)
	}

	var phantom []string
	for svc := range observe {
		if !create[svc] {
			phantom = append(phantom, svc)
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("%s services with an observe dispatch but no create: %v — either a "+
			"discover-only service (say so here) or a stale case", "azure", phantom)
	}
}
