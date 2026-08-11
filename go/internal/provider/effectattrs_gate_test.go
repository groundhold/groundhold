package provider_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
)

// D748. Thirteen entries in two days fixed one mistake thirteen times: an attribute whose
// NAME claims an effect was computed from a NOUN — a container standing for its contents,
// a switch for what it switches, a name for the thing named.
//
//	Locked            -> which lock mode          (D724)
//	IsLogging         -> delivery                 (D725)
//	an action list    -> whether an alarm is armed (D726)
//	a plan's cadence  -> whether it protects anything (D733)
//	a sink's flag     -> a destination grant      (D738)
//	a policy's mode   -> whether it is enabled    (D739)
//	a subnet's switch -> whether it samples       (D742)
//	a road            -> where traffic may go     (D743)
//	an NSG's presence -> its own rules            (D744)
//	a redrive policy  -> a queue that exists      (D745)
//	a config set      -> anything routing to it   (D746)
//
// Each fix has a mutant, so none can silently regress. What no mutant covers is a NEW
// driver — a fourth cloud, a new service — making the same substitution for the first
// time. That is what this gate is for: for every attribute this series taught, whichever
// file emits it must consult the field that decides the effect.
//
// It is a CURATED list and says so. It cannot recognise the class in the abstract; it
// recognises the places the class has already been found, across whatever file emits
// them. A driver that adds one of these attributes without the deciding field fails here
// before it ships.
//
// THREE VERSIONS OF THIS GATE WERE SATISFIABLE BY SOMETHING OTHER THAN THE CODE, and each
// was found by a mutant rather than by thinking. Searching the raw source, a mutant that
// DELETED the dead-letter lookup passed — the COMMENT explaining it named the field.
// Stripping comments, it passed again — a DIAGNOSTIC MESSAGE named it. Stripping strings,
// it passed a third time — the deleted helper's own DECLARATION named it.
//
// So the gate reads the AST and counts identifier USES, skipping declaration sites.
// Comments and string literals are not identifiers, and a `func deadLetterTarget` header
// or a `ActionsEnabled bool` struct field is a declaration, not a use. All three holes
// close at once, and the general rule they share is worth more than the gate:
// PROSE ABOUT A THING, AND THE DECLARATION OF A THING, ARE EXACTLY WHAT REMAINS WHEN THE
// THING ITSELF IS DELETED.

// uses returns every identifier the file USES, excluding the sites that merely declare a
// name: a func's own name, and the field names of a struct type. `x.Foo` counts as a use
// of Foo (SelectorExpr.Sel), which is how these driver fields are read.
func uses(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0) // 0: comments dropped
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	declared := map[ast.Node]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.FuncDecl:
			declared[d.Name] = true
		case *ast.StructType:
			for _, fld := range d.Fields.List {
				for _, nm := range fld.Names {
					declared[nm] = true
				}
			}
		case *ast.TypeSpec:
			declared[d.Name] = true
		}
		return true
	})
	out := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && !declared[id] {
			out[id.Name] = true
		}
		return true
	})
	return out
}

// emits reports whether the file names this observation path in a string literal. The
// attribute is DATA (a quoted path); the deciding field is CODE (an identifier). Asking
// each question of the right half is what makes the gate honest.
func emits(t *testing.T, path, attr string) bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			if v, err := strconv.Unquote(lit.Value); err == nil && v == attr {
				found = true
			}
		}
		return true
	})
	return found
}

func TestEffectAttributesConsultTheFieldThatDecides(t *testing.T) {
	root := repoRoot(t)
	type rule struct {
		attr    string   // the observation path whose NAME claims an effect
		file    string   // repo-relative source that emits it
		mustUse []string // at least one must be USED (not merely declared) in that file
		why     string   // the entry that taught it, in the words of the failure
	}
	rules := []rule{
		{"alert.notify", "go/internal/aws/cwalarm_net.go", []string{"ActionsEnabled"},
			"an alarm with actions disabled invokes nothing (D726)"},
		{"alert.notify", "go/internal/gcp/alertpolicy_net.go", []string{"Enabled"},
			"a disabled policy never fires (D726)"},
		{"alert.notify", "go/internal/azure/azalert_net.go", []string{"Enabled"},
			"a disabled alert invokes nothing (D726)"},
		{"flowLogs.enabled", "go/internal/aws/vpc_net.go", []string{"delivering", "deliverLogsStatus"},
			"a flow log AWS reports as FAILED writes nothing (D725)"},
		{"flowLogs.enabled", "go/internal/gcp/vpc_net.go", []string{"FlowSampling"},
			"a subnet sampling zero records no flows (D742)"},
		{"egress.restricted", "go/internal/aws/vpc_net.go", []string{"openEgress"},
			"a road says which way traffic leaves, never where to (D743)"},
		{"reliability.deadLetter", "go/internal/aws/sqs_net.go", []string{"deadLetterTarget"},
			"a redrive policy names a queue; it does not make one exist (D745)"},
		{"bounce.tracked", "go/internal/aws/ses_sending_net.go", []string{"ConfigurationSetName"},
			"a configuration set captures nothing unless something routes to it (D746)"},
		{"retention.lockMode", "go/internal/aws/backupvault_net.go", []string{"LockDate"},
			"Locked is true in both lock modes (D724)"},
		// D752 found this one BY HAND, one cloud over from a site already in this
		// table — the curated list's limitation working exactly as the entry said it
		// would. The gate cannot generalise; it holds what has been found. Adding the
		// twin each time is the discipline that keeps it worth having.
		{"retention.lockMode", "go/internal/gcp/cloudbackupdr_net.go", []string{"EffectiveTime"},
			"a vault nobody has locked is not WORM (D752)"},
		{"availability.class", "go/internal/azure/cosmos_net.go", []string{"IsZoneRedundant"},
			"one write region is not the same as replicated across zones (D753)"},
		{"availability.class", "go/internal/aws/ecs_net.go", []string{"distinctSubnetZones"},
			"tasks run only where their subnets are (D754)"},
		{"managed.ruleset", "go/internal/aws/wafv2_net.go", []string{"wafProtectsSomething"},
			"a firewall that guards nothing protects nobody (D765)"},
		{"encryption.inTransit", "go/internal/azure/flexserver_net.go",
			[]string{"flexRequireSecureTransport"},
			"a default is not a guarantee; require_secure_transport can be off (D761)"},
		{"policy.mode", "go/internal/azure/frontdoorwaf_net.go", []string{"EnabledState"},
			"a disabled policy blocks nothing, whatever its mode says (D739)"},
		// D798: a budget threshold fires on what has been SPENT or on what is
		// FORECAST. Two clouds filtered on that discriminator and one did not, so the
		// rule is stated for all three — the attribute means a spend threshold on
		// every cloud or on none.
		{"alert.threshold", "go/internal/aws/budgets_net.go", []string{"ThresholdType"},
			"an ACTUAL threshold and a FORECASTED one are different alerts (D798)"},
		{"alert.threshold", "go/internal/azure/consumptionbudget_net.go", []string{"ThresholdType"},
			"an Actual threshold and a Forecasted one are different alerts (D798)"},
		{"alert.threshold", "go/internal/gcp/billingbudget_net.go", []string{"SpendBasis"},
			"a CURRENT_SPEND rule and a FORECASTED_SPEND rule are different alerts (D798)"},
		// D800: every encrypted resource reports a key; only KMS says who manages it.
		// Three drivers inferred BYOK from presence while two others in the same package
		// refused that inference — so the rule is stated for all of them.
		{"encryption.customerManagedKeys", "go/internal/aws/efs_net.go",
			[]string{"kmsKeyIsCustomerManaged"},
			"a default-encrypted file system reports the aws/elasticfilesystem key (D800)"},
		{"encryption.customerManagedKeys", "go/internal/aws/elasticache_net.go",
			[]string{"kmsKeyIsCustomerManaged"},
			"a default-encrypted cache reports the aws/elasticache key (D800)"},
		{"encryption.customerManagedKeys", "go/internal/aws/opensearch_net.go",
			[]string{"kmsKeyIsCustomerManaged"},
			"a default-encrypted domain reports the aws/es key (D800)"},
	}

	checked := 0
	for _, r := range rules {
		path := filepath.Join(root, r.file)
		if !emits(t, path, r.attr) {
			t.Errorf("%s no longer emits %q — this gate has lost its subject and would "+
				"report a clean sweep over nothing (D328). Move the rule or drop it, "+
				"with a reason.", r.file, r.attr)
			continue
		}
		checked++
		u := uses(t, path)
		hit := false
		for _, want := range r.mustUse {
			if u[want] {
				hit = true
				break
			}
		}
		if !hit {
			sort.Strings(r.mustUse)
			t.Errorf("%s emits %s and USES none of %v — %s An attribute whose NAME "+
				"claims an effect must be computed from the field that decides it, not "+
				"from the presence of a container (D748).",
				r.file, r.attr, r.mustUse, r.why)
		}
	}
	if checked != len(rules) {
		t.Fatalf("only %d of %d effect-claiming attributes were examined", checked, len(rules))
	}
	t.Logf("%d effect-claiming attributes checked across four driver packages", checked)
}
