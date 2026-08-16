package provider_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1123. The published drivers page listed FOUR optional interfaces under the heading
// "Optional capabilities", with no hedge. The package defines sixteen, and every one is
// implemented by a shipped cloud driver. `spec/providers/AUTHORING.md` — the document
// that page sends a would-be driver author to — named none of them.
//
// The cost is not a thin page. `CompetingManagers` is the guard that notices another
// controller already manages an object; without it a driver certifies, ships, and
// adopts on top of someone else's resource. That was found on a live cluster, where six
// of ten mapped k8s services failed exactly that way. An author who cannot learn the
// interface exists writes the hole in.
//
// So the register moves into AUTHORING.md — all sixteen, grouped by what skipping each
// one costs — and this gate pins it in BOTH directions. A new interface cannot be
// defined without being documented, and the document cannot name one that no longer
// exists. D1090 said the useful gate needed a deliberate register rather than the cheap
// check that every named interface exists; this is that register.
func TestEveryOptionalInterfaceIsDocumented(t *testing.T) {
	root := repoRoot(t)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "go", "internal", "provider", "provider.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	defined := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		if _, isIface := ts.Type.(*ast.InterfaceType); !isIface {
			return true
		}
		// `Provider` is the core every driver implements; the register is about what
		// a driver may additionally opt into.
		if ts.Name.Name != "Provider" {
			defined[ts.Name.Name] = true
		}
		return true
	})
	if len(defined) < 10 {
		t.Fatalf("found %d optional interfaces in provider.go — the AST walk broke, and "+
			"this gate would pass on a register naming almost nothing (D328)", len(defined))
	}

	raw, err := os.ReadFile(filepath.Join(root, "spec", "providers", "AUTHORING.md"))
	if err != nil {
		t.Skipf("no authoring spec here: %v", err)
	}
	doc := string(raw)
	start := strings.Index(doc, "## The optional interfaces, all of them")
	if start < 0 {
		t.Fatal("spec/providers/AUTHORING.md no longer carries the optional-interface " +
			"register. That register is the only place a driver author can learn which " +
			"interfaces exist — the published page deliberately carries a subset.")
	}
	end := strings.Index(doc[start+10:], "\n## ")
	if end < 0 {
		end = len(doc) - start - 10
	}
	section := doc[start : start+10+end]

	documented := map[string]bool{}
	for _, m := range regexp.MustCompile("(?m)^\\| `([A-Z][A-Za-z]*)` \\|").FindAllStringSubmatch(section, -1) {
		documented[m[1]] = true
	}

	var undocumented, phantom []string
	for name := range defined {
		if !documented[name] {
			undocumented = append(undocumented, name)
		}
	}
	for name := range documented {
		if !defined[name] {
			phantom = append(phantom, name)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(phantom)

	if len(undocumented) > 0 {
		t.Errorf("these optional interfaces exist and the register does not name them:\n  %s\n\n"+
			"An author who cannot learn an interface exists cannot implement it, and for "+
			"the safety ones that means shipping a driver with a hole. Add it to the "+
			"register in the commit that defines it.", strings.Join(undocumented, ", "))
	}
	if len(phantom) > 0 {
		t.Errorf("the register names interfaces the package does not define:\n  %s\n\n"+
			"A driver author would implement something nothing calls.", strings.Join(phantom, ", "))
	}
}

// The published page carries a SUBSET by design — the harm-shaped one. That is only
// honest if the page says so and points at the full register; otherwise it reads as a
// complete list again, which is the condition this whole entry is about.
func TestTheDriversPageAdmitsItsListIsPartial(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "website", "pages", "drivers.md"))
	if err != nil {
		t.Skipf("no drivers page here: %v", err)
	}
	page := string(raw)

	if !regexp.MustCompile(`(?i)not the whole set|subset`).MatchString(page) {
		t.Error("the drivers page no longer says its interface table is partial. It " +
			"listed four of sixteen under \"Optional capabilities\" for months, and a " +
			"reader had no way to know the rest existed.")
	}
	if !strings.Contains(page, "AUTHORING.md") {
		t.Error("the drivers page no longer points at the full register — an admission " +
			"that the list is partial is only useful with somewhere to go")
	}
	// The safety interfaces earn their place ON the page, not only in the register.
	for _, must := range []string{"CompetingManagers", "ResourcePreflighter", "Claimer"} {
		if !strings.Contains(page, must) {
			t.Errorf("the drivers page no longer names %s. It is on the page because "+
				"omitting it is a hole rather than a missing feature — a driver without "+
				"it certifies and then does something unsafe quietly.", must)
		}
	}
}

// D1126. D1123 fixed the drivers page and stopped there. The same claim stood on
// `extending.md`, which names the core interface and then "optional
// `Discoverer`/`Reconciler`/`Prober`" — three of sixteen, phrased as a list rather
// than an example. Fixing one copy of a claim and not looking for the others is the
// shape this project keeps finding in other people's work; here it was mine, hours old.
//
// The two pages want different things and the gate says so. `drivers.md` is a
// reference: it carries the harm-shaped subset in a table and must admit the subset.
// `extending.md` is an overview: it should not carry a table at all, only avoid
// implying the set is three. So this checks the WEAKER property that matches the page's
// job — the count is named and the register is pointed at — rather than demanding a
// list the page has no business holding.
//
// The core interface is checked exactly, because there a full list IS the page's job
// and it was correct: seven methods, same names, same order as `provider.Provider`.
func TestTheExtendingPageDoesNotImplyThreeOptionalInterfaces(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "website", "pages", "extending.md"))
	if err != nil {
		t.Skipf("no extending page here: %v", err)
	}
	page := string(raw)

	// The core, exactly — names and order, against the interface itself.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(root, "go", "internal", "provider", "provider.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var core []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "Provider" {
			return true
		}
		it, ok := ts.Type.(*ast.InterfaceType)
		if !ok {
			return true
		}
		for _, m := range it.Methods.List {
			for _, nm := range m.Names {
				core = append(core, nm.Name)
			}
		}
		return false
	})
	if len(core) < 5 {
		t.Fatalf("parsed %d methods from provider.Provider — the AST walk broke", len(core))
	}
	want := "`" + strings.Join(core, " · ") + "`"
	if !strings.Contains(page, want) {
		t.Errorf("the extending page no longer prints the core interface as %s.\n"+
			"A driver author reads this list to know what they must implement; a method "+
			"missing from it is one they will not write.", want)
	}

	// The optional set: the page must name its SIZE and send the reader to the
	// register. It must not read as a three-item list, which is what it did.
	if regexp.MustCompile("optional `Discoverer`/`Reconciler`/`Prober`").MatchString(page) {
		t.Error("the extending page again names three optional interfaces as if that " +
			"were the set. There are sixteen, and some are safety rather than " +
			"convenience — a reader who takes three as complete writes a driver without " +
			"the guard against adopting another controller's object.")
	}
	if !regexp.MustCompile(`(?i)sixteen optional interfaces`).MatchString(page) {
		t.Error("the extending page no longer names how many optional interfaces there " +
			"are. The number is what stops a reader treating an example as a list.")
	}
	if !strings.Contains(page, "AUTHORING.md") {
		t.Error("the extending page no longer points at the authoring guide, which is " +
			"where the full register lives")
	}
}
