package provider_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// unpagedARMClaimCeiling is how many ARM list reads OUTSIDE a discovery sweep decode a
// list envelope without following a nextLink. It may only go DOWN.
//
// D869. The Azure driver already has a ratchet over sweeps (`unpagedAzureSweepCeiling`),
// and a truncated sweep is DISCLOSED: the transport notes any response that said there was
// more, and the crawl turns that note into an incomplete scope (D803). That disclosure has
// exactly one consumer, `crawlProvider` in the main loop. A read that is not part of a
// crawl leaves the same note and nobody collects it — so its claim goes out unqualified.
//
// Two such claims existed, and both were made from page one:
//
//	effectivePermissions   the AUTHORITATIVE resource-scope denial `internal/apply` refuses on
//	listAOIDeployments     `inference.destinationRegions`, the deterministic residency trap
//
// The rest of the count is not an accusation. Some are leaves under a sweep, where D803's
// note does reach the number they feed; one asks "is this list empty", which one page
// settles because pages fill in order (D861); one reads a collection ARM's own
// specification marks unpageable. What the number says is that nobody has established
// which, and that it may not grow while that is true.
const unpagedARMClaimCeiling = 8

// TestARMListClaimsOutsideASweepFollowTheirPages counts them.
//
// The subject is a DECODE SITE, not a function name — the D866 lesson from AWS, where a
// gate that asked "does some function naming this operation page" scored a mutant as
// caught because a sibling function paged. A function decoding two envelopes and following
// one nextLink is one unfollowed read, not zero.
func TestARMListClaimsOutsideASweepFollowTheirPages(t *testing.T) {
	root := repoRoot(t)
	dir := filepath.Join(root, "go", "internal", "azure")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the azure driver: %v", err)
	}

	total, unfollowed := 0, 0
	var names []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil || strings.HasPrefix(fn.Name.Name, "discover") {
				continue // the sweeps have their own ratchet, and their own disclosure
			}
			envelopes := armListEnvelopes(fn)
			if envelopes == 0 {
				continue
			}
			total += envelopes
			body := string(src[fn.Pos()-1 : fn.End()-1])
			if strings.Contains(body, "listAllARMPages") || strings.Contains(body, "nextLink") {
				continue
			}
			unfollowed += envelopes
			names = append(names, fn.Name.Name+" ("+name+")")
		}
	}

	// D328: a subject that went empty would make this gate pass over nothing.
	if total < 5 {
		t.Fatalf("only %d ARM list decodes found outside the sweeps — the detector stopped "+
			"seeing its subject, and a gate that finds nothing passes", total)
	}
	sort.Strings(names)
	if unfollowed > unpagedARMClaimCeiling {
		t.Errorf("%d ARM list reads outside a sweep do not follow a nextLink, ceiling %d:\n  %s\n\n"+
			"A new one means a claim is made from page one of a listing ARM pages, and unlike a "+
			"sweep nothing downstream says so (D803's note has one consumer, the crawl). Follow "+
			"the pages, or establish that this collection does not have any (D869).",
			unfollowed, unpagedARMClaimCeiling, strings.Join(names, "\n  "))
	}
	if unfollowed < unpagedARMClaimCeiling {
		t.Errorf("%d unfollowed ARM list reads but the ceiling still says %d. Lower it: a "+
			"ceiling that trails the work stops being a ratchet.", unfollowed, unpagedARMClaimCeiling)
	}
}

// armListEnvelopes counts the ARM list envelopes a function decodes: an anonymous struct
// with a `Value []T` field tagged `json:"value"`. T is required to be a named or struct
// type — an ARM listing's elements are resources, never bare strings, and requiring that
// keeps a DNS record's `Value []string` out of a count about pagination.
func armListEnvelopes(fn *ast.FuncDecl) int {
	n := 0
	ast.Inspect(fn, func(nd ast.Node) bool {
		st, ok := nd.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fl := range st.Fields.List {
			if len(fl.Names) != 1 || fl.Names[0].Name != "Value" {
				continue
			}
			arr, ok := fl.Type.(*ast.ArrayType)
			if !ok {
				continue
			}
			if id, ok := arr.Elt.(*ast.Ident); ok {
				switch id.Name {
				case "string", "int", "int64", "bool", "float64", "any", "byte":
					continue
				}
			}
			if fl.Tag == nil || !strings.Contains(fl.Tag.Value, `json:"value"`) {
				continue
			}
			n++
		}
		return true
	})
	return n
}
