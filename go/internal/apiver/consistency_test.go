package apiver

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// consistency_test.go is the fence that makes the pin real (D236). It parses the
// actual driver source and enforces both directions:
//
//   - registry ⊆ code: every pinned Version is a literal the driver actually
//     embeds. A pin cannot claim a version we do not use.
//   - code ⊆ registry ∪ allowlist: every version-shaped literal in the driver
//     source is a registered pin (or an explicit, named exception). A NEW
//     un-registered version literal fails the build — the anti-scatter tripwire.
//
// It reads source via go/parser, so string literals inside COMMENTS (e.g.
// "compute/v1" in a doc comment) are never mistaken for embedded versions.

// awsPolicyLangAllow is the ONE dated literal in AWS source that is NOT an API
// version: "2012-10-17" is the IAM policy-LANGUAGE version, embedded in JSON
// policy documents. It must never be registered as an API version, and must
// never be "fixed" into the registry.
const awsPolicyLangAllow = "2012-10-17"

var (
	dateRe    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(-preview)?$`)
	gcpVerRe  = regexp.MustCompile(`googleapis\.com/(([a-z]+/)?v[0-9][a-z0-9]*)`)
	azVerName = regexp.MustCompile(`APIVersion$`)
)

// driverDir maps a provider to its driver package directory (relative to this
// test's package dir, go/internal/apiver).
func driverDir(provider string) string {
	switch provider {
	case "aws":
		return filepath.Join("..", "aws")
	case "gcp":
		return filepath.Join("..", "gcp")
	case "azure":
		return filepath.Join("..", "azure")
	}
	return ""
}

// stringLits returns every string-literal value in the non-test .go files of a
// directory (comments excluded — go/parser gives us only real BasicLits).
func stringLits(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	forEachDriverFile(t, dir, func(f *ast.File) {
		ast.Inspect(f, func(n ast.Node) bool {
			if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
				if s, err := strconv.Unquote(bl.Value); err == nil {
					out = append(out, s)
				}
			}
			return true
		})
	})
	return out
}

// namedConsts returns const/var (name -> value) for string-valued specs whose
// name matches want, across the non-test .go files of a directory.
func namedConsts(t *testing.T, dir string, want *regexp.Regexp) map[string]string {
	t.Helper()
	out := map[string]string{}
	forEachDriverFile(t, dir, func(f *ast.File) {
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok || len(vs.Names) != len(vs.Values) {
				return true
			}
			for i, name := range vs.Names {
				if !want.MatchString(name.Name) {
					continue
				}
				if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
					if s, err := strconv.Unquote(bl.Value); err == nil {
						out[name.Name] = s
					}
				}
			}
			return true
		})
	})
	return out
}

func forEachDriverFile(t *testing.T, dir string, fn func(*ast.File)) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		fn(f)
	}
}

// TestRegistrySubsetOfCode: registry ⊆ code. Every pinned version must be a
// literal the driver actually embeds — the pin cannot lie.
func TestRegistrySubsetOfCode(t *testing.T) {
	for _, provider := range []string{"aws", "gcp", "azure"} {
		lits := stringLits(t, driverDir(provider))
		for _, p := range ByProvider(provider) {
			if !embedsVersion(provider, p.Version, lits) {
				t.Errorf("%s/%s: pinned version %q is not embedded anywhere in the driver source "+
					"— the registry lies, or the driver moved off it", provider, p.Service, p.Version)
			}
		}
	}
}

// embedsVersion reports whether the pinned version appears in the driver source
// per that provider's embedding.
func embedsVersion(provider, version string, lits []string) bool {
	switch provider {
	case "gcp":
		// version is a path suffix ("compute/v1", "v1"); it appears inside a
		// googleapis base-URL literal.
		for _, s := range lits {
			for _, m := range gcpVerRe.FindAllStringSubmatch(s, -1) {
				if m[1] == version {
					return true
				}
			}
		}
		return false
	default:
		// aws/azure: the version is the literal itself.
		for _, s := range lits {
			if s == version {
				return true
			}
		}
		return false
	}
}

// TestCodeSubsetOfRegistry: code ⊆ registry ∪ allowlist. Every version-shaped
// literal in the driver source is a registered pin — a new un-registered version
// fails here (anti-scatter tripwire).
func TestCodeSubsetOfRegistry(t *testing.T) {
	// AWS: any bare YYYY-MM-DD literal must be a registered version, except the
	// IAM policy-language version.
	awsReg := versionSet("aws")
	for _, s := range stringLits(t, driverDir("aws")) {
		if !dateRe.MatchString(s) {
			continue
		}
		if s == awsPolicyLangAllow || awsReg[s] {
			continue
		}
		t.Errorf("aws: dated literal %q is not a registered API version and is not the "+
			"IAM policy-language allowlist entry — register it in apiver or add a named exception", s)
	}

	// GCP: every googleapis path version suffix must be a registered version.
	gcpReg := versionSet("gcp")
	for _, s := range stringLits(t, driverDir("gcp")) {
		for _, m := range gcpVerRe.FindAllStringSubmatch(s, -1) {
			if !gcpReg[m[1]] {
				t.Errorf("gcp: URL version segment %q (from %q) is not a registered API version", m[1], s)
			}
		}
	}

	// Azure: every const named *APIVersion must carry a registered version.
	azReg := versionSet("azure")
	for name, val := range namedConsts(t, driverDir("azure"), azVerName) {
		if !azReg[val] {
			t.Errorf("azure: const %s = %q is not a registered API version — register it in apiver", name, val)
		}
	}
}
