package gcp

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1232. A unit test that reaches a REAL cloud API is not a unit test, and this
// package had 52 such requests per run across 20 production Google hosts.
//
// They were invisible for the reason D1230 named: the failure falls to the
// conservative branch. `List` sweeps every discoverer, an unpinned base URL sends its
// request to the real host, the request fails (no credentials, or no network), the
// sweep records the failure and carries on — and the assertion downstream counts only
// what the FIXTURE served, so it passes either way. The route recorder even wrote the
// production URLs into the checked-in baseline under a "-" marker, where they read as
// legitimate routes rather than as escapes.
//
// pinAllBaseURLs closes it by CONSTRUCTION rather than by diligence: it reflects over
// the Driver and points every `*BaseURL` field at the fixture. A base URL added
// tomorrow is pinned the day it appears, which hand-maintained lists never are — the
// sweep test pinned 5 of 26 and nobody noticed for as long as that.
func pinAllBaseURLs(t *testing.T, d *Driver, url string) {
	t.Helper()
	v := reflect.ValueOf(d).Elem()
	typ := v.Type()
	pinned := 0
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !strings.HasSuffix(f.Name, "BaseURL") || f.Type.Kind() != reflect.String {
			continue
		}
		if !v.Field(i).CanSet() {
			t.Fatalf("%s is not settable — an unexported base URL cannot be pinned, so a "+
				"test using it would reach the real host", f.Name)
		}
		v.Field(i).SetString(url)
		pinned++
	}
	// D328: a gate must have a subject. A reflect walk that matched nothing would
	// "pin" everything by pinning nothing.
	if pinned < 20 {
		t.Fatalf("pinned only %d base URLs — the driver declares far more; the reflect "+
			"walk is broken and this helper is protecting nothing", pinned)
	}
	pinPackageSeams(t, url)
}

// pinPackageSeams points the PACKAGE-LEVEL overrides at the fixture too.
//
// D1233. Reflection over the Driver reaches struct fields and nothing else, and eight
// GCP services keep their test seam in a package var instead — a deliberate choice
// their comments explain ("the driver's endpoint lives in its own files; the Driver
// struct is not edited"). So D1232's helper left exactly those eight able to escape,
// which is why the ratchet stopped at 8 rather than 0. The list below is hand-written
// BUT it cannot rot: TestEveryPackageSeamIsPinned reads this file and the package's
// sources and fails the build if a seam exists that this function does not set.
//
// They are globals, so they are restored on cleanup — a leaked override would make the
// NEXT test read a fixture that has already been torn down, which fails in a way that
// points at the wrong test.
func pinPackageSeams(t *testing.T, url string) {
	t.Helper()
	seams := []*string{
		&suBaseOverride,
		&sccBaseURLOverride,
		&gkeBaseURLOverride,
		&gkeAddonBaseOverride,
		&cloudBillingBaseURLOverride,
		&billingBudgetsBaseURLOverride,
		&auditLogsBaseURLOverride,
		&vertexAIBaseURLOverride,
	}
	for _, p := range seams {
		prev := *p
		restore := p
		t.Cleanup(func() { *restore = prev })
		*p = url
	}
}

// The helper's own gate: every base-URL field the driver declares must end up
// pointing at the fixture. Asserted by re-reading the struct, not by trusting the
// loop that wrote it.
func TestPinAllBaseURLsLeavesNoFieldOnAProductionHost(t *testing.T) {
	d := NewDriver("acme-prod")
	pinAllBaseURLs(t, d, "http://127.0.0.1:1")
	v := reflect.ValueOf(d).Elem()
	typ := v.Type()
	var stray []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if !strings.HasSuffix(f.Name, "BaseURL") || f.Type.Kind() != reflect.String {
			continue
		}
		if got := v.Field(i).String(); got != "http://127.0.0.1:1" {
			stray = append(stray, f.Name+"="+got)
		}
	}
	if len(stray) > 0 {
		t.Fatalf("these base URLs were not pinned and would reach the real host: %s",
			strings.Join(stray, ", "))
	}
}

// An empty base URL is what makes an unpinned field dangerous: the driver falls back
// to the production constant. This states that relationship, so the helper's purpose
// survives a refactor that changes how the fallback is spelled.
func TestAnEmptyBaseURLFallsBackToProduction(t *testing.T) {
	d := NewDriver("acme-prod")
	d.IAMBaseURL = ""
	if got := d.iamBase(); !strings.HasPrefix(got, "https://") {
		t.Fatalf("an unset base URL must fall back to the production host — that is why "+
			"pinning matters; got %q", got)
	}
}

// deadLocal is a LOCAL host that answers "not found" to everything. It is how a test
// says "this service has nothing" without letting the request reach a real host — the
// distinction D1232 exists to keep. A 404 with a GCP-shaped error body is what the
// drivers read as an authoritative absence rather than a failure to read.
func deadLocal(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":404,"message":"not found"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// TestEveryPackageSeamIsPinned is the forcing function that keeps pinPackageSeams from
// rotting. A hand-written list is exactly what failed in D1232 (5 of 26 base URLs), so
// this one is not trusted to be complete — it is CHECKED, by reading the package's own
// sources for seam declarations and requiring each to appear in the pinning list.
//
// The convention it enforces: a package-level test seam is a `var <name> string` whose
// name ends in `Override`. A new service that adds one and does not add it here fails
// the build, on the day it is added, instead of quietly escaping to a real host until
// somebody re-reads a routes file.
func TestEveryPackageSeamIsPinned(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	seamDecl := regexp.MustCompile(`(?m)^var ([A-Za-z0-9_]*Override) string`)
	declared := map[string]string{} // name -> file
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range seamDecl.FindAllStringSubmatch(string(src), -1) {
			declared[m[1]] = n
		}
	}
	// D328: assert the subject. A regex that matched nothing would pass over nothing.
	if len(declared) < 5 {
		t.Fatalf("found only %d package-level seams — the scan is broken, so this lint is "+
			"protecting nothing", len(declared))
	}

	helper, err := os.ReadFile("hermetic_test.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(helper)
	missing := unpinnedSeams(declared, body)
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("%d package-level seam(s) exist that pinPackageSeams does not set:\n  %s\n\n"+
			"A test using that service reaches the REAL cloud host (D1232). Add it to the "+
			"seam list in pinPackageSeams.", len(missing), strings.Join(missing, "\n  "))
	}
}

// unpinnedSeams is the lint's judgement, separated from the file reading so the
// property that matters can be witnessed directly.
//
// A seam counts as pinned only when it appears as an ADDRESS-OF inside the list —
// `&name,`. A bare-name search would be satisfied by the prose in this very file,
// which mentions several seams by name while explaining them: the D1225 trap where a
// check accepting a WORD accepts the paragraph about the word. That property has no
// live instance today (every declared seam is pinned), so it needs a constructed
// witness rather than a passing run — see TestUnpinnedSeamsIgnoresAProseMention.
func unpinnedSeams(declared map[string]string, helperBody string) []string {
	var missing []string
	for name, file := range declared {
		if !strings.Contains(helperBody, "&"+name+",") {
			missing = append(missing, name+" ("+file+")")
		}
	}
	return missing
}

// The witness: a seam that is TALKED ABOUT but not pinned must still be reported.
func TestUnpinnedSeamsIgnoresAProseMention(t *testing.T) {
	declared := map[string]string{"exampleBaseOverride": "example_net.go"}

	prose := "// exampleBaseOverride points the example API at a stub in tests.\n"
	if got := unpinnedSeams(declared, prose); len(got) != 1 {
		t.Fatalf("a seam only MENTIONED in a comment is not pinned — the lint must still "+
			"report it, got %v", got)
	}
	pinned := "\t\t&exampleBaseOverride,\n"
	if got := unpinnedSeams(declared, pinned); len(got) != 0 {
		t.Fatalf("a seam taken by address in the list IS pinned, got %v", got)
	}
	// and the two together — the real file's shape, where prose and list coexist
	if got := unpinnedSeams(declared, prose+pinned); len(got) != 0 {
		t.Fatalf("prose beside the pin must not change the verdict, got %v", got)
	}
}
