package azure

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// azureRoutesFile is the checked-in set of (method, resource-type path) the Azure
// drivers construct — the subject of the permission-sufficiency gate (D1014) and a
// route-reality diff.
var azureRoutesFile = filepath.Join("testdata", "azure-routes.txt")

// D1014. GCP and Azure had no permission-sufficiency gate: an operation whose ARM
// permission was declared NOWHERE passed the preflight and walled mid-apply, and only
// hand-tracing caught it. AWS derives its subject from the routes the drivers build
// (D717); Azure now does the same. Every ARM request passes doARMHeader; TestMain
// records what it sees during the existing suite, normalises instance names to {}, and
// yields the resource-type paths the drivers actually call.
//
// The recorded set is compared against testdata/azure-routes.txt on every unfiltered
// run, so a driver that starts calling a new ARM type cannot do it invisibly — it is a
// reviewable diff, and the permission gate reads the same file. Refresh with:
//
//	GROUNDHOLD_ROUTE_CAPTURE=testdata/azure-routes.txt go test ./internal/azure/
//
// The comparison is skipped for a filtered or -short run, where the capture is a subset
// by construction and a mismatch would mean nothing.
func TestMain(m *testing.M) {
	var mu sync.Mutex
	seen := map[string]bool{}
	azureRouteSink = func(method, rawURL string) {
		rec, ok := azureRouteRecord(method, rawURL)
		if !ok {
			return
		}
		mu.Lock()
		seen[rec] = true
		mu.Unlock()
	}

	code := m.Run()
	azureRouteSink = nil

	got := make([]string, 0, len(seen))
	for r := range seen {
		got = append(got, r)
	}
	sort.Strings(got)

	if dest := os.Getenv("GROUNDHOLD_ROUTE_CAPTURE"); dest != "" && code == 0 {
		body := strings.Join(got, "\n") + "\n"
		if err := os.WriteFile(dest, []byte(body), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "route capture: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "route capture: wrote %d routes to %s\n", len(got), dest)
		os.Exit(code)
	}

	// A filtered or -short run captured only a subset; comparing it would be noise.
	if code == 0 && !testing.Short() && !runFiltered() {
		if err := compareAzureRoutes(got); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	os.Exit(code)
}

// runFiltered reports whether -run/-test.run narrowed this invocation, in which case
// the capture is a subset by construction.
func runFiltered() bool {
	for _, a := range os.Args {
		if strings.HasPrefix(a, "-test.run=") && a != "-test.run=" && a != "-test.run=.*" {
			return true
		}
	}
	return false
}

func compareAzureRoutes(got []string) error {
	want, err := os.ReadFile(azureRoutesFile)
	if err != nil {
		return fmt.Errorf("read %s: %v (refresh with GROUNDHOLD_ROUTE_CAPTURE=%s)", azureRoutesFile, err, azureRoutesFile)
	}
	wantSet := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(want)), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			wantSet[l] = true
		}
	}
	gotSet := map[string]bool{}
	for _, l := range got {
		gotSet[l] = true
	}
	var missing, extra []string
	for r := range wantSet {
		if !gotSet[r] {
			missing = append(missing, r)
		}
	}
	for r := range gotSet {
		if !wantSet[r] {
			extra = append(extra, r)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "azure route set drifted from %s — refresh with "+
		"GROUNDHOLD_ROUTE_CAPTURE=%s go test ./internal/azure/\n", azureRoutesFile, azureRoutesFile)
	for _, r := range extra {
		fmt.Fprintf(&b, "  + %s (a driver now calls this; the permission gate must cover it)\n", r)
	}
	for _, r := range missing {
		fmt.Fprintf(&b, "  - %s (no test drives this any more)\n", r)
	}
	return fmt.Errorf("%s", b.String())
}

// azureRouteRecord normalises one ARM request to "<METHOD>\t<type-path>", where the
// type path keeps the resource TYPE segments and replaces each instance NAME with {}.
// The last /providers/ wins (an extension resource — a role assignment or diagnostic
// setting scoped ONTO another resource — is what the request acts on). The api-version
// query and every other query key are dropped; ARM selects the operation by path and
// method, never by a query key.
func azureRouteRecord(method, rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	path := u.EscapedPath()
	idx := strings.LastIndex(path, "/providers/")
	if idx < 0 {
		return "", false
	}
	rest := strings.Trim(path[idx+len("/providers/"):], "/")
	if rest == "" {
		return "", false
	}
	segs := strings.Split(rest, "/")
	// segs[0] is the resource provider (Microsoft.X); then type,name,type,name...
	// The NAME segments are at even indices (2, 4, 6, ...) — replace each with {}.
	for i := 2; i < len(segs); i += 2 {
		segs[i] = "{}"
	}
	return method + "\t" + strings.Join(segs, "/"), true
}
