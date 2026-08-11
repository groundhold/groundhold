package gcp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
)

// routesFile is the checked-in set of routes the GCP drivers construct — the subject
// of TestLiveGCPEndpointReality (D718).
var routesFile = filepath.Join("testdata", "gcp-routes.txt")

// productionBase maps a Driver override field to the base URL the binary uses when
// that field is empty. Tests point every driver at a fixture, so a recorded URL

// carries a fixture host; this is how it is put back. A field used at capture time and
// missing here is a make-check failure, not a route quietly left unasked.
var productionBase = map[string]string{
	"ARBaseURL":          artifactRegistryBaseURL,
	"AssetFeedBaseURL":   assetFeedBaseURL,
	"BQBaseURL":          bigQueryBaseURL,
	"BackupDRBaseURL":    backupDRBaseURL,
	"CRMBaseURL":         crmBaseURL,
	"CertManagerBaseURL": certManagerBaseURL,
	"CfBaseURL":          cloudfunctionsBaseURL,
	"ComputeBaseURL":     computeBaseURL,
	"DNSBaseURL":         cloudDNSBaseURL,
	"DashboardBaseURL":   dashboardBaseURL,
	"FilestoreBaseURL":   filestoreBaseURL,
	"FirestoreBaseURL":   firestoreBaseURL,
	"BaseURL":            baseURL, // Cloud SQL, the package's original driver
	// Package-variable overrides (D718) — not Driver fields, so reflection is blind to
	// them and resolveBase names them explicitly.
	"suBaseOverride":                serviceUsageBaseURL,
	"gkeBaseURLOverride":            gkeBaseURL,
	"gkeAddonBaseOverride":          gkeAddonContainerBaseURL,
	"sccBaseURLOverride":            sccBaseURL,
	"auditLogsBaseURLOverride":      loggingBaseURL,
	"vertexAIBaseURLOverride":       "https://aiplatform.googleapis.com/v1",
	"billingBudgetsBaseURLOverride": billingBudgetsBaseURL,
	"cloudBillingBaseURLOverride":   cloudBillingBaseURL,
	"GcsBaseURL":                    gcsBaseURL,
	"IAMBaseURL":                    iamCustomRoleBaseURL,
	"KMSBaseURL":                    cloudKMSBaseURL,
	"LoggingBaseURL":                loggingBaseURL,
	"ManagedKafkaBaseURL":           managedKafkaBaseURL,
	"MemorystoreBaseURL":            memorystoreBaseURL,
	"MonitoringBaseURL":             monitoringBaseURL,
	"OrgPolicyBaseURL":              orgPolicyBaseURL,
	"PubSubBaseURL":                 pubsubBaseURL,
	"RunBaseURL":                    runBaseURL,
	"SchedulerBaseURL":              cloudSchedulerBaseURL,
	"SecretBaseURL":                 secretManagerBaseURL,
	"UptimeBaseURL":                 uptimeBaseURL,
}

// TestMain records what the GCP drivers build. Same mechanism as the AWS side (D717):
// the subject of the live route-reality gate is derived from the drivers, and the
// checked-in file is compared against a fresh recording on every unfiltered run, so a
// driver that starts calling a new route arrives as a reviewable diff.
//
//	GROUNDHOLD_ROUTE_CAPTURE=testdata/gcp-routes.txt go test ./internal/gcp/
func TestMain(m *testing.M) {
	var mu sync.Mutex
	seen := map[string]bool{}
	unresolved := map[string]bool{}
	gcpRouteSink = func(d *Driver, method, rawURL string) {
		// The QUERY is dropped: on GCP the path selects the route, and a fixture's
		// query carries its own server URL — random port and all — which made the
		// recorded set differ between two runs of the same tree, so the drift gate
		// could never be satisfied.
		if i := strings.IndexByte(rawURL, '?'); i >= 0 {
			rawURL = rawURL[:i]
		}
		field, rest := resolveBase(d, rawURL)
		mu.Lock()
		defer mu.Unlock()
		if field == "" {
			// No override matched, so the driver used a PRODUCTION base — the test
			// intercepts at the transport instead of the URL. That URL is already the
			// real one; keep it verbatim under a marker rather than dropping it.
			if strings.HasPrefix(rawURL, "https://") {
				seen["-\t"+method+"\t"+rawURL] = true
			} else {
				unresolved[method+" "+rawURL] = true
			}
			return
		}
		seen[field+"\t"+method+"\t"+rest] = true
	}

	code := m.Run()

	mu.Lock()
	got := make([]string, 0, len(seen))
	for k := range seen {
		got = append(got, k)
	}
	stray := len(unresolved)
	mu.Unlock()
	sort.Strings(got)

	if out := os.Getenv("GROUNDHOLD_ROUTE_CAPTURE"); out != "" {
		if err := os.WriteFile(out, []byte(strings.Join(got, "\n")+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "route capture:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "route capture: %d routes -> %s (%d unresolved)\n", len(got), out, stray)
	}
	if code == 0 && !filteredRun() {
		if err := compareRoutes(got); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	os.Exit(code)
}

// resolveBase finds which of the driver's base-URL overrides this call went through,
// returning the field name and the path beneath it. The longest match wins: several
// GCP services share a host and differ only by version prefix.
func resolveBase(d *Driver, rawURL string) (field, rest string) {
	// Some services keep their override in a PACKAGE variable rather than a Driver
	// field (D718). Reflection over the struct cannot see those, and a call through one
	// of them was attributed to whichever field the same fixture URL also matched —
	// which made the live gate accuse Artifact Registry of building Service Usage
	// paths. They are matched first, and longest wins among them.
	pkgBases := map[string]string{
		"suBaseOverride":                suBaseOverride,
		"gkeBaseURLOverride":            gkeBaseURLOverride,
		"gkeAddonBaseOverride":          gkeAddonBaseOverride,
		"sccBaseURLOverride":            sccBaseURLOverride,
		"auditLogsBaseURLOverride":      auditLogsBaseURLOverride,
		"vertexAIBaseURLOverride":       vertexAIBaseURLOverride,
		"billingBudgetsBaseURLOverride": billingBudgetsBaseURLOverride,
		"cloudBillingBaseURLOverride":   cloudBillingBaseURLOverride,
	}
	pkgBest := ""
	var pkgTied []string
	for name, base := range pkgBases {
		if base == "" || !strings.HasPrefix(rawURL, base) {
			continue
		}
		if len(base) > len(pkgBest) {
			pkgBest, pkgTied = base, []string{name}
		} else if base == pkgBest {
			pkgTied = append(pkgTied, name)
		}
	}
	v := reflect.ValueOf(d).Elem()
	t := v.Type()
	best := ""
	var tied []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !strings.HasSuffix(f.Name, "BaseURL") || v.Field(i).Kind() != reflect.String {
			continue
		}
		base := v.Field(i).String()
		if base == "" || !strings.HasPrefix(rawURL, base) {
			continue
		}
		if len(base) > len(best) {
			best, field, rest, tied = base, f.Name, strings.TrimPrefix(rawURL, base), []string{f.Name}
		} else if len(base) == len(best) && base == best {
			tied = append(tied, f.Name)
		}
	}
	if pkgBest != "" && len(pkgBest) >= len(best) {
		tied = append(tied[:0:0], pkgTied...)
		if len(best) > len(pkgBest) {
			tied = nil
		}
		if len(pkgBest) > len(best) {
			rest = strings.TrimPrefix(rawURL, pkgBest)
		} else {
			for i := 0; i < t.NumField(); i++ {
				f := t.Field(i)
				if strings.HasSuffix(f.Name, "BaseURL") && v.Field(i).Kind() == reflect.String &&
					v.Field(i).String() == pkgBest {
					tied = append(tied, f.Name)
				}
			}
		}
		sort.Strings(tied)
		if len(tied) == 1 {
			return tied[0], rest
		}
		return "AMBIGUOUS:" + strings.Join(tied, ","), rest
	}
	if len(tied) > 1 {
		sort.Strings(tied)
		return "AMBIGUOUS:" + strings.Join(tied, ","), rest
	}
	if field == "" {
		return "", ""
	}
	if rest == "" {
		rest = "/"
	}
	return field, rest
}

func filteredRun() bool {
	for _, a := range os.Args {
		if a == "-test.short=true" {
			return true
		}
		if strings.HasPrefix(a, "-test.run=") {
			v := strings.TrimPrefix(a, "-test.run=")
			if v != "" && v != "." && v != ".*" {
				return true
			}
		}
	}
	return false
}

func compareRoutes(got []string) error {
	raw, err := os.ReadFile(routesFile)
	if err != nil {
		return fmt.Errorf("route drift gate cannot read %s: %w", routesFile, err)
	}
	want := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l != "" {
			want[l] = true
		}
	}
	if len(got) == 0 {
		return fmt.Errorf("route drift gate recorded NO routes over a full run of this "+
			"package — the recorder is not wired into call(), and %s is unchecked", routesFile)
	}
	seen := map[string]bool{}
	var added, missing []string
	for _, g := range got {
		seen[g] = true
		if !want[g] {
			added = append(added, g)
		}
	}
	for w := range want {
		if !seen[w] {
			missing = append(missing, w)
		}
	}
	if len(added) == 0 && len(missing) == 0 {
		return nil
	}
	sort.Strings(added)
	sort.Strings(missing)
	var b strings.Builder
	fmt.Fprintf(&b, "the GCP drivers no longer call the routes recorded in %s.\n", routesFile)
	for _, a := range added {
		fmt.Fprintf(&b, "  + %s\n", strings.ReplaceAll(a, "\t", " "))
	}
	for _, m := range missing {
		fmt.Fprintf(&b, "  - %s\n", strings.ReplaceAll(m, "\t", " "))
	}
	b.WriteString("A new route is not wrong — it is unverified. Refresh the file " +
		"(GROUNDHOLD_ROUTE_CAPTURE=testdata/gcp-routes.txt go test ./internal/gcp/) " +
		"and let TestLiveGCPEndpointReality ask Google whether the route exists before shipping it.")
	return fmt.Errorf("%s", b.String())
}

// TestTheGCPRouteRecorderIsWired is the positive control. Unwire the recorder and the
// file freezes, the comparison finds nothing to report, and the live gate goes on
// asking about routes no driver builds. Every one of those failures is silent.
func TestTheGCPRouteRecorderIsWired(t *testing.T) {
	var mu sync.Mutex
	var got []string
	prev := gcpRouteSink
	gcpRouteSink = func(d *Driver, method, rawURL string) {
		if prev != nil {
			prev(d, method, rawURL)
		}
		mu.Lock()
		got = append(got, method+" "+rawURL)
		mu.Unlock()
	}
	defer func() { gcpRouteSink = prev }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	d := testDriver(t, srv)
	_, _, _ = d.call("GET", srv.URL+"/projects/p/instances/i", nil)

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatalf("the driver made a request and the recorder saw nothing — gcpRouteSink "+
			"is not wired into call(), so %s can no longer drift and the live gate is "+
			"asking about a frozen list", routesFile)
	}
}

// TestEveryRecordedGCPBaseHasAProductionURL keeps the live gate from covering less
// than it reports: a base with no production URL cannot be asked about.
func TestEveryRecordedGCPBaseHasAProductionURL(t *testing.T) {
	raw, err := os.ReadFile(routesFile)
	if err != nil {
		t.Fatalf("read %s: %v", routesFile, err)
	}
	bases := map[string]bool{}
	n := 0
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		n++
		bases[strings.SplitN(l, "\t", 2)[0]] = true
	}
	if n < 40 {
		t.Fatalf("only %d routes in %s — the file is a stub and the live gate would "+
			"report a clean run over almost nothing", n, routesFile)
	}
	var unmapped []string
	for b := range bases {
		for _, f := range candidateFields(b) {
			if productionBase[f] == "" {
				unmapped = append(unmapped, f)
			}
		}
	}
	if len(unmapped) > 0 {
		sort.Strings(unmapped)
		t.Errorf("no production URL for %v — TestLiveGCPEndpointReality cannot ask Google "+
			"about their routes, and would accuse the drivers of building paths that do "+
			"not exist when the truth is that this table is incomplete", unmapped)
	}
	// D718: a positive control for the check above. It was written, then an edit removed
	// its report and left the collection in place; the gate went on passing while
	// `BaseURL` — Cloud SQL, the oldest driver in the package — was missing from the
	// table. Collecting evidence and never reading it is the same as not looking.
	if productionBase["a-field-no-driver-has"] != "" {
		t.Fatal("the lookup answers for a field that does not exist — the check above " +
			"cannot distinguish mapped from unmapped")
	}
	// The recorded paths must be parseable as URLs against their base, or the replay
	// silently asks a mangled question.
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		p := strings.SplitN(l, "\t", 3)
		if len(p) != 3 {
			t.Fatalf("malformed line in %s: %q", routesFile, l)
		}
		for _, u := range candidateURLs(p[0], p[2]) {
			if _, err := url.Parse(u); err != nil {
				t.Errorf("unparseable route %q: %v", l, err)
			}
		}
	}
}

// candidateFields reads the base marker a recorded line carries. A plain field name is
// one candidate; "AMBIGUOUS:a,b" is several (the test that produced the line pointed
// more than one override at one fixture, so the origin cannot say which service it
// was); "-" is a line that already carries a production URL.
func candidateFields(marker string) []string {
	switch {
	case marker == "-":
		return nil
	case strings.HasPrefix(marker, "AMBIGUOUS:"):
		return strings.Split(strings.TrimPrefix(marker, "AMBIGUOUS:"), ",")
	default:
		return []string{marker}
	}
}

// candidateURLs turns a recorded line into the production URLs it could mean.
func candidateURLs(marker, rest string) []string {
	if marker == "-" {
		return []string{rest}
	}
	var out []string
	for _, f := range candidateFields(marker) {
		if b := productionBase[f]; b != "" {
			out = append(out, b+rest)
		}
	}
	return out
}
