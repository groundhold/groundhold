package aws

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

// routesFile is the checked-in set of (service, method, path) the AWS drivers
// construct — the subject of the live route-reality gate (D717).
var routesFile = filepath.Join("testdata", "aws-routes.txt")

// D717. D694 shipped a driver reading a route AWS does not have, and the gate meant
// to catch that class (TestLiveAWSEndpointReality, D274) covered two services out of
// forty because both of its route lists were typed by hand. A list someone must
// remember to extend is not a mechanism, so the subject is DERIVED now: every request
// any driver builds passes doSignedH, TestMain records what it sees, and one run of
// this package yields the routes the drivers actually believe in.
//
// The recorded set is compared against testdata/aws-routes.txt on every unfiltered
// run, so a driver that starts calling a new route cannot do it invisibly — it shows
// up as a reviewable diff. Refresh with:
//
//	GROUNDHOLD_ROUTE_CAPTURE=testdata/aws-routes.txt go test ./internal/aws/
//
// The comparison is skipped for a filtered or -short run, where the capture is a
// subset by construction and a mismatch would mean nothing.
func TestMain(m *testing.M) {
	var mu sync.Mutex
	seen := map[string]bool{}
	sites := map[string]bool{}
	routeSink = func(method, rawURL, service, op, chain string) {
		u, err := url.Parse(rawURL)
		if err != nil {
			return
		}
		path := u.EscapedPath()
		if path == "" {
			path = "/"
		}
		// For the Query-protocol services (IAM, EC2, SNS, ...) the operation is
		// selected by Action=, not by the path. Keep Action/Version.
		var keep []string
		for _, k := range []string{"Action", "Version"} {
			if v := u.Query().Get(k); v != "" {
				keep = append(keep, k+"="+v)
			}
		}
		// D850: keep the VALUELESS keys too. This used to drop everything else as
		// "whatever a fixture happened to pass", which is right for a filter or a
		// pagination marker — they all carry values — and wrong for S3, where the query
		// IS the operation: `?tagging`, `?versioning`, `?object-lock` are different
		// operations on one path, and CloudFront's `?WithTags` picks a different create.
		// Dropped, `GET /some-bucket` matched thirty-six modelled S3 operations, so the
		// permission gate could not attribute it at all (D849). Valueless-vs-valued is
		// the discriminator, and it needs no per-service list.
		var marks []string
		for k, vs := range u.Query() {
			if k == "Action" || k == "Version" {
				continue
			}
			if len(vs) == 1 && vs[0] == "" {
				marks = append(marks, k)
			}
		}
		sort.Strings(marks)
		keep = append(keep, marks...)
		// D853: the operation a Query/JSON request names in its body or header. For
		// those services the path is bare, so without this every call collapsed to one
		// recorded line and the permission gate could attribute none of them.
		if op != "" && u.Query().Get("Action") == "" {
			keep = append(keep, "Op="+op)
		}
		key := service + "\t" + method + "\t" + path
		if len(keep) > 0 {
			key += "?" + strings.Join(keep, "&")
		}
		mu.Lock()
		seen[key] = true
		// D871: WHO called, so the paging ratchet can join a recorded operation to the
		// code that issued it. An operation NAME is not a join key — ListTagsForResource
		// paginates for wafv2 and the literal appears at twenty-three call sites across
		// thirteen other services.
		if op != "" && chain != "" {
			sites[service+"	"+op+"	"+chain] = true
		}
		mu.Unlock()
	}

	code := m.Run()

	mu.Lock()
	got := make([]string, 0, len(seen))
	for k := range seen {
		got = append(got, k)
	}
	mu.Unlock()
	sort.Strings(got)

	if out := os.Getenv("GROUNDHOLD_ROUTE_CAPTURE"); out != "" {
		if err := os.WriteFile(out, []byte(strings.Join(got, "\n")+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "route capture:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "route capture: %d routes -> %s\n", len(got), out)
		mu.Lock()
		cs := make([]string, 0, len(sites))
		for k := range sites {
			cs = append(cs, k)
		}
		mu.Unlock()
		sort.Strings(cs)
		csOut := filepath.Join(filepath.Dir(out), "aws-callsites.txt")
		if err := os.WriteFile(csOut, []byte(strings.Join(cs, "\n")+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "call-site capture:", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "call-site capture: %d chains -> %s\n", len(cs), csOut)
	}
	if code == 0 && !filteredRun() {
		if err := compareRoutes(got); err != nil {
			fmt.Fprintln(os.Stderr, err)
			code = 1
		}
	}
	os.Exit(code)
}

// filteredRun reports whether this binary was asked for a subset of its tests, in
// which case the recorded routes are a subset too and prove nothing about drift.
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
	// D328: a gate whose subject is empty passes for the wrong reason. If nothing was
	// recorded, the sink is not wired and every green run below means nothing.
	if len(got) == 0 {
		return fmt.Errorf("route drift gate recorded NO routes over a full run of this "+
			"package — the recorder is not wired into doSignedH, and %s is unchecked", routesFile)
	}
	var added, missing []string
	for _, g := range got {
		if !want[g] {
			added = append(added, g)
		}
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
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
	fmt.Fprintf(&b, "the AWS drivers no longer call the routes recorded in %s.\n", routesFile)
	for _, a := range added {
		fmt.Fprintf(&b, "  + %s\n", strings.ReplaceAll(a, "\t", " "))
	}
	for _, m := range missing {
		fmt.Fprintf(&b, "  - %s\n", strings.ReplaceAll(m, "\t", " "))
	}
	b.WriteString("A new route is not wrong — it is unverified. Refresh the file " +
		"(GROUNDHOLD_ROUTE_CAPTURE=testdata/aws-routes.txt go test ./internal/aws/) " +
		"and let TestLiveAWSEndpointReality ask AWS whether the route exists before shipping it.")
	return fmt.Errorf("%s", b.String())
}

// TestTheRouteRecorderSeesWhatTheDriversBuild is the positive control for the
// recorder. Everything above rests on doSignedH calling routeSink: unwire it and the
// checked-in file freezes, the drift comparison reports nothing to report, and the
// live gate goes on asking AWS about routes no driver builds any more. The failure is
// silent in both places, so the wiring gets asserted directly, against a driver call.
func TestTheRouteRecorderSeesWhatTheDriversBuild(t *testing.T) {
	var mu sync.Mutex
	var got []string
	prev := routeSink
	routeSink = func(method, rawURL, service, op, chain string) {
		if prev != nil {
			prev(method, rawURL, service, op, chain)
		}
		mu.Lock()
		got = append(got, service+" "+method+" "+rawURL)
		mu.Unlock()
	}
	defer func() { routeSink = prev }()

	srv := mskServer(t, "bus", "3.5.1", false)
	defer srv.Close()
	d := mskDriver(t, srv)
	if _, _, err := d.getMSKByName("eu-central-1", "pv-c"); err != nil {
		t.Fatalf("fixture read failed, so this test proves nothing about the recorder: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, g := range got {
		if strings.HasPrefix(g, "kafka GET ") && strings.Contains(g, mskPath) {
			return
		}
	}
	t.Fatalf("the driver made a request and the recorder saw %v — routeSink is not wired "+
		"into doSignedH, so %s can no longer drift and the live gate is asking about a "+
		"frozen list", got, routesFile)
}

// TestEveryRecordedServiceHasAHost keeps the live gate from quietly covering less than
// it claims: the replay resolves a host per SigV4 service name, and a service with no
// mapping would simply not be asked. That refusal has to happen where make check can
// see it, not on the pre-ship box.
func TestEveryRecordedServiceHasAHost(t *testing.T) {
	raw, err := os.ReadFile(routesFile)
	if err != nil {
		t.Fatalf("read %s: %v", routesFile, err)
	}
	services := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l == "" {
			continue
		}
		services[strings.SplitN(l, "\t", 2)[0]] = true
	}
	if len(services) < 30 {
		t.Fatalf("only %d services in %s — the file is a stub, and the live gate would "+
			"report a clean run over almost nothing", len(services), routesFile)
	}
	var unmapped []string
	for s := range services {
		if awsServiceHost(s, "eu-central-1") == "" {
			unmapped = append(unmapped, s)
		}
	}
	if len(unmapped) > 0 {
		sort.Strings(unmapped)
		t.Errorf("no endpoint host for %v — TestLiveAWSEndpointReality cannot ask AWS "+
			"about their routes, and would pass without checking them", unmapped)
	}
}
