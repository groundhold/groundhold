package provider_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1247. The D1127 gate above publishes a strong sentence — "exactly these packages
// may issue an outbound request; a new one is either a driver or traffic nobody agreed
// to" — and enforces it with a regex over VARIABLE NAMES: `.Do(req`, `.Do(r`,
// `client.Get(`, `client.Do(`. Rename the variable and the gate goes quiet.
//
// That is not hypothetical. Two packages in this tree reach the network today and the
// D1127 set names neither, because both send through the TRANSPORT rather than through
// a client method:
//
//	internal/fixture     Recorder.RoundTrip delegates to http.DefaultTransport (D234)
//	internal/certifynet  countRT wraps http.DefaultTransport, calls inner.RoundTrip
//
// Measured before this gate: both are imported ONLY by _test.go files, so neither ships
// in the binary and no published claim about the RUNTIME was false. That is the honest
// scope of the finding — the coverage was narrower than the wording, not the wording
// wrong. But injecting a Transport is the most natural way to add egress, and it was
// the one shape the gate could not see.
//
// So this gate asks the question by what it MEANS: which packages that actually ship
// can send, and are the ones that cannot ship named DELIBERATELY rather than missed?

// netSends are the shapes by which Go code hands bytes to the network. The first four
// are the D1127 set, kept verbatim so this gate is a superset and not a replacement.
// The last three are the transport layer that set could not see — the ones that caught
// fixture and certifynet.
var netSends = regexp.MustCompile(
	`\.Do\(req|\.Do\(r\b|http\.Get\(|http\.Post\(|client\.Get\(|client\.Do\(` +
		`|&http\.Client\{|http\.DefaultTransport|http\.DefaultClient|\.RoundTrip\(`)

// testOnlyReachers reach the network but are imported only by tests, so they never
// ship. Naming them is the point: a deliberate omission has to be visible, and this
// list is checked in BOTH directions — an entry that starts shipping fails below.
var testOnlyReachers = map[string]string{
	"internal/fixture": "records the DRIVER's own exchanges through its transport, so " +
		"the destination is whatever the driver was pointed at (D234); runs only where " +
		"real credentials exist",
	"internal/certifynet": "drives a driver against a server the test stood up, counting " +
		"round-trips through a wrapping transport",
}

// packagesThatSend returns every package under go/ whose non-test sources import
// net/http AND contain a send shape. The import is required so that `sched.Do(...)` in
// internal/crawl — a pace scheduler, not a client — is not read as egress.
func packagesThatSend(t *testing.T, goRoot string) map[string]bool {
	t.Helper()
	send := map[string]bool{}
	imports := map[string]bool{}
	walkGoFiles(t, goRoot, func(rel string, raw []byte) {
		if strings.Contains(string(raw), `"net/http"`) {
			imports[rel] = true
		}
		if netSends.Match(raw) {
			send[rel] = true
		}
	})
	out := map[string]bool{}
	for pkg := range send {
		if imports[pkg] {
			out[pkg] = true
		}
	}
	return out
}

// walkGoFiles calls fn for every non-test .go file, keyed by its package directory.
//
// A vanished entry is SKIPPED rather than fatal. The mutation meter copies a source to
// `<file>.mut.orig` and moves it back moments later, and a walk that aborts on the
// first lstat error turns that into a red with nothing wrong — which cost a full gate
// run to diagnose. Skipping is safe here only because the package-set assertions below
// would catch an under-scan; without them this would be the quiet hole, not the fix.
func walkGoFiles(t *testing.T, goRoot string, fn func(rel string, raw []byte)) {
	t.Helper()
	err := filepath.Walk(goRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if skipWalkErr(err) {
				return nil // removed under us; the parity checks below still bind
			}
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			if skipWalkErr(err) {
				return nil
			}
			return err
		}
		rel, err := filepath.Rel(goRoot, filepath.Dir(path))
		if err != nil {
			return err
		}
		fn(filepath.ToSlash(rel), raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// skipWalkErr says whether a walk error means "this entry is gone" — the only error a
// tree scan may ignore. Anything else (a directory it may not read, a broken mount) is
// a scan that did not see the whole tree, and a gate whose scan was cut short must not
// report a clean set. Pulled out as a function because the concurrency that produces
// the first case cannot be staged in a unit test, so the DECISION is what gets tested.
func skipWalkErr(err error) bool { return os.IsNotExist(err) }

// The two directions, on constructed errors: a vanished file is skipped, and an
// unreadable one still stops the scan.
func TestOnlyAVanishedEntryIsSkipped(t *testing.T) {
	if !skipWalkErr(os.ErrNotExist) {
		t.Error("a file removed mid-walk must be skipped — the mutation meter creates and " +
			"removes `<file>.mut.orig` while tests run, and aborting there is a red with " +
			"nothing wrong")
	}
	for _, err := range []error{os.ErrPermission, os.ErrInvalid, os.ErrClosed} {
		if skipWalkErr(err) {
			t.Errorf("%v is not a vanished entry — swallowing it lets the walk miss whole "+
				"directories and still report an exhaustive set, which is the failure this "+
				"gate exists to prevent", err)
		}
	}
}

// shippingPackages is every package reachable from the binary's main by non-test
// imports. Test files are excluded deliberately: a helper a test imports does not
// travel to an operator, and the whole distinction this gate draws rests on that.
func shippingPackages(t *testing.T, goRoot string) map[string]bool {
	t.Helper()
	const mainPkg = "cmd/groundhold"
	seen := map[string]bool{}
	queue := []string{mainPkg}
	fset := token.NewFileSet()
	for len(queue) > 0 {
		pkg := queue[0]
		queue = queue[1:]
		if seen[pkg] {
			continue
		}
		seen[pkg] = true
		entries, err := os.ReadDir(filepath.Join(goRoot, pkg))
		if err != nil {
			t.Fatalf("read package %s: %v", pkg, err)
		}
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, filepath.Join(goRoot, pkg, n), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s/%s: %v", pkg, n, err)
			}
			for _, imp := range f.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if !strings.HasPrefix(p, "groundhold/") {
					continue
				}
				queue = append(queue, strings.TrimPrefix(p, "groundhold/"))
			}
		}
	}
	delete(seen, mainPkg)
	return seen
}

// The gate. Every package that can send is either named as a shipping destination, or
// named as test-only — and nothing is in neither list.
func TestEverySendingPackageIsNamedOrDeliberatelyExempt(t *testing.T) {
	goRoot := filepath.Join(repoRoot(t), "go")
	senders := packagesThatSend(t, goRoot)
	shipping := shippingPackages(t, goRoot)

	// D328: a scan that finds nothing must not pass. Nine drivers and destinations were
	// measured when this was written; the floor is deliberately just under that.
	if len(senders) < 9 {
		t.Fatalf("found %d packages that can send — the scan is broken, and a gate that "+
			"finds nothing must not report success", len(senders))
	}
	if len(shipping) < 20 {
		t.Fatalf("the binary reaches %d packages — the import walk is broken", len(shipping))
	}

	var unnamed []string
	for pkg := range senders {
		_, ships := netReachAllowed[pkg]
		_, exempt := testOnlyReachers[pkg]
		if ships || exempt {
			continue
		}
		where := "does not ship"
		if shipping[pkg] {
			where = "SHIPS in the binary"
		}
		unnamed = append(unnamed, pkg+" ("+where+")")
	}
	sort.Strings(unnamed)
	if len(unnamed) > 0 {
		t.Errorf("these packages can hand bytes to the network and no list names them:\n  %s\n\n"+
			"SECURITY.md publishes an EXHAUSTIVE set of destinations. Add a shipping one "+
			"to netReachAllowed with the destination it opens, or a test-only helper to "+
			"testOnlyReachers with why it cannot reach an operator.",
			strings.Join(unnamed, "\n  "))
	}

	// The direction that matters most: a test-only helper that starts SHIPPING carries
	// its egress into the binary, and its exemption — written when it could not reach an
	// operator — would then be a licence rather than a fact.
	for pkg, why := range testOnlyReachers {
		if !senders[pkg] {
			t.Errorf("%s is exempted as a test-only sender (%s) but no longer sends — "+
				"drop the exemption rather than leaving a name that means nothing", pkg, why)
		}
		if shipping[pkg] {
			t.Errorf("%s is exempted from the destination list BECAUSE only tests import "+
				"it — and it now ships in the binary. Its egress travels to operators; "+
				"move it to netReachAllowed and say which destination it opens, or cut "+
				"the import.", pkg)
		}
	}

	// And every shipping name must actually ship, or the published list describes a
	// destination the binary does not have.
	for pkg := range netReachAllowed {
		if !shipping[pkg] {
			t.Errorf("%s is published as a destination of the binary but is not reachable "+
				"from main — the note claims more egress than there is", pkg)
		}
	}
}

// The transport shapes have to be the reason this gate sees more than D1127's did. A
// witness constructed here rather than asserted about the tree: if the added
// alternatives are dropped, these fail while the tree stays green, which is what a
// regex weakening actually looks like.
func TestTheTransportLayerCountsAsSending(t *testing.T) {
	for name, src := range map[string]string{
		"wrapping DefaultTransport": `rt := &countRT{inner: http.DefaultTransport}`,
		"delegating a RoundTrip":    `resp, err := s.inner.RoundTrip(req)`,
		"building a client to hand out": `func (r *Recorder) Client() *http.Client ` +
			`{ return &http.Client{Transport: r} }`,
		"the default client": `resp, err := http.DefaultClient.Get(u)`,
	} {
		if !netSends.MatchString(src) {
			t.Errorf("%s is a way to reach the network and the shape set misses it:\n  %s",
				name, src)
		}
	}
	// ...and the shape set must not read a scheduler as a client. internal/crawl calls
	// sched.Do(conn.Provider, ...) and contacts nothing; the net/http import is what
	// separates them, so both halves are asserted.
	if netSends.MatchString(`_, err := sched.Do(conn.Provider, func() pace.Result {`) {
		t.Error("sched.Do is a pace scheduler, not an HTTP client — matching it would " +
			"put packages on the destination list that contact nothing, and a list with " +
			"false entries stops being read")
	}
}
