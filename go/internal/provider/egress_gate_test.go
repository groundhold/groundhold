package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1127. "Zero telemetry" is published in six places, and the honesty page calls it
// structural — "guaranteed by the absence of any network call in the core rather than
// by a case". The core half is true and was never in doubt. The sentence around it was
// not: SECURITY.md told researchers that "any network traffic beyond the configured
// provider is a vulnerability — report it", and the runtime opens two further
// destinations, both documented features.
//
//	notify  — POSTs to the URL the operator passed to --notify-url (D229)
//	reach   — GETs the resource's own address after apply, to see if it is public (D537)
//
// Neither is telemetry: the operator asked for both, and nothing reports back to us.
// But a researcher who observes either and files, on the strength of that sentence,
// gets told it is a feature — and the next thing they will not do is file again. The
// claim failed in the safe direction and still cost what such claims are for.
//
// The fix is precision, not retraction, so the gate is a NAMED set: exactly these
// packages may issue an outbound request. A new one is either a driver (add it here
// deliberately) or a destination nobody agreed to.
// netReachAllowed is the published set: exactly these packages, shipped in the binary,
// may issue an outbound request. It lives at package scope because D1247 added a second
// gate over the same claim, and two copies of a closed set drift — the answer is one
// registry read by both, not two lists kept in step by hand.
var netReachAllowed = map[string]string{
	// The configured provider.
	"internal/aws": "driver", "internal/azure": "driver", "internal/gcp": "driver",
	"internal/k8s": "driver", "internal/cloudflare": "driver",
	"internal/hetzner": "driver", "internal/upstash": "driver",
	// The two the security note now names.
	"internal/notify": "operator-supplied --notify-url (D229)",
	"internal/reach":  "post-apply reachability probe of the resource itself (D537)",
}

func TestOnlyNamedPackagesReachTheNetwork(t *testing.T) {
	allowed := netReachAllowed

	root := repoRoot(t)
	goRoot := filepath.Join(root, "go")

	// A call, not an import: `errorclass.go` uses http.Header and http.ParseTime and
	// contacts nothing, so importing net/http cannot be the test.
	call := regexp.MustCompile(`\.Do\(req|\.Do\(r\b|http\.Get\(|http\.Post\(|client\.Get\(|client\.Do\(`)

	found := map[string]bool{}
	err := filepath.Walk(goRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil // harnesses may reach a httptest server
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !call.Match(raw) {
			return nil
		}
		rel, err := filepath.Rel(goRoot, filepath.Dir(path))
		if err != nil {
			return err
		}
		found[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) < 5 {
		t.Fatalf("found %d packages issuing outbound calls — the probe broke, and a "+
			"gate that finds nothing must not report success (D328)", len(found))
	}

	var unnamed []string
	for pkg := range found {
		if _, ok := allowed[pkg]; !ok {
			unnamed = append(unnamed, pkg)
		}
	}
	sort.Strings(unnamed)
	if len(unnamed) > 0 {
		t.Errorf("these packages issue outbound HTTP and the security note does not "+
			"name them:\n  %s\n\nSECURITY.md publishes an EXHAUSTIVE list of "+
			"destinations and tells researchers anything else is a vulnerability. A new "+
			"caller is either a driver — add it here, deliberately — or traffic nobody "+
			"agreed to.", strings.Join(unnamed, ", "))
	}

	// The other direction: a named non-driver that stops calling means the security
	// note now lists a destination that does not exist, which reads as more egress
	// than there is.
	for pkg, why := range allowed {
		if strings.HasSuffix(why, "driver") {
			continue
		}
		if !found[pkg] {
			t.Errorf("%s no longer issues an outbound call, but SECURITY.md still lists "+
				"it (%s). Remove it there in the same change — an over-broad disclosure "+
				"is still an inaccurate one.", pkg, why)
		}
	}
}

// The published note must keep naming all three destinations. Losing one returns the
// claim to the state this entry is about: true about telemetry, wrong about traffic.
func TestTheSecurityNoteNamesEveryDestination(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "SECURITY.md"))
	if err != nil {
		t.Fatal(err)
	}
	note := string(raw)
	i := strings.Index(note, "ZERO telemetry")
	if i < 0 {
		t.Fatal("SECURITY.md no longer states the telemetry claim — this gate has lost " +
			"its subject, and the claim is published in five other places that would " +
			"now stand alone")
	}
	end := strings.Index(note[i:], "\n- ")
	if end < 0 {
		end = len(note) - i
	}
	section := note[i : i+end]

	for _, must := range []string{"--notify-url", "reachability"} {
		if !strings.Contains(section, must) {
			t.Errorf("the security note no longer names %q as a destination. The runtime "+
				"opens it; a researcher who sees that traffic and reads this note files a "+
				"report about a documented feature.", must)
		}
	}
	if !regexp.MustCompile(`(?i)vulnerability`).MatchString(section) {
		t.Error("the security note no longer tells researchers what to do about traffic " +
			"outside the list — the list is only useful with that sentence")
	}
}
