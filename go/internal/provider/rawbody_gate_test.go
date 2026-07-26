package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D309: a driver diagnostic may never carry a provider response body wholesale.
//
// This is not a style rule. A CreateResult.Reason is copied verbatim into
// receipt["reason"] by apply.go, which is a PERSISTED ledger event that `export`
// publishes and `capsule` signs and ships to a third party. A response body is
// attacker- and provider-controlled, unbounded, and can echo values the driver
// itself sent — including the credentials it is required to send (Aurora's
// MasterUserPassword, Azure's administratorLoginPassword).
//
// The replacement is per-cloud: mutDetail / mutDetailAz lift the provider's own
// error message, bounded and newline-free, and fall back to its error code.
// The credential scrub at the driver boundary (internal/provider/redact.go) is
// the second, independent defence — this gate is the first.
//
// Unlike the read-diagnostics ratchet (readdiag_ratchet_test.go), this one has
// never had a budget: it went in with the debt already paid, so it is an
// invariant from birth.
var (
	// a stringified response body, by the names the drivers actually use
	rawBodyExpr = regexp.MustCompile(`string\((body|resp|b|raw|payload)\)`)
	// ...appearing in something an operator (or a receipt) will read
	diagnosticLine = regexp.MustCompile(`Reason|Errorf|Sprintf|append\(diags|append\(\*diags`)
	// a helper that exists to paste a bounded slice of a body
	bodyTruncator = regexp.MustCompile(`func (truncate|truncateAz|truncateBody)\(`)
)

func TestNoRawBodyInDriverDiagnostics(t *testing.T) {
	// EVERY provider package, not just the three big clouds: the receipt channel
	// is the same one whatever wrote the resource, and k8s carried the identical
	// paste until D309 found it here.
	checked := 0
	for _, pkg := range []string{"aws", "azure", "gcp", "k8s", "cloudflare", "hetzner", "upstash"} {
		dir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			checked++
			for i, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "//") {
					continue // prose describing this very rule
				}
				switch {
				case rawBodyExpr.MatchString(line) && diagnosticLine.MatchString(line):
					t.Errorf("%s:%d pastes a raw response body into a diagnostic. The "+
						"Reason is persisted in the ledger and signed into capsules — use "+
						"mutDetail/mutDetailAz (bounded message + provider error code).\n\t%s",
						path, i+1, strings.TrimSpace(line))
				case bodyTruncator.MatchString(line):
					t.Errorf("%s:%d reintroduces a body truncator. Truncating a body does "+
						"not make it safe to persist — lift the provider's own error message "+
						"instead (mutDetail/mutDetailAz).\n\t%s",
						path, i+1, strings.TrimSpace(line))
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("the gate scanned ZERO files — it would pass whatever the drivers do")
	}
}
