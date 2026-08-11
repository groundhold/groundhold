package azure

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D467: the subscription boundary, asserted as a class — GCP's D466 on the other cloud,
// and the failure mode is different enough to be worth its own sentence.
//
// On GCP a mismatched project in the providerId sends the request to the OTHER project,
// so the guard stops us reaching someone else's estate. On Azure it does not: armURL
// builds every URL from d.Subscription, never from the subscription bound out of the
// providerId. So a foreign-subscription providerId never left our own subscription — it
// silently RETARGETED the operation at the same resource group and name HERE. The
// binding named one resource and the driver acted on a different one, and if both exist
// the operator retires the wrong estate believing they retired the other.
//
// Sixty-four of sixty-seven sub-bearing paths refused it. Three parsed the subscription
// and threw it away with `_ = sub` — a line whose only purpose is to silence the
// compiler about an ownership signal.

var azBindsSub = regexp.MustCompile(`\n\tsub, [^\n]*= split\w*ProviderID\(providerID\)`)

func TestSubscriptionBearingPathsGuardTheBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fnDecl := regexp.MustCompile(`func \(d \*Driver\) ((?:observe|delete|update|create)\w+)\(`)
	guard := regexp.MustCompile(`sub != d\.Subscription`)

	var checked int
	var unguarded []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(n)
		if err != nil {
			continue
		}
		src := string(raw)
		locs := fnDecl.FindAllStringSubmatchIndex(src, -1)
		for i, loc := range locs {
			end := len(src)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			body := src[loc[0]:end]
			if !azBindsSub.MatchString(body) {
				continue
			}
			checked++
			if !guard.MatchString(body) {
				unguarded = append(unguarded, src[loc[2]:loc[3]])
			}
		}
	}
	if checked < 40 {
		t.Fatalf("only %d subscription-bearing paths found — the detector is "+
			"under-counting what it guards (D463)", checked)
	}
	sort.Strings(unguarded)
	if len(unguarded) > 0 {
		t.Errorf("driver paths that take a SUBSCRIPTION from the providerId and do not "+
			"check it against the driver's: %v\nARM URLs are built from d.Subscription, "+
			"so an unchecked mismatch does not reach the other subscription — it "+
			"retargets the operation at the same name in ours.", unguarded)
	}
}

// TestNoSilentlyDiscardedSubscription pins the specific shape this found: `_ = sub`
// after a providerId split. A compiler-silencing discard of an ownership signal should
// never be how that decision is recorded.
func TestNoSilentlyDiscardedSubscription(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var offenders []string
	var scanned int
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(n)
		if err != nil {
			continue
		}
		scanned++
		if strings.Contains(string(raw), "\t_ = sub\n") {
			offenders = append(offenders, n)
		}
	}
	// A scan that read nothing finds nothing and reports success (D328/D488).
	if scanned < 20 {
		t.Fatalf("only %d driver files scanned — the gate would be vacuous", scanned)
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("`_ = sub` discards a bound subscription in: %v — if the boundary does "+
			"not apply, say why in a comment and do not bind it; a discard reads as an "+
			"oversight because that is what it was three times (D467)", offenders)
	}
}
