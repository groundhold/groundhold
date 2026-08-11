package aws

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D468: the account boundary as a class. See accountboundary.go for the argument; this
// pins it so the twenty-first path cannot land without it.

var awsBindsAccount = regexp.MustCompile(`\n\t(?:\w+, )*account, [^\n]*= split\w*ProviderID\(providerID\)`)

func TestAccountBearingPathsGuardTheBoundary(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fnDecl := regexp.MustCompile(`func \(d \*Driver\) ((?:observe|delete|update|create)\w+)\(`)

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
			if !awsBindsAccount.MatchString(body) {
				continue
			}
			checked++
			if !strings.Contains(body, "d.sameAccount(account)") {
				unguarded = append(unguarded, src[loc[2]:loc[3]])
			}
		}
	}
	if checked < 15 {
		t.Fatalf("only %d account-bearing paths found — the detector is under-counting "+
			"what it guards (D463)", checked)
	}
	sort.Strings(unguarded)
	if len(unguarded) > 0 {
		t.Errorf("driver paths that take an ACCOUNT from the providerId and do not check "+
			"it against the acting one: %v\nAn AWS ARN names the account directly, so an "+
			"unchecked mismatch aims the request at another estate — and cross-account "+
			"access to SQS/SNS/S3/ECR is ordinary, which makes the aim real.", unguarded)
	}
}

// TestSameAccountIsNoOpWhenUnresolved pins the D29 half: a driver that has not resolved
// an identity must not turn "we do not know" into a refusal.
func TestSameAccountIsNoOpWhenUnresolved(t *testing.T) {
	d := &Driver{}
	if err := d.sameAccount("000000000000"); err != nil {
		t.Errorf("an unresolved acting account must be a no-op, not a refusal: %v", err)
	}
	d.Account = "000000000000"
	if err := d.sameAccount(""); err != nil {
		t.Errorf("a providerId that carries no account must be a no-op: %v", err)
	}
	if err := d.sameAccount("999999999999"); err == nil {
		t.Error("a resolved mismatch must refuse")
	}
	if err := d.sameAccount("000000000000"); err != nil {
		t.Errorf("a match must pass: %v", err)
	}
}
