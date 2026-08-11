package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D756. Five entries in one day were slowed by the same thing: a fixture that served only
// the fields the driver already read, so the branch under repair could not be exercised
// until the fake was taught to carry its input. preflightFake modelled no silent
// guardrail (D750); iamRoleXML served no trust policy (D751); bkdrServer no effectiveTime
// (D752); cosmosServer no locations (D753); ecsServer no subnets and no EC2 (D754).
//
// A fake agrees with the code by construction — the same person writes both, in the same
// hour, with the same blind spot. It becomes evidence only when someone makes it
// disagree.
//
// This gate holds the narrower, checkable half of that: a field the drivers DECODE must
// appear in at least one fixture that SERVES it. It cannot see a field nobody decodes yet
// (which is what four of those five actually were), and it says so rather than implying
// otherwise. What it does catch is a decoded field whose branch no test can reach — the
// GCP ingress rule was exactly that, decoded since it was written and never once served,
// so `firewallsAllowPublicIngress` could only ever return false in the suite.
//
// The allowlist below is DEBT, not safety: each entry is a field the drivers read and no
// fixture supplies. The gate exists so the list only shrinks.
func TestEveryDecodedFieldIsServedBySomeFixture(t *testing.T) {
	root := repoRoot(t)
	// Fields decoded but never served, as measured when this gate was written. Removing
	// one requires serving it in a fixture; adding one requires a reason in this list.
	allowed := map[string]bool{
		// pagination and list envelopes — exercised only by a paginated fixture,
		// which these packages model with explicit page fakes instead.
		"aws:IdentityName": true,
		// CloudTrail's optional delivery targets: the driver reads them to explain
		// where a trail sends, and the fixtures model the trail without them.
		"aws:SnsTopicARN": true, "aws:CloudWatchLogsLogGroupArn": true,

		"aws:VPCOptions": true,

		// GCP: an optional budget filter and a TCP uptime check shape.
		"gcp:budgetFilter": true, "gcp:tcpCheck": true,
		// Azure: budget forecast/contacts.
		"azure:endDate": true, "azure:forecastSpend": true, "azure:contactGroups": true,
		// Azure Postgres CMEK: decoded, and the platform-key case emits nothing at
		// all — recorded under D756, deferred because it BLOCKS rather than lies.
		"azure:dataEncryption": true,

		// ---- triaged when this gate was written (D756) ----
		// Pagination and envelope plumbing: read, but only a paginated fixture would
		// serve them, and these packages model paging with explicit page fakes.
		// DECODED AND NEVER READ anywhere — dead decodes, harmless, left in place
		// rather than removed under a freeze that admits only false statements.
		"aws:invalidParameter": true, "aws:storedBytes": true,
		// CloudTrail's global-service-events flag is an OPERAND the create sets and
		// nothing reads back: no vocabulary attribute carries it, so a trail adopted
		// with global events OFF is invisible rather than misreported. Missing
		// visibility, the deferred bucket.
		"aws:IncludeGlobalServiceEvents": true,
		// SES identity-list shapes, exercised through the discovery fixtures rather
		// than the per-identity ones.
		"aws:EmailIdentities": true, "aws:IdentityType": true,
		// GCP budget period/precision and the audit-log sink list: read, and served
		// only by the discovery fixtures, which this sweep does not read.
		"gcp:calendarPeriod": true, "gcp:nanos": true, "gcp:sinks": true,
	}

	tag := regexp.MustCompile("`json:\"([A-Za-z0-9_]+)[\",]")
	var missing []string
	allowlistUsed := map[string]bool{}
	nowServed := map[string]bool{}
	decoded := 0
	for _, pkg := range []string{"aws", "gcp", "azure"} {
		dir := filepath.Join(root, "go", "internal", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", pkg, err)
		}
		var fixtures strings.Builder
		var sources []string
		for _, e := range entries {
			name := e.Name()
			switch {
			case strings.HasSuffix(name, "_test.go"):
				raw, err := os.ReadFile(filepath.Join(dir, name))
				if err == nil {
					fixtures.Write(raw)
				}
			case strings.HasSuffix(name, "_net.go"):
				sources = append(sources, name)
			}
		}
		served := fixtures.String()
		for _, src := range sources {
			raw, err := os.ReadFile(filepath.Join(dir, src))
			if err != nil {
				continue
			}
			for _, m := range tag.FindAllStringSubmatch(string(raw), -1) {
				field := m[1]
				decoded++
				if allowed[pkg+":"+field] {
					allowlistUsed[pkg+":"+field] = true
					// D803: and check whether the debt has since been PAID. An entry
					// that names a field a fixture now serves is a permission nobody
					// needs, and it silently covers the next field that lands on it.
					if strings.Contains(served, `"`+field+`"`) ||
						strings.Contains(served, `\"`+field+`\"`) {
						nowServed[pkg+":"+field] = true
					}
					continue
				}
				// A fixture serves a field by naming it as a JSON key, quoted plainly
				// or escaped inside a Go string.
				if strings.Contains(served, `"`+field+`"`) ||
					strings.Contains(served, `\"`+field+`\"`) {
					continue
				}
				missing = append(missing, pkg+":"+field+" ("+src+")")
			}
		}
	}
	if len(nowServed) > 0 {
		var paid []string
		for k := range nowServed {
			paid = append(paid, k)
		}
		sort.Strings(paid)
		t.Errorf("%d allowlist entr(ies) name a field that a fixture NOW serves:\n  %s\n\n"+
			"The allowlist is debt (D756); an entry whose debt has been paid is a "+
			"permission nobody needs, and it covers the next field that lands on it. "+
			"Delete them (D803).", len(paid), strings.Join(paid, "\n  "))
	}
	var orphaned []string
	for k := range allowed {
		if !allowlistUsed[k] {
			orphaned = append(orphaned, k)
		}
	}
	if len(orphaned) > 0 {
		sort.Strings(orphaned)
		t.Errorf("%d allowlist entr(ies) name a field no driver decodes any more:\n  %s\n\n"+
			"An exemption for something that is not there is a claim about nothing, and it "+
			"waits to cover the next field with that name (D803).",
			len(orphaned), strings.Join(orphaned, "\n  "))
	}
	if decoded < 500 {
		t.Fatalf("the sweep found only %d decoded fields — it has lost its subject and "+
			"would pass over drivers that decode nothing (D328)", decoded)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("%d field(s) the drivers DECODE that no fixture SERVES:\n  %s\n\n"+
			"The branch that reads such a field cannot be reached by any test, in either "+
			"value. Serve it in a fixture, or add it to the allowlist with a reason — and "+
			"note that the allowlist is debt (D756).", len(missing), strings.Join(missing, "\n  "))
	}
	t.Logf("%d decoded fields checked; %d allowlisted as unserved", decoded, len(allowed))
}
