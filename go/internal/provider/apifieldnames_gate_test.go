package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D793/D794. A driver reads a field the provider does not return, and the decoder does
// what decoders do: it leaves the zero value and reports no error. Nothing anywhere says
// a name was wrong. The zero value then travels the same road every real measurement
// travels — derivation "measured", into an observation, into a verdict — and a
// misspelled tag becomes a confident false statement about someone's estate.
//
//	`json:"isZoneRedundant"`   vs   the API's zoneRedundant   -> "not zone redundant"
//	`json:"effectiveState"`    vs   the API's effectiveEnablementState -> "not enabled"
//
// Fixtures cannot catch this. The fixture-coverage gate (D756) proves every decoded field
// is exercised by SOME fixture, but we wrote the fixture too: a typo repeated on both
// sides agrees with itself. That is the D317 lesson in a new place — a scrape of our own
// material cannot prove anything about reality; only the provider can say what it returns.
//
// Both providers publish exactly that, without credentials: Google as discovery documents,
// AWS as the botocore service models. So the question is asked of them, and the answer is
// checked in.
//
// The gate itself runs OFFLINE, deliberately. A network-gated test is skipped in CI, and a
// gate that skips is not a gate (D328). So the network step is a refresh
// (scripts/refresh-{gcp,aws}-fieldnames.sh) and the gate is a comparison: a tag absent
// from the verified list has never been confronted with the real API, and the gate fails
// rather than assume it. That direction is the point — a NEW name is exactly when a typo
// enters, and the failure says to go check it against the provider.
func TestEveryGCPFieldNameExistsInTheProviderAPI(t *testing.T) {
	checkFieldNames(t, "gcp", "gcp_api_fieldnames.verified", 400, 200, map[string]string{
		// Service-account key FILE, not an API response. Its shape is the credential
		// format, described in Google's auth documentation rather than in any API.
		"client_email":   "service-account key file field (auth.go), not an API response",
		"private_key":    "service-account key file field (auth.go), not an API response",
		"private_key_id": "service-account key file field (auth.go), not an API response",
		"token_uri":      "service-account key file field (auth.go), not an API response",
		// securitycentermanagement.googleapis.com serves its discovery document only to
		// an authenticated caller (403 without credentials), and we do not hold any. The
		// names come from that API's published reference; they are UNCONFIRMED here and
		// this record says so rather than letting them pass as verified.
		"effectiveEnablementState": "securitycentermanagement discovery doc is 403 without credentials — unconfirmed",
		"intendedEnablementState":  "securitycentermanagement discovery doc is 403 without credentials — unconfirmed",
	})
}

// TestEveryAWSFieldNameExistsInTheProviderAPI is the same question asked of AWS, and it
// exists because D793 published the wrong answer to "can it be asked?" (see D794).
//
// AWS's exceptions are one recurring shape rather than a list of oddities: a JSON
// DOCUMENT carried INSIDE an API, whose inner fields the API model does not describe
// because to the API they are an opaque string. An IAM policy, a dashboard body, a
// redrive policy. Those names are real and documented — just not in the wire model, so
// the model cannot confirm them and this table says so.
func TestEveryAWSFieldNameExistsInTheProviderAPI(t *testing.T) {
	checkFieldNames(t, "aws", "aws_api_fieldnames.verified", 400, 200, map[string]string{
		// The AWS JSON protocol's error envelope, not a shape in any service model.
		"__type": "AWS JSON protocol error envelope, not a modeled field",
		// Documents inside APIs — the model calls the whole thing a string.
		"Effect":              "IAM policy document field (a string to the API), not a modeled field",
		"NotAction":           "IAM policy document field (a string to the API), not a modeled field",
		"AWS":                 "IAM policy principal field (a string to the API), not a modeled field",
		"Sid":                 "IAM policy statement id (a string to the API), not a modeled field",
		"ArnLike":             "IAM policy condition operator (a string to the API), not a modeled field",
		"Federated":           "IAM trust policy principal kind (a string to the API), not a modeled field",
		"widgets":             "CloudWatch dashboard body (a string to the API), not a modeled field",
		"metrics":             "CloudWatch dashboard widget body (a string to the API), not a modeled field",
		"deadLetterTargetArn": "SQS RedrivePolicy document (a string to the API), not a modeled field",
		// ECR lifecycle policy document fields the observe reverse-map DECODES from the
		// lifecyclePolicyText JSON string (D1029) — the inner age-out shape is not a
		// modeled API field (rules/action/lifecyclePolicyText themselves are, and are
		// confirmed in the verified list).
		"selection":       "ECR lifecycle policy document field (inside lifecyclePolicyText), not a modeled field",
		"countType":       "ECR lifecycle policy document field (inside lifecyclePolicyText), not a modeled field",
		"countUnit":       "ECR lifecycle policy document field (inside lifecyclePolicyText), not a modeled field",
		"countNumber":     "ECR lifecycle policy document field (inside lifecyclePolicyText), not a modeled field",
		"maxReceiveCount": "SQS RedrivePolicy document (a string to the API), not a modeled field",
		"AllowFromPublic": "OpenSearch Serverless network policy document (a string to the API)",
		// encoding/json's ignore directive, not a field name at all.
		"-": "encoding/json ignore directive, not a field name",
	})
}

// TestEveryAzureFieldNameExistsInTheProviderAPI closes the gap D794 named. Azure's specs
// are public like the other two — what made them "work rather than a fetch" is that the
// repository defeats the ordinary listing (the tree API truncates, silently) and that
// within one namespace different resource types ship on different api-versions, so
// "newest directory" is the wrong selection. Both are handled in the refresh script, and
// both first showed up as phantom findings: twelve real Azure fields reported unknown.
func TestEveryAzureFieldNameExistsInTheProviderAPI(t *testing.T) {
	checkFieldNames(t, "azure", "azure_api_fieldnames.verified", 400, 150, map[string]string{
		// A dashboard tile's contents. The Portal spec types a part's metadata as a
		// generic object, so the spec cannot vouch for what is inside it — the same
		// shape as CloudWatch's widgets/metrics one cloud over.
		"chart": "Azure Portal dashboard tile body (a generic object to the spec), not a specified field",
		// D947: the location-capabilities flag the flex-server create preflights before
		// issuing a ZoneRedundant create. It lives on the DBforPostgreSQL locations
		// capabilities API (a location descriptor), not on the flexibleServers resource
		// the verified list is built from.
		"zoneRedundantHaSupported": "PostgreSQL Flexible Server location-capabilities flag (DBforPostgreSQL/locations/capabilities), not a flexibleServers resource field",
		// D948: the subscription's per-region availability-zone mapping, read to fill a
		// zone-redundant Redis cache's `zones` and refuse a region with too few AZs. These
		// live on the Microsoft.Resources subscription-locations API, not on a Cache resource.
		"availabilityZoneMappings": "subscription locations AZ mapping (Microsoft.Resources /subscriptions/locations), not a Cache/Redis resource field",
		"logicalZone":              "a logical availability-zone id in the subscription locations AZ mapping (Microsoft.Resources), not a Cache/Redis resource field",
	})
}

// checkFieldNames confronts one driver package's JSON tags with the checked-in answer
// from that provider's own published API description.
func checkFieldNames(t *testing.T, pkg, verifiedFile string, minOccurrences, minNames int,
	exempt map[string]string) {
	t.Helper()
	root := filepath.Join("..", "..", "internal", pkg)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read %s: %v", root, err)
	}

	tag := regexp.MustCompile("`json:\"([A-Za-z0-9_.-]+)")
	used := map[string][]string{} // name -> files
	occurrences := 0
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, n))
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		for _, m := range tag.FindAllStringSubmatch(string(src), -1) {
			occurrences++
			if !contains(used[m[1]], n) {
				used[m[1]] = append(used[m[1]], n)
			}
		}
	}

	verified := map[string]bool{}
	blob, err := os.ReadFile(filepath.Join("testdata", verifiedFile))
	if err != nil {
		t.Fatalf("read verified list: %v", err)
	}
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		verified[line] = true
	}

	// The gate must have a subject (D328): a run that parsed no tags, or read an empty
	// verified list, would pass while checking nothing.
	if occurrences < minOccurrences || len(used) < minNames {
		t.Fatalf("%s gate has no subject: %d tag occurrences, %d distinct names — "+
			"the drivers decode far more than that; the scan is broken", pkg, occurrences, len(used))
	}
	if len(verified) < minNames {
		t.Fatalf("%s verified list holds only %d names — it cannot cover what the drivers read",
			pkg, len(verified))
	}

	var unchecked []string
	for name, files := range used {
		if verified[name] || exempt[name] != "" {
			continue
		}
		sort.Strings(files)
		unchecked = append(unchecked, name+" ("+strings.Join(files, ", ")+")")
	}
	sort.Strings(unchecked)
	if len(unchecked) > 0 {
		t.Errorf("%d %s field name(s) never confirmed against the provider's own API "+
			"description:\n  %s\n\nA decoder reading a name the API does not return gets the "+
			"zero value and no error, and reports it as measured. Run "+
			"scripts/refresh-%s-fieldnames.sh to confirm them against the provider's published "+
			"models, or add an exception saying why the check cannot apply.",
			len(unchecked), pkg, strings.Join(unchecked, "\n  "), pkg)
	}

	// An exception for a name no driver reads any more is a claim about nothing, and it
	// hides the next name that lands on it.
	for name, why := range exempt {
		if len(used[name]) == 0 {
			t.Errorf("stale %s exception %q (%s): no driver reads that field any more", pkg, name, why)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
