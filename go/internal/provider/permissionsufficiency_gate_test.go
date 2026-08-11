package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// iamPrefixOf maps a SigV4 SIGNING NAME to the IAM prefix its permissions are spelled
// with. Two differ, and without the map this gate reports `monitoring:PutDashboard`
// undeclared while `cloudwatch:PutDashboard` sits in the table — a false gap, which is
// the failure mode that wastes the most time (D853).
func iamPrefixOf(signing string) string {
	switch signing {
	case "monitoring":
		return "cloudwatch"
	case "tagging":
		return "tag"
	}
	return signing
}

// operationsCheckedFloor is how many operations this gate resolves from the recorded
// routes. It may only RISE: a subject that quietly shrinks turns a clean run into a
// statement about almost nothing (D328).
const operationsCheckedFloor = 100

// ambiguousRouteCount is how many recorded routes still match more than one modelled
// operation. It was thirteen while the recorded file dropped its query string; keeping the
// valueless markers (D850) resolved the S3 sub-resources and left six — the calls whose
// operation turns on a query key that CARRIES A VALUE, such as CloudFront's tagging POST,
// where `?Operation=Tag` and `?Operation=Untag` are TagResource and UntagResource. Pinned
// exactly, in both directions: a rise is a growing blind spot, a fall means the constant is
// trailing what the gate can now see (D849).
const ambiguousRouteCount = 6

// discoveryOnlyOperations are operations the drivers call OUTSIDE a plan action, where no
// `requiredPermissions` declaration covers them because there is no action to attach one
// to. Every entry was traced to its caller by hand — a register whose reasons are guessed
// is worse than no register, and following one of these to its caller is how D847 was
// found.
// D849 re-traced all seventeen. One was not a discovery call at all —
// bedrock:ListInferenceProfiles runs inside createBedrock's create-adoption branch, and is
// declared on create now — and two were artifacts of the gate's own resolution rather than
// calls the driver makes. D850 then made the S3 sub-resource reads visible for the first
// time and added six, each traced the same way. Twenty entries; the count is not the point,
// the tracing is.
var discoveryOnlyOperations = map[string]string{
	"backup:ListBackupPlans":       "discoverBackupPlans — the onboarding sweep",
	"backup:ListBackupVaults":      "discoverBackupVaults — the onboarding sweep",
	"cloudfront:ListDistributions": "discoverCloudFront, and observeWAF's protection read",
	"eks:ListAddons":               "discoverEKSAddon and reconcileEKSAddon, which runs under resume",
	"eks:ListClusters":             "discoverEKS/discoverEKSAddon/discoverEKSPodIdentity and the pod-identity reconcile scan",
	"es:ListDomainNames":           "discoverOpenSearch — the onboarding sweep",
	"lambda:ListFunctions":         "discoverLambda — the paged onboarding sweep (D809)",
	"route53:ListHealthChecks":     "discoverRoute53Health — the onboarding sweep",
	"route53:ListHostedZones":      "discoverRoute53 and reconcileRoute53's rc7ListHostedZones, which runs under resume",
	// The S3 sub-resource reads, visible only since the recorded routes kept their
	// markers (D850). Each is a read behind observe or discovery; the one that was NOT —
	// the pre-delete object-lock guard — is declared on delete instead.
	"s3:GetBucketEncryption":   "observeS3's encryption read",
	"s3:GetBucketLocation":     "discoverS3's s3BucketRegion and observeS3's s3DestinationRegion",
	"s3:GetBucketPolicyStatus": "observeS3's public-policy read",
	"s3:GetBucketReplication":  "observeS3's replication read",
	"s3:GetBucketVersioning":   "observeS3's versioning read",
	"s3:GetPublicAccessBlock":  "observeS3 via bucketRPB/effectiveRestrictPublicBuckets",
	"s3:HeadBucket":            "observeS3's presence read",
	// D853: the Query/JSON services, visible for the first time now that the recorder
	// keeps the operation each request names. Every reason below was traced to its
	// caller; the six that turned out to be on ACTION paths are declared instead.
	"aoss:ListCollections":                       "discoverOpenSearchServerless — the onboarding sweep",
	"apprunner:DescribeAutoScalingConfiguration": "observeAppRunner's min-size read",
	"cloudtrail:GetTrailStatus":                  "observeCloudTrail's trailIsLogging read",
	"cloudtrail:ListTrails":                      "discoverCloudTrail — the onboarding sweep",
	"dynamodb:ListTables":                        "discoverDynamoDB — the onboarding sweep",
	"ec2:DescribeRegions":                        "Enumerate — the region sweep, outside any plan",
	"ecs:ListClusters":                           "discoverECS — the onboarding sweep",
	"ecs:ListServices":                           "discoverECS — the onboarding sweep",
	"iam:ListPolicies":                           "discoverCustomPolicies — the onboarding sweep",
	"iam:ListRoles":                              "discoverIAM — the onboarding sweep",
	"iam:SimulatePrincipalPolicy":                "the preflight's OWN call (D75); a missing grant makes the preflight inconclusive, which is handled",
	"kinesis:ListStreams":                        "discoverKinesis — the onboarding sweep",
	"monitoring:ListDashboards":                  "discoverCloudWatchDashboards — the onboarding sweep",
	"rds:DescribeDBClusterParameters":            "observeAurora's clusterParamOn read",
	"rds:DescribeDBParameters":                   "observeRDS's dbForceSSL read",
	"rds:DescribeDBClusterSnapshots":             "probeRTOAurora's latestClusterSnapshot — an intrusive probe under double consent (D59), not a plan action",
	"rds:DescribeDBSnapshots":                    "probeRTORDS's latestDBSnapshot — same probe path",
	"rds:RestoreDBClusterFromSnapshot":           "probeRTOAurora — the RTO probe's restore, double-consented and outside any plan",
	"rds:RestoreDBInstanceFromDBSnapshot":        "probeRTORDS — same probe path",
	"redshift-serverless:ListWorkgroups":         "discoverRedshiftServerless — the onboarding sweep",
	"secretsmanager:GetResourcePolicy":           "observeASM's getASMPolicy read",
	"secretsmanager:ListSecrets":                 "discoverSecrets — the onboarding sweep",
	"ses:ListReceiptRuleSets":                    "discoverSESInbound — the onboarding sweep",
	"sns:ListTopics":                             "discoverSNS — the onboarding sweep",
	"sqs:ListQueues":                             "discoverSQS — the onboarding sweep",
	"scheduler:ListSchedules":                    "discoverEventBridgeSchedulers — the onboarding sweep",
	"ses:GetAccount":                             "observeSESSending's sending-account read",
	"ses:ListEmailIdentities":                    "discoverSESSending — the onboarding sweep",
}

// TestDeclaredPermissionsCoverTheOperationsTheDriversCall asks the half D846 said it could
// not settle: not whether a declared permission EXISTS, but whether the declared set is
// SUFFICIENT for what the drivers actually do (D848).
//
// An under-declared permission is worse than a misspelled one. A misspelling cannot be
// granted, so it refuses before the lease. A missing one passes the preflight, the executor
// takes the lease, and the denial lands MID-PLAN: `updateEKS` upgrades the control plane —
// which cannot be undone — and then calls UpdateNodegroupVersion, which nothing declared.
//
// The authority is AWS's own `Operations[].AuthorizedActions` (which action authorizes
// which API call), joined to the routes the drivers build.
//
// THREE limits, stated because a gate whose reach is unstated reads as a clean sweep:
//   - a recorded route matching more than one modelled operation is UNRESOLVED, not
//     guessed. Six still are — the ones an operation-selecting query key with a VALUE
//     distinguishes, which the capture does not keep (D849, D850).
//   - the subject is `aws-routes.txt`, which records the routes the SUITE has driven, not
//     every route a driver can construct. `s3:DeleteBucketPolicy` was missing and invisible
//     here; it was found by reading `updateS3` (D848).
//   - only services with PATH-bearing routes are covered. The Query and JSON services
//     (ec2, rds, sqs, sns...) select their operation with an Action field or an
//     X-Amz-Target header, so a recorded route says nothing about which operation it was.
func TestDeclaredPermissionsCoverTheOperationsTheDriversCall(t *testing.T) {
	root := repoRoot(t)

	auth := map[string][]string{} // "service:Operation" -> authorizing actions
	blob, err := os.ReadFile(filepath.Join("testdata", "aws_operation_actions.verified"))
	if err != nil {
		t.Fatalf("read verified operation actions: %v", err)
	}
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("verified line is not service|operation|actions: %q", line)
		}
		auth[parts[0]+":"+parts[1]] = strings.Fields(parts[2])
	}
	if len(auth) < 1200 {
		t.Fatalf("only %d operations in the verified file — refresh it with "+
			"scripts/refresh-aws-opactions.sh", len(auth))
	}

	// A route carries its sub-resource markers (D850): S3 selects the operation BY query,
	// so the marker set is part of the identity of the call, not decoration.
	type modelledRoute struct {
		knownRoute
		marks string
	}
	var known []modelledRoute
	rblob, err := os.ReadFile(filepath.Join("testdata", "aws_route_operations.verified"))
	if err != nil {
		t.Fatalf("read verified routes: %v", err)
	}
	for _, line := range strings.Split(string(rblob), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) != 4 {
			continue
		}
		known = append(known, modelledRoute{
			knownRoute: knownRoute{service: p[0], method: p[1], re: uriPattern(p[0], p[2]), op: p[3]},
			marks:      valuelessMarks(p[2]),
		})
	}

	recorded, err := os.ReadFile(filepath.Join(root, "go", "internal", "aws", "testdata", "aws-routes.txt"))
	if err != nil {
		t.Fatalf("read recorded routes: %v", err)
	}
	calls := map[string]bool{} // "service:Operation"
	ambiguous := 0
	for _, l := range strings.Split(strings.TrimSpace(string(recorded)), "\n") {
		p := strings.SplitN(l, "\t", 3)
		if len(p) != 3 {
			continue
		}
		// D853: a Query/JSON request NAMES its operation — `?Op=` from the recorder's
		// X-Amz-Target/Action hint, or `?Action=` straight off the URL. That is the
		// operation, with no model lookup and no ambiguity: it came from the request,
		// not from matching a bare path against thirty-six candidates.
		if op := namedOperation(p[2]); op != "" {
			calls[p[0]+":"+op] = true
			continue
		}
		path := strings.SplitN(p[2], "?", 2)[0]
		if strings.Trim(path, "/") == "" {
			continue // a protocol root carrying no operation and no name for one
		}
		marks := valuelessMarks(p[2])
		var matched []string
		for _, k := range known {
			if k.service == p[0] && k.method == p[1] && k.marks == marks &&
				k.re.MatchString(normalizeRoutePath(p[0], path)) {
				matched = append(matched, k.op)
			}
		}
		// D849: a route matching MORE THAN ONE modelled operation is unresolved, never
		// guessed. The recorded file carries no query string and S3 selects its
		// operation BY query (?location, ?tagging, ?versioning), so `GET /some-bucket`
		// fits thirty-six S3 operations. Taking the first reported `s3:ListObjects` as a
		// call the driver never makes — and an arbitrary pick can just as easily land on
		// an operation that IS declared, hiding a real gap behind a false pass.
		switch len(matched) {
		case 0:
		case 1:
			calls[p[0]+":"+matched[0]] = true
		default:
			ambiguous++
		}
	}
	if ambiguous != ambiguousRouteCount {
		t.Errorf("%d recorded routes match more than one modelled operation, expected %d — "+
			"the share of the subject this gate cannot attribute moved. If it GREW, the "+
			"blind spot grew with it; if it shrank, lower the constant (D849).",
			ambiguous, ambiguousRouteCount)
	}
	if len(calls) < operationsCheckedFloor {
		t.Fatalf("only %d operations resolved from the recorded routes, floor %d — this gate "+
			"stopped applying to its subject", len(calls), operationsCheckedFloor)
	}

	src, err := os.ReadFile(filepath.Join(root, "go", "internal", "provider", "provider.go"))
	if err != nil {
		t.Fatalf("read provider.go: %v", err)
	}
	declared := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([a-z0-9-]{2,20}):([A-Z][A-Za-z0-9]{2,60})"`).
		FindAllStringSubmatch(string(src), -1) {
		declared[m[1]+":"+m[2]] = true
	}
	if len(declared) < 300 {
		t.Fatalf("only %d permissions found in provider.go — the extraction stopped matching "+
			"its subject", len(declared))
	}

	var uncovered []string
	for call := range calls {
		if _, ok := discoveryOnlyOperations[call]; ok {
			continue
		}
		actions, ok := auth[call]
		if !ok {
			continue // AWS names no same-service authorizer for it
		}
		service := iamPrefixOf(strings.SplitN(call, ":", 2)[0])
		// D853: when one authorized action carries the OPERATION's own name, that one
		// is the primary and must be declared. AWS lists conditional extras beside it —
		// `AddTagsToResource` for a create-with-tags — and accepting "any of them"
		// counted an operation as covered because the TAG action was declared. Two real
		// gaps hid behind exactly that. Where no action shares the name (API Gateway's
		// verbs, CloudFront's WithTags create), the alternatives rule stands (D846).
		operation := strings.SplitN(call, ":", 2)[1]
		need := actions
		for _, a := range actions {
			if a == operation {
				need = []string{a}
				break
			}
		}
		covered := false
		for _, a := range need {
			if declared[service+":"+a] {
				covered = true
				break
			}
		}
		if !covered {
			uncovered = append(uncovered, call+" (needs one of: "+strings.Join(need, ", ")+")")
		}
	}
	sort.Strings(uncovered)

	if len(uncovered) > 0 {
		t.Errorf("%d operation(s) the drivers call have no declared permission:\n  %s\n\n"+
			"The preflight passes and the denial lands mid-plan, after the lease and after "+
			"whatever the plan already did. Declare the action, or register the call in "+
			"discoveryOnlyOperations WITH the caller you traced it to (D848).",
			len(uncovered), strings.Join(uncovered, "\n  "))
	}
	for call, reason := range discoveryOnlyOperations {
		if !calls[call] {
			t.Errorf("register entry %q (%s) covers a call nothing records any more — drop it", call, reason)
		}
	}
}

// valuelessMarks renders the sub-resource markers of a URI — the query keys that carry NO
// value — as a stable string. S3 selects its operation with them (`?tagging`,
// `?versioning`, `?object-lock`), and CloudFront picks a different create with `?WithTags`;
// a key WITH a value is a filter or a pagination cursor and says nothing about which
// operation this is, so it is ignored on both sides (D850).
func valuelessMarks(uri string) string {
	_, q, ok := strings.Cut(uri, "?")
	if !ok {
		return ""
	}
	var marks []string
	for _, kv := range strings.Split(q, "&") {
		if kv == "" || strings.Contains(kv, "=") {
			continue
		}
		marks = append(marks, kv)
	}
	sort.Strings(marks)
	return strings.Join(marks, "&")
}

// namedOperation returns the operation a recorded route names outright, if any. The
// Query protocol puts it in `Action=`, the JSON protocol in an `X-Amz-Target` header
// the recorder stores as `Op=`; for those services the path names nothing, and before
// D853 every call to one collapsed into a single unattributable line.
func namedOperation(target string) string {
	_, q, ok := strings.Cut(target, "?")
	if !ok {
		return ""
	}
	for _, kv := range strings.Split(q, "&") {
		for _, key := range []string{"Op=", "Action="} {
			if strings.HasPrefix(kv, key) {
				return strings.TrimPrefix(kv, key)
			}
		}
	}
	return ""
}
