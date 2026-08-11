package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// uncheckableRouteCeiling is how many recorded routes carry NEITHER a path to check nor an
// operation name to ask about. It was 28 — one per Query/JSON service, each standing for
// every call that service makes — until the recorder began keeping the operation those
// requests name (D853); now those routes are checked by name and one remains. It may only
// go DOWN, because a check that quietly stops applying to more and more of its subject is
// how a gate becomes decorative.
const uncheckableRouteCeiling = 1

// namedOpRouteFloor is how many recorded routes are checked by the OPERATION they name
// rather than by their path (D853). The Query and JSON services put the operation in an
// `Action` field or an `X-Amz-Target` header, and the recorder keeps it — so a route
// whose path proves nothing is still confrontable with AWS's own list of operations.
// A floor, because a fall means the recorder stopped carrying the name and 240 routes
// went back to being unverifiable in silence.
const namedOpRouteFloor = 200

// TestEveryRouteTheDriverBuildsIsARouteAWSHas confronts every route internal/aws
// constructs with AWS's own published API models (D820).
//
// D274 asked this question of AWS itself, and D717 made its subject derived from what the
// drivers actually build rather than from two hand-written lists. Both were right, and
// neither ran here: that gate needs network egress and an opt-in variable, so `make check`
// never asks. Worse, it could not have answered for most services even when it did run —
// its classifier looked for the message AWS's Query/JSON frontend gives an unmatched
// route, and the REST services answer `<UnknownOperationException/>` instead, which read
// as "recognised". Every fabricated REST path passed.
//
// This asks the same question offline, of the same authority AWS publishes, on every run.
// It found two: `discoverOpenSearch` and the OpenSearch tag read were calling
// `/2021-01-01/opensearch/domain` and `/2021-01-01/opensearch/tags/`, and AWS has
// ListDomainNames at `/2021-01-01/domain` and ListTags at `/2021-01-01/tags/` — the same
// API really does mix the two prefixes, and DescribeDomain, CreateDomain and DeleteDomain
// do carry `/opensearch`. So four of the driver's six OpenSearch routes were right, which
// is exactly how a wrong constant survives review.
func TestEveryRouteTheDriverBuildsIsARouteAWSHas(t *testing.T) {
	root := repoRoot(t)

	// Exceptions carry a reason, and a stale one fails: a permission nobody needs covers
	// the next route that lands on it (the D803 allowlist did exactly that).
	exempt := map[string]string{}

	var have []knownRoute
	blob, err := os.ReadFile(filepath.Join("testdata", "aws_route_operations.verified"))
	if err != nil {
		t.Fatalf("read verified routes: %v", err)
	}
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			t.Fatalf("verified route line is not service|method|uri|operation: %q", line)
		}
		have = append(have, knownRoute{
			service: parts[0],
			method:  parts[1],
			re:      uriPattern(parts[0], parts[2]),
			op:      parts[3],
		})
	}

	routes, err := os.ReadFile(filepath.Join(root, "go", "internal", "aws", "testdata", "aws-routes.txt"))
	if err != nil {
		t.Fatalf("read recorded routes: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(routes)), "\n")

	// D328: assert the subject before reporting on it. Either side going thin would make
	// this print a clean sweep over nothing.
	if len(have) < 800 {
		t.Fatalf("only %d routes in the verified file — the model index went thin; refresh "+
			"it with scripts/refresh-aws-routeops.sh", len(have))
	}
	if len(lines) < 100 {
		t.Fatalf("only %d recorded routes — aws-routes.txt is not the real set", len(lines))
	}

	// The operations AWS models, for the routes whose path proves nothing (D853).
	modelledOps := map[string]bool{}
	opBlob, err := os.ReadFile(filepath.Join("testdata", "aws_operation_actions.verified"))
	if err != nil {
		t.Fatalf("read verified operation actions: %v", err)
	}
	for _, line := range strings.Split(string(opBlob), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.SplitN(line, "\t", 3)
		if len(p) == 3 {
			modelledOps[p[0]+":"+p[1]] = true
		}
	}
	if len(modelledOps) < 3000 {
		t.Fatalf("only %d modelled operations — refresh with scripts/refresh-aws-opactions.sh", len(modelledOps))
	}

	var missing, uncheckable []string
	checked, namedChecked := 0, 0
	for _, l := range lines {
		parts := strings.SplitN(l, "\t", 3)
		if len(parts) != 3 {
			t.Fatalf("malformed line in aws-routes.txt: %q", l)
		}
		service, method, target := parts[0], parts[1], parts[2]
		path := strings.SplitN(target, "?", 2)[0]
		if strings.Trim(path, "/") == "" {
			// A protocol root: the path names no operation. If the REQUEST named one
			// (D853), ask whether AWS has an operation by that name on this service —
			// a different question from "does this path exist", and the only one
			// available for the Query and JSON protocols.
			if op := namedOperation(target); op != "" {
				namedChecked++
				if !modelledOps[service+":"+op] {
					missing = append(missing, service+" "+method+" "+target+
						" (no such operation in AWS's model)")
				}
				continue
			}
			uncheckable = append(uncheckable, service+" "+method+" "+target)
			continue
		}
		key := service + " " + method + " " + path
		if _, ok := exempt[key]; ok {
			continue
		}
		checked++
		if !routeIsKnown(have, service, method, path) {
			missing = append(missing, key)
		}
	}

	// The same guard one layer in: if almost nothing were path-checkable, the run above
	// would be clean and would mean nothing.
	if checked < 100 {
		t.Fatalf("only %d routes carried a path to check — this gate stopped applying to "+
			"its subject", checked)
	}
	sort.Strings(missing)

	if len(missing) > 0 {
		t.Errorf("%d route(s) the driver builds are not routes AWS has:\n  %s\n\n"+
			"A path AWS does not serve answers 404 forever: a read reports an estate as "+
			"empty that is not, and a create fails on every attempt. Check the operation's "+
			"requestUri in the provider's model (D820).",
			len(missing), strings.Join(missing, "\n  "))
	}
	if namedChecked < namedOpRouteFloor {
		t.Errorf("only %d routes were checked by the operation they name, floor %d — the "+
			"recorder stopped carrying the operation hint and the Query/JSON services went "+
			"back to being unverifiable (D853)", namedChecked, namedOpRouteFloor)
	}
	if len(uncheckable) > uncheckableRouteCeiling {
		t.Errorf("%d recorded routes carry no path to check, ceiling %d — the share of the "+
			"subject this gate cannot see grew:\n  %s",
			len(uncheckable), uncheckableRouteCeiling, strings.Join(uncheckable, "\n  "))
	}
	if len(uncheckable) < uncheckableRouteCeiling {
		t.Errorf("%d uncheckable routes but the ceiling still says %d. Lower it: a ceiling "+
			"that trails the work stops being a ratchet.", len(uncheckable), uncheckableRouteCeiling)
	}
	for key, reason := range exempt {
		t.Errorf("exception %q (%s) covers a route nothing records any more — drop it", key, reason)
	}
}

// knownRoute is one route AWS's published model says exists.
type knownRoute struct {
	service string
	method  string
	re      *regexp.Regexp
	op      string
}

// routeIsKnown reports whether AWS has this route, ON THIS SERVICE.
//
// The service is half the question, and leaving it out is not a loosening — it is the
// difference between a check and a formality. S3 models GetObject as `GET /{Bucket}/{Key+}`,
// a pattern that fits any path of two segments or more, so without the service every
// unmatched route in the file is absorbed by S3 and the gate reports clean over a tree with
// two fabricated routes in it. It did exactly that on its first run.
func routeIsKnown(have []knownRoute, service, method, path string) bool {
	for _, k := range have {
		if k.service == service && k.method == method &&
			k.re.MatchString(normalizeRoutePath(service, path)) {
			return true
		}
	}
	return false
}

// TestTheRouteGateWillNotMatchAcrossServices pins that half directly, because a permissive
// matcher passes a healthy tree — removing the service check breaks nothing until the day
// something is wrong, which is the day the gate is needed.
func TestTheRouteGateWillNotMatchAcrossServices(t *testing.T) {
	have := []knownRoute{
		{service: "s3", method: "GET", re: uriPattern("s3", "/{Bucket}/{Key+}"), op: "GetObject"},
		{service: "es", method: "GET", re: uriPattern("es", "/2021-01-01/domain"), op: "ListDomainNames"},
	}
	// The route this project actually shipped, and AWS answers 404 to.
	if routeIsKnown(have, "es", "GET", "/2021-01-01/opensearch/domain") {
		t.Fatal("an OpenSearch route was matched against S3's GetObject pattern — the gate " +
			"would report every fabricated path as real (D820)")
	}
	// The real one still matches, so the check above is not passing by refusing everything.
	if !routeIsKnown(have, "es", "GET", "/2021-01-01/domain") {
		t.Fatal("the real ListDomainNames route was not recognised — the matcher is broken")
	}
	// And S3's own permissive pattern still serves S3.
	if !routeIsKnown(have, "s3", "GET", "/bucket-prod-1a2b3c4d/some/key") {
		t.Fatal("S3's own route stopped matching")
	}
}

// uriPattern turns a modelled request URI into a matcher. Path parameters stand for one
// segment, except the greedy `{x+}` form, which AWS uses where a parameter contains slashes.
func uriPattern(service, uri string) *regexp.Regexp {
	u := strings.SplitN(uri, "?", 2)[0]
	u = strings.TrimSuffix(u, "/")
	if u == "" {
		u = "/"
	}
	var b strings.Builder
	b.WriteString("^")
	for {
		i := strings.Index(u, "{")
		if i < 0 {
			b.WriteString(regexp.QuoteMeta(u))
			break
		}
		j := strings.Index(u[i:], "}")
		if j < 0 {
			b.WriteString(regexp.QuoteMeta(u))
			break
		}
		b.WriteString(regexp.QuoteMeta(u[:i]))
		if strings.HasSuffix(u[i:i+j], "+") {
			b.WriteString(".+")
		} else {
			b.WriteString("[^/]+")
		}
		u = u[i+j+1:]
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String())
}

// normalizeRoutePath drops the trailing slash, which the models carry inconsistently and
// which no service distinguishes.
func normalizeRoutePath(service, path string) string {
	p := strings.TrimSuffix(path, "/")
	if p == "" {
		return "/"
	}
	return p
}
