package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// unfollowedPagingSiteCeiling is how many RECORDED call chains issue an operation AWS
// paginates without any function in the chain naming a continuation. It may only go DOWN.
//
// D871 replaces the subject of D866's ratchet, which counted matches of an operation
// NAME in the driver's source. That join cannot be right: `ListTagsForResource` paginates
// for wafv2 and the same literal appears at twenty-three call sites across thirteen other
// services, `ListServices` belongs to both App Runner and ECS, `ListClusters` to both ECS
// and EKS. The number it produced was neither an over- nor an under-count; it was a
// different quantity.
//
// The recorder now says who called (aws-callsites.txt: service, operation, and the chain
// of driver functions that led to the request). A chain rather than one frame because "the
// call site" is genuinely ambiguous — a read may follow its pages in the reader, in a
// per-page helper, or in a shared loop — and paging is followed if ANY of them handles the
// continuation.
//
// The trade this makes, stated because it is real: the recorder sees only what the test
// suite EXERCISES, where the source scrape saw every literal. That is D317's direction
// (ask the drivers, do not scrape them) and it is why the coverage assertion below is not
// optional.
const unfollowedPagingSiteCeiling = 59

func TestRecordedPagingCallSitesFollowTheirToken(t *testing.T) {
	root := repoRoot(t)

	paging := map[string]bool{}
	blob, err := os.ReadFile(filepath.Join("testdata", "aws_paginating_operations.verified"))
	if err != nil {
		t.Fatalf("read the paginating operations (refresh: scripts/refresh-aws-paginating.sh): %v", err)
	}
	for _, line := range strings.Split(string(blob), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.SplitN(line, "\t", 2)
		if len(p) != 2 {
			t.Fatalf("verified line is not service|operation: %q", line)
		}
		paging[p[0]+"\t"+p[1]] = true
	}
	if len(paging) < 30 {
		t.Fatalf("only %d paginating operations in the verified file — refresh it", len(paging))
	}

	sites, err := os.ReadFile(filepath.Join(root, "go", "internal", "aws", "testdata", "aws-callsites.txt"))
	if err != nil {
		t.Fatalf("read the recorded call sites (refresh: GROUNDHOLD_ROUTE_CAPTURE=testdata/aws-routes.txt go test ./internal/aws/): %v", err)
	}

	// The driver's source, to ask whether a function in a chain names a continuation.
	dir := filepath.Join(root, "go", "internal", "aws")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read the aws driver: %v", err)
	}
	bodies := map[string]string{}
	funcRE := regexp.MustCompile(`\nfunc (?:\([^)]*\) )?(\w+)\(`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		src := "\n" + string(raw)
		idx := funcRE.FindAllStringSubmatchIndex(src, -1)
		for i, m := range idx {
			end := len(src)
			if i+1 < len(idx) {
				end = idx[i+1][0]
			}
			name := src[m[2]:m[3]]
			bodies[name] += src[m[0]:end]
		}
	}
	if len(bodies) < 200 {
		t.Fatalf("only %d driver functions parsed — the subject went thin", len(bodies))
	}

	token := regexp.MustCompile(`NextToken|nextToken|NextMarker|IsTruncated|Truncated|` +
		`Marker|LastEvaluated|ExclusiveStart|maxAWSListPages`)

	covered := map[string]bool{}
	// The KEY is the tail of the chain: reader, per-service helper, transport. The head
	// names who wanted the read and the tail names the read itself, and one read reached
	// from four entry points is one read — `Delete>deleteASG>describeASG>asgPost` and
	// `Observe>observeASG>describeASG>asgPost` are the same unpaged `describeASG`. Two
	// DIFFERENT readers of one operation stay two entries, which is the D864 case (one
	// operation, three call sites, mixed) the previous ratchet could not see.
	const tail = 3
	seen := map[string]bool{}
	unfollowed := 0
	var names []string
	for _, line := range strings.Split(string(sites), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p := strings.SplitN(line, "\t", 3)
		if len(p) != 3 {
			t.Fatalf("call-site line is not service|operation|chain: %q", line)
		}
		svc, op, chain := p[0], p[1], p[2]
		covered[svc+"\t"+op] = true
		if !paging[svc+"\t"+op] {
			continue
		}
		frames := strings.Split(chain, ">")
		if len(frames) > tail {
			frames = frames[len(frames)-tail:]
		}
		key := svc + "\t" + op + "\t" + strings.Join(frames, ">")
		if seen[key] {
			continue
		}
		seen[key] = true

		followed := false
		for _, fn := range strings.Split(chain, ">") {
			if b, ok := bodies[fn]; ok && token.MatchString(b) {
				followed = true
				break
			}
		}
		if followed {
			continue
		}
		unfollowed++
		names = append(names, svc+":"+op+" via "+chain)
	}

	// D328, and the price of asking the drivers instead of the source: a capture that
	// exercised nothing would make this gate pass over nothing.
	if len(covered) < 100 {
		t.Fatalf("the recorded call sites cover only %d (service, operation) pairs — the "+
			"capture is thin, so this ratchet is measuring almost nothing", len(covered))
	}

	sort.Strings(names)
	if unfollowed > unfollowedPagingSiteCeiling {
		t.Errorf("%d recorded call chains issue a paginating operation without following a "+
			"token, ceiling %d:\n  %s\n\nA new one means a driver reads page one of a listing "+
			"AWS pages. That is only safe when a quota bounds the collection, a server-side "+
			"filter names one item, or the question is \"is this empty\" — establish which, "+
			"or follow the token (D871).",
			unfollowed, unfollowedPagingSiteCeiling, strings.Join(names, "\n  "))
	}
	if unfollowed < unfollowedPagingSiteCeiling {
		t.Errorf("%d unfollowed paging call chains but the ceiling still says %d. Lower it: "+
			"a ceiling that trails the work stops being a ratchet.",
			unfollowed, unfollowedPagingSiteCeiling)
	}
}
