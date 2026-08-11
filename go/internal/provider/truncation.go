package provider

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// D803. Cloud list APIs answer in PAGES. A response that carries a continuation token is
// the provider saying "there is more", and 138 of the 140 discovery sweeps in this
// repository read the first page and stopped.
//
// That is not a missing feature — it is a false statement, because of what sits
// downstream. `posture` reports a shadow count, and marks it `shadowLowerBound` only when
// a SCOPE was incomplete (D650). A truncated page is not an error, so the scope was
// recorded complete and the count of unmanaged resources went out as EXACT. On any estate
// larger than one page, the tool affirms a number it cannot know, in the direction that
// makes an operator stop looking.
//
// The signal is a property of the RESPONSE, so it is read where responses arrive — at
// each driver's transport chokepoint — rather than in 138 places that would each have to
// remember.
//
// D818 corrects what that chokepoint can and cannot see. A truncated response is evidence
// of an INCOMPLETE answer only if nobody went and fetched the rest, and the transport
// sees only the first half of that. A sweep that follows its pages correctly hands the
// chokepoint a truncated response on every page but the last — so after D809-D817 taught
// twenty-four sweeps to paginate, those twenty-four reported themselves incomplete, while
// three that read one page reported themselves complete. The signal was not merely noisy;
// on those cases it pointed the wrong way.
//
// So the note is CONDITIONAL, and the condition is the same assertion the tests make: was
// the continuation this response handed back ever USED? A later request carrying that
// exact value is the sweep saying it went and got the rest, and it clears the note. A
// value that is never used leaves the note standing.
//
// The detector is deliberately CONSERVATIVE about what counts as "there is more". A false
// positive costs an honest "at least N" where the count was exact; a false negative
// restores the lie. So it fires only on signals whose presence unambiguously means more
// results exist, and never on a bare `Marker` or `ContinuationToken` — S3's own model says
// of ListObjects' Marker that it "is included in the response if it was sent with the
// request", which is an echo and not an answer. Services whose ONLY continuation signal is
// that ambiguous field (ElastiCache's Describe* family) cannot be covered here at all;
// there the sweep must follow its own pages, and D818 makes it.
var (
	// The leading letter's CASE is part of the wire, not of the SDK. EC2 models its field
	// as NextToken and puts `<nextToken>` on the wire (botocore ec2/2016-11-15 gives
	// locationName: nextToken for DescribeInstances, DescribeVolumes, DescribeSubnets,
	// DescribeVpcs and their siblings) — so a case-sensitive pattern made truncation
	// invisible for every EC2 sweep there is. Only the unambiguous `next*` family is
	// case-tolerant; a bare Marker stays out in either case.
	jsonContinuation = regexp.MustCompile(
		`"(?:[Nn]extToken|[Nn]extMarker|nextPageToken|nextLink|[Nn]extContinuationToken|LastEvaluatedTableName)"\s*:\s*"([^"]+)"`)
	jsonTruncated = regexp.MustCompile(
		`"(?:IsTruncated|Truncated|HasMoreStreams)"\s*:\s*true`)
	xmlContinuation = regexp.MustCompile(
		`<(?:[Nn]extToken|[Nn]extMarker|[Nn]extContinuationToken)>([^<\s][^<]*)</`)
	xmlTruncated = regexp.MustCompile(`<IsTruncated>\s*true\s*</IsTruncated>`)
)

// ListingContinuation reports whether a provider response says more results exist, and
// returns the continuation values a follow-up request would have to carry. The values are
// what makes the note conditional: they are how the record recognises a sweep that
// followed.
//
// A response can say "there is more" with a flag and hand back no value this vocabulary
// knows (Kinesis's legacy ListStreams shape). That is reported as truncated with no
// values, which cannot be cleared — the safe direction, and the reason such sweeps
// paginate rather than rely on this.
func ListingContinuation(body []byte) (bool, []string) {
	var vals []string
	for _, m := range jsonContinuation.FindAllSubmatch(body, -1) {
		vals = append(vals, string(m[1]))
	}
	for _, m := range xmlContinuation.FindAllSubmatch(body, -1) {
		vals = append(vals, string(m[1]))
	}
	more := len(vals) > 0 || jsonTruncated.Match(body) || xmlTruncated.Match(body)
	return more, vals
}

// ListingTruncated reports whether a provider response says more results exist.
func ListingTruncated(body []byte) bool {
	more, _ := ListingContinuation(body)
	return more
}

// isContinuationParam reports whether a request parameter NAME is one a provider uses to
// ask for the next page.
//
// The name matters, not just the value. DynamoDB's continuation for ListTables is the name
// of the last table on the page — so a sweep that lists one page and then DESCRIBES that
// table sends the same string, and matching on the value alone would read that as "the
// sweep followed the listing" when it did no such thing. That is a false "complete", the
// dangerous direction, and it was caught by D818's own test before it shipped.
func isContinuationParam(name string) bool {
	n := strings.ToLower(name)
	return strings.Contains(n, "token") || strings.Contains(n, "marker") ||
		strings.HasPrefix(n, "exclusivestart")
}

// RequestValues returns the continuation values an outgoing request carries, so a
// continuation handed back earlier can be recognised when it is USED.
//
// It compares VALUES exactly rather than by substring, because a substring match on a
// short token would clear a note against an unrelated request. Query parameters,
// form-encoded bodies and the top level of a JSON body are all the places these APIs put a
// continuation.
func RequestValues(rawURL string, body []byte) []string {
	// The whole URL is itself a candidate: Azure's nextLink is a complete URL the
	// response chose, so "the sweep followed it" means the next request IS that value.
	vals := []string{rawURL}
	add := func(name string, got ...string) {
		if isContinuationParam(name) {
			vals = append(vals, got...)
		}
	}
	if u, err := url.Parse(rawURL); err == nil {
		for k, vs := range u.Query() {
			add(k, vs...)
		}
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return vals
	}
	if strings.HasPrefix(trimmed, "{") {
		var doc map[string]any
		if json.Unmarshal(body, &doc) == nil {
			for k, v := range doc {
				if s, ok := v.(string); ok {
					add(k, s)
				}
			}
			return vals
		}
	}
	if q, err := url.ParseQuery(trimmed); err == nil {
		for k, vs := range q {
			add(k, vs...)
		}
	}
	return vals
}

// TruncationNote is what a driver records when it sees one, and what the crawl turns into
// an incomplete scope. It names the CALL, because "something was truncated" sends nobody
// anywhere.
type TruncationNote struct {
	Call string // the operation whose listing was cut short
}

// ListingCompleteness is an OPTIONAL driver capability, in the shape of Enumerator: it
// reports whether the listings this driver has made since the last reset were complete.
// A driver that does not implement it is treated as unknown-but-not-claiming — the crawl
// records what it is told and never invents completeness.
type ListingCompleteness interface {
	// TruncatedListings returns the calls whose responses said more results existed and
	// were never followed, and RESETS the record, so one sweep's truncation cannot be
	// reported by the next.
	TruncatedListings() []TruncationNote
}

// ListingRecord is the shared bookkeeping behind all three cloud drivers' chokepoints
// (D818). It lives here rather than three times over, because the rule it encodes — a
// truncation is only evidence if the continuation went unused — is a property of how
// paging works, not of any one provider.
type ListingRecord struct {
	mu    sync.Mutex
	order []string          // call names, first-seen order, so the report is stable
	open  map[string]bool   // call -> still believed to have left results unread
	owner map[string]string // continuation value -> the call that handed it out
}

// Note records that a response for call said more results exist, and remembers the values
// that would prove someone went and read them.
func (r *ListingRecord) Note(call string, values []string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.open == nil {
		r.open = map[string]bool{}
		r.owner = map[string]string{}
	}
	if _, seen := r.open[call]; !seen {
		r.order = append(r.order, call)
	}
	r.open[call] = true
	for _, v := range values {
		if v != "" {
			r.owner[v] = call
		}
	}
}

// Followed clears the note belonging to any continuation value this request carries. It is
// called with the values of an OUTGOING request, before it is sent.
func (r *ListingRecord) Followed(values []string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range values {
		if call, ok := r.owner[v]; ok {
			r.open[call] = false
			delete(r.owner, v)
		}
	}
}

// Take returns the calls that left results unread, and RESETS the record.
func (r *ListingRecord) Take() []TruncationNote {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []TruncationNote
	for _, call := range r.order {
		if r.open[call] {
			out = append(out, TruncationNote{Call: call})
		}
	}
	r.order, r.open, r.owner = nil, nil, nil
	return out
}
