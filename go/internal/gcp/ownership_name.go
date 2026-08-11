package gcp

import (
	"regexp"
	"strings"
)

// D451: the GCP half of the D443-D449 blind spot. Where a provider offers NO LABELS on a
// resource, this codebase used the deterministic NAME as ownership evidence on the create
// path and forgot it on the delete path — five times on AWS, and the same shape exists
// here. A delete is handed a providerId from the ledger, and a ledger can be wrong: a
// mistaken adoption, a stale binding, or a hand-authored plan the executor is explicitly
// built to expect (D47/D48).
//
// nameLooksOursGCP reconstructs what CAN be known without the generation, which a delete
// is never given: the prefix, the capability+environment slug, and a tail of the right
// shape and length. It cannot say WHICH generation produced the name and does not try. It
// says the resource belongs to this contract's capability rather than to somebody else,
// which is exactly what a label would have answered.
func nameLooksOursGCP(name, capability, environment, prefix, sep string,
	bad *regexp.Regexp, tailLen int) bool {
	slug := capability
	if environment != "" {
		slug += sep + environment
	}
	slug = strings.Trim(bad.ReplaceAllString(strings.ToLower(slug), sep), sep)
	want := prefix + slug + sep
	if !strings.HasPrefix(name, want) {
		return false
	}
	tail := name[len(want):]
	// a generation suffix (-g2) may sit between the slug and the hash (D48)
	if i := strings.Index(tail, sep+"g"); i == 0 {
		if j := strings.Index(tail[1:], sep); j >= 0 {
			tail = tail[j+2:]
		}
	}
	if len(tail) != tailLen {
		return false
	}
	for _, c := range tail {
		if !((c >= 'a' && c <= 'f') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}
