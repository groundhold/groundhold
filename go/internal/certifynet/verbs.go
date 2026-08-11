package certifynet

import (
	"regexp"
	"sort"
	"strings"
)

// D461 — the meta-gate: which VERBS has anyone asked the ownership question of?
//
// Three registers now exist, one per verb: create binds what is already ours
// (D391-D438), delete refuses what is not (D439-D458), update refuses it too
// (D459-D460). Together they decided 339 driver paths and found eleven live defects.
//
// The registers were built in that order because that is the order I thought of them,
// and that is the problem this file exists to fix. The update register found two defects
// on a verb nobody had asked about — not because it was hard, but because "create and
// delete" felt like the whole surface until it did not. Nothing in the repo would have
// said otherwise, and nothing would say otherwise about the next verb either.
//
// So: enumerate the driver-facing methods a provider can implement, straight from the
// interface declarations in provider.go, and require every one of them to be CLASSIFIED
// — mutating (needs a foreign-refusal register) or read-only (does not). A method that
// appears in provider.go and in no classification fails the gate. This is the D338 shape
// applied to verbs rather than to event types: a closed set, published once, checked
// against the source that defines it.

// ProviderMethods extracts every method name declared by an interface in the given
// provider.go source. Deriving them beats listing them: a new optional interface with a
// new mutating method lands unclassified and the gate says so, which is exactly the
// notification that did not exist when Update was added.
func ProviderMethods(src string) []string {
	var out []string
	seen := map[string]bool{}
	decl := regexp.MustCompile(`^type ([A-Z][A-Za-z]*) interface \{`)
	method := regexp.MustCompile(`^\t([A-Z][A-Za-z]*)\(`)
	inInterface := false
	for _, ln := range strings.Split(src, "\n") {
		switch {
		case decl.MatchString(ln):
			inInterface = true
		case inInterface && ln == "}":
			inInterface = false
		case inInterface:
			if m := method.FindStringSubmatch(ln); m != nil && !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	sort.Strings(out)
	return out
}
