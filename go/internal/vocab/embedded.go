// The full attribute vocabulary is COMPILED INTO the binary (go:embed), so a
// freshly downloaded groundhold knows its whole type system with no external files
// and no --vocab flag — "ready to use immediately after download". The embedded
// copy under embedded/ mirrors spec/vocab/ (the canonical source); embedded_test
// fails the build if the two drift. --vocab still replaces the embedded set for
// custom/override vocabularies; --no-vocab forces the empty set (D23: a
// vocabulary is an optional, strengthening input).
package vocab

import (
	"embed"
	"io/fs"
	"sort"
)

//go:embed embedded/*.yaml
var embeddedFS embed.FS

// Embedded returns the vocabularies compiled into the binary, indexed by
// capability type — the default when no --vocab is given.
func Embedded() (map[string]Vocabulary, error) {
	entries, err := fs.Glob(embeddedFS, "embedded/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	out := map[string]Vocabulary{}
	for _, p := range entries {
		raw, err := embeddedFS.ReadFile(p)
		if err != nil {
			return nil, err
		}
		v, err := parseDoc(raw, p)
		if err != nil {
			return nil, err
		}
		out[v.Capability] = v
	}
	return out, nil
}
