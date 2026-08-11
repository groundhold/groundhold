package parity

import (
	"sort"
	"strings"
)

// clouds is the fixed column order of the matrix.
var clouds = []string{"aws", "gcp", "azure"}

const matrixHeader = `# Cross-cloud capability parity matrix — GENERATED, DO NOT EDIT.
#
# Regenerate with: go test ./internal/parity -run TestParityMatrix -update
# (or: make parity). TestParityMatrix proves this file byte-for-byte against the
# three drivers' ServiceCapabilities() maps + the authored structural gaps, so it
# can never drift or over-claim.
#
# Each (capability, cloud) cell is exactly one of:
#   fulfilled: [tokens]  — one or more SERVICE tokens fulfil the capability (D76)
#   gap: {class, reason} — the cloud STRUCTURALLY cannot fulfil it (a fact about
#                          the cloud; class is from a closed set)
#   fulfilledOutsideTheClouds: [provider/service]
#                        — the capability IS built, by a provider that is not one of the
#                          three clouds (today: the Kubernetes driver). The cloud cells
#                          still read honestly; this stops unbuilt from being read as
#                          "groundhold has not built this" when it has (D502).
#   unbuilt: true        — DERIVED: no token, no declared gap (a fact about groundhold —
#                          a driver could be written; the cloud is not the blocker)
#
# The gap-vs-unbuilt distinction is the point: it tells the bake-off (D92) when a
# cloud CANNOT satisfy a contract versus when groundhold simply lacks the driver.
`

// BuildMatrixYAML renders the deterministic parity matrix. caps maps each cloud to
// its (serviceToken -> capabilityTYPE) map; vocabTypes is every capability TYPE in
// spec/vocab (so a TYPE no cloud fulfils still gets an honest all-unbuilt row).
// BuildMatrixYAML with the non-cloud providers folded in. `outside` maps a capability
// TYPE to the "provider/service" tokens that fulfil it OFF the three clouds — today,
// the Kubernetes driver's mappings.
//
// D502: the matrix stays cross-CLOUD (Kubernetes is a substrate that runs on them, not
// a fourth cloud), but `unbuilt: true` is defined by this file's own header as a fact
// about GROUNDHOLD — "no token, no declared gap". Three capabilities were reported
// unbuilt on all three clouds while shipping in the k8s driver: cluster.namespace,
// compute.quota and gitops.application. A generated artifact that crosses the export
// boundary was under-claiming what the project builds, and it would have regenerated
// wrong forever, because the generator had never been told the driver exists.
func BuildMatrixYAML(caps map[string]map[string]string, vocabTypes []string) string {
	return BuildMatrixYAMLWith(caps, vocabTypes, nil)
}

func BuildMatrixYAMLWith(caps map[string]map[string]string, vocabTypes []string,
	outside map[string][]string) string {
	var b strings.Builder
	b.WriteString(matrixHeader)
	b.WriteString("version: \"0.1\"\n")
	b.WriteString("clouds:\n")
	for _, c := range clouds {
		b.WriteString("  - " + c + "\n")
	}
	b.WriteString("capabilities:\n")

	types := append([]string(nil), vocabTypes...)
	sort.Strings(types)
	for _, typ := range types {
		b.WriteString("  " + typ + ":\n")
		for _, cloud := range clouds {
			b.WriteString("    " + cloud + ":\n")
			toks := tokensFor(caps[cloud], typ)
			switch {
			case len(toks) > 0:
				b.WriteString("      fulfilled: [" + strings.Join(toks, ", ") + "]\n")
			default:
				if g, ok := structuralGaps[typ][cloud]; ok {
					b.WriteString("      gap:\n")
					b.WriteString("        class: " + g.Class + "\n")
					b.WriteString("        reason: " + yamlQuote(g.Reason) + "\n")
				} else {
					b.WriteString("      unbuilt: true\n")
				}
			}
		}
		if o := outside[typ]; len(o) > 0 {
			sorted := append([]string(nil), o...)
			sort.Strings(sorted)
			b.WriteString("    fulfilledOutsideTheClouds: [" +
				strings.Join(sorted, ", ") + "]\n")
		}
	}
	return b.String()
}

// tokensFor returns the sorted SERVICE tokens in a cloud's map that fulfil typ
// (one TYPE may have several — rds and aurora both fulfil database.relational).
func tokensFor(m map[string]string, typ string) []string {
	var out []string
	for tok, t := range m {
		if t == typ {
			out = append(out, tok)
		}
	}
	sort.Strings(out)
	return out
}

// yamlQuote double-quotes a scalar and escapes embedded quotes/backslashes so the
// rendered reason is always a valid, single-line YAML string.
func yamlQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
