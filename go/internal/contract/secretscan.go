// Plaintext-credential detection in candidates (D364).
//
// Reported from the field: a candidate may carry a credential as a literal
// value, and the ledger then persists it verbatim — so the ledger silently
// inherits the sensitivity of the most sensitive value in the document, and
// nothing says so. A team that keeps its ledger next to its IaC files is one
// `git add` away from publishing a private key.
//
// This is NOT a refusal. groundhold recorded exactly what it was told to record,
// which is correct; the defect is that nobody was warned what that implied. A
// refusal would also be wrong on the merits: a value that LOOKS like a credential
// sometimes is not one, and a heuristic must never block a run it cannot prove
// anything about. Compare the redactor (D309), which is deliberately EXACT rather
// than pattern-based because it decides what to hide; this decides what to say
// out loud, so a pattern is the right instrument and a false positive costs a
// sentence rather than an outage.
//
// The same scan catches an UNSUBSTITUTED PLACEHOLDER, which is the failure that
// actually took the reporter's API down: `{{secret:...}}` reached a Lambda's
// environment verbatim because the substitution step was never written. The tool
// could see that and said nothing. It can now.
package contract

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// SecretFinding names one suspicious value and why it is suspicious. `Pointer`
// is the document path an operator can go and look at; the VALUE is never
// carried, because a warning that quotes the secret defeats itself.
type SecretFinding struct {
	// Code is the STABLE, machine-routable name. An agent driving groundhold reads
	// this; the prose below is for a human. A warning only a human can parse is a
	// warning an agent will not act on (D365).
	Code    string
	Pointer string // e.g. capabilities.api.implementation.environment.DATABASE_URL
	Kind    string // what the pattern recognised, in prose
	Advice  string // what to do instead — a warning that only alarms is half a warning
}

// Advisory codes. Two, because the remedies differ: one is a secret that must not
// be stored, the other is a template that was never filled in.
const (
	CodePlaintextCredential      = "plaintext-credential"
	CodeUnsubstitutedPlaceholder = "unsubstituted-placeholder"
)

// credentialPatterns are shapes that are credentials essentially always. Kept
// narrow on purpose: a pattern that fires on ordinary configuration trains people
// to ignore the warning, which is worse than not having it.
var credentialPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"a PEM private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"a PEM certificate", regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)},
	{"a connection string with an inline password", regexp.MustCompile(`^[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`)},
	{"an AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"a Google OAuth client secret", regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{10,}`)},
	{"a SendGrid API key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`)},
	{"a Brevo API key", regexp.MustCompile(`\bxkeysib-[A-Za-z0-9]{32,}`)},
	{"a Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
	{"a private key in OpenSSH format", regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`)},
}

// placeholderPatterns are template markers that should have been substituted
// before the document reached groundhold. Reaching a provider verbatim is not a
// security problem — it is an OUTAGE, and the reporter's was thirteen minutes.
var placeholderPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"an unsubstituted {{...}} placeholder", regexp.MustCompile(`\{\{[^}]+\}\}`)},
	{"an unsubstituted ${...} placeholder", regexp.MustCompile(`\$\{[^}]+\}`)},
	{"an unsubstituted <...> placeholder", regexp.MustCompile(`^<[A-Za-z0-9_. -]+>$`)},
}

const (
	adviceCredential = "keep the secret in a secret manager and have the application fetch it " +
		"at start-up, or pass a reference the runtime resolves — never the value itself"
	advicePlaceholder = "substitute it before running, or remove it — groundhold will apply this " +
		"string literally, exactly as written"
)

// ScanForPlaintextSecrets walks a candidate's implementation operands and
// attribute values, and reports every value whose SHAPE says it should not be in
// a stored document. Findings are sorted so output is deterministic.
//
// Only string leaves are examined, and only their shape: no value is ever copied
// into a finding.
func ScanForPlaintextSecrets(c *Candidate) []SecretFinding {
	if c == nil {
		return nil
	}
	var out []SecretFinding
	// Extras carries the free-form non-attribute keys (D26) — `implementation`
	// above all, which is where environment blocks and other operator material
	// live. Vocabulary ATTRIBUTES are typed scalars drawn from a closed set, so a
	// credential cannot hide there; the operand block is the one that accepts
	// anything, which is exactly why it is the one worth scanning.
	capIDs := make([]string, 0, len(c.Extras))
	for id := range c.Extras {
		capIDs = append(capIDs, id)
	}
	sort.Strings(capIDs)
	for _, capID := range capIDs {
		extras := c.Extras[capID]
		keys := make([]string, 0, len(extras))
		for k := range extras {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			scanValue(&out, "capabilities."+capID+"."+k, extras[k])
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pointer < out[j].Pointer })
	return out
}

// scanValue recurses through the free-form shapes a YAML operand block can take.
func scanValue(out *[]SecretFinding, pointer string, v any) {
	switch t := v.(type) {
	case string:
		if f, ok := classifySecretish(pointer, t); ok {
			*out = append(*out, f)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			scanValue(out, pointer+"."+k, t[k])
		}
	case []any:
		for i, e := range t {
			scanValue(out, fmt.Sprintf("%s[%d]", pointer, i), e)
		}
	}
}

// classifySecretish decides whether one string leaf is worth warning about.
func classifySecretish(pointer, s string) (SecretFinding, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return SecretFinding{}, false
	}
	for _, p := range credentialPatterns {
		if p.re.MatchString(trimmed) {
			return SecretFinding{Code: CodePlaintextCredential, Pointer: pointer, Kind: p.name, Advice: adviceCredential}, true
		}
	}
	for _, p := range placeholderPatterns {
		if p.re.MatchString(trimmed) {
			return SecretFinding{Code: CodeUnsubstitutedPlaceholder, Pointer: pointer, Kind: p.name, Advice: advicePlaceholder}, true
		}
	}
	return SecretFinding{}, false
}
