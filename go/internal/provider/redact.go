// Secret redaction for driver diagnostics (D309).
//
// A failed mutation's Reason is not a log line: apply.go copies it verbatim into
// receipt["reason"], which becomes a PERSISTED ledger event that `export`
// publishes and `capsule` signs and ships to a third party. So anything a driver
// puts there is, in effect, published.
//
// Two independent defences, because either alone is insufficient:
//
//  1. STRUCTURAL (per-cloud, in awsread.go/armread.go/gcpread.go and their
//     mutation twins): never paste a raw response body — lift the provider's own
//     error code and a bounded message.
//  2. VALUE-BASED (here): a provider MAY echo a value we sent back at us inside
//     that message ("Invalid value for MasterUserPassword=..."), and no amount of
//     structure prevents that. The driver knows exactly which values it supplied
//     as credentials — it took them from the candidate's implementation block —
//     so it removes THOSE EXACT STRINGS from every diagnostic it emits.
//
// Value-based redaction is deliberately exact rather than pattern-guessing: it
// never has to recognise a provider's message format, and it cannot silently
// miss a secret it was handed. What it does not cover is a secret the driver
// never saw (one the provider minted itself); defence 1 is what bounds that.
package provider

import (
	"strings"

	"groundhold/internal/secretshape"
)

// secretKeyMarks are the implementation-key substrings that denote a CREDENTIAL
// VALUE. Deliberately narrow: `kms_key`, `key_vault_key` and friends name a KEY
// RESOURCE (an ARN or resource path), not key material — redacting those would
// blind the operator to which key was refused while protecting nothing. Matching
// is case-insensitive over the key with separators stripped, so master_password,
// masterPassword and MasterUserPassword all land on "password".
// D648: the alphabet moved to internal/secretshape, shared with the publish-time
// scan and the capsule certifier. Three narrower copies of this list is how a
// plaintext DSN got certified while a bearer token was refused.

// minRedactableLen guards the diagnostic against a pathological redaction: a
// one- or two-character "secret" would blank out unrelated substrings of every
// message. A credential shorter than this is not protectable by substring
// removal and is a problem at its source, not here.
const minRedactableLen = 6

// RedactionMark replaces a redacted value. It names WHY the text is gone — an
// operator reading a receipt must be able to tell redaction from truncation.
const RedactionMark = "[redacted-credential]"

// SecretValuesIn collects the credential values a candidate's implementation
// block carries, walking nested maps and slices (a driver may take
// implementation.auth.password). Non-strings and values shorter than
// minRedactableLen are skipped.
func SecretValuesIn(impl map[string]any) []string {
	var out []string
	collectSecrets(impl, false, &out)
	return out
}

func collectSecrets(v any, underSecretKey bool, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			collectSecrets(child, underSecretKey || isSecretKey(k), out)
		}
	case []any:
		for _, child := range t {
			collectSecrets(child, underSecretKey, out)
		}
	case string:
		if len(t) < minRedactableLen {
			return
		}
		// D648: a value whose SHAPE is a credential is remembered whatever key it
		// sits under. `implementation.environment.DATABASE_URL` is not a
		// secret-named key, and the DSN under it reached the ledger, the capsule
		// and the public export in a provider's own error text.
		if _, looksSecret := secretshape.ValueLooksLikeCredential(t); underSecretKey ||
			looksSecret {
			*out = append(*out, t)
		}
	}
}

// isSecretKey reports whether a key names a credential value.
func isSecretKey(k string) bool { return secretshape.KeyLooksLikeCredential(k) }

// Redactor holds the credential values seen for the mutation in flight. The zero
// value is usable and redacts nothing, so a driver that never registers anything
// behaves exactly as before.
type Redactor struct {
	values []string
}

// Remember registers credential values for the current mutation. Call it at the
// driver's entry point (Create/Update), where the implementation block arrives.
func (r *Redactor) Remember(impl map[string]any) {
	r.values = append(r.values, SecretValuesIn(impl)...)
}

// Forget clears the set. A driver instance outlives one action, and a credential
// from action N must never redact — or be carried into — action N+1.
func (r *Redactor) Forget() { r.values = nil }

// Scrub removes every remembered credential from s. Applied at the driver
// boundary to the final Reason, it covers every diagnostic the action produced
// without each call site having to remember to ask.
func (r *Redactor) Scrub(s string) string {
	if s == "" || len(r.values) == 0 {
		return s
	}
	for _, v := range r.values {
		if v == "" {
			continue
		}
		s = strings.ReplaceAll(s, v, RedactionMark)
	}
	return s
}
