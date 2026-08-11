// Package secretshape owns the one question four packages were answering
// separately: does this look like a credential?
//
// D648. There were four alphabets — `provider.secretKeyMarks` (what the redactor
// remembers), `contract.credentialPatterns` (what `publish` warns about and what
// `backup` scans capsules for), `collector.secretKey` and `collector.secretValue`
// (what `certify-capsule` refuses) — and no two agreed. Measured consequences: a
// capsule carrying `postgres://app:hunter2@db.internal:5432/orders` in a receipt
// reason was CERTIFIED and backed up with `"credentialWarnings": 0`, while the same
// capsule carrying a bearer token was refused; `admin_pwd`, `db_pass`, `auth`,
// `access_key_id` and a DSN under a generic key all passed the redactor that the
// collector's own regex would have caught.
//
// The alphabet is the union, and it lives once. A detector that is narrower than
// its siblings is not conservative — it is the hole they were each covering for
// each other without knowing it.
package secretshape

import (
	"regexp"
	"strings"
)

// The key alphabet has two halves, because one list cannot be both safe and
// complete. `password` is unambiguous wherever it appears; `pass`, `pwd` and
// `auth` are only credential names when they stand alone as a TOKEN — as
// substrings they match `bypass_cache`, `passthrough_host` and, worse,
// `capability.authorization.grant`, which the capsule certifier feeds through this
// same question as an observation PATH. Flagging that would refuse honest evidence.
//
// So the key is tokenised (separators and camelCase), exact tokens are matched
// against the short list, and the separator-stripped form against the compound
// list. Deliberately still absent: key-RESOURCE names. `kms_key`,
// `key_vault_key` name an ARN or a resource path, not key material, and redacting
// them blinds the operator to WHICH key was refused while protecting nothing.
var exactTokens = map[string]bool{
	"pass": true, "pwd": true, "auth": true, "token": true, "secret": true,
	"secrets": true, "password": true, "passwd": true, "passphrase": true,
	"credential": true, "credentials": true,
}

var compoundMarks = []string{
	"password", "passwd", "secret", "token", "credential",
	"privatekey", "apikey", "passphrase", "accesskey", "sessiontoken",
	"clientsecret",
}

// tokens splits a key into lowercase words on separators and camelCase humps.
func tokens(k string) []string {
	var out []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, strings.ToLower(cur.String()))
			cur.Reset()
		}
	}
	runes := []rune(k)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ' || r == '/':
			flush()
		case r >= 'A' && r <= 'Z':
			// a hump starts a new token, except inside an acronym run (AWSKey)
			if i > 0 && (runes[i-1] < 'A' || runes[i-1] > 'Z') {
				flush()
			}
			cur.WriteRune(r)
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// valuePatterns are shapes that are credentials essentially always, whatever key
// they sit under. Kept narrow on purpose: a pattern that fires on ordinary
// configuration trains people to ignore the warning, which is worse than silence.
var valuePatterns = []struct {
	Name string
	re   *regexp.Regexp
}{
	{"a PEM private key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"a private key in OpenSSH format", regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`)},
	{"a PEM key block", regexp.MustCompile(`-----BEGIN [A-Z ]*KEY-----`)},
	{"a PEM certificate", regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)},
	// D648: this pattern used to be anchored at `^`, so a DSN sitting inside a
	// sentence — which is exactly how one arrives, quoted back inside a provider's
	// error message — never matched. The scheme is case-insensitive for the same
	// reason: `POSTGRES://` was invisible.
	{"a connection string with an inline password",
		regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@`)},
	{"an AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"a bearer token", regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._-]{16,}`)},
	{"a JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9._-]{20,}`)},
	{"a Google OAuth client secret", regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{10,}`)},
	{"a SendGrid API key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`)},
	{"a Brevo API key", regexp.MustCompile(`\bxkeysib-[A-Za-z0-9]{32,}`)},
	{"a Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
}

// KeyLooksLikeCredential reports whether a key NAME says its value is a secret.
func KeyLooksLikeCredential(k string) bool {
	for _, t := range tokens(k) {
		if exactTokens[t] {
			return true
		}
	}
	norm := strings.ToLower(k)
	for _, sep := range []string{"_", "-", ".", " ", "/"} {
		norm = strings.ReplaceAll(norm, sep, "")
	}
	for _, mark := range compoundMarks {
		if strings.Contains(norm, mark) {
			return true
		}
	}
	return false
}

// ValueLooksLikeCredential reports whether a string VALUE carries an unambiguous
// credential signature, and names the shape so a finding can say what it saw.
func ValueLooksLikeCredential(s string) (string, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return "", false
	}
	for _, p := range valuePatterns {
		if p.re.MatchString(trimmed) {
			return p.Name, true
		}
	}
	return "", false
}

// KeyMarks and ValueShapes expose the alphabet so a gate can assert that every
// consumer sees the SAME one rather than a copy that has drifted.
func KeyMarks() []string { return append([]string(nil), compoundMarks...) }

func ValueShapes() []string {
	out := make([]string, 0, len(valuePatterns))
	for _, p := range valuePatterns {
		out = append(out, p.Name)
	}
	return out
}
