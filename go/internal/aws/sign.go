// AWS Signature Version 4 (D86): the auth foundation of the AWS driver. Unlike
// GCP's bearer token, every AWS request is SIGNED — a canonical request is
// hashed, a string-to-sign is built, a date/region/service-scoped key is
// derived by chained HMAC, and the signature rides in the Authorization header.
// This is pure and deterministic (golden-tested against AWS's official
// sig-v4 test vectors); the network shell calls Sign before each request.
package aws

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
)

// Credentials for signing. SessionToken is set for temporary (STS) creds.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

const emptyPayloadHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// letterHash encodes a digest as n lowercase letters (a-z) — for deterministic
// resource ids whose charset forbids digits (RDS identifiers letters-only tail).
func letterHash(input string, n int) string {
	sum := sha256.Sum256([]byte(input))
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = 'a' + (sum[i] % 26)
	}
	return string(out)
}

// Sign computes the SigV4 Authorization header for a request and returns the
// headers to add (Authorization, X-Amz-Date, X-Amz-Content-Sha256, and
// X-Amz-Security-Token when a session token is present). amzDate is
// "YYYYMMDDTHHMMSSZ" (the caller supplies the clock — no wall-time here). The
// payloadHash is hex(SHA256(body)); pass emptyPayloadHash for an empty body.
func Sign(method string, u *url.URL, headers map[string]string, payloadHash,
	region, service, amzDate string, creds Credentials) map[string]string {

	dateStamp := amzDate[:8] // YYYYMMDD

	// ---- canonical headers: host + x-amz-date + whatever the caller signs.
	// The payload hash goes into the canonical request's LAST line for every
	// service, but x-amz-content-sha256 is only a signed HEADER when the caller
	// (S3) passes it in `headers` — the generic services do not sign it. ----
	signed := map[string]string{"host": u.Host, "x-amz-date": amzDate}
	if creds.SessionToken != "" {
		signed["x-amz-security-token"] = creds.SessionToken
	}
	for k, v := range headers {
		signed[strings.ToLower(k)] = strings.TrimSpace(v)
	}
	names := make([]string, 0, len(signed))
	for k := range signed {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, n := range names {
		canonHeaders.WriteString(n)
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(signed[n])
		canonHeaders.WriteByte('\n')
	}
	signedHeaders := strings.Join(names, ";")

	// ---- canonical query string: sorted, RFC3986-encoded ----
	canonQuery := canonicalQuery(u.Query())

	// ---- canonical URI (S3 keeps the path single-encoded; path is "/" for the
	// query/POST services we sign — encode each segment once) ----
	canonURI := canonicalURI(u.EscapedPath())

	canonicalRequest := method + "\n" + canonURI + "\n" + canonQuery + "\n" +
		canonHeaders.String() + "\n" + signedHeaders + "\n" + payloadHash

	scope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" +
		sha256hex([]byte(canonicalRequest))

	// ---- derive the signing key by chained HMAC ----
	kDate := hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	auth := "AWS4-HMAC-SHA256 " +
		"Credential=" + creds.AccessKeyID + "/" + scope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature

	out := map[string]string{
		"Authorization": auth,
		"X-Amz-Date":    amzDate,
	}
	if creds.SessionToken != "" {
		out["X-Amz-Security-Token"] = creds.SessionToken
	}
	// echo back the caller's signed headers (e.g. S3's X-Amz-Content-Sha256) so
	// the request actually carries what was signed.
	for k, v := range headers {
		out[k] = v
	}
	return out
}

// canonicalQuery sorts params by key (then value) and RFC3986-encodes both.
func canonicalQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		vals := append([]string(nil), q[k]...)
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, rfc3986(k)+"="+rfc3986(v))
		}
	}
	return strings.Join(parts, "&")
}

func canonicalURI(escapedPath string) string {
	if escapedPath == "" {
		return "/"
	}
	// re-encode each segment to the AWS canonical form (Go's EscapedPath is
	// close; AWS wants RFC3986 with '~' and '/' preserved between segments).
	segs := strings.Split(escapedPath, "/")
	for i, s := range segs {
		un, err := url.PathUnescape(s)
		if err != nil {
			un = s
		}
		segs[i] = rfc3986(un)
	}
	return strings.Join(segs, "/")
}

// rfc3986 encodes per AWS rules: unreserved (A-Z a-z 0-9 -_.~) stay; everything
// else is %XX uppercase. (Go's url.QueryEscape uses '+' for space and does not
// encode all the right bytes, so we do it by hand.)
func rfc3986(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}
