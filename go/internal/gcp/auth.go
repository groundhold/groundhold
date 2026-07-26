// GCP auth: a deliberately NARROW adapter (D43), not ADC compatibility.
// Token sources, in order:
//  1. GROUNDHOLD_GCP_ACCESS_TOKEN — a ready token (CI, testing)
//  2. GROUNDHOLD_GCP_KEY_FILE — a service-account key JSON (type
//     "service_account" ONLY; no federation configs, no user creds),
//     self-signed RS256 JWT exchanged at the token endpoint
//  3. GCE metadata server
//
// Tokens are cached until 60s before expiry; JWT claims use a 5-minute
// backdated iat against clock skew. Auth is the network shell — the
// only wall-clock reader in the driver — and stays out of the
// conformance surface.
package gcp

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// cloud-platform: the driver is multi-service (Cloud SQL, Cloud Run, GCS) and
// also calls Cloud Resource Manager for the D75 permission preflight — a
// service-narrow scope (sqlservice.admin) would fail-closed on every non-SQL
// call even with correct IAM. The env-token path (GROUNDHOLD_GCP_ACCESS_TOKEN)
// carries whatever scope the caller minted; this scope applies to the
// key-file JWT exchange only.
const scope = "https://www.googleapis.com/auth/cloud-platform"

type authenticator struct {
	http        *http.Client
	metadataURL string
	now         func() time.Time

	cached string
	expiry time.Time
}

func (a *authenticator) token() (string, error) {
	if t := os.Getenv("GROUNDHOLD_GCP_ACCESS_TOKEN"); t != "" {
		return t, nil
	}
	if a.cached != "" && a.now().Before(a.expiry.Add(-60*time.Second)) {
		return a.cached, nil
	}
	if keyFile := os.Getenv("GROUNDHOLD_GCP_KEY_FILE"); keyFile != "" {
		tok, ttl, err := a.serviceAccountToken(keyFile)
		if err != nil {
			return "", err
		}
		a.cached, a.expiry = tok, a.now().Add(ttl)
		return tok, nil
	}
	tok, ttl, err := a.metadataToken()
	if err != nil {
		return "", fmt.Errorf("no usable GCP credentials "+
			"(set GROUNDHOLD_GCP_ACCESS_TOKEN or GROUNDHOLD_GCP_KEY_FILE, "+
			"or run on GCE): %v", err)
	}
	a.cached, a.expiry = tok, a.now().Add(ttl)
	return tok, nil
}

type saKey struct {
	Type         string `json:"type"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
	ClientEmail  string `json:"client_email"`
	TokenURI     string `json:"token_uri"`
}

func (a *authenticator) serviceAccountToken(path string) (string, time.Duration, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, err
	}
	var key saKey
	if err := json.Unmarshal(raw, &key); err != nil {
		return "", 0, err
	}
	if key.Type != "service_account" {
		return "", 0, fmt.Errorf(
			"key file type %q not supported — this adapter accepts "+
				"service_account keys only (no ADC/federation)", key.Type)
	}
	block, _ := pem.Decode([]byte(key.PrivateKey))
	if block == nil {
		return "", 0, fmt.Errorf("key file: no PEM block in private_key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", 0, fmt.Errorf("key file: %v (PKCS#8 RSA only)", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return "", 0, fmt.Errorf("key file: not an RSA key")
	}

	now := a.now()
	header, _ := json.Marshal(map[string]string{
		"alg": "RS256", "typ": "JWT", "kid": key.PrivateKeyID})
	claims, _ := json.Marshal(map[string]any{
		"iss":   key.ClientEmail,
		"scope": scope,
		"aud":   key.TokenURI,
		"iat":   now.Add(-5 * time.Minute).Unix(), // clock-skew backdate
		"exp":   now.Add(55 * time.Minute).Unix(),
	})
	b64 := base64.RawURLEncoding.EncodeToString
	signing := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", 0, err
	}
	assertion := signing + "." + b64(sig)

	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	resp, err := a.http.PostForm(key.TokenURI, form)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("token exchange: HTTP %d: %s",
			resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", 0, fmt.Errorf("token exchange: bad response")
	}
	return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
}

func (a *authenticator) metadataToken() (string, time.Duration, error) {
	req, err := http.NewRequest("GET", a.metadataURL+
		"/computeMetadata/v1/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Metadata-Flavor", "Google")
	resp, err := a.http.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("metadata: HTTP %d", resp.StatusCode)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", 0, fmt.Errorf("metadata: bad token response")
	}
	return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
}
