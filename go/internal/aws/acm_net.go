// ACM network shell (D117): the SigV4-signed, JSON-protocol half of the AWS
// capability.certificate.tls driver. The CertificateArn is SERVER-ASSIGNED; a
// deterministic IdempotencyToken makes RequestCertificate idempotent, and a lost
// create is recovered by ListCertificates + domain/tag match — never a stranded
// cert (DeterministicID=false). Ownership is TAGS. The create succeeds when the cert
// is REQUESTED (validation completes out of band once the DNS record is published).
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

const acmTarget = "CertificateManager"

// acmCertIDOK bounds the certificate id (the UUID tail of the ARN).
var acmCertIDOK = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (d *Driver) acmBase(region string) string {
	if d.ACMBaseURL != "" {
		return d.ACMBaseURL
	}
	return "https://acm." + region + ".amazonaws.com"
}

func acmProviderID(region, account, certID string) string {
	return "acm:" + region + ":" + account + ":" + certID
}

func splitACMProviderID(providerID string) (region, account, certID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "acm" {
		return "", "", "", fmt.Errorf("providerId %q is not acm:region:account:certId", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !acmCertIDOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId certId %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

func acmARN(region, account, certID string) string {
	return "arn:aws:acm:" + region + ":" + account + ":certificate/" + certID
}

// acmCertIDFromARN extracts the UUID tail; "" if malformed.
func acmCertIDFromARN(arn string) string {
	i := strings.LastIndex(arn, "/")
	if i < 0 {
		return ""
	}
	id := arn[i+1:]
	if !acmCertIDOK.MatchString(id) {
		return ""
	}
	return id
}

func (d *Driver) acmCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.1",
		"X-Amz-Target": acmTarget + "." + action,
	}
	return d.doSigned("POST", d.acmBase(region)+"/", "acm", region, h, []byte(body))
}

type acmCertificate struct {
	CertificateArn          string `json:"CertificateArn"`
	DomainName              string `json:"DomainName"`
	Status                  string `json:"Status"`
	Type                    string `json:"Type"`
	RenewalEligibility      string `json:"RenewalEligibility"`
	DomainValidationOptions []struct {
		ValidationMethod string `json:"ValidationMethod"`
	} `json:"DomainValidationOptions"`
}

// describeACM reads the certificate. D296: a read that produced nothing returns
// an error NAMING the cause (status + the service's own code); an authoritative
// ResourceNotFound stays found=false with NO error, so the four-valued meaning
// is unchanged — only the diagnosis is new.
func (d *Driver) describeACM(region, arn string) (acmCertificate, bool, error) {
	const op = "DescribeCertificate"
	st, resp, err := d.acmCall(region, op, jsonBody(map[string]any{"CertificateArn": arn}))
	if err != nil {
		return acmCertificate{}, false, readTransport(op, err)
	}
	if strings.Contains(acmErr(resp), "ResourceNotFound") {
		return acmCertificate{}, false, nil
	}
	if st != http.StatusOK {
		return acmCertificate{}, false, readHTTP(op, st, acmErr(resp))
	}
	var out struct {
		Certificate acmCertificate `json:"Certificate"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return acmCertificate{}, false, readBody(op, st)
	}
	return out.Certificate, true, nil
}

func (d *Driver) acmTags(region, arn string) (map[string]string, error) {
	const op = "ListTagsForCertificate"
	st, resp, err := d.acmCall(region, "ListTagsForCertificate", jsonBody(map[string]any{"CertificateArn": arn}))
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, acmErr(resp))
	}
	var out struct {
		Tags []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

func acmErr(body []byte) string {
	var e struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	s := strings.TrimSpace(e.Type + " " + e.Message + " " + e.Msg)
	if s == "" {
		return "" // D309: never the raw body — this string reaches a persisted receipt
	}
	return boundMsg(s)
}

func (d *Driver) createACM(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildACM(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	st, resp, err := d.acmCall(region, "RequestCertificate", jsonBody(plan.createBody(capability, environment)))
	switch {
	case err != nil:
		// server-assigned arn: no deterministic pid, but the IdempotencyToken makes a
		// RETRY idempotent — so an ambiguous outcome is unknown, reconcilable by domain.
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; a retry is idempotent by IdempotencyToken): %v", err)}
	case st == http.StatusOK:
		var out struct {
			CertificateArn string `json:"CertificateArn"`
		}
		if json.Unmarshal(resp, &out) != nil || acmCertIDFromARN(out.CertificateArn) == "" {
			return provider.CreateResult{Status: "unknown", Reason: "create returned no certificate arn — reconcile by domain"}
		}
		return provider.CreateResult{ProviderID: acmProviderID(region, account, acmCertIDFromARN(out.CertificateArn)), Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile by domain", st)}
	default:
		if r := provider.MutationResult(st, acmErr(resp), nil, "", "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s)", st, acmErr(resp))}
	}
}

func (d *Driver) observeACM(capability, providerID string) ([]provider.Observation, []string, error) {
	region, account, certID, err := splitACMProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	if err := d.sameAccount(account); err != nil {
		return nil, nil, err
	}
	arn := acmARN(region, account, certID)
	cert, found, rerr := d.describeACM(region, arn)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 (D520): a BOUND resource the API authoritatively 404s is GONE.
		// A diagnostic alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"certificate not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if cert.DomainName != "" {
		obs = append(obs, provider.Observation{Path: "domain", Value: cert.DomainName, Derivation: "measured"})
	}
	// auto.renew: an AMAZON_ISSUED cert is MANAGED — it auto-renews by nature; an
	// IMPORTED cert does not. F16-A: RenewalEligibility is TRANSIENT — INELIGIBLE means
	// "not currently in use / not yet scheduled", NOT "will not renew". Keying auto.renew
	// on it made an unused-but-managed cert observe false against a declared true, so
	// reconcile emitted a no-op update on every plan that never settled. The managed
	// nature (Type) is the honest, stable signal.
	obs = append(obs, provider.Observation{Path: "auto.renew",
		Value: cert.Type == "AMAZON_ISSUED", Derivation: "measured"})
	// validation.method: DescribeCertificate reports it per domain
	// (DomainValidationOptions[].ValidationMethod = DNS|EMAIL). Emitting it lets a
	// reconcile of a BOUND certificate confirm the declared method instead of
	// refusing "validation.method: no observation" (F17).
	if len(cert.DomainValidationOptions) > 0 {
		if m := strings.ToLower(cert.DomainValidationOptions[0].ValidationMethod); m == "dns" || m == "email" {
			obs = append(obs, provider.Observation{Path: "validation.method", Value: m, Derivation: "measured"})
		}
	}
	diags := []string{fmt.Sprintf("certificate status is %s (validation completes out of band once the DNS record is published)", cert.Status)}
	return obs, diags, nil
}

func (d *Driver) deleteACM(capability, environment, providerID string) provider.CreateResult {
	region, account, certID, err := splitACMProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := acmARN(region, account, certID)
	_, found, rerr := d.describeACM(region, arn)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.acmTags(region, arn)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "certificate tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.acmCall(region, "DeleteCertificate", jsonBody(map[string]any{"CertificateArn": arn}))
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if strings.Contains(acmErr(resp), "ResourceNotFound") {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if strings.Contains(acmErr(resp), "ResourceInUse") {
		return provider.CreateResult{Status: "failed",
			Reason: "the certificate is still in use (attached to a load balancer/CloudFront) and cannot be deleted — detach it first (never forced)"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st != http.StatusOK {
		if r := provider.MutationResult(st, acmErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, acmErr(resp))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// classifyACMChange is the ACM in-place change classification (D46). A certificate
// is essentially immutable — its domain, validation method and region are fixed at
// issuance, so a change to any of them is a REPLACEMENT (a new certificate). The
// exception is auto.renew: ACM MANAGES renewal eligibility, and a freshly-issued
// certificate is not yet ELIGIBLE (it becomes auto-renewing once DNS validation
// completes). That transient difference is a managed convergence, NOT an operator
// patch and NOT a reason to replace a healthy certificate — so it is `caveated`
// (a no-op the Update path records), never the default "unsupported" that would
// block every incremental apply after a certificate is bound (the F15 report).
func classifyACMChange(path string) (string, string) {
	switch path {
	case "auto.renew":
		return "caveated", "ACM manages renewal eligibility; a newly-issued " +
			"certificate becomes auto-renewing once validation completes — no in-place " +
			"patch is issued (the reconcile is a no-op that converges as ACM validates)"
	case "domain", "validation.method", "location.region":
		return "immutable", "a certificate's domain, validation method and region are " +
			"fixed at issuance — a change is a new certificate (a replacement)"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no ACM in-place mapping for " + path
	}
}

// updateACM handles the ONLY caveated ACM change — auto.renew, which ACM converges
// itself. There is nothing to patch: re-check ownership so we never touch a foreign
// certificate, then record success (a later observe confirms the managed
// convergence). Any other path reaching here is a classification bug, refused.
func (d *Driver) updateACM(capability, environment, providerID string,
	changes []string) provider.CreateResult {
	region, account, certID, err := splitACMProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn := acmARN(region, account, certID)
	tags, terr := d.acmTags(region, arn)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "certificate tags do not match — refusing to patch a resource that is not ours"}
	}
	for _, p := range changes {
		if p != "auto.renew" {
			return provider.CreateResult{Status: "failed",
				Reason: "no ACM in-place update for " + p + " — a certificate is immutable (replace it)"}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded",
		Reason: "auto.renew is managed by ACM — no patch issued; renewal converges as validation completes"}
}
