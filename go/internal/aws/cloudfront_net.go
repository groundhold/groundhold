// CloudFront network shell (D118): the SigV4-signed, REST-XML half of the AWS
// capability.cdn.distribution driver. CloudFront is GLOBAL (signed us-east-1, no
// regional endpoint). The distribution Id is SERVER-ASSIGNED, so the providerId is
// parsed from the create response (DeterministicID=false); ownership is TAGS. Delete
// requires the ETag (an HTTP header) as If-Match, and SURFACES the disable-before-
// delete precondition rather than forcing it. D29/D87 honesty throughout.
package aws

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

const cloudFrontPath = "/2020-05-31"

// cfIDOK bounds a server-assigned distribution id (E + uppercase alnum).
var cfIDOK = regexp.MustCompile(`^E[A-Z0-9]{6,30}$`)

func (d *Driver) cloudFrontBase() string {
	if d.CloudFrontBaseURL != "" {
		return d.CloudFrontBaseURL
	}
	return "https://cloudfront.amazonaws.com"
}

func cfProviderID(account, distID string) string { return "cf:" + account + ":" + distID }

// cfArn renders a distribution ARN from the pid parts (CloudFront is global, so
// the ARN has no region segment) — fully derivable, no read.
func cfArn(account, distID string) string {
	return "arn:aws:cloudfront::" + account + ":distribution/" + distID
}

func splitCFProviderID(providerID string) (account, distID string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "cf" {
		return "", "", fmt.Errorf("providerId %q is not cf:account:distId", providerID)
	}
	if !account12.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId account %q is invalid", parts[1])
	}
	if !cfIDOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId distribution %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// cfDo signs (global, us-east-1) and sends a REST-XML request, returning the ETag
// response header (CloudFront's concurrency token).
func (d *Driver) cfDo(method, path, body string) (int, []byte, string, error) {
	var b []byte
	if body != "" {
		b = []byte(body)
	}
	st, resp, hdr, err := d.doSignedH(method, d.cloudFrontBase()+path, "cloudfront", "us-east-1",
		map[string]string{"Content-Type": "text/xml"}, b)
	etag := ""
	if hdr != nil {
		etag = hdr.Get("ETag")
	}
	return st, resp, etag, err
}

func cfErrCode(body []byte) string {
	var e struct {
		Code string `xml:"Error>Code"`
	}
	_ = xml.Unmarshal(body, &e)
	return e.Code
}

type cfDistribution struct {
	Id                 string `xml:"Id"`
	ARN                string `xml:"ARN"`
	Status             string `xml:"Status"`
	DomainName         string `xml:"DomainName"`
	DistributionConfig struct {
		Enabled bool `xml:"Enabled"`
		Origins struct {
			Items struct {
				Origin []struct {
					DomainName            string `xml:"DomainName"`
					OriginAccessControlId string `xml:"OriginAccessControlId"`
				} `xml:"Origin"`
			} `xml:"Items"`
		} `xml:"Origins"`
		DefaultCacheBehavior struct {
			ViewerProtocolPolicy string `xml:"ViewerProtocolPolicy"`
		} `xml:"DefaultCacheBehavior"`
	} `xml:"DistributionConfig"`
}

// getCF reads a distribution + its ETag. found=false + readable=true is an
// authoritative "does not exist".
func (d *Driver) getCF(distID string) (cfDistribution, string, bool, error) {
	st, resp, etag, err := d.cfDo("GET", cloudFrontPath+"/distribution/"+distID, "")
	if err != nil {
		return cfDistribution{}, "", false, readTransport("GetDistribution", err)
	}
	if st == http.StatusNotFound || cfErrCode(resp) == "NoSuchDistribution" {
		return cfDistribution{}, "", false, nil
	}
	if st != http.StatusOK {
		return cfDistribution{}, "", false, readHTTP("GetDistribution", st, cfErrCode(resp))
	}
	var doc cfDistribution
	if xml.Unmarshal(resp, &doc) != nil {
		return cfDistribution{}, "", false, readBody("GetDistribution", st)
	}
	return doc, etag, true, nil
}

func (d *Driver) cfTags(arn string) (map[string]string, error) {
	const op = "ListTagsForResource"
	st, resp, _, err := d.cfDo("GET", cloudFrontPath+"/tagging?Resource="+arn, "")
	if err != nil || st != http.StatusOK {
		if err != nil {
			return nil, readTransport(op, err)
		}
		return nil, readHTTP(op, st, ecsErr(resp))
	}
	var r struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"Items>Tag"`
	}
	if xml.Unmarshal(resp, &r) != nil {
		return nil, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range r.Tags {
		m[t.Key] = t.Value
	}
	return m, nil
}

func (d *Driver) createCloudFront(account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildCloudFront(environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}

	// Origin Access Control first (its id is needed in the distribution's origin).
	// A retry before the distribution lands may create a duplicate OAC (CloudFront
	// does not dedupe by Name) — the deterministic Name marks it ours for cleanup.
	oacID := ""
	if plan.OACEnabled {
		id, r := d.createOAC(plan)
		if r != nil {
			return *r
		}
		oacID = id
	}

	st, resp, _, err := d.cfDo("POST", cloudFrontPath+"/distribution?WithTags", plan.createXML(capability, environment, oacID))
	var dist cfDistribution
	switch {
	case err != nil:
		// server-assigned id: no deterministic pid, but the CallerReference makes a
		// retry idempotent — unknown, reconcilable by CallerReference.
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown (may have landed; a retry is idempotent by CallerReference): %v", err)}
	case st == http.StatusCreated || st == http.StatusOK:
		// the CreateDistributionWithTags response root IS <Distribution>.
		if xml.Unmarshal(resp, &dist) != nil || !cfIDOK.MatchString(dist.Id) {
			return provider.CreateResult{Status: "unknown", Reason: "create returned no distribution id — reconcile by CallerReference"}
		}
	case st >= 500:
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create HTTP %d (server error — may have landed) — reconcile by CallerReference", st)}
	default:
		if r := provider.MutationResult(st, cfErrCode(resp), nil, "", "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create HTTP %d (%s): %s", st, cfErrCode(resp), mutDetail(resp))}
	}

	pid := cfProviderID(account, dist.Id)

	// The invoke grant (Model 2): the distribution grants ITSELF invoke on its
	// origin lambda. The SourceArn is the distribution's OWN post-create ARN
	// (preferred from the response; derived from the pid otherwise) — least
	// privilege, scoped to exactly this distribution, and NEVER a hand-pasted
	// literal (it is a value only knowable after this create). A grant that cannot
	// complete demotes to unknown WITH the pid (the distribution exists; reconcile).
	if plan.GrantLambdaArn != "" {
		srcArn := dist.ARN
		if srcArn == "" {
			srcArn = cfArn(account, dist.Id)
		}
		if r := d.grantCloudFrontInvoke(plan.GrantLambdaArn, dist.Id, srcArn, pid); r != nil {
			return *r
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// createOAC issues CreateOriginAccessControl and returns the server-assigned id.
// A non-nil result is the honest unknown/failed (no distribution exists yet, so
// no pid to carry). Returns ("", nil) is impossible — a 2xx must yield an id.
func (d *Driver) createOAC(plan CloudFrontPlan) (string, *provider.CreateResult) {
	st, resp, _, err := d.cfDo("POST", cloudFrontPath+"/origin-access-control", plan.oacXML())
	switch {
	case err != nil:
		return "", &provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateOriginAccessControl outcome unknown: %v", err)}
	case st == http.StatusCreated || st == http.StatusOK:
		var oac struct {
			Id string `xml:"Id"`
		}
		if xml.Unmarshal(resp, &oac) != nil || oac.Id == "" {
			return "", &provider.CreateResult{Status: "unknown", Reason: "CreateOriginAccessControl returned no id — reconcile"}
		}
		return oac.Id, nil
	case st >= 500:
		return "", &provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("CreateOriginAccessControl HTTP %d (server error) — reconcile", st)}
	default:
		return "", &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateOriginAccessControl HTTP %d (%s)", st, cfErrCode(resp))}
	}
}

// grantCloudFrontInvoke cross-writes the ORIGIN lambda's resource policy so
// principal cloudfront.amazonaws.com may invoke it, conditioned on SourceArn =
// this distribution's ARN (least privilege — only this distribution). AWS changed
// Function-URL behaviour ~Oct 2025: a URL created after that date requires the
// caller's resource policy to allow BOTH lambda:InvokeFunctionUrl AND
// lambda:InvokeFunction (older URLs work with InvokeFunctionUrl alone). We grant
// both, always (granting both is backward-safe — older URLs ignore the extra
// allow — so we never gate on a date). AddPermission is one Action per call, so
// this is TWO calls with distinct statement ids; each folds the distribution id so
// a second distribution fronting the same function adds distinct statements. The
// FunctionUrlAuthType=AWS_IAM condition applies only to the InvokeFunctionUrl
// grant. Idempotent (409 = already present).
func (d *Driver) grantCloudFrontInvoke(lambdaARN, distID, sourceArn, pid string) *provider.CreateResult {
	region, name, err := splitLambdaArn(lambdaARN)
	if err != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: "grant_invoke_lambda: " + err.Error()}
	}
	// InvokeFunctionUrl (with the FunctionUrlAuthType condition) keeps its
	// original statement id so a pre-fix distribution's existing statement stays
	// idempotent on reconcile. InvokeFunction is a distinct statement (no
	// FunctionUrlAuthType condition — SourceArn alone is sufficient).
	grants := []map[string]any{
		{
			"StatementId":         "groundhold-cf-" + distID,
			"Action":              "lambda:InvokeFunctionUrl",
			"Principal":           "cloudfront.amazonaws.com",
			"SourceArn":           sourceArn,
			"FunctionUrlAuthType": "AWS_IAM",
		},
		{
			"StatementId": "groundhold-cf-invoke-" + distID,
			"Action":      "lambda:InvokeFunction",
			"Principal":   "cloudfront.amazonaws.com",
			"SourceArn":   sourceArn,
		},
	}
	for _, g := range grants {
		body, _ := json.Marshal(g)
		st, resp, e := d.lambdaDo("POST", region, lambdaFnPath+"/"+name+"/policy", body)
		switch {
		case e != nil:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("AddPermission (cloudfront %s) outcome unknown: %v", g["Action"], e)}
		case st == http.StatusCreated || st == http.StatusOK, st == http.StatusConflict:
			// created, or already present (idempotent)
		case st >= 500:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("AddPermission (cloudfront %s) HTTP %d (server error) — reconcile", g["Action"], st)}
		default:
			return &provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("AddPermission (cloudfront %s) HTTP %d: %s", g["Action"], st, lambdaErr(resp))}
		}
	}
	return nil
}

// viewerToVocab reverse-maps a CloudFront ViewerProtocolPolicy to the vocab value.
func viewerToVocab(p string) string {
	switch p {
	case "https-only", "redirect-to-https", "allow-all":
		return p
	}
	return p
}

func (d *Driver) observeCloudFront(capability, providerID string) ([]provider.Observation, []string, error) {
	_, distID, err := splitCFProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	doc, _, found, rerr := d.getCF(distID)
	if rerr != nil {
		return nil, nil, rerr
	}
	if !found {
		return nil, []string{"distribution not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "service.managed", Value: true, Derivation: "measured"},
	}
	if v := doc.DistributionConfig.DefaultCacheBehavior.ViewerProtocolPolicy; v != "" {
		obs = append(obs, provider.Observation{Path: "viewer.protocol", Value: viewerToVocab(v), Derivation: "measured"})
	}
	if items := doc.DistributionConfig.Origins.Items.Origin; len(items) > 0 && items[0].DomainName != "" {
		obs = append(obs, provider.Observation{Path: "origin.domain", Value: items[0].DomainName, Derivation: "measured"})
	}
	return obs, nil, nil
}

func (d *Driver) deleteCloudFront(capability, environment, providerID string) provider.CreateResult {
	_, distID, err := splitCFProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	doc, etag, found, rerr := d.getCF(distID)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags, terr := d.cfTags(doc.ARN)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: "pre-delete tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "distribution tags do not match — refusing to delete a resource that is not ours"}
	}
	if doc.DistributionConfig.Enabled {
		return provider.CreateResult{Status: "failed",
			Reason: "the distribution is enabled — CloudFront requires it be disabled and fully " +
				"deployed before deletion; disable it first (never forced)"}
	}
	// the delete carries the ETag as If-Match (CloudFront's optimistic-concurrency
	// token) so a concurrent config change since the read makes it fail, not clobber.
	st, resp, _, e := d.doSignedH("DELETE", d.cloudFrontBase()+cloudFrontPath+"/distribution/"+distID,
		"cloudfront", "us-east-1", map[string]string{"If-Match": etag}, nil)
	if e != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete outcome unknown: %v", e)}
	}
	if cfErrCode(resp) == "NoSuchDistribution" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if cfErrCode(resp) == "DistributionNotDisabled" {
		return provider.CreateResult{Status: "failed",
			Reason: "the distribution must be disabled and fully deployed before deletion — never forced"}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown", Reason: fmt.Sprintf("delete HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 {
		if r := provider.MutationResult(st, cfErrCode(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("delete HTTP %d (%s)", st, cfErrCode(resp))}
	}
	// Reverse-delete the OAC we own (its id was read from the origin above). The
	// distribution is gone, so the OAC is no longer referenced and can be removed.
	// Best-effort + idempotent: a leftover OAC does not block the delete's success
	// (it is unreferenced and marked ours), so an OAC teardown failure is surfaced
	// as unknown WITH the pid rather than masking the distribution's deletion.
	var oacID string
	if o := doc.DistributionConfig.Origins.Items.Origin; len(o) > 0 {
		oacID = o[0].OriginAccessControlId
	}
	if oacID != "" {
		if r := d.deleteOAC(oacID, providerID); r != nil {
			return *r
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// deleteOAC removes an Origin Access Control by id (GET for its ETag, then DELETE
// with If-Match). Idempotent: a 404/NoSuchOriginAccessControl is success. Returns
// nil on success; a non-nil result is unknown WITH the pid (reconcile).
func (d *Driver) deleteOAC(oacID, pid string) *provider.CreateResult {
	st, resp, etag, err := d.cfDo("GET", cloudFrontPath+"/origin-access-control/"+oacID, "")
	if err != nil {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("OAC teardown read outcome unknown: %v — reconcile", err)}
	}
	if st == http.StatusNotFound || cfErrCode(resp) == "NoSuchOriginAccessControl" {
		return nil // already gone
	}
	if st != http.StatusOK {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("OAC teardown read HTTP %d — reconcile", st)}
	}
	st, resp, _, err = d.doSignedH("DELETE", d.cloudFrontBase()+cloudFrontPath+"/origin-access-control/"+oacID,
		"cloudfront", "us-east-1", map[string]string{"If-Match": etag}, nil)
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("OAC teardown outcome unknown: %v — reconcile", err)}
	case st == http.StatusNotFound, cfErrCode(resp) == "NoSuchOriginAccessControl",
		st == http.StatusNoContent, st == http.StatusOK, st == http.StatusAccepted:
		return nil
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("OAC teardown HTTP %d (server error) — reconcile", st)}
	default:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("OAC teardown HTTP %d (%s) — reconcile", st, cfErrCode(resp))}
	}
}
