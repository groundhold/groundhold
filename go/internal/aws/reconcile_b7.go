// AWS receipt reconciliation, BATCH 7 (D57, F19): the Reconciler capability for six
// services whose ids are SERVER-ASSIGNED but which expose a LIST wrapper + ownership
// tags — route53, acm, efs, eks-podidentity, backupplan, guardduty. Concluding a
// PENDING create is therefore a LIST + tag-scan, exactly the reconcileBedrock shape:
// list the candidates, read each, and conclude
//
//   - succeeded — a readable, listed resource carries our ownership tags (return its
//     server id as the providerId), AND it is past any async provisioning gate;
//   - failed    — a readable, COMPLETE list has no owned match (the create never
//     landed, so the pending intent clears and a re-plan recreates);
//   - unknown   — the list, or any candidate read, is unreadable, OR an owned resource
//     is still provisioning (e.g. an EFS file system in LifeCycleState "creating").
//
// A deterministic providerId in the receipt (targetProviderId) is used as a TIER-1
// fast path: resolve it directly and short-circuit on a positive (our resource, ready)
// BEFORE the list scan. The list scan is the authority and the required fallback — it
// concludes receipts that carry no providerId. STRICTLY READ-ONLY throughout.
package aws

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"

	"groundhold/internal/provider"
)

// rc7Read is one candidate's ownership+readiness signal for rc7Scan. The zero value
// (readable=false) is the honest "cannot read" that becomes unknown — never a
// fabricated absence.
type rc7Read struct {
	err      error  // why this candidate's ownership/state read gave no answer (nil => read)
	owned    bool   // does it carry our ownership tags?
	ready    bool   // is it past any async provisioning gate?
	pid      string // the live identity to return on a match
	notReady string // the unknown reason when owned but not yet ready
}

// rc7Scan is the shared list+tag-scan reconcile core (reconcileBedrock's structure).
// It lists candidate ids and reads each in turn: a list or a candidate read that
// gave no answer is unknown (an owned resource could hide behind it); an owned+ready match
// is succeeded WITH its server id; an owned-but-not-ready match is unknown (reconcile
// again once it settles); a readable, COMPLETE list with no owned match is failed.
func rc7Scan(service string, list func() ([]string, error), read func(id string) rc7Read) provider.ReconcileResult {
	ids, lerr := list()
	if lerr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: service + " list gave no answer — cannot conclude the pending create: " + lerr.Error()}
	}
	for _, id := range ids {
		c := read(id)
		if c.err != nil {
			return provider.ReconcileResult{Status: "unknown",
				Reason: "a " + service + " read gave no answer — cannot conclude the pending create: " + c.err.Error()}
		}
		if c.owned {
			if !c.ready {
				return provider.ReconcileResult{Status: "unknown", Reason: c.notReady}
			}
			return provider.ReconcileResult{Status: "succeeded", ProviderID: c.pid}
		}
	}
	return provider.ReconcileResult{Status: "failed",
		Reason: "no " + service + " resource carries our ownership tags — the create did not land"}
}

// None of the batch-7 services need the receipt's generation (a server id + ownership
// tags are the whole handle), but the signature stays uniform with the deterministic
// reconcilers. The generation is read once in Reconcile via the shared receiptGeneration.

// ---- route53 (GLOBAL — no region) -----------------------------------------

func (d *Driver) reconcileRoute53(capability, environment string, generation int, pid string) provider.ReconcileResult {
	if pid != "" {
		if r, ok := d.rc7Route53ByPID(capability, environment, pid); ok {
			return r
		}
	}
	return rc7Scan("route53 hosted zone",
		func() ([]string, error) { return d.rc7ListHostedZones() },
		func(id string) rc7Read {
			tags, terr := d.r53Tags(id)
			if terr != nil {
				return rc7Read{err: terr}
			}
			return rc7Read{
				owned: groundholdTagsMatch(tags, capability, environment),
				ready: true, pid: r53ProviderID(id)}
		})
}

// rc7Route53ByPID short-circuits on a positive: the zone our pid names exists and is
// ours. Anything else falls through to the list scan (the pid may be stale).
func (d *Driver) rc7Route53ByPID(capability, environment, pid string) (provider.ReconcileResult, bool) {
	id, err := splitR53ProviderID(pid)
	if err != nil {
		return provider.ReconcileResult{}, false
	}
	_, found, rerr := d.getHostedZone(id)
	if rerr != nil || !found {
		return provider.ReconcileResult{}, false
	}
	tags, terr := d.r53Tags(id)
	if terr == nil && groundholdTagsMatch(tags, capability, environment) {
		return provider.ReconcileResult{Status: "succeeded", ProviderID: r53ProviderID(id)}, true
	}
	return provider.ReconcileResult{}, false
}

// rc7ListHostedZones enumerates every hosted zone (paginated by marker). A complete
// list is what lets the scan honestly conclude "failed" instead of false-failing a
// zone on a later page. readable=false on any transport/HTTP/parse failure.
func (d *Driver) rc7ListHostedZones() ([]string, error) {
	var ids []string
	marker := ""
	for {
		path := route53Path + "/hostedzone"
		if marker != "" {
			path += "?marker=" + url.QueryEscape(marker)
		}
		st, resp, err := d.r53Do("GET", path, "")
		if err != nil || st != http.StatusOK {
			if err != nil {
				return nil, readTransport("ListHostedZones", err)
			}
			return nil, readHTTP("ListHostedZones", st, awsErrCodeOf(resp))
		}
		var r struct {
			Zones []struct {
				ID string `xml:"Id"`
			} `xml:"HostedZones>HostedZone"`
			IsTruncated bool   `xml:"IsTruncated"`
			NextMarker  string `xml:"NextMarker"`
		}
		if xml.Unmarshal(resp, &r) != nil {
			return nil, readBody("ListHostedZones", st)
		}
		for _, z := range r.Zones {
			if id := stripZoneID(z.ID); id != "" {
				ids = append(ids, id)
			}
		}
		if !r.IsTruncated || r.NextMarker == "" {
			return ids, nil
		}
		marker = r.NextMarker
	}
}

// ---- acm (region-scoped) --------------------------------------------------

// A certificate resource exists the instant RequestCertificate returns (synchronous),
// so existence + ownership tags IS a landed create — PENDING_VALIDATION is downstream,
// out-of-band DNS validation (observeACM surfaces it), not resource provisioning. So
// the reconcile does NOT gate on the cert status: gating there would be a false-unknown
// that blocks resume for a certificate that genuinely exists.
func (d *Driver) reconcileACM(capability, environment string, generation int, pid string) provider.ReconcileResult {
	// tier-1 pid path resolves from the pid's own region, so it works region-agnostic.
	if pid != "" {
		if r, ok := d.rc7ACMByPID(capability, environment, pid); ok {
			return r
		}
	}
	region := d.Region
	if region == "" {
		return regionlessReconcile("acm")
	}
	return rc7Scan("acm certificate",
		func() ([]string, error) { return d.rc7ListACMArns(region) },
		func(arn string) rc7Read {
			account, certID, ok := splitACMArn(arn)
			if !ok {
				// an ARN we cannot represent as a providerId is not a handle we own.
				return rc7Read{}
			}
			tags, terr := d.acmTags(region, arn)
			if terr != nil {
				return rc7Read{err: terr}
			}
			return rc7Read{
				owned: groundholdTagsMatch(tags, capability, environment),
				ready: true, pid: acmProviderID(region, account, certID)}
		})
}

func (d *Driver) rc7ACMByPID(capability, environment, pid string) (provider.ReconcileResult, bool) {
	region, account, certID, err := splitACMProviderID(pid)
	if err != nil {
		return provider.ReconcileResult{}, false
	}
	arn := acmARN(region, account, certID)
	_, found, rerr := d.describeACM(region, arn)
	if rerr != nil || !found {
		return provider.ReconcileResult{}, false
	}
	tags, terr := d.acmTags(region, arn)
	if terr == nil && groundholdTagsMatch(tags, capability, environment) {
		return provider.ReconcileResult{Status: "succeeded", ProviderID: acmProviderID(region, account, certID)}, true
	}
	return provider.ReconcileResult{}, false
}

// splitACMArn pulls (account, certId) out of an ACM certificate ARN; ok=false for a
// malformed ARN (never a fabricated identity).
func splitACMArn(arn string) (account, certID string, ok bool) {
	p := strings.Split(arn, ":")
	if len(p) != 6 {
		return "", "", false
	}
	account = p[4]
	certID = acmCertIDFromARN(arn)
	if !account12.MatchString(account) || certID == "" {
		return "", "", false
	}
	return account, certID, true
}

// rc7ListACMArns lists every certificate ARN (paginated by NextToken).
func (d *Driver) rc7ListACMArns(region string) ([]string, error) {
	var arns []string
	token := ""
	for {
		req := map[string]any{"MaxItems": 100}
		if token != "" {
			req["NextToken"] = token
		}
		st, resp, err := d.acmCall(region, "ListCertificates", jsonBody(req))
		if err != nil || st != http.StatusOK {
			if err != nil {
				return nil, readTransport("ListCertificates", err)
			}
			return nil, readHTTP("ListCertificates", st, awsErrCodeOf(resp))
		}
		var out struct {
			CertificateSummaryList []struct {
				CertificateArn string `json:"CertificateArn"`
			} `json:"CertificateSummaryList"`
			NextToken string `json:"NextToken"`
		}
		if json.Unmarshal(resp, &out) != nil {
			return nil, readBody("ListCertificates", st)
		}
		for _, c := range out.CertificateSummaryList {
			if c.CertificateArn != "" {
				arns = append(arns, c.CertificateArn)
			}
		}
		if out.NextToken == "" {
			return arns, nil
		}
		token = out.NextToken
	}
}

// ---- efs (region-scoped, async ready-state) -------------------------------

// EFS is async: CreateFileSystem returns immediately with the fs in LifeCycleState
// "creating", usable only at "available". So an owned fs that is still creating is
// unknown (reconcile again once available), never a premature succeeded.
func (d *Driver) reconcileEFS(capability, environment string, generation int, pid string) provider.ReconcileResult {
	if pid != "" {
		if r, ok := d.rc7EFSByPID(capability, environment, pid); ok {
			return r
		}
	}
	region := d.Region
	if region == "" {
		return regionlessReconcile("efs")
	}
	account, err := d.resolveAccount()
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "cannot resolve the account for the EFS providerId — cannot conclude the pending create: " + err.Error()}
	}
	return rc7Scan("efs file system",
		func() ([]string, error) { return d.rc7ListEFS(region) },
		func(id string) rc7Read {
			fs, found, rerr := d.describeEFS(region, "FileSystemId="+id)
			if rerr != nil {
				return rc7Read{err: rerr}
			}
			if !found {
				return rc7Read{}
			}
			tags, terr := d.efsTags(region, id)
			if terr != nil {
				return rc7Read{err: terr}
			}
			return rc7Read{
				owned:    groundholdTagsMatch(tags, capability, environment),
				ready:    fs.LifeCycleState == "available",
				pid:      efsProviderID(region, account, id),
				notReady: "an owned EFS file system is still creating (LifeCycleState " + fs.LifeCycleState + ") — reconcile again once available"}
		})
}

func (d *Driver) rc7EFSByPID(capability, environment, pid string) (provider.ReconcileResult, bool) {
	region, account, id, err := splitEFSProviderID(pid)
	if err != nil {
		return provider.ReconcileResult{}, false
	}
	fs, found, rerr := d.describeEFS(region, "FileSystemId="+id)
	if rerr != nil || !found || fs.LifeCycleState != "available" {
		return provider.ReconcileResult{}, false
	}
	tags, terr := d.efsTags(region, id)
	if terr == nil && groundholdTagsMatch(tags, capability, environment) {
		return provider.ReconcileResult{Status: "succeeded", ProviderID: efsProviderID(region, account, id)}, true
	}
	return provider.ReconcileResult{}, false
}

// rc7ListEFS lists every file-system id (paginated by Marker/NextMarker).
func (d *Driver) rc7ListEFS(region string) ([]string, error) {
	var ids []string
	marker := ""
	for {
		q := ""
		if marker != "" {
			q = "?Marker=" + url.QueryEscape(marker)
		}
		st, resp, err := d.efsDo("GET", region, efsPath+"/file-systems"+q, "")
		if err != nil || st != http.StatusOK {
			if err != nil {
				return nil, readTransport("DescribeFileSystems", err)
			}
			return nil, readHTTP("DescribeFileSystems", st, awsErrCodeOf(resp))
		}
		var out struct {
			FileSystems []struct {
				FileSystemId string `json:"FileSystemId"`
			} `json:"FileSystems"`
			NextMarker string `json:"NextMarker"`
		}
		if json.Unmarshal(resp, &out) != nil {
			return nil, readBody("DescribeFileSystems", st)
		}
		for _, fs := range out.FileSystems {
			if fs.FileSystemId != "" {
				ids = append(ids, fs.FileSystemId)
			}
		}
		if out.NextMarker == "" {
			return ids, nil
		}
		marker = out.NextMarker
	}
}

// ---- backupplan (region-scoped, synchronous) ------------------------------

func (d *Driver) reconcileBackupPlan(capability, environment string, generation int, pid string) provider.ReconcileResult {
	if pid != "" {
		if r, ok := d.rc7BackupPlanByPID(capability, environment, pid); ok {
			return r
		}
	}
	region := d.Region
	if region == "" {
		return regionlessReconcile("backupplan")
	}
	return rc7Scan("backup plan",
		func() ([]string, error) { return d.rc7ListBackupPlans(region) },
		func(planID string) rc7Read {
			doc, found, rerr := d.getBackupPlan(region, planID)
			if rerr != nil {
				return rc7Read{err: rerr}
			}
			if !found {
				return rc7Read{}
			}
			// ownership tags are read via the ARN GetBackupPlan returns (we OBSERVE the
			// ARN, never build it — the vault shell's bkvTags).
			tags, terr := d.bkvTags(region, doc.BackupPlanArn)
			if terr != nil {
				return rc7Read{err: terr}
			}
			return rc7Read{
				owned: groundholdTagsMatch(tags, capability, environment),
				ready: true, pid: backupPlanProviderID(region, planID)}
		})
}

func (d *Driver) rc7BackupPlanByPID(capability, environment, pid string) (provider.ReconcileResult, bool) {
	region, planID, err := splitBackupPlanProviderID(pid)
	if err != nil {
		return provider.ReconcileResult{}, false
	}
	doc, found, rerr := d.getBackupPlan(region, planID)
	if rerr != nil || !found {
		return provider.ReconcileResult{}, false
	}
	tags, terr := d.bkvTags(region, doc.BackupPlanArn)
	if terr == nil && groundholdTagsMatch(tags, capability, environment) {
		return provider.ReconcileResult{Status: "succeeded", ProviderID: backupPlanProviderID(region, planID)}, true
	}
	return provider.ReconcileResult{}, false
}

// rc7ListBackupPlans lists every plan id (paginated by NextToken).
func (d *Driver) rc7ListBackupPlans(region string) ([]string, error) {
	var ids []string
	token := ""
	for {
		path := "/backup/plans/"
		if token != "" {
			path += "?nextToken=" + url.QueryEscape(token)
		}
		st, resp, err := d.backupCall("GET", region, path, nil)
		if err != nil || st != http.StatusOK {
			if err != nil {
				return nil, readTransport("ListBackupPlans", err)
			}
			return nil, readHTTP("ListBackupPlans", st, awsErrCodeOf(resp))
		}
		var out struct {
			BackupPlansList []struct {
				BackupPlanId string `json:"BackupPlanId"`
			} `json:"BackupPlansList"`
			NextToken string `json:"NextToken"`
		}
		if json.Unmarshal(resp, &out) != nil {
			return nil, readBody("ListBackupPlans", st)
		}
		for _, pl := range out.BackupPlansList {
			if pl.BackupPlanId != "" {
				ids = append(ids, pl.BackupPlanId)
			}
		}
		if out.NextToken == "" {
			return ids, nil
		}
		token = out.NextToken
	}
}

// ---- guardduty (region-scoped, singleton detector, synchronous) -----------

// The detector is a singleton per account+region addressed by an AWS-assigned id;
// ListDetectors + GetDetector's ownership tags are the whole handle (exactly bedrock).
func (d *Driver) reconcileGuardDuty(capability, environment string, generation int, pid string) provider.ReconcileResult {
	if pid != "" {
		if r, ok := d.rc7GuardDutyByPID(capability, environment, pid); ok {
			return r
		}
	}
	region := d.Region
	if region == "" {
		return regionlessReconcile("guardduty")
	}
	return rc7Scan("guardduty detector",
		func() ([]string, error) { return d.listDetectorIDs(region) },
		func(id string) rc7Read {
			det, found, rerr := d.getDetector(region, id)
			if rerr != nil {
				return rc7Read{err: rerr}
			}
			if !found {
				return rc7Read{}
			}
			return rc7Read{
				owned: groundholdTagsMatch(det.Tags, capability, environment),
				ready: true, pid: guardDutyProviderID(region, id)}
		})
}

func (d *Driver) rc7GuardDutyByPID(capability, environment, pid string) (provider.ReconcileResult, bool) {
	region, id, err := splitGuardDutyProviderID(pid)
	if err != nil {
		return provider.ReconcileResult{}, false
	}
	det, found, rerr := d.getDetector(region, id)
	if rerr == nil && found && groundholdTagsMatch(det.Tags, capability, environment) {
		return provider.ReconcileResult{Status: "succeeded", ProviderID: guardDutyProviderID(region, id)}, true
	}
	return provider.ReconcileResult{}, false
}

// ---- eks-podidentity (region-scoped, deterministic identity) --------------

// The associationId is server-generated, but the providerId
// (eks-podidentity:region:cluster/namespace/serviceAccount) is DETERMINISTIC — the
// receipt carries it, so the reconcile concludes AUTHORITATIVELY from it: resolve the
// association for our ns+sa, then read its ownership tags. No cluster scan is needed
// when the pid is present. Without a pid, fall back to scanning every cluster.
func (d *Driver) reconcileEKSPodIdentity(capability, environment string, generation int, pid string) provider.ReconcileResult {
	if pid != "" {
		return d.rc7PodIdentityConclude(capability, environment, pid)
	}
	if d.Region == "" {
		return regionlessReconcile("eks-podidentity")
	}
	return d.rc7PodIdentityScan(capability, environment, d.Region)
}

func (d *Driver) rc7PodIdentityConclude(capability, environment, pid string) provider.ReconcileResult {
	region, cluster, namespace, serviceAccount, err := splitEKSPodIdentityProviderID(pid)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "pod-identity providerId invalid — cannot conclude the pending create: " + err.Error()}
	}
	id, found, rerr := d.resolvePodIdentityID(region, cluster, namespace, serviceAccount)
	if rerr != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "the pod-identity list gave no answer — cannot conclude the pending create: " + rerr.Error()}
	}
	if !found {
		return provider.ReconcileResult{Status: "failed",
			Reason: "no pod-identity association for our serviceAccount — the create did not land"}
	}
	a, f2, r2 := d.describePodIdentity(region, cluster, id)
	if r2 != nil {
		return provider.ReconcileResult{Status: "unknown",
			Reason: "the pod-identity association read gave no answer — cannot conclude the pending create: " + r2.Error()}
	}
	if !f2 {
		return provider.ReconcileResult{Status: "failed",
			Reason: "the pod-identity association vanished on read — the create did not land"}
	}
	if groundholdTagsMatch(a.Tags, capability, environment) {
		return provider.ReconcileResult{Status: "succeeded",
			ProviderID: eksPodIdentityProviderID(region, cluster, namespace, serviceAccount)}
	}
	return provider.ReconcileResult{Status: "failed",
		Reason: "an association for our serviceAccount exists but is not ours — the create did not land as ours"}
}

// rc7PodIdentityScan is the no-providerId fallback: enumerate clusters + associations
// and match ownership tags (the discover shape). Any read that gives no answer is unknown.
func (d *Driver) rc7PodIdentityScan(capability, environment, region string) provider.ReconcileResult {
	const listOp = "ListClusters"
	st, resp, err := d.eksDo("GET", region, "/clusters", nil)
	if err != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
			"pending pod-identity create: " + readTransport(listOp, err).Error()}
	}
	if st != http.StatusOK {
		return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
			"pending pod-identity create: " + readHTTP(listOp, st, eksErr(resp)).Error()}
	}
	var cl struct {
		Clusters []string `json:"clusters"`
	}
	if json.Unmarshal(resp, &cl) != nil {
		return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
			"pending pod-identity create: " + readBody(listOp, st).Error()}
	}
	for _, cluster := range cl.Clusters {
		const assocOp = "ListPodIdentityAssociations"
		st, resp, err := d.eksDo("GET", region, "/clusters/"+cluster+"/pod-identity-associations", nil)
		if err != nil {
			return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
				"pending create: " + readTransport(assocOp, err).Error()}
		}
		if st != http.StatusOK {
			return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
				"pending create: " + readHTTP(assocOp, st, eksErr(resp)).Error()}
		}
		var out struct {
			Associations []eksPodIdentity `json:"associations"`
		}
		if json.Unmarshal(resp, &out) != nil {
			return provider.ReconcileResult{Status: "unknown", Reason: "cannot conclude the " +
				"pending create: " + readBody(assocOp, st).Error()}
		}
		for _, a := range out.Associations {
			det, f2, r2 := d.describePodIdentity(region, cluster, a.AssociationID)
			if r2 != nil {
				return provider.ReconcileResult{Status: "unknown",
					Reason: "a pod-identity association read gave no answer — cannot conclude the pending create: " + r2.Error()}
			}
			if f2 && groundholdTagsMatch(det.Tags, capability, environment) {
				return provider.ReconcileResult{Status: "succeeded",
					ProviderID: eksPodIdentityProviderID(region, cluster, a.Namespace, a.ServiceAccount)}
			}
		}
	}
	return provider.ReconcileResult{Status: "failed",
		Reason: "no pod-identity association carries our ownership tags — the create did not land"}
}
