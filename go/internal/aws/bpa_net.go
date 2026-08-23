package aws

import "encoding/xml"

// bpa_net.go folds the EFFECTIVE S3 Block Public Access into observeS3's
// publicExposure verdict (D240, AWS twin of the GCS effective-org-policy fix
// D238). GetBucketPolicyStatus.IsPublic is a static verdict on the BUCKET POLICY
// document alone — it does not fold in Block Public Access at EITHER the bucket or
// the account level. So a public bucket policy under an effective
// RestrictPublicBuckets=true reads IsPublic=true though it is effectively private
// (a false positive on the privacy constraint — the safe over-reporting direction,
// but imprecise). This resolves the EFFECTIVE RestrictPublicBuckets (bucket-level
// OR account-level, the most-restrictive combination AWS applies) and observeS3
// downgrades publicExposure to false ONLY on positive enforcement evidence; an
// unreadable BPA never fabricates "private".

// s3ControlBase is the account-level S3 Control endpoint. Two traps live here and
// both cost a read that looks like something else.
//
// SigV4 signs it under service name "s3" (the s3control model's signingName), not
// "s3-control" — signing it as "s3-control" yields a 403 that masquerades as
// permission-denied.
//
// D1230: and the host carries the ACCOUNT ID as a DNS PREFIX. There is no
// `s3-control.<region>.amazonaws.com` — the name does not resolve, in any region,
// which is what this returned since D240. Every account-level Block Public Access
// read therefore failed against real AWS with a DNS error, and nothing noticed: the
// read is lazy (only when a policy already reads public), its failure keeps the
// CONSERVATIVE public verdict, and every test overrides S3ControlBaseURL, so the
// hostname was never once exercised. Found by reading a diagnostic that named its
// own cause in a field run — the message worked even though the code did not.
func (d *Driver) s3ControlBase(region, account string) string {
	if d.S3ControlBaseURL != "" {
		return d.S3ControlBaseURL
	}
	return "https://" + account + ".s3-control." + region + ".amazonaws.com"
}

// effectiveRestrictPublicBuckets reports whether RestrictPublicBuckets is
// effectively enforced for a bucket. restricted=true requires POSITIVE evidence
// from either the bucket-level or the account-level BPA; a non-nil error names
// the read that could not be resolved when no positive evidence was found, so the
// caller stays conservative (keeps the public verdict — never a fabricated
// private). Bucket-level is tried first and short-circuits on true (no account
// call, no account-id needed).
func (d *Driver) effectiveRestrictPublicBuckets(region, bucket string) (restricted bool, err error) {
	bRPB, bErr := d.bucketRPB(region, bucket)
	if bErr == nil && bRPB {
		return true, nil // bucket-level positively restricts — short-circuit, no account call
	}
	aRPB, aErr := d.accountRPB(region)
	if aErr == nil && aRPB {
		return true, nil // account-level positively restricts
	}
	if bErr == nil && aErr == nil {
		return false, nil // both definitively NOT restricted
	}
	if bErr != nil {
		return false, bErr // a needed read gave no answer; nothing positively restricts
	}
	return false, aErr
}

// bucketRPB reads the bucket-level PublicAccessBlock (s3:GetBucketPublicAccessBlock).
func (d *Driver) bucketRPB(region, bucket string) (restricted bool, err error) {
	st, body, cerr := d.s3Do("GET", region, bucket, "/?publicAccessBlock", "")
	return parseRPB("GetBucketPublicAccessBlock", st, body, cerr)
}

// accountRPB reads the account-level PublicAccessBlock (s3:GetAccountPublicAccessBlock
// via the s3-control endpoint). The account id comes from the acting identity
// (cached STS); a cross-account bucket makes this read effectively unreadable, so
// the caller stays conservative.
func (d *Driver) accountRPB(region string) (restricted bool, err error) {
	const op = "GetAccountPublicAccessBlock"
	acct, aerr := d.resolveAccount()
	if aerr != nil {
		return false, &awsReadError{Op: op, Cause: "transport",
			Detail: "cannot resolve the acting account: " + aerr.Error()}
	}
	if acct == "" {
		return false, &awsReadError{Op: op, Cause: "transport",
			Detail: "the acting identity carries no account id"}
	}
	url := d.s3ControlBase(region, acct) + "/v20180820/configuration/publicAccessBlock"
	st, body, cerr := d.doSigned("GET", url, "s3", region,
		map[string]string{"x-amz-account-id": acct}, nil)
	return parseRPB(op, st, body, cerr)
}

// parseRPB maps a GetPublicAccessBlock response to (restricted, why-not). A 200
// parses RestrictPublicBuckets (an absent element is false). A 404 carrying
// NoSuchPublicAccessBlockConfiguration is a DEFINITIVE answer (not set = not
// restricted) — matched on the error code, never a bare 404 (a wrong-account /
// NoSuchBucket 404 keeps its error). Everything else names its cause.
func parseRPB(op string, st int, body []byte, err error) (restricted bool, rerr error) {
	return parsePABFlag(op, st, body, err, func(c pabConfig) string { return c.RestrictPublicBuckets })
}

// pabConfig is the PublicAccessBlockConfiguration this driver reads. The two flags
// answer DIFFERENT questions: RestrictPublicBuckets neutralizes a public POLICY,
// IgnorePublicAcls neutralizes public OBJECT ACLs — the one anonymous path a
// bucket-scope read otherwise cannot close (D1229).
type pabConfig struct {
	RestrictPublicBuckets string `xml:"RestrictPublicBuckets"`
	IgnorePublicAcls      string `xml:"IgnorePublicAcls"`
}

// parsePABFlag is the shared ladder for ONE flag of the PublicAccessBlock. One
// implementation on purpose: a second copy of "a NoSuchPublicAccessBlockConfiguration
// 404 is a DEFINITIVE not-set" is a second place for that judgement to drift.
func parsePABFlag(op string, st int, body []byte, err error,
	pick func(pabConfig) string) (enforced bool, rerr error) {
	if err != nil {
		return false, readTransport(op, err)
	}
	if st == 200 {
		var c pabConfig
		if xml.Unmarshal(body, &c) != nil {
			return false, readBody(op, st)
		}
		return pick(c) == "true", nil
	}
	if awsErrCode(body) == "NoSuchPublicAccessBlockConfiguration" {
		return false, nil // definitively not set
	}
	return false, readHTTP(op, st, awsErrCode(body))
}

// cachedFlag memoizes one boolean provider answer, INCLUDING the failure. Re-asking
// after a 403 would burn a request per bucket to be denied identically each time.
type cachedFlag struct {
	done bool
	val  bool
	err  error
}

// effectiveIgnorePublicAcls reports whether public OBJECT ACLs are neutralized for a
// bucket. D1229, and note the ordering: ACCOUNT level first, cached for the run.
//
// That inversion (effectiveRestrictPublicBuckets tries the bucket first) is the whole
// cost argument. An account that enforces IgnorePublicAcls closes the residual for
// EVERY bucket after one request per run; only an account that does not enforce it
// pays a request per bucket, and only for buckets that already measured non-public.
// Bucket-first would have cost a request per bucket unconditionally.
//
// Conservatism is unchanged from its RestrictPublicBuckets twin: enforced=true needs
// POSITIVE evidence, and an unresolved read returns the error so the caller keeps the
// full caveat rather than a comfortable "closed".
func (d *Driver) effectiveIgnorePublicAcls(region, bucket string) (enforced bool, err error) {
	aIPA, aErr := d.accountIPA(region)
	if aErr == nil && aIPA {
		return true, nil
	}
	bIPA, bErr := d.bucketIPA(region, bucket)
	if bErr == nil && bIPA {
		return true, nil
	}
	if aErr == nil && bErr == nil {
		return false, nil // both definitively NOT enforcing
	}
	if bErr != nil {
		return false, bErr
	}
	return false, aErr
}

func (d *Driver) bucketIPA(region, bucket string) (enforced bool, err error) {
	st, body, cerr := d.s3Do("GET", region, bucket, "/?publicAccessBlock", "")
	return parsePABFlag("GetBucketPublicAccessBlock", st, body, cerr,
		func(c pabConfig) string { return c.IgnorePublicAcls })
}

// accountIPA is the account-level read, memoized for the run.
func (d *Driver) accountIPA(region string) (enforced bool, err error) {
	if d.acctIPA == nil {
		d.acctIPA = &cachedFlag{}
	}
	if d.acctIPA.done {
		return d.acctIPA.val, d.acctIPA.err
	}
	v, e := d.accountIPAUncached(region)
	*d.acctIPA = cachedFlag{done: true, val: v, err: e}
	return v, e
}

func (d *Driver) accountIPAUncached(region string) (enforced bool, err error) {
	const op = "GetAccountPublicAccessBlock"
	acct, aerr := d.resolveAccount()
	if aerr != nil {
		return false, &awsReadError{Op: op, Cause: "transport",
			Detail: "cannot resolve the acting account: " + aerr.Error()}
	}
	if acct == "" {
		return false, &awsReadError{Op: op, Cause: "transport",
			Detail: "the acting identity carries no account id"}
	}
	url := d.s3ControlBase(region, acct) + "/v20180820/configuration/publicAccessBlock"
	st, body, cerr := d.doSigned("GET", url, "s3", region,
		map[string]string{"x-amz-account-id": acct}, nil)
	return parsePABFlag(op, st, body, cerr,
		func(c pabConfig) string { return c.IgnorePublicAcls })
}
