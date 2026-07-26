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

// s3ControlBase is the account-level S3 Control endpoint. The endpoint prefix is
// "s3-control" but SigV4 signs it under service name "s3" (the s3control service
// model's signingName) — signing it as "s3-control" yields a 403 that masquerades
// as permission-denied.
func (d *Driver) s3ControlBase(region string) string {
	if d.S3ControlBaseURL != "" {
		return d.S3ControlBaseURL
	}
	return "https://s3-control." + region + ".amazonaws.com"
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
	url := d.s3ControlBase(region) + "/v20180820/configuration/publicAccessBlock"
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
	if err != nil {
		return false, readTransport(op, err)
	}
	if st == 200 {
		var c struct {
			RestrictPublicBuckets string `xml:"RestrictPublicBuckets"`
		}
		if xml.Unmarshal(body, &c) != nil {
			return false, readBody(op, st)
		}
		return c.RestrictPublicBuckets == "true", nil
	}
	if awsErrCode(body) == "NoSuchPublicAccessBlockConfiguration" {
		return false, nil // definitively not set
	}
	return false, readHTTP(op, st, awsErrCode(body))
}
