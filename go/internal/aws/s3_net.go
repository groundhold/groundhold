// S3 network shell (D86): the thin, SigV4-signed half of the AWS storage.object
// driver. Multi-step create (bucket -> tags -> public-access-block -> optional
// versioning -> optional public policy), the providerId attached once the
// bucket exists so a partial is failed/unknown WITH the pid, never succeeded.
// Ownership is TAGS (the AWS analogue of GCS labels / VPC markers). The global-
// namespace squat concern (D82) is handled by AWS's own 409 signal:
// BucketAlreadyOwnedByYou (ours) vs BucketAlreadyExists (a foreign account) —
// a direct answer GCS's API did not give.
package aws

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

func (d *Driver) s3Base(region, bucket string) string {
	if d.S3BaseURL != "" {
		return d.S3BaseURL + "/" + bucket // path-style for tests
	}
	return "https://" + bucket + ".s3." + region + ".amazonaws.com"
}

func s3ProviderID(region, bucket string) string {
	return "s3:" + region + ":" + bucket
}

// splitS3ProviderID validates components before use (D73).
func splitS3ProviderID(providerID string) (region, bucket string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "s3" {
		return "", "", fmt.Errorf("providerId %q is not s3:region:bucket", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !bucketNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId bucket %q is not a valid bucket name", parts[2])
	}
	return parts[1], parts[2], nil
}

// s3Do signs (with the bucket's region) and sends a request to a bucket
// sub-resource. Region-explicit so the SigV4 scope matches the endpoint.
// Body-bearing config PUTs (tagging, public-access-block, versioning) REQUIRE a
// body checksum — Content-MD5 or x-amz-checksum-* — and we send the SHA-256 one,
// field-verified live (PutObjectLockConfiguration + PutBucketTagging both accept it).
func (d *Driver) s3Do(method, region, bucket, path, body string) (int, []byte, error) {
	return d.s3DoH(method, region, bucket, path, nil, body)
}

// s3DoH is s3Do with extra signed request headers — the create-time Object Lock
// enable (x-amz-bucket-object-lock-enabled) is a header, not a body, so it must
// ride the CreateBucket call itself (SigV4 signs whatever we pass here).
func (d *Driver) s3DoH(method, region, bucket, path string, extra map[string]string, body string) (int, []byte, error) {
	var b []byte
	h := map[string]string{}
	for k, v := range extra {
		h[k] = v
	}
	if body != "" {
		b = []byte(body)
		h["Content-Type"] = "application/xml"
		// SHA-256 body checksum, not the legacy Content-MD5. AWS accepts
		// x-amz-checksum-sha256 in place of Content-MD5 on the body PUTs that once
		// required it — field-verified live on PutObjectLockConfiguration (200) and
		// PutBucketTagging (204) — and MD5 raised a CodeQL weak-hash alert on the
		// public repo (the body is an integrity checksum, never a secret, but the
		// modern header is the honest fix). doSigned signs whatever we pass here.
		sum := sha256.Sum256(b)
		h["x-amz-checksum-sha256"] = base64.StdEncoding.EncodeToString(sum[:])
	}
	return d.doSigned(method, d.s3Base(region, bucket)+path, "s3", region, h, b)
}

// awsErrCode pulls the <Code> out of an S3 XML error body.
func awsErrCode(body []byte) string {
	var e struct {
		Code string `xml:"Code"`
	}
	_ = xml.Unmarshal(body, &e)
	return e.Code
}

// createS3 runs the ordered plan. Bucket create is synchronous. A 409 continues
// ONLY on BucketAlreadyOwnedByYou (ours) — BucketAlreadyExists is a foreign
// account in the global namespace and is refused (the D82 concern, answered by
// AWS directly).
func (d *Driver) createS3(account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildS3Requests(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	bucket := plan.Bucket
	pid := s3ProviderID(plan.Region, bucket)

	// ---- create bucket ---- (carries the create-time Object Lock enable header
	// when the contract asks for WORM; born object-lock-enabled or not at all).
	status, body, err := d.s3DoH(plan.Create.Method, plan.Region, bucket, plan.Create.Path, plan.Create.Headers, plan.Create.Body)
	if err != nil {
		// the name is deterministic — carry the pid so reconcile keeps the handle
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create outcome unknown: %v", err)}
	}
	switch {
	case status == http.StatusConflict || status == http.StatusForbidden:
		code := awsErrCode(body)
		switch code {
		case "BucketAlreadyOwnedByYou":
			// same account (AWS confirmed). Continue ONLY if the bucket already
			// carries OUR ownership tags — an untagged or foreign-tagged same-name
			// bucket is NOT provably ours (the strict ownership invariant), so we
			// refuse to auto-adopt/configure/publicize it. An untagged bucket is
			// almost always our own partial-create leftover, but the driver has no
			// ledger proof of that, so it surfaces as unknown for reconcile rather
			// than being silently taken over (adversarial review).
			existing, terr := d.s3Tags(plan.Region, bucket)
			if terr != nil {
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "name conflict, existing bucket tags gave no answer — reconcile: " + terr.Error()}
			}
			if !groundholdTagsMatch(existing, capability, environment) {
				if existing["groundhold-capability"] == "" {
					return provider.CreateResult{ProviderID: pid, Status: "unknown",
						Reason: "a same-account bucket with this name exists but is UNTAGGED " +
							"— if it is a groundhold leftover, remove it or adopt it explicitly; " +
							"refusing to silently take over an unowned bucket"}
				}
				return provider.CreateResult{Status: "failed",
					Reason: "a bucket with this name exists in our account tagged for " +
						"a different groundhold capability — refusing"}
			}
			// ours (tags match) — fall through to re-assert config idempotently.
		case "BucketAlreadyExists":
			return provider.CreateResult{Status: "failed",
				Reason: "bucket name is taken by ANOTHER AWS account (global " +
					"namespace) — refusing a cross-account collision (D82)"}
		default:
			// D237: a live 403 with no S3 conflict code is a permission denial —
			// unknown (the bucket name is deterministic, carry the pid), never a
			// terminal failed. An unrecognized 409 stays terminal below.
			if r := provider.MutationResult(status, code, nil, pid, "create"); r != nil {
				return *r
			}
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("create: HTTP %d (%s): %s", status, code, mutDetail(body))}
		}
	case status >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create: HTTP %d (server error — may have landed): %s", status, mutDetail(body))}
	case status >= 400:
		// D237: a throttle (429), service-unavailable, or a live 403 is unknown
		// (the bucket name is deterministic, so carry the pid), never a terminal
		// failed; only a clean 4xx refusal fails below.
		if r := provider.MutationResult(status, awsErrCode(body), nil, pid, "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("create: HTTP %d (%s): %s", status, awsErrCode(body), mutDetail(body))}
	case status < 200 || status >= 300:
		// a 3xx (e.g. 301 PermanentRedirect for a wrong-region host) is NOT a
		// created bucket — never fall through to the config steps as success.
		return provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("create: unexpected HTTP %d — reconcile", status)}
	}

	// ---- tag (ownership) ----
	if r := d.s3Step(plan.Region, bucket, plan.Tagging, pid, "tagging"); r != nil {
		return *r
	}
	// ---- public-access-block ----
	if r := d.s3Step(plan.Region, bucket, plan.PublicAccessBlk, pid, "public-access-block"); r != nil {
		return *r
	}
	// ---- versioning (optional) ----
	if plan.Versioning != nil {
		if r := d.s3Step(plan.Region, bucket, *plan.Versioning, pid, "versioning"); r != nil {
			return *r
		}
	}
	// ---- Object Lock default retention (WORM; after versioning, before CRR) ----
	// the bucket was already born object-lock-enabled via the create header; this
	// sets the DefaultRetention (mode + days) on it. Ordered before replication:
	// both presuppose versioning, and the WORM guarantee should be in place before
	// objects begin replicating.
	if plan.ObjectLock != nil {
		if r := d.s3Step(plan.Region, bucket, *plan.ObjectLock, pid, "object-lock"); r != nil {
			return *r
		}
	}
	// ---- cross-region replication (optional; CRR requires versioning first) ----
	if plan.Replication != nil {
		if r := d.s3Step(plan.Region, bucket, *plan.Replication, pid, "replication"); r != nil {
			return *r
		}
	}
	// ---- lifecycle expiration (retention.maximum, optional) ----
	if plan.Lifecycle != nil {
		if r := d.s3Step(plan.Region, bucket, *plan.Lifecycle, pid, "lifecycle"); r != nil {
			return *r
		}
	}
	// ---- default SSE-KMS encryption (customerManagedKeys, optional) ----
	if plan.Encryption != nil {
		if r := d.s3Step(plan.Region, bucket, *plan.Encryption, pid, "encryption"); r != nil {
			return *r
		}
	}
	// ---- public policy (second exposure gate) ----
	if plan.Public {
		st, pb, e := d.s3Do("PUT", plan.Region, bucket, "/?policy", PublicReadPolicy(bucket))
		if e != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "bucket created but public policy outcome unknown — reconcile"}
		}
		if st >= 500 {
			// a 5xx can front a mutation that landed — unknown, not failed (D29)
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("bucket created; public policy HTTP %d (server error) — reconcile", st)}
		}
		if st < 200 || st >= 300 {
			// the bucket exists but is NOT public as the contract requires
			return provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("bucket created but public policy failed "+
					"(NOT public): HTTP %d (%s): %s", st, awsErrCode(pb), mutDetail(pb))}
		}
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// s3Step runs one config PUT; nil = ok, non-nil = a terminal result WITH pid.
func (d *Driver) s3Step(region, bucket string, req s3Req, pid, what string) *provider.CreateResult {
	st, body, err := d.s3Do(req.Method, region, bucket, req.Path, req.Body)
	if err != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("bucket created; %s outcome unknown — reconcile", what)}
		return &r
	}
	if st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("bucket created; %s HTTP %d (server error) — reconcile", what, st)}
		return &r
	}
	if st < 200 || st >= 300 { // 3xx (wrong-region redirect) or 4xx
		// D237: a throttle/503/live-403 on a config step is unknown (bucket
		// landed — reconcile), never a terminal failed.
		if r := provider.MutationResult(st, awsErrCode(body), nil, pid, "bucket created; "+what); r != nil {
			return r
		}
		r := provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("bucket created but %s failed: HTTP %d (%s)", what, st, awsErrCode(body))}
		return &r
	}
	return nil
}

// s3Tags reads the bucket's tag set. readable is false on a transport/HTTP
// error (three-valued — an unreadable bucket is never "no tags"). A bucket with
// no tag set at all returns an empty map + readable true (S3 answers 404
// NoSuchTagSet, which we treat as "readable, empty").
// s3ReadWhy renders the cause of a failed observe-side S3 read as one bounded
// line — the same vocabulary as awsReadError, for the inline
// `if st, body, err := d.s3Do(...); err == nil && st == 200 { } else { }` blocks
// that cannot return an error (a partial observation is a fact, not a failure).
func s3ReadWhy(op string, st int, body []byte, err error) string {
	if err != nil {
		return readTransport(op, err).Error()
	}
	return readHTTP(op, st, awsErrCode(body)).Error()
}

func (d *Driver) s3Tags(region, bucket string) (tags map[string]string, err error) {
	const op = "GetBucketTagging"
	st, body, cerr := d.s3Do("GET", region, bucket, "/?tagging", "")
	if cerr != nil {
		return nil, readTransport(op, cerr)
	}
	if st == http.StatusNotFound || awsErrCode(body) == "NoSuchTagSet" {
		return map[string]string{}, nil
	}
	if st != http.StatusOK {
		return nil, readHTTP(op, st, awsErrCode(body))
	}
	m, perr := parseS3Tags(body)
	if perr != nil {
		return nil, readBody(op, st) // a garbled 200 is unreadable, never "empty tags"
	}
	return m, nil
}

func parseS3Tags(body []byte) (map[string]string, error) {
	var t struct {
		Tags []struct {
			Key   string `xml:"Key"`
			Value string `xml:"Value"`
		} `xml:"TagSet>Tag"`
	}
	if err := xml.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	m := map[string]string{}
	for _, tag := range t.Tags {
		m[tag.Key] = tag.Value
	}
	return m, nil
}

// s3DestinationRegion MEASURES the region a replica lands in. The replication
// rule names the destination as an ARN (arn:aws:s3:::<bucket>) which carries no
// region — that is exactly why residency must be measured, not read off the
// rule. It extracts the bucket name and calls GetBucketLocation on it (served
// from us-east-1 regardless of the bucket's own region). diag may be non-empty
// even when ok=true (an advisory, e.g. the legacy "EU" constraint).
func (d *Driver) s3DestinationRegion(destARN string) (region string, ok bool, diag string) {
	m := s3BucketARNOK.FindStringSubmatch(destARN)
	if m == nil {
		return "", false, fmt.Sprintf(
			"replication.destinationRegion not observed: destination %q is not a bucket ARN", destARN)
	}
	st, body, err := d.s3Do("GET", "us-east-1", m[1], "/?location", "")
	if err != nil || st != http.StatusOK {
		return "", false, "replication.destinationRegion not observed: " +
			s3ReadWhy("GetBucketLocation", st, body, err) + " on the destination"
	}
	var loc struct {
		Value string `xml:",chardata"`
	}
	if xml.Unmarshal(body, &loc) != nil {
		return "", false, "replication.destinationRegion not observed: GetBucketLocation unparseable"
	}
	lc := strings.TrimSpace(loc.Value)
	switch {
	case lc == "":
		return "us-east-1", true, "" // an empty LocationConstraint IS us-east-1
	case lc == "EU":
		// legacy alias for eu-west-1: deterministic, but flag the ambiguous form
		return "eu-west-1", true,
			`replication.destinationRegion: destination reports the legacy "EU" LocationConstraint, mapped to eu-west-1`
	case regionOK.MatchString(lc):
		return lc, true, ""
	default:
		return "", false, fmt.Sprintf(
			"replication.destinationRegion not observed: GetBucketLocation returned unrecognized constraint %q", lc)
	}
}

// observeS3 reverse-maps a live bucket.
func (d *Driver) observeS3(capability, providerID string) ([]provider.Observation, []string, error) {
	region, bucket, err := splitS3ProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	// F-LC3 (D520): does the bucket EXIST? This read never asked. It went straight
	// to emitting region/managed/encryption/durability — four facts derived from the
	// providerId string and a constant, two of them marked "measured" — so a DELETED
	// bucket observed as a healthy one and converge agreed with it. That is worse
	// than the silence D513 found: silence plans nothing, this fabricates a world.
	if st, _, err := d.s3Do("HEAD", region, bucket, "", ""); err == nil && st == http.StatusNotFound {
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"bucket not found — bound resource is gone (will re-create)"}, nil
	}
	var obs []provider.Observation
	var diags []string
	obs = append(obs,
		// Present (or unreadable — an error is never an absence): clear the marker.
		provider.Observation{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		provider.Observation{Path: "location.region", Value: region, Derivation: "measured"},
		provider.Observation{Path: "service.managed", Value: true, Derivation: "measured"},
		// encryption.atRest is emitted BELOW, from the GetBucketEncryption read this
		// observer already makes (D729). It used to be asserted here unconditionally as
		// config-intent — true, because S3 encrypts every object, but a statement about
		// the SERVICE rather than a reading of this bucket. After D722 that meant a
		// hard constraint asking for provider-api evidence on the three buckets that
		// actually hold data could never be satisfied, while the same attribute was
		// MEASURED for queues, topics and secrets. A field report named that spread as
		// the worst possible one, and it was: the call was already being made.
		// F16-C: an S3 bucket is regional (multi-AZ) by construction — single-zone is
		// refused at create. Emitting it lets a bound-bucket reconcile confirm the
		// declared durability instead of refusing "durability.class: no observation".
		provider.Observation{Path: "durability.class", Value: "regional", Derivation: "config-intent"},
	)
	// versioning
	if st, body, err := d.s3Do("GET", region, bucket, "/?versioning", ""); err == nil && st == http.StatusOK {
		var v struct {
			Status string `xml:"Status"`
		}
		if xml.Unmarshal(body, &v) != nil {
			diags = append(diags, "versioning.enabled not observed: GetBucketVersioning unparseable")
		} else {
			obs = append(obs, provider.Observation{Path: "versioning.enabled",
				Value: v.Status == "Enabled", Derivation: "measured"})
		}
	} else {
		diags = append(diags, "versioning.enabled not observed: "+s3ReadWhy("GetBucketVersioning", st, body, err))
	}
	// retention.minimum / retention.locked: S3 Object Lock DefaultRetention. Days
	// reverse-map to a duration floor, Mode==COMPLIANCE reverse-maps to the WORM
	// lock (GOVERNANCE is a soft, bypassable floor -> locked=false). A 404
	// ObjectLockConfigurationNotFoundError means the bucket is not object-lock-
	// enabled — the paths are simply absent, not an error.
	if st, body, err := d.s3Do("GET", region, bucket, "/?object-lock", ""); err == nil && st == http.StatusOK {
		var olc struct {
			Enabled string `xml:"ObjectLockEnabled"`
			Rule    struct {
				DefaultRetention struct {
					Mode  string `xml:"Mode"`
					Days  *int   `xml:"Days"`
					Years *int   `xml:"Years"`
				} `xml:"DefaultRetention"`
			} `xml:"Rule"`
		}
		if xml.Unmarshal(body, &olc) != nil {
			diags = append(diags, "retention.minimum not observed: GetObjectLockConfiguration unparseable")
		} else if olc.Enabled == "Enabled" {
			dr := olc.Rule.DefaultRetention
			switch {
			case dr.Days != nil:
				obs = append(obs, provider.Observation{Path: "retention.minimum",
					Value: fmt.Sprintf("%dd", *dr.Days), Derivation: "measured"})
			case dr.Years != nil:
				// the driver only ever writes Days; a Years default is honored by
				// reverse-mapping at 365 days/year and flagging the conversion.
				obs = append(obs, provider.Observation{Path: "retention.minimum",
					Value: fmt.Sprintf("%dd", *dr.Years*365), Derivation: "measured"})
				diags = append(diags, "retention.minimum: Object Lock default retention is in Years, mapped at 365 days/year")
			}
			if dr.Mode != "" {
				obs = append(obs, provider.Observation{Path: "retention.locked",
					Value: dr.Mode == "COMPLIANCE", Derivation: "measured"})
			}
		}
	} else if err == nil && (st == http.StatusNotFound || awsErrCode(body) == "ObjectLockConfigurationNotFoundError") {
		// D1041: no Object Lock is an AUTHORITATIVE read (a 404/NotFoundError, not a read
		// failure) — the bucket is freely mutable, so it is definitively NOT
		// COMPLIANCE-locked: a MEASURED retention.locked=false, not an absence. Omitting
		// it let a `retention.locked: true` candidate be adopted over an unlocked bucket,
		// and Object Lock is enable-at-creation-only so no later converge could make the
		// claim true — a PERMANENT false WORM assurance. retention.minimum stays absent
		// (there genuinely is no minimum to measure).
		obs = append(obs, provider.Observation{Path: "retention.locked",
			Value: false, Derivation: "measured"})
	} else {
		diags = append(diags, "retention.minimum not observed: "+s3ReadWhy("GetObjectLockConfiguration", st, body, err))
	}
	// retention.maximum: a lifecycle Expiration rule (whole days). A 404
	// NoSuchLifecycleConfiguration means no expiry — the path is simply absent.
	if st, body, err := d.s3Do("GET", region, bucket, "/?lifecycle", ""); err == nil && st == http.StatusOK {
		var lc struct {
			Rules []struct {
				Status     string `xml:"Status"`
				Expiration struct {
					Days *int `xml:"Days"`
				} `xml:"Expiration"`
			} `xml:"Rule"`
		}
		if xml.Unmarshal(body, &lc) != nil {
			diags = append(diags, "retention.maximum not observed: GetBucketLifecycle unparseable")
		} else {
			for _, r := range lc.Rules {
				if r.Status == "Enabled" && r.Expiration.Days != nil {
					obs = append(obs, provider.Observation{Path: "retention.maximum",
						Value: fmt.Sprintf("%dd", *r.Expiration.Days), Derivation: "measured"})
					break
				}
			}
		}
	} else if err == nil && (st == http.StatusNotFound || awsErrCode(body) == "NoSuchLifecycleConfiguration") {
		// no lifecycle configured — retention.maximum simply absent, not an error
	} else {
		diags = append(diags, "retention.maximum not observed: "+s3ReadWhy("GetBucketLifecycle", st, body, err))
	}
	// customerManagedKeys: default encryption is SSE-KMS with a customer key.
	// Unlike RDS this IS reliably distinguishable — SSE-S3 (AES256) is not a
	// CMEK, and aws:kms WITHOUT a KMSMasterKeyID is the aws/s3 default key (also
	// not customer-managed). Only aws:kms + a non-empty key id is a CMEK.
	if st, body, err := d.s3Do("GET", region, bucket, "/?encryption", ""); err == nil && st == http.StatusOK {
		var enc struct {
			Rules []struct {
				ByDefault struct {
					SSEAlgorithm   string `xml:"SSEAlgorithm"`
					KMSMasterKeyID string `xml:"KMSMasterKeyID"`
				} `xml:"ApplyServerSideEncryptionByDefault"`
			} `xml:"Rule"`
		}
		if xml.Unmarshal(body, &enc) != nil {
			diags = append(diags, "encryption.customerManagedKeys not observed: GetBucketEncryption unparseable")
		} else {
			cmek := false
			for _, r := range enc.Rules {
				// D985: a key id is not enough — the AWS-managed `aws/s3` key also
				// answers SSEAlgorithm=aws:kms with a key id, and it is NOT a customer
				// key. Exclude the managed alias, as every other AWS driver does
				// (isAWSManagedKMSKey), so an aws/s3-encrypted bucket does not report a
				// BYOK control it does not have.
				if r.ByDefault.SSEAlgorithm == "aws:kms" && r.ByDefault.KMSMasterKeyID != "" &&
					!isAWSManagedKMSKey(r.ByDefault.KMSMasterKeyID, "s3") {
					cmek = true
					break
				}
			}
			// The encryption config was read as part of this GET; whether a customer
			// key is in force is a MEASURED fact either way. Emit it unconditionally —
			// staying silent on cmek==false is a false-clean (D1003): a contract
			// demanding customerManagedKeys:true would pass VACUOUSLY over an
			// SSE-S3 / aws-managed-key bucket with nothing to contradict it.
			obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
				Value: cmek, Derivation: "measured"})
			// D729: a default-encryption rule IS this bucket's own configuration, read
			// from the provider. Same call, same response, one more fact.
			if len(enc.Rules) > 0 {
				obs = append(obs, provider.Observation{Path: "encryption.atRest",
					Value: true, Derivation: "measured"})
			} else {
				obs = append(obs, provider.Observation{Path: "encryption.atRest",
					Value: true, Derivation: "platform-invariant"})
				diags = append(diags, "encryption.atRest is config-intent: this bucket has "+
					"no default-encryption rule, so the value rests on S3 encrypting every "+
					"object as a platform guarantee rather than on anything read here")
			}
		}
	} else if err == nil && (st == http.StatusNotFound || awsErrCode(body) == "ServerSideEncryptionConfigurationNotFoundError") {
		// no explicit default encryption — SSE-S3 baseline, not a CMEK. This is a
		// definitive read (the API said the config does not exist), so cmek is a
		// MEASURED false, not an absence (D1003) — a customerManagedKeys:true
		// contract must be contradicted, never pass vacuously.
		obs = append(obs, provider.Observation{Path: "encryption.customerManagedKeys",
			Value: false, Derivation: "measured"})
		// D729: the platform guarantee still holds, and it is not a reading.
		obs = append(obs, provider.Observation{Path: "encryption.atRest",
			Value: true, Derivation: "platform-invariant"})
	} else {
		diags = append(diags, "encryption.customerManagedKeys not observed: "+s3ReadWhy("GetBucketEncryption", st, body, err))
		// The read failed, so nothing about encryption was witnessed. Withhold rather
		// than assert the platform guarantee as though it had been measured (D729).
		diags = append(diags, "encryption.atRest not observed: "+s3ReadWhy("GetBucketEncryption", st, body, err))
	}
	// replication (CRR): GetBucketReplication reverse-maps replication.enabled; a
	// 404 / ReplicationConfigurationNotFoundError is a definitive "no replica".
	// replication.destinationRegion is the SUBSTANCE of DR residency and is
	// MEASURED, never read off the rule: the rule holds a region-less
	// arn:aws:s3:::<bucket> ARN, so we GetBucketLocation on THAT bucket. Returning
	// a region from the operand on faith would make residency theatre.
	if st, body, err := d.s3Do("GET", region, bucket, "/?replication", ""); err == nil && st == http.StatusOK {
		var rc struct {
			Rules []struct {
				Status      string `xml:"Status"`
				Destination struct {
					Bucket string `xml:"Bucket"`
				} `xml:"Destination"`
			} `xml:"Rule"`
		}
		if xml.Unmarshal(body, &rc) != nil {
			diags = append(diags, "replication.enabled not observed: GetBucketReplication unparseable")
		} else {
			destARN := ""
			for _, r := range rc.Rules {
				if r.Status == "Enabled" {
					destARN = r.Destination.Bucket
					break
				}
			}
			obs = append(obs, provider.Observation{Path: "replication.enabled",
				Value: destARN != "", Derivation: "measured"})
			if destARN != "" {
				reg, ok, diag := d.s3DestinationRegion(destARN)
				if diag != "" {
					diags = append(diags, diag)
				}
				if ok {
					obs = append(obs, provider.Observation{Path: "replication.destinationRegion",
						Value: reg, Derivation: "measured"})
				}
			}
		}
	} else if err == nil && (st == http.StatusNotFound || awsErrCode(body) == "ReplicationConfigurationNotFoundError") {
		obs = append(obs, provider.Observation{Path: "replication.enabled",
			Value: false, Derivation: "measured"})
	} else {
		diags = append(diags, "replication.enabled not observed: "+s3ReadWhy("GetBucketReplication", st, body, err))
	}
	// publicExposure: policy-status IsPublic is AWS's verdict on the BUCKET POLICY
	// document's publicness — it folds in Block Public Access at NEITHER the bucket
	// nor the account level (D240). So a public policy under an effective
	// RestrictPublicBuckets is effectively private: when IsPublic=true we resolve
	// the effective BPA and downgrade to false ONLY on positive enforcement
	// evidence (bucket or account), keeping the conservative public verdict when
	// the BPA is unreadable (never-fabricate — a false negative is the dangerous
	// direction). A missing policy (404 / NoSuchBucketPolicy) means not public.
	st, body, perr := d.s3Do("GET", region, bucket, "/?policyStatus", "")
	switch {
	case perr == nil && st == http.StatusOK:
		var ps struct {
			IsPublic string `xml:"IsPublic"`
		}
		switch {
		case xml.Unmarshal(body, &ps) != nil:
			diags = append(diags, "network.publicExposure not observed: GetBucketPolicyStatus unparseable")
		case ps.IsPublic == "true":
			// D240: fold in the effective Block Public Access (lazy — only now that
			// the policy reads public).
			if restricted, bpaErr := d.effectiveRestrictPublicBuckets(region, bucket); restricted {
				obs = append(obs, provider.Observation{Path: "network.publicExposure",
					Value: false, Derivation: "measured"})
				diags = append(diags, "network.publicExposure: the bucket policy is public but "+
					"RestrictPublicBuckets is effectively enforced (bucket or account BPA) — the policy "+
					"is masked and would expose the bucket if BPA is lifted; remove it")
			} else {
				if bpaErr != nil {
					diags = append(diags, "network.publicExposure: effective RestrictPublicBuckets "+
						"gave no answer ("+bpaErr.Error()+") — reporting the public policy status "+
						"conservatively (account BPA may in fact restrict it; cross-account?)")
				}
				obs = append(obs, provider.Observation{Path: "network.publicExposure",
					Value: true, Derivation: "measured"})
			}
		default:
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: false, Derivation: "measured"})
		}
	case perr == nil && (st == http.StatusNotFound || awsErrCode(body) == "NoSuchBucketPolicy"):
		obs = append(obs, provider.Observation{Path: "network.publicExposure",
			Value: false, Derivation: "measured"})
	default:
		diags = append(diags, "network.publicExposure not observed: "+s3ReadWhy("GetBucketPolicyStatus", st, body, perr))
	}
	return obs, diags, nil
}

// classifyS3Change (D46): PURE — can this capability.storage.object transition
// be honored in place on an existing bucket? location.region and the durability
// class are baked into the bucket at birth (a change is a replacement, D48);
// versioning / lifecycle expiry / default encryption / public exposure are all
// re-assertable sub-resource PUTs, so they are mutable; anything S3 fixes at the
// platform (always-on at-rest encryption) or that is create-time-only (Object
// Lock) is unsupported — never a silent "mutable".
func classifyS3Change(path string, desired any, impl map[string]any) (string, string) {
	switch path {
	case "location.region":
		return "immutable", "an S3 bucket's region is fixed at creation — a change is a replacement"
	case "durability.class":
		// D833: a general-purpose S3 bucket is regional, always — observe emits exactly
		// that constant, and the builder's own refusal for "single-zone" explains why. So a
		// replacement reaches the SAME durability class the original had: the contract is
		// still unsatisfied and every object in the bucket is gone. That is the D823
		// contradiction on the resource where it costs most.
		return "unsupported", "a general-purpose S3 bucket is regional (multi-AZ) by " +
			"construction — no other durability class can be honored, and replacing the " +
			"bucket would produce another regional one (=single-zone and =multi-regional " +
			"cannot be honored)"
	case "versioning.enabled":
		return "mutable", ""
	case "retention.maximum":
		return "mutable", ""
	case "network.publicExposure":
		return "mutable", ""
	case "encryption.customerManagedKeys":
		return "mutable", ""
	case "replication.enabled", "replication.destinationRegion":
		// CRR config is a re-assertable PutBucketReplication (or a
		// DeleteBucketReplication when turned off). Changing destinationRegion means
		// pointing the SAME source bucket at a different replica bucket operand — one
		// PutBucketReplication, not a replacement of the source. Mutable in place.
		return "mutable", ""
	case "encryption.atRest":
		return "unsupported", "S3 always encrypts objects at rest (SSE-S3 baseline) — nothing to patch"
	case "retention.locked":
		// S3 Object Lock enablement is create-time-only (the CreateBucket header) and
		// irreversible, so this one is a genuine impossibility.
		return "immutable", "S3 Object Lock (WORM) is enabled at bucket birth and " +
			"irreversible — turning it off is a replacement"
	case "retention.minimum":
		// D824: this shared a case with retention.locked, and the comment above it already
		// said the quiet part — "The DefaultRetention days CAN be re-PUT on an already-
		// object-locked bucket". D821 read that as a deliberate policy choice and left it;
		// D822 settled that the test is not whether the prose is honest but what the verdict
		// makes the tool DO, and this one destroys a bucket and every object in it to
		// lengthen a retention floor that PutObjectLockConfiguration re-PUTs. A COMPLIANCE
		// floor still cannot be SHORTENED — which is a reason to refuse that direction, not
		// a reason to delete the data.
		return "unsupported", "in-place retention-floor change is not wired for S3 in this " +
			"slice — AWS does support raising it (PutObjectLockConfiguration re-PUTs the " +
			"DefaultRetention on an object-locked bucket; a COMPLIANCE floor cannot be " +
			"shortened), so this is a gap in groundhold rather than a reason to replace the " +
			"bucket and its objects"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no S3 in-place mapping for " + path
	}
}

// updateS3: ownership (tags) re-check FIRST, then re-issue ONLY the changed
// paths' sub-resource PUTs. The desired bodies are built from the SAME create
// builder (BuildS3Requests) so an update and a create speak identical XML; the
// "off" transitions the create path never emits (versioning Suspended, default
// SSE-S3, a removed public policy) are handled explicitly. account is a
// placeholder — the bucket comes from the pinned providerId, not the builder.
func (d *Driver) updateS3(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, bucket, err := splitS3ProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// ownership re-check BEFORE any mutation (D29/D87): an unreadable tag set is
	// unknown (never "not ours"); a mismatch/untagged bucket is refused.
	tags, terr := d.s3Tags(region, bucket)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update tag read gave no answer — reconcile: " + terr.Error()}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "bucket tags do not match — refusing to patch a resource that is not ours"}
	}
	// desired plan (create-XML reuse). A refusal here (an attribute S3 cannot
	// honor) surfaces as failed, never a half-applied patch.
	plan, err := BuildS3Requests("pv", environment, capability, attrs, impl, 1)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	for _, path := range changes {
		switch path {
		case "versioning.enabled":
			body := s3VersioningSuspendedBody
			if enabled, _ := attrs[path].(bool); enabled && plan.Versioning != nil {
				body = plan.Versioning.Body
			}
			if r := d.s3PatchStep(region, bucket, "PUT", "/?versioning", body, providerID, "versioning"); r != nil {
				return *r
			}
		case "retention.maximum":
			if plan.Lifecycle == nil {
				return provider.CreateResult{Status: "failed",
					Reason: "retention.maximum change carries no honorable lifecycle rule"}
			}
			if r := d.s3PatchStep(region, bucket, "PUT", "/?lifecycle", plan.Lifecycle.Body, providerID, "lifecycle"); r != nil {
				return *r
			}
		case "encryption.customerManagedKeys":
			body := s3SSES3Body // desired false -> reset default to SSE-S3 (AES256)
			if want, _ := attrs[path].(bool); want && plan.Encryption != nil {
				body = plan.Encryption.Body
			}
			if r := d.s3PatchStep(region, bucket, "PUT", "/?encryption", body, providerID, "encryption"); r != nil {
				return *r
			}
		case "replication.enabled", "replication.destinationRegion":
			// both fold to ONE re-assertion of the bucket's replication config; when
			// disabling, remove it. The desired body carries the (possibly new)
			// destination/role operands. If both paths change at once this runs twice
			// with an identical body — idempotent, never half-applied.
			if enabled, _ := attrs["replication.enabled"].(bool); enabled {
				if plan.Replication == nil {
					return provider.CreateResult{Status: "failed",
						Reason: "replication.enabled change carries no honorable replication rule " +
							"(missing versioning presupposition or destination/role operands)"}
				}
				if r := d.s3PatchStep(region, bucket, "PUT", "/?replication", plan.Replication.Body, providerID, "replication"); r != nil {
					return *r
				}
			} else {
				if r := d.s3DeleteReplicationStep(region, bucket, providerID); r != nil {
					return *r
				}
			}
		case "network.publicExposure":
			// re-assert the public-access-block for the desired state first, then
			// add (public) or remove (private) the anonymous-read bucket policy.
			if r := d.s3PatchStep(region, bucket, "PUT", "/?publicAccessBlock", plan.PublicAccessBlk.Body, providerID, "public-access-block"); r != nil {
				return *r
			}
			if plan.Public {
				if r := d.s3PatchStep(region, bucket, "PUT", "/?policy", PublicReadPolicy(bucket), providerID, "public policy"); r != nil {
					return *r
				}
			} else {
				if r := d.s3DeletePolicyStep(region, bucket, providerID); r != nil {
					return *r
				}
			}
		default:
			// a non-mutable path must never reach here (the compiler classifies
			// first); if it does, refuse rather than half-apply.
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("s3 path %s is not patchable in place", path)}
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// s3VersioningSuspendedBody / s3SSES3Body are the two "off" bodies the create
// path never emits (create only turns versioning ON and CMEK ON).
const s3VersioningSuspendedBody = "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
	"<Status>Suspended</Status></VersioningConfiguration>"
const s3SSES3Body = "<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
	"<Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>" +
	"</ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"

// s3PatchStep runs one update sub-resource call; nil = ok, non-nil = a terminal
// result. err/5xx are unknown WITH the pid (the patch may have landed — D29);
// a 4xx or 3xx (a redirect is NOT success) is failed.
func (d *Driver) s3PatchStep(region, bucket, method, path, body, pid, what string) *provider.CreateResult {
	st, resp, err := d.s3Do(method, region, bucket, path, body)
	if err != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("%s patch outcome unknown — reconcile", what)}
		return &r
	}
	if st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("%s patch HTTP %d (server error) — reconcile", what, st)}
		return &r
	}
	if st < 200 || st >= 300 {
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s patch failed: HTTP %d (%s)", what, st, awsErrCode(resp))}
		return &r
	}
	return nil
}

// s3DeletePolicyStep removes the bucket policy (private transition). A missing
// policy (404 / NoSuchBucketPolicy) is already-private, i.e. success.
func (d *Driver) s3DeletePolicyStep(region, bucket, pid string) *provider.CreateResult {
	st, resp, err := d.s3Do("DELETE", region, bucket, "/?policy", "")
	if err != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "public policy removal outcome unknown — reconcile"}
		return &r
	}
	if st == http.StatusNotFound || awsErrCode(resp) == "NoSuchBucketPolicy" {
		return nil // already private
	}
	if st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("public policy removal HTTP %d (server error) — reconcile", st)}
		return &r
	}
	if st < 200 || st >= 300 {
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("public policy removal failed: HTTP %d (%s)", st, awsErrCode(resp))}
		return &r
	}
	return nil
}

// s3DeleteReplicationStep removes the bucket's replication config (CRR off). A
// missing config (404 / ReplicationConfigurationNotFoundError) is already-off.
func (d *Driver) s3DeleteReplicationStep(region, bucket, pid string) *provider.CreateResult {
	st, resp, err := d.s3Do("DELETE", region, bucket, "/?replication", "")
	if err != nil {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "replication removal outcome unknown — reconcile"}
		return &r
	}
	if st == http.StatusNotFound || awsErrCode(resp) == "ReplicationConfigurationNotFoundError" {
		return nil // already off
	}
	if st >= 500 {
		r := provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("replication removal HTTP %d (server error) — reconcile", st)}
		return &r
	}
	if st < 200 || st >= 300 {
		r := provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("replication removal failed: HTTP %d (%s)", st, awsErrCode(resp))}
		return &r
	}
	return nil
}

// deleteS3: ownership (tags) pre-check, then DELETE. A non-empty bucket refuses
// (objects are data — retirement is data loss, never forced).
func (d *Driver) deleteS3(capability, environment, providerID string) provider.CreateResult {
	region, bucket, err := splitS3ProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// existence + ownership. NOTE: GetBucketTagging returns 404 NoSuchTagSet for
	// an EXISTING untagged bucket — branch on the CODE, never on 404 alone, or a
	// standing untagged bucket would be reported retired without being deleted.
	st, body, err := d.s3Do("GET", region, bucket, "/?tagging", "")
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-delete read failed: %v", err)}
	}
	code := awsErrCode(body)
	if code == "NoSuchBucket" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	tags := map[string]string{}
	switch {
	case code == "NoSuchTagSet":
		// bucket exists but is untagged — the ownership check below refuses it
	case st == http.StatusOK:
		parsed, perr := parseS3Tags(body)
		if perr != nil {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "pre-delete tag read unparseable — refusing an ambiguous delete"}
		}
		tags = parsed
	default:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("pre-delete tag read: HTTP %d (%s)", st, code)}
	}
	if tags["groundhold-capability"] != sanitizeTag(capability) ||
		tags["groundhold-environment"] != sanitizeTag(environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "bucket tags do not match — refusing to delete a resource that is not ours"}
	}
	// D469 — the compliance hold, refused UP FRONT. The GCS twin has always read
	// retentionPolicy.isLocked and refused before trying; S3 went straight to the
	// DELETE and translated whatever came back, so the same situation reached the
	// operator as "bucket is not empty" or a raw HTTP error. AWS would have refused
	// too — this is not about damage, it is about which sentence the operator reads,
	// and about D47's rule that protection is never auto-lifted being applied on one
	// cloud and not its twin.
	if r := d.refuseIfObjectLockCompliance(region, bucket); r != nil {
		return *r
	}
	st, dbody, err := d.s3Do("DELETE", region, bucket, "/", "")
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete outcome unknown: %v", err)}
	}
	if st == http.StatusConflict || awsErrCode(dbody) == "BucketNotEmpty" {
		return provider.CreateResult{Status: "failed",
			Reason: "bucket is not empty — objects are data; delete them explicitly " +
				"first (retirement is data loss), never forced"}
	}
	if st == http.StatusNotFound || awsErrCode(dbody) == "NoSuchBucket" {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete: HTTP %d (server error) — reconcile", st)}
	}
	if st < 200 || st >= 300 { // 4xx or a 3xx redirect — NOT a confirmed delete
		// D237: a throttle/503/live-403 is unknown (keep the handle for reconcile),
		// never a terminal failed.
		if r := provider.MutationResult(st, awsErrCode(dbody), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("delete: HTTP %d (%s)", st, awsErrCode(dbody))}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// refuseIfObjectLockCompliance mirrors the GCS lock check (gcs_net.go): a bucket whose
// Object Lock default retention is in COMPLIANCE mode is under a WORM hold nothing lifts,
// including us. GOVERNANCE is deliberately NOT a refusal — it is bypassable by design and
// observe already reverse-maps it to retention.locked=false, so refusing on it would
// claim a hold that is not there.
//
// An unreadable or unparseable configuration is `unknown`, never "not locked": reading a
// zero value out of a garbled body and deleting on it is the same ambiguity the GCS twin
// refuses, and this is the verb where being wrong is not recoverable.
func (d *Driver) refuseIfObjectLockCompliance(region, bucket string) *provider.CreateResult {
	st, body, err := d.s3Do("GET", region, bucket, "/?object-lock", "")
	switch {
	case err != nil:
		return &provider.CreateResult{Status: "unknown",
			Reason: "pre-delete object-lock read gave no answer — refusing an ambiguous " +
				"delete: " + err.Error()}
	case st == http.StatusNotFound || awsErrCode(body) == "ObjectLockConfigurationNotFoundError":
		return nil // not object-lock-enabled — nothing to hold the delete
	case st != http.StatusOK:
		return &provider.CreateResult{Status: "unknown",
			Reason: fmt.Sprintf("pre-delete object-lock read: HTTP %d (%s) — refusing an "+
				"ambiguous delete", st, awsErrCode(body))}
	}
	var olc struct {
		Enabled string `xml:"ObjectLockEnabled"`
		Rule    struct {
			DefaultRetention struct {
				Mode string `xml:"Mode"`
			} `xml:"DefaultRetention"`
		} `xml:"Rule"`
	}
	if xml.Unmarshal(body, &olc) != nil {
		return &provider.CreateResult{Status: "unknown",
			Reason: "pre-delete object-lock read unparseable — refusing an ambiguous delete"}
	}
	if olc.Enabled == "Enabled" && olc.Rule.DefaultRetention.Mode == "COMPLIANCE" {
		return &provider.CreateResult{Status: "failed",
			Reason: "bucket Object Lock is in COMPLIANCE mode — deletion is blocked by a " +
				"compliance hold, never auto-lifted"}
	}
	return nil
}
