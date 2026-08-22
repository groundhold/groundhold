// S3 request building (D86): the semantic core of the AWS storage.object driver
// — the SAME capability.storage.object vocabulary GCS fulfils, proving the
// provider-agnostic thesis (D85). S3 is XML, region-endpoint'd, and its public-
// exposure mechanism differs from GCS (PublicAccessBlock + a bucket policy vs
// GCS's PAP + IAM) — the driver bridges that; the vocab attribute stays neutral.
// Bucket names are a GLOBAL namespace (like GCS): the D82 cross-owner concern
// applies, handled in the shell via the bucket's owner account.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"groundhold/internal/scalars"
)

// s3Req is one ordered S3 API call the create sequence issues.
type s3Req struct {
	Method  string
	Path    string            // "/" or "/?tagging" etc. (bucket is the host, not the path)
	Body    string            // XML, "" for none
	Headers map[string]string // extra signed headers (e.g. the create-time Object Lock enable)
}

// S3Plan is the ordered sequence a bucket create issues: create -> tagging ->
// public-access-block (-> policy if public). The shell sequences and signs them.
type S3Plan struct {
	Bucket          string
	Region          string
	Create          s3Req
	Tagging         s3Req
	PublicAccessBlk s3Req
	Public          bool // if true the shell must relax the block + put a policy
	Versioning      *s3Req
	ObjectLock      *s3Req // retention.minimum/locked -> PutObjectLockConfiguration (WORM)
	Lifecycle       *s3Req // retention.maximum -> a lifecycle expiration rule
	Encryption      *s3Req // encryption.customerManagedKeys -> SSE-KMS default
	Replication     *s3Req // replication.enabled -> PutBucketReplication (CRR)
	// Cors: cors.allowedOrigins -> PutBucketCors (non-empty) or DeleteBucketCors
	// (declared empty). Undeclared leaves it nil — the surface is unmanaged.
	Cors *s3Req
	// ObjectLock* mirror the ObjectLock request in scalar form (create-time facts
	// the shell/observe reason about without re-parsing XML).
	ObjectLockEnabled bool
	ObjectLockMode    string // COMPLIANCE (retention.locked) | GOVERNANCE (retention.minimum only)
	ObjectLockDays    int64
}

// bucketNameOK bounds an S3 bucket name (DNS-compatible subset): lowercase
// alnum + hyphen + dot, 3-63, start/end alnum. Keeps '/', ':' etc. out of the
// host/path (the D73 boundary).
var bucketNameOK = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// BucketName is the deterministic name (<=63). The AWS account id keeps it
// globally unique without colliding with another groundhold install's buckets.
func BucketName(account, environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.ToLower(nonDNS.ReplaceAllString(slug, "-"))
	hashInput := account + "|" + environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	// prefix with a short account fragment for global uniqueness
	prefix := "pv-"
	maxSlug := 63 - len(prefix) - len(tail)
	if len(slug) > maxSlug {
		slug = slug[:maxSlug]
	}
	slug = strings.Trim(slug, "-.")
	return prefix + slug + tail
}

var nonDNS = regexp.MustCompile(`[^a-z0-9.-]+`)

// regionOK bounds an AWS region token before it is interpolated into a host.
var regionOK = regexp.MustCompile(`^[a-z]{2}-[a-z]+-[0-9]+$`)

// s3BucketARNOK bounds a replication destination ARN (arn:aws:s3:::<bucket>)
// before it is interpolated into the replication XML (D73). The capture group
// is the bucket name observe extracts to GetBucketLocation on the replica.
var s3BucketARNOK = regexp.MustCompile(`^arn:aws:s3:::([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])$`)

// iamRoleARNOK bounds the replication role ARN before it reaches the XML (D73).
var iamRoleARNOK = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]+$`)

func s3Tag(capability, environment string) string {
	return "<Tagging><TagSet>" +
		"<Tag><Key>groundhold-capability</Key><Value>" + xmlEsc(sanitizeTag(capability)) + "</Value></Tag>" +
		"<Tag><Key>groundhold-environment</Key><Value>" + xmlEsc(sanitizeTag(environment)) + "</Value></Tag>" +
		"</TagSet></Tagging>"
}

// BuildS3Requests maps capability.storage.object attributes to the S3 create
// sequence. Every error is a refusal apply surfaces in preflight.
func BuildS3Requests(account, environment, capability string,
	attrs, impl map[string]any, generation int) (S3Plan, error) {
	if generation < 1 {
		generation = 1
	}
	region := ""
	public := false
	versioning := false
	expiryDays := int64(0)
	kmsKeyID := ""
	replication := false
	retentionMinDays := int64(0)
	retentionMinSet := false
	retentionLocked := false
	var corsOrigins []string
	corsSet := false
	var prefixRet []prefixExpiry // retention.maximumByPrefix, parsed
	prefixRetSet := false

	paths := sortedKeys(attrs)
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "durability.class":
			if raw == "single-zone" {
				return S3Plan{}, fmt.Errorf(
					"durability.class single-zone cannot be honored by an S3 bucket: " +
						"a general-purpose bucket is multi-AZ by construction (One Zone " +
						"storage classes are per-object lifecycle economics, not bucket " +
						"durability, and an Express One Zone directory bucket is a " +
						"different resource this driver does not map) — declare regional " +
						"or drop the attribute")
			}
		case "versioning.enabled":
			versioning, _ = raw.(bool)
		case "network.publicExposure":
			public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return S3Plan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by S3 (objects are " +
						"always encrypted at rest with SSE-S3)")
			}
		case "retention.maximumByPrefix":
			pr, err := parsePrefixExpiry(toStrSlice(raw))
			if err != nil {
				return S3Plan{}, err
			}
			prefixRet, prefixRetSet = pr, true
		case "cors.allowedOrigins":
			// the EFFECT: the origin set the contract asserts. The rule DOCUMENT is
			// the implementation.cors operand; the projection gate below requires the
			// operand's origin-union to equal this set, so the attribute cannot claim
			// an effect the rules do not produce (the write-only-operand smuggling
			// channel the forged-plan-field lesson closes).
			corsOrigins = toStrSlice(raw)
			corsSet = true
		case "encryption.customerManagedKeys":
			// CMEK: default encryption stays SSE-S3 unless a customer key is
			// declared. Only true is actionable — a true value sets the bucket's
			// default SSE-KMS with the customer key (a PUT /?encryption on the
			// SAME bucket, not a second resource). The key id is impl detail.
			if raw == true {
				kmsKeyID, _ = impl["kms_key_id"].(string)
				if kmsKeyID == "" {
					return S3Plan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires " +
							"implementation.kms_key_id (a customer KMS key) — " +
							"the SSE-S3 / aws/s3 default does not satisfy it")
				}
			}
		case "retention.minimum":
			// WORM at birth (D86): S3 Object Lock is enabled at CreateBucket (the
			// x-amz-bucket-object-lock-enabled header) and its default retention is a
			// PutObjectLockConfiguration on that same object-lock-enabled bucket.
			// Because we now own create from zero, both parts land in one coherent
			// create — there is no "409-continue cannot re-assert" problem (the bucket
			// is BORN object-lock-enabled). retention.minimum is the DefaultRetention
			// floor in whole days (mirror retention.maximum: duration -> days).
			sc, err := scalars.Parse(raw)
			if err != nil || sc.Kind != scalars.Duration {
				return S3Plan{}, fmt.Errorf("retention.minimum is not a duration")
			}
			retentionMinDays = int64(sc.Value.(float64)) / 86400000
			if retentionMinDays < 1 {
				return S3Plan{}, fmt.Errorf(
					"retention.minimum below 1 day cannot be honored by an S3 Object Lock " +
						"default retention (DefaultRetention.Days is whole days)")
			}
			retentionMinSet = true
		case "retention.locked":
			// retention.locked=true selects COMPLIANCE mode (a hard WORM nobody — not
			// even the account root — can shorten), false/unset selects GOVERNANCE
			// (overridable with s3:BypassGovernanceRetention). It PRESUPPOSES
			// retention.minimum (you cannot lock nothing) — enforced after the loop.
			retentionLocked, _ = raw.(bool)
		case "retention.maximum":
			sc, err := scalars.Parse(raw)
			if err != nil || sc.Kind != scalars.Duration {
				return S3Plan{}, fmt.Errorf("retention.maximum is not a duration")
			}
			// a CEILING (objects must not outlive it): round DOWN to whole days —
			// S3 lifecycle Expiration.Days is a whole-day integer.
			expiryDays = int64(sc.Value.(float64)) / 86400000
			if expiryDays < 1 {
				return S3Plan{}, fmt.Errorf(
					"retention.maximum below 1 day cannot be honored by an S3 " +
						"lifecycle rule (Expiration.Days is whole days)")
			}
		case "replication.enabled":
			replication, _ = raw.(bool)
		case "replication.destinationRegion":
			// The SUBSTANCE of DR residency, but OBSERVED not built: the region
			// lives on the destination bucket, not in PutBucketReplication (the rule
			// holds a region-less ARN). Accept the desired value so a contract can
			// assert it, but emit no request — observe MEASURES it via
			// GetBucketLocation and never trusts a declared value (residency mierzona).
		case "service.managed":
			if raw != true {
				return S3Plan{}, fmt.Errorf("service.managed=false cannot be honored by S3")
			}
		default:
			return S3Plan{}, fmt.Errorf(
				"attribute %s has no S3 mapping — refusing rather than silently dropping it", path)
		}
	}
	if region == "" {
		return S3Plan{}, fmt.Errorf("s3 requires location.region")
	}
	// region is interpolated into the endpoint host AND the SigV4 scope — bound
	// it before it reaches either (D73 boundary).
	if !regionOK.MatchString(region) {
		return S3Plan{}, fmt.Errorf("location.region %q is not a valid AWS region", region)
	}
	bucket := BucketName(account, environment, capability, generation)

	plan := S3Plan{Bucket: bucket, Region: region, Public: public}
	// create: LocationConstraint required for every region except us-east-1.
	createBody := ""
	if region != "us-east-1" {
		createBody = "<CreateBucketConfiguration><LocationConstraint>" +
			xmlEsc(region) + "</LocationConstraint></CreateBucketConfiguration>"
	}
	plan.Create = s3Req{Method: "PUT", Path: "/", Body: createBody}
	plan.Tagging = s3Req{Method: "PUT", Path: "/?tagging", Body: s3Tag(capability, environment)}
	// public-access-block: private baseline blocks everything; a public bucket
	// relaxes the policy gates (BlockPublicPolicy/RestrictPublicBuckets false) so
	// the shell can attach an allUsers-equivalent read policy as the second gate.
	blockAcls := "true"
	blockPolicy := "true"
	if public {
		blockPolicy = "false"
	}
	plan.PublicAccessBlk = s3Req{Method: "PUT", Path: "/?publicAccessBlock",
		Body: "<PublicAccessBlockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
			"<BlockPublicAcls>" + blockAcls + "</BlockPublicAcls>" +
			"<IgnorePublicAcls>true</IgnorePublicAcls>" +
			"<BlockPublicPolicy>" + blockPolicy + "</BlockPublicPolicy>" +
			"<RestrictPublicBuckets>" + blockPolicy + "</RestrictPublicBuckets>" +
			"</PublicAccessBlockConfiguration>"}
	if versioning {
		v := s3Req{Method: "PUT", Path: "/?versioning",
			Body: "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
				"<Status>Enabled</Status></VersioningConfiguration>"}
		plan.Versioning = &v
	}
	// Object Lock (WORM), create-time (D86). retention.locked without a floor is
	// meaningless — you cannot lock nothing (presupposition, the CRR-needs-
	// versioning pattern). Object Lock also PRESUPPOSES versioning (S3 only WORM-
	// protects versioned objects), so refuse rather than half-apply if a retention
	// floor/lock is asked without versioning.
	if retentionLocked && !retentionMinSet {
		return S3Plan{}, fmt.Errorf(
			"retention.locked (WORM) presupposes retention.minimum — you cannot lock " +
				"nothing; declare a retention floor or drop the lock")
	}
	if retentionMinSet || retentionLocked {
		if !versioning {
			return S3Plan{}, fmt.Errorf(
				"retention.minimum/retention.locked (S3 Object Lock, WORM) presupposes " +
					"versioning.enabled=true — S3 only retention-protects versioned objects; " +
					"refusing rather than half-applying it")
		}
		mode := "GOVERNANCE"
		if retentionLocked {
			mode = "COMPLIANCE"
		}
		plan.ObjectLockEnabled = true
		plan.ObjectLockMode = mode
		plan.ObjectLockDays = retentionMinDays
		// the bucket must be BORN object-lock-enabled — a create-time-only header.
		if plan.Create.Headers == nil {
			plan.Create.Headers = map[string]string{}
		}
		plan.Create.Headers["x-amz-bucket-object-lock-enabled"] = "true"
		ol := s3Req{Method: "PUT", Path: "/?object-lock",
			Body: fmt.Sprintf("<ObjectLockConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"+
				"<ObjectLockEnabled>Enabled</ObjectLockEnabled>"+
				"<Rule><DefaultRetention><Mode>%s</Mode><Days>%d</Days></DefaultRetention></Rule>"+
				"</ObjectLockConfiguration>", mode, retentionMinDays)}
		plan.ObjectLock = &ol
	}
	if expiryDays > 0 || prefixRetSet {
		// G1: a per-prefix ceiling can only TIGHTEN the bucket-wide one. S3 applies the
		// EARLIEST matching expiration, so a per-prefix rule LONGER than a bucket-wide one
		// is silently unhonored (the object dies at the bucket-wide age) — refuse rather
		// than let the contract assert a retention S3 will not deliver.
		if expiryDays > 0 {
			for _, r := range prefixRet {
				if r.days > expiryDays {
					return S3Plan{}, fmt.Errorf(
						"retention.maximumByPrefix %q is %dd but the bucket-wide retention.maximum is "+
							"%dd — S3 applies the EARLIEST matching expiration, so a longer per-prefix "+
							"rule is silently unhonored; a per-prefix ceiling can only tighten the "+
							"bucket-wide one", r.prefix, r.days, expiryDays)
				}
			}
		}
		// G2: a lifecycle rule must not delete before an Object-Lock retention floor —
		// WORM says keep, lifecycle says delete is a contract contradiction.
		if retentionMinSet {
			for _, r := range prefixRet {
				if r.days < retentionMinDays {
					return S3Plan{}, fmt.Errorf(
						"retention.maximumByPrefix %q is %dd but retention.minimum is %dd — a lifecycle "+
							"rule that deletes before the Object-Lock floor is a contradiction "+
							"(WORM keeps, lifecycle deletes)", r.prefix, r.days, retentionMinDays)
				}
			}
		}
		if expiryDays == 0 && len(prefixRet) == 0 {
			// retention.maximumByPrefix declared EMPTY and no bucket-wide rule -> the owned
			// lifecycle document is empty, so REMOVE it (DeleteBucketLifecycle), like cors [].
			plan.Lifecycle = &s3Req{Method: "DELETE", Path: "/?lifecycle"}
		} else {
			plan.Lifecycle = &s3Req{Method: "PUT", Path: "/?lifecycle",
				Body: buildLifecycleBody(expiryDays, prefixRet)}
		}
	}
	if kmsKeyID != "" {
		enc := s3Req{Method: "PUT", Path: "/?encryption",
			Body: "<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
				"<Rule><ApplyServerSideEncryptionByDefault>" +
				"<SSEAlgorithm>aws:kms</SSEAlgorithm>" +
				"<KMSMasterKeyID>" + xmlEsc(kmsKeyID) + "</KMSMasterKeyID>" +
				"</ApplyServerSideEncryptionByDefault></Rule>" +
				"</ServerSideEncryptionConfiguration>"}
		plan.Encryption = &enc
	}
	if replication {
		// CRR PRESUPPOSES versioning on the source (S3 only replicates versioned
		// objects) — honest-refuse rather than half-apply, the retention.locked
		// presupposes retention.minimum pattern.
		if !versioning {
			return S3Plan{}, fmt.Errorf(
				"replication.enabled (cross-region replication) presupposes " +
					"versioning.enabled=true on the source bucket — S3 CRR only " +
					"replicates versioned objects; refusing rather than half-applying it")
		}
		// operands (D26): the replica bucket ARN + the IAM role S3 assumes. The
		// replica is a SEPARATE capability.storage.object in another region — this
		// driver does not create it; it only points at it.
		destARN, _ := impl["replication_destination_bucket_arn"].(string)
		roleARN, _ := impl["replication_role_arn"].(string)
		if destARN == "" || roleARN == "" {
			return S3Plan{}, fmt.Errorf(
				"replication.enabled requires implementation.replication_destination_bucket_arn " +
					"(the replica bucket, a separate capability.storage.object in another " +
					"region) and implementation.replication_role_arn (the IAM role S3 " +
					"assumes to replicate) — refusing rather than half-applying it")
		}
		if !s3BucketARNOK.MatchString(destARN) {
			return S3Plan{}, fmt.Errorf(
				"implementation.replication_destination_bucket_arn %q is not a valid "+
					"arn:aws:s3:::<bucket>", destARN)
		}
		if !iamRoleARNOK.MatchString(roleARN) {
			return S3Plan{}, fmt.Errorf(
				"implementation.replication_role_arn %q is not a valid IAM role ARN", roleARN)
		}
		rep := s3Req{Method: "PUT", Path: "/?replication",
			Body: "<ReplicationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">" +
				"<Role>" + xmlEsc(roleARN) + "</Role>" +
				"<Rule><ID>groundhold-crr</ID><Status>Enabled</Status><Priority>1</Priority>" +
				"<Filter></Filter>" +
				"<DeleteMarkerReplication><Status>Disabled</Status></DeleteMarkerReplication>" +
				"<Destination><Bucket>" + xmlEsc(destARN) + "</Bucket></Destination>" +
				"</Rule></ReplicationConfiguration>"}
		plan.Replication = &rep
	}
	if corsSet {
		if len(corsOrigins) == 0 {
			// declared empty -> "no cross-origin", enforced: DeleteBucketCors.
			plan.Cors = &s3Req{Method: "DELETE", Path: "/?cors"}
		} else {
			rulesRaw, ok := impl["cors"].([]any)
			if !ok || len(rulesRaw) == 0 {
				return S3Plan{}, fmt.Errorf(
					"cors.allowedOrigins declares origins but implementation.cors is missing — " +
						"the rule document (origins/methods/headers) is the source the attribute " +
						"projects; refusing rather than synthesising a default rule that would pass " +
						"verify and still block the browser call")
			}
			body, union, err := buildCorsBody(rulesRaw)
			if err != nil {
				return S3Plan{}, err
			}
			// projection gate: the attribute MUST be the exact origin-union of the
			// operand, or the effect the contract asserts is not the effect the rules
			// produce (operand is write-only; the attribute is what observe compares).
			if !stringSetEqual(union, corsOrigins) {
				return S3Plan{}, fmt.Errorf(
					"cors.allowedOrigins %v is not the origin-union of implementation.cors %v — "+
						"the attribute must be the exact projection of the rules (else a hard "+
						"constraint would pass over a rule set that allows different origins)",
					sortedUnique(corsOrigins), sortedUnique(union))
			}
			plan.Cors = &s3Req{Method: "PUT", Path: "/?cors", Body: body}
		}
	}
	return plan, nil
}

// buildCorsBody renders a CORSConfiguration from the implementation.cors operand (a
// list of rules) and returns the body plus the UNION of allowed origins across rules —
// the value observe reverse-maps and the projection gate checks the attribute against.
func buildCorsBody(rulesRaw []any) (body string, originUnion []string, err error) {
	var b strings.Builder
	b.WriteString(`<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	seen := map[string]bool{}
	for i, rr := range rulesRaw {
		rule, ok := rr.(map[string]any)
		if !ok {
			return "", nil, fmt.Errorf("implementation.cors[%d] must be a rule map "+
				"(allowedOrigins/allowedMethods/allowedHeaders/exposeHeaders/maxAgeSeconds)", i)
		}
		origins := toStrSlice(rule["allowedOrigins"])
		methods := toStrSlice(rule["allowedMethods"])
		if len(origins) == 0 || len(methods) == 0 {
			return "", nil, fmt.Errorf("implementation.cors[%d] needs at least one "+
				"allowedOrigins and one allowedMethods (an S3 CORS rule requires both)", i)
		}
		b.WriteString("<CORSRule>")
		for _, o := range origins {
			b.WriteString("<AllowedOrigin>" + xmlEsc(o) + "</AllowedOrigin>")
			if !seen[o] {
				seen[o] = true
				originUnion = append(originUnion, o)
			}
		}
		for _, m := range methods {
			b.WriteString("<AllowedMethod>" + xmlEsc(m) + "</AllowedMethod>")
		}
		for _, h := range toStrSlice(rule["allowedHeaders"]) {
			b.WriteString("<AllowedHeader>" + xmlEsc(h) + "</AllowedHeader>")
		}
		for _, h := range toStrSlice(rule["exposeHeaders"]) {
			b.WriteString("<ExposeHeader>" + xmlEsc(h) + "</ExposeHeader>")
		}
		if ma, ok := intOperand(rule["maxAgeSeconds"]); ok && ma > 0 {
			b.WriteString("<MaxAgeSeconds>" + strconv.Itoa(ma) + "</MaxAgeSeconds>")
		}
		b.WriteString("</CORSRule>")
	}
	b.WriteString("</CORSConfiguration>")
	sort.Strings(originUnion)
	return b.String(), originUnion, nil
}

// stringSetEqual compares two string slices as SETS (order/dup-insensitive).
func stringSetEqual(a, b []string) bool {
	return equalStringSlices(sortedUnique(a), sortedUnique(b))
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// prefixExpiry is one parsed retention.maximumByPrefix element: a key prefix and its
// whole-day expiration ceiling.
type prefixExpiry struct {
	prefix string
	days   int64
}

var prefixExpiryRE = regexp.MustCompile(`^(.+)=([0-9]+)d$`)

// parsePrefixExpiry parses retention.maximumByPrefix elements "<prefix>=<N>d" fail-closed:
// a malformed element, N<1, or a duplicate prefix REFUSES rather than being silently
// dropped (a dropped rule would be a per-prefix retention nobody applied).
func parsePrefixExpiry(elems []string) ([]prefixExpiry, error) {
	out := make([]prefixExpiry, 0, len(elems))
	seen := map[string]bool{}
	for _, e := range elems {
		m := prefixExpiryRE.FindStringSubmatch(e)
		if m == nil {
			return nil, fmt.Errorf("retention.maximumByPrefix element %q is not `<prefix>=<N>d` "+
				"(whole days) — refusing rather than misreading a lifecycle ceiling", e)
		}
		days, _ := strconv.ParseInt(m[2], 10, 64)
		if m[1] == "" || days < 1 {
			return nil, fmt.Errorf(
				"retention.maximumByPrefix element %q needs a non-empty prefix and at least 1 day", e)
		}
		if seen[m[1]] {
			return nil, fmt.Errorf(
				"retention.maximumByPrefix declares prefix %q twice — one ceiling per prefix", m[1])
		}
		seen[m[1]] = true
		out = append(out, prefixExpiry{prefix: m[1], days: days})
	}
	return out, nil
}

var lifecycleSlugRE = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// buildLifecycleBody renders ONE LifecycleConfiguration: the bucket-wide rule (if any)
// plus one Enabled prefix-filtered rule per prefix, sorted for a stable body. A single
// PUT /?lifecycle replaces the whole document, so the contract OWNS it — an out-of-band
// rule is drift, removed on the next converge.
func buildLifecycleBody(bucketWideDays int64, prefixes []prefixExpiry) string {
	var b strings.Builder
	b.WriteString(`<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	if bucketWideDays > 0 {
		b.WriteString(fmt.Sprintf(
			"<Rule><ID>groundhold-retention-maximum</ID><Filter></Filter><Status>Enabled</Status>"+
				"<Expiration><Days>%d</Days></Expiration></Rule>", bucketWideDays))
	}
	sorted := append([]prefixExpiry(nil), prefixes...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].prefix < sorted[j].prefix })
	for _, r := range sorted {
		slug := strings.Trim(lifecycleSlugRE.ReplaceAllString(r.prefix, "-"), "-")
		b.WriteString(fmt.Sprintf(
			"<Rule><ID>groundhold-retention-prefix-%s</ID><Filter><Prefix>%s</Prefix></Filter>"+
				"<Status>Enabled</Status><Expiration><Days>%d</Days></Expiration></Rule>",
			slug, xmlEsc(r.prefix), r.days))
	}
	b.WriteString("</LifecycleConfiguration>")
	return b.String()
}

// PublicReadPolicy is the bucket policy granting anonymous s3:GetObject — the
// S3 analogue of GCS's allUsers objectViewer (the public-exposure second gate).
func PublicReadPolicy(bucket string) string {
	return `{"Version":"2012-10-17","Statement":[{"Sid":"groundholdPublicRead",` +
		`"Effect":"Allow","Principal":"*","Action":"s3:GetObject",` +
		`"Resource":"arn:aws:s3:::` + bucket + `/*"}]}`
}

func xmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// sanitizeTag bounds an ownership tag value to a safe charset (AWS tag values
// are permissive, but keep parity with the GCP label discipline).
var tagBad = regexp.MustCompile(`[^A-Za-z0-9_.\-]+`)

func sanitizeTag(s string) string {
	return tagBad.ReplaceAllString(strings.ToLower(s), "-")
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// deterministic order for golden tests
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
