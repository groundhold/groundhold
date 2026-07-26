// Secrets Manager request building (D97): the AWS half of the capability.secret
// driver — the SAME thin vocabulary GCP Secret Manager fulfils. The bound
// resource is one Secret; the VALUE is never written by groundhold (it is data,
// supplied out of band — CreateSecret is issued with no SecretString, yielding a
// versionless handle). The residency contrast with GCP is the lesson: Secret
// Manager defaults to GLOBAL replication and must be pinned; Secrets Manager is
// REGIONAL by construction, so the region is honest with nothing to pin — the
// secret lives in the endpoint's region, full stop (cross-region replication is
// an opt-in we do not request).
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// asmNameOK bounds a Secrets Manager secret name before it is interpolated into
// a request/ARN (D73 boundary). Secrets Manager allows [A-Za-z0-9/_+=.@-] up to
// 512; the driver GENERATES a lowercase alnum+hyphen subset, but the parser
// accepts the full safe set so a hand-adopted name is not rejected.
var asmNameOK = regexp.MustCompile(`^[A-Za-z0-9/_+=.@-]{1,512}$`)

// asmBad collapses everything outside the generated (lowercase) name charset.
var asmBad = regexp.MustCompile(`[^a-z0-9-]+`)

// asmDefaultKeyAlias is the AWS-managed KMS key Secrets Manager uses when no key
// is given — genuine at-rest encryption, provider-managed. It does NOT satisfy
// customer-managed keys.
const asmDefaultKeyAlias = "alias/aws/secretsmanager"

// ASMSecretName is the deterministic secret name (the idempotency key —
// CreateSecret dedupes on the name within account+region, returning
// ResourceExistsException on a hit). environment+capability salt the hash;
// g>=2 (D48 replacements) coexist via the -gN salt.
func ASMSecretName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(asmBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	const maxLen = 512
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
		slug = strings.TrimRight(slug, "-")
	}
	name := slug + tail
	if name == "" || !(name[0] >= 'a' && name[0] <= 'z') {
		name = "s" + strings.TrimLeft(name, "-")
	}
	return name
}

// ASMPlan is the attribute-derived shape a create assembles: the deterministic
// name/region, the CMEK key (empty = the aws/secretsmanager default), and
// whether a public resource policy is required.
type ASMPlan struct {
	Name     string
	Region   string
	KmsKeyID string // "" = AWS-managed default; else a customer key (CMEK)
	Public   bool
}

// BuildSecretsManagerCreate maps capability.secret attributes + the impl block to
// a Secrets Manager create plan. Every error is a refusal apply surfaces in
// preflight, before any mutation — never a silently dropped attribute. The value,
// rotation, access and expiry are all out of scope BY DESIGN (the value is data;
// rotation is the producer's job; access is IAM; expiry is lifecycle policy).
func BuildSecretsManagerCreate(environment, capability string,
	attrs, impl map[string]any, generation int) (ASMPlan, error) {
	if generation < 1 {
		generation = 1
	}
	region := ""
	public := false
	cmek := false

	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "network.publicExposure":
			public, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return ASMPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored (Secrets Manager always encrypts at rest)")
			}
		case "encryption.customerManagedKeys":
			cmek, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return ASMPlan{}, fmt.Errorf("service.managed=false cannot be honored by Secrets Manager")
			}
		default:
			return ASMPlan{}, fmt.Errorf(
				"attribute %s has no Secrets Manager mapping — refusing rather than "+
					"silently dropping it (the value is data supplied out of band, rotation "+
					"is the producer's job, access is IAM — all out of scope by design)", path)
		}
	}

	kmsKeyID := ""
	if cmek {
		kmsKeyID, _ = impl["kms_key_id"].(string)
		if kmsKeyID == "" {
			return ASMPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys requires implementation.kms_key_id " +
					"(a customer KMS key) — the AWS-managed aws/secretsmanager key does not satisfy it")
		}
		if kmsKeyID == asmDefaultKeyAlias || kmsKeyID == "aws/secretsmanager" {
			return ASMPlan{}, fmt.Errorf(
				"implementation.kms_key_id names the AWS-managed key, not a customer key — " +
					"it does not satisfy encryption.customerManagedKeys")
		}
	}

	if region == "" {
		return ASMPlan{}, fmt.Errorf("secret requires location.region")
	}
	if !regionOK.MatchString(region) {
		return ASMPlan{}, fmt.Errorf("location.region %q is not a valid AWS region", region)
	}
	return ASMPlan{
		Name:     ASMSecretName(environment, capability, generation),
		Region:   region,
		KmsKeyID: kmsKeyID,
		Public:   public,
	}, nil
}

// asmPublicPolicy is the secret resource policy granting anonymous
// GetSecretValue — the exposure second gate (rare for a secret; the parallel to
// SNS's anonymous publish / S3's Principal:"*"). Absent this, only the owner
// account (via IAM) can read.
func asmPublicPolicy(arn string) string {
	res := `"*"`
	if arn != "" {
		res = `"` + arn + `"`
	}
	return `{"Version":"2012-10-17","Statement":[{"Sid":"groundholdPublicRead",` +
		`"Effect":"Allow","Principal":"*","Action":"secretsmanager:GetSecretValue",` +
		`"Resource":` + res + `}]}`
}
