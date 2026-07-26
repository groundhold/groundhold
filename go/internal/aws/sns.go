// SNS request building (D94): the semantic core of the AWS messaging.topic
// driver — the SAME capability.messaging.topic vocabulary GCP Pub/Sub fulfils
// (the provider-agnostic thesis, D85). SNS is the AWS Query protocol (like RDS)
// and a topic is REGIONAL, so the topic ARN is fully deterministic from
// (region, account, name) — the handle is always knowable, even on a lost
// create response (D29). A topic holds nothing the author owns (subscribers own
// their copies), so the mapping is thin: encryption (a KMS key), a resource
// policy for public publish, ownership tags. FIFO/subscriptions/filters are the
// consumer's business, never the topic's.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// snsNameOK bounds an SNS topic name before it is interpolated into an ARN/path
// (D73 boundary). SNS allows [A-Za-z0-9_-] up to 256; the driver GENERATES a
// lowercase alnum+hyphen subset, but the parser accepts the full safe set so a
// hand-adopted name is not rejected.
var snsNameOK = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)

// snsBad collapses everything outside the SNS name charset (note: unlike S3,
// '.' is NOT allowed in a topic name).
var snsBad = regexp.MustCompile(`[^a-z0-9-]+`)

// TopicName is the deterministic topic name (the idempotency mechanism — SNS
// CreateTopic has no idempotency-key parameter, it dedupes on the name within
// the account+region). Account+environment+capability salt the hash so two
// installs never collide; g>=2 (D48 replacements) coexist via the -gN salt.
func TopicName(account, environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Trim(snsBad.ReplaceAllString(strings.ToLower(slug), "-"), "-")
	hashInput := account + "|" + environment + "|" + capability
	if generation >= 2 {
		hashInput += fmt.Sprintf("|g%d", generation)
	}
	sum := sha256.Sum256([]byte(hashInput))
	tail := "-" + hex.EncodeToString(sum[:])[:8]
	const maxLen = 256
	if len(slug)+len(tail) > maxLen {
		slug = slug[:maxLen-len(tail)]
		slug = strings.TrimRight(slug, "-")
	}
	name := slug + tail
	if name == "" || !(name[0] >= 'a' && name[0] <= 'z') {
		name = "t" + strings.TrimLeft(name, "-")
	}
	return name
}

// snsAWSManagedKey is the AWS-managed SNS SSE key alias: setting it enables
// server-side encryption at rest with the provider-default key (NOT a customer
// key). SNS has NO SSE without a KMS key, so encryption.atRest=true is honored
// by this alias — genuine at-rest encryption, provider-managed.
const snsAWSManagedKey = "alias/aws/sns"

// SNSPlan is the semantic outcome of mapping the vocabulary to SNS: the
// deterministic name/region, the KMS key to set (empty = no encryption), and
// whether a public publish policy is required. The shell assembles the ARN
// (needs the account) and the ordered call sequence.
type SNSPlan struct {
	Name     string
	Region   string
	KmsKeyID string // "" = unencrypted; alias/aws/sns = provider default; else a customer key
	Public   bool
}

// BuildSNSCreate maps capability.messaging.topic attributes + the impl block to
// an SNS create plan. Every error is a refusal apply surfaces in preflight,
// before any mutation — never a silently dropped attribute.
func BuildSNSCreate(account, environment, capability string,
	attrs, impl map[string]any, generation int) (SNSPlan, error) {
	if generation < 1 {
		generation = 1
	}
	region := ""
	public := false
	atRest := false
	cmek := false

	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			region, _ = raw.(string)
		case "network.publicExposure":
			public, _ = raw.(bool)
		case "encryption.atRest":
			// Only true is meaningful (vocab). false = SNS's unencrypted default,
			// which is honestly honorable by doing nothing (SNS does NOT encrypt at
			// rest by default) — unlike S3/GCS which always encrypt.
			atRest, _ = raw.(bool)
		case "encryption.customerManagedKeys":
			cmek, _ = raw.(bool)
		case "service.managed":
			if raw != true {
				return SNSPlan{}, fmt.Errorf("service.managed=false cannot be honored by SNS")
			}
		default:
			return SNSPlan{}, fmt.Errorf(
				"attribute %s has no SNS mapping — refusing rather than silently dropping it", path)
		}
	}

	// Encryption decision (honest, documented):
	//   - CMEK true  -> a customer key is REQUIRED (impl.kms_key_id); the
	//     provider-default alias/aws/sns does NOT satisfy customer-managed keys.
	//   - atRest true, no CMEK -> the AWS-managed alias/aws/sns key. SNS has no
	//     SSE without a KMS key, so this alias IS the provider-default at-rest
	//     encryption (genuine, provider-managed) — honored rather than refused.
	//   - neither -> no KMS key (SNS's unencrypted default).
	kmsKeyID := ""
	switch {
	case cmek:
		kmsKeyID, _ = impl["kms_key_id"].(string)
		if kmsKeyID == "" {
			return SNSPlan{}, fmt.Errorf(
				"encryption.customerManagedKeys requires implementation.kms_key_id " +
					"(a customer KMS key) — the AWS-managed alias/aws/sns key does not satisfy it")
		}
		if kmsKeyID == snsAWSManagedKey {
			return SNSPlan{}, fmt.Errorf(
				"implementation.kms_key_id=alias/aws/sns is the AWS-managed key, not a " +
					"customer key — it does not satisfy encryption.customerManagedKeys")
		}
	case atRest:
		kmsKeyID = snsAWSManagedKey
	}

	if region == "" {
		return SNSPlan{}, fmt.Errorf("sns requires location.region")
	}
	if !regionOK.MatchString(region) {
		return SNSPlan{}, fmt.Errorf("location.region %q is not a valid AWS region", region)
	}
	return SNSPlan{
		Name:     TopicName(account, environment, capability, generation),
		Region:   region,
		KmsKeyID: kmsKeyID,
		Public:   public,
	}, nil
}

// snsPublicPolicy is the topic resource policy granting anonymous sns:Publish —
// the SNS analogue of GCS's allUsers objectViewer / S3's Principal:"*" bucket
// policy (the public-exposure second gate). Absent this, SNS's default policy
// restricts publish to the owner account.
func snsPublicPolicy(arn string) string {
	return `{"Version":"2012-10-17","Statement":[{"Sid":"groundholdPublicPublish",` +
		`"Effect":"Allow","Principal":"*","Action":"sns:Publish",` +
		`"Resource":"` + arn + `"}]}`
}
