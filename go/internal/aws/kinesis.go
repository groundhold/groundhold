// Kinesis request building (D114): the semantic core of the AWS
// capability.streaming.pipe driver — the SAME vocabulary Azure Event Hubs fulfils
// (GCP has no managed streaming twin, so the domain is honestly two-cloud). A
// Kinesis Data Stream is a managed regional record stream. Shard/capacity mode
// (on-demand is the reference default) and consumer registrations are
// implementation sizing; residency, retention window, availability and encryption
// are the capability. A Kinesis stream is ALWAYS regionally/multi-AZ replicated,
// so availability.class=zonal is an honest refusal here (never a silent upgrade).
package aws

import (
	"fmt"
	"regexp"
	"strings"

	"groundhold/internal/scalars"
)

// kinesisNameOK bounds a Kinesis stream name (1-128: alnum, dot, dash, underscore).
var kinesisNameOK = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,128}$`)

// KinesisStreamName is the deterministic stream name (the idempotency handle).
func KinesisStreamName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, slug)
	slug = strings.Trim(slug, "-")
	return "pv-" + slug + "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
}

// KinesisPlan is the attribute-derived shape a create assembles.
type KinesisPlan struct {
	Stream         string
	RetentionHours int // 24-8760; 0 = leave the 24h default
	CMEK           bool
	KmsKeyId       string
}

// durationHours converts a duration scalar to whole hours (Kinesis retention is
// hour-granular). Sub-hour is refused, never rounded to zero.
func durationHours(raw any) (int, error) {
	sc, err := scalars.Parse(raw)
	if err != nil || sc.Kind != scalars.Duration {
		return 0, fmt.Errorf("not a duration")
	}
	ms, _ := sc.Value.(float64)
	hours := int(ms) / 3600000
	if hours < 1 {
		return 0, fmt.Errorf("below 1 hour cannot be honored (Kinesis retention is whole hours)")
	}
	return hours, nil
}

// BuildKinesis maps capability.streaming.pipe attributes + impl to a plan. Every
// error is a preflight refusal, never a silent drop.
func BuildKinesis(environment, capability string,
	attrs, impl map[string]any, generation int) (KinesisPlan, error) {
	p := KinesisPlan{Stream: KinesisStreamName(environment, capability, generation)}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// region is the driver scope (createScope); nothing in the body.
		case "retention.window":
			hours, err := durationHours(raw)
			if err != nil {
				return KinesisPlan{}, fmt.Errorf("retention.window: %v", err)
			}
			if hours < 24 || hours > 8760 {
				return KinesisPlan{}, fmt.Errorf(
					"retention.window %dh is outside the Kinesis range (24h..8760h)", hours)
			}
			p.RetentionHours = hours
		case "availability.class":
			switch raw {
			case "regional":
				// a Kinesis stream is always regional (multi-AZ) — the native mode
			case "zonal":
				return KinesisPlan{}, fmt.Errorf(
					"availability.class=zonal cannot be honored by Kinesis — a stream is always " +
						"regionally/multi-AZ replicated; refusing rather than misrepresenting it as zonal")
			default:
				return KinesisPlan{}, fmt.Errorf("availability.class %v has no Kinesis mapping", raw)
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.CMEK = true
				p.KmsKeyId, _ = impl["kms_key_id"].(string)
				if p.KmsKeyId == "" {
					return KinesisPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_id")
				}
			}
		case "service.managed":
			if raw != true {
				return KinesisPlan{}, fmt.Errorf("service.managed=false cannot be honored by Kinesis")
			}
		default:
			return KinesisPlan{}, fmt.Errorf(
				"attribute %s has no Kinesis mapping — refusing rather than silently dropping it "+
					"(shard/capacity mode, consumer registrations are implementation sizing)", path)
		}
	}
	if !kinesisNameOK.MatchString(p.Stream) {
		return KinesisPlan{}, fmt.Errorf("derived stream name %q is invalid", p.Stream)
	}
	return p, nil
}

// createBody is the CreateStream request body (on-demand capacity is the default).
func (p KinesisPlan) createBody() map[string]any {
	return map[string]any{
		"StreamName":        p.Stream,
		"StreamModeDetails": map[string]any{"StreamMode": "ON_DEMAND"},
	}
}
