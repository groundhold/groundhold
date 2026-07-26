// EFS request building (D111): the semantic core of the AWS
// capability.storage.filesystem driver — the SAME vocabulary GCP Filestore and
// Azure Files fulfil. EFS is a managed regional NFS file share (NFSv4.1). It
// speaks NFS only, so protocol smb/N is an honest refusal here (SMB on AWS is
// FSx for Windows, a different service), not a config toggle. The FileSystemId
// is SERVER-ASSIGNED, so — like Route 53 — the providerId is parsed from the
// response, not deterministic; a deterministic CreationToken is the idempotency
// key that lets a lost create be recovered. Capacity/throughput are elastic
// (no sizing knob); residency, protocol, availability and CMEK are the capability.
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// efsIDOK bounds a server-assigned EFS file-system id before it is placed in a URL.
var efsIDOK = regexp.MustCompile(`^fs-[0-9a-f]{8,40}$`)

// EFSPlan is the attribute-derived shape a create assembles into the JSON body.
type EFSPlan struct {
	CreationToken    string // deterministic idempotency key
	Encrypted        bool
	KmsKeyId         string // CMEK, from impl; "" = provider-managed key
	OneZone          bool   // availability.class=zonal => One Zone storage
	AvailabilityZone string // required when OneZone (impl.availability_zone)
}

// nfsProtocolOKAWS accepts nfs/N and REFUSES smb/N (SMB on AWS is FSx, not EFS).
func nfsProtocolOKAWS(protocol string) error {
	engine, _, ok := strings.Cut(protocol, "/")
	switch {
	case !ok:
		return fmt.Errorf("protocol %q is not a protocol/version (e.g. nfs/4.1)", protocol)
	case strings.ToLower(engine) == "nfs":
		return nil
	case strings.ToLower(engine) == "smb":
		return fmt.Errorf(
			"protocol smb cannot be honored by EFS (SMB on AWS is FSx for Windows, a " +
				"separate service) — refusing rather than mis-provisioning")
	default:
		return fmt.Errorf("protocol %q has no EFS mapping (nfs/N only)", protocol)
	}
}

// BuildEFSCreate maps capability.storage.filesystem attributes + impl to an EFS
// create plan. Every error is a preflight refusal, never a silent drop.
func BuildEFSCreate(environment, capability string,
	attrs, impl map[string]any, generation int) (EFSPlan, error) {
	p := EFSPlan{
		CreationToken: "groundhold-" + letterHash(environment+"|"+capability+genSuffix(generation), 24),
		Encrypted:     true, // EFS is created encrypted; false is refused below
	}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// region is the driver scope (createScope); nothing to place in the body.
		case "protocol":
			proto, _ := raw.(string)
			if err := nfsProtocolOKAWS(proto); err != nil {
				return EFSPlan{}, err
			}
		case "availability.class":
			switch raw {
			case "zonal":
				p.OneZone = true
			case "regional":
				p.OneZone = false
			default:
				return EFSPlan{}, fmt.Errorf(
					"availability.class %v has no EFS mapping (zonal|regional)", raw)
			}
		case "encryption.atRest":
			if raw != true {
				return EFSPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by EFS (created encrypted)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyId, _ = impl["kms_key_id"].(string)
				if p.KmsKeyId == "" {
					return EFSPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_id")
				}
			}
		case "service.managed":
			if raw != true {
				return EFSPlan{}, fmt.Errorf("service.managed=false cannot be honored by EFS")
			}
		default:
			return EFSPlan{}, fmt.Errorf(
				"attribute %s has no EFS mapping — refusing rather than silently dropping it "+
					"(capacity/throughput are elastic, mount targets are topology)", path)
		}
	}
	// One Zone storage is placed in a single AZ — that AZ is topology (impl).
	if p.OneZone {
		p.AvailabilityZone, _ = impl["availability_zone"].(string)
		if p.AvailabilityZone == "" {
			return EFSPlan{}, fmt.Errorf(
				"availability.class=zonal (One Zone) requires implementation.availability_zone " +
					"(One Zone storage lives in a single AZ)")
		}
	}
	return p, nil
}

// createBody is the CreateFileSystem JSON body. Ownership is tags.
func (p EFSPlan) createBody(capability, environment string) map[string]any {
	body := map[string]any{
		"CreationToken":   p.CreationToken,
		"Encrypted":       p.Encrypted,
		"PerformanceMode": "generalPurpose",
		"Tags": []any{
			map[string]any{"Key": "groundhold-capability", "Value": sanitizeTag(capability)},
			map[string]any{"Key": "groundhold-environment", "Value": sanitizeTag(environment)},
		},
	}
	if p.KmsKeyId != "" {
		body["KmsKeyId"] = p.KmsKeyId
	}
	if p.OneZone {
		body["AvailabilityZoneName"] = p.AvailabilityZone
	}
	return body
}
