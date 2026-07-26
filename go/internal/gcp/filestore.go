// GCP Filestore request building (D111): the semantic core of the GCP
// capability.storage.filesystem driver — the SAME vocabulary AWS EFS and Azure
// Files fulfil. Filestore is a managed regional NFS file share. It speaks NFS
// only, so protocol smb/N is an honest refusal here (SMB has no managed GCP
// twin), not a config toggle. Async create/delete via LRO (like Cloud SQL /
// Memorystore). Capacity GiB, tier sizing and the mount network are
// implementation detail; residency, protocol, availability and CMEK are the
// capability.
package gcp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const filestoreBaseURL = "https://file.googleapis.com/v1"

// fsLocationOK bounds a Filestore location before it is interpolated into an
// instance URL (D73 boundary): a region (europe-west1) or a zone (europe-west1-b).
var fsLocationOK = regexp.MustCompile(`^[a-z]+-[a-z]+[0-9](-[a-z])?$`)

// FilestorePlan is the attribute-derived shape a create assembles into the
// instance body.
type FilestorePlan struct {
	Name       string
	Location   string // region or zone (verbatim from location.region)
	Tier       string // BASIC_HDD (zonal) | ENTERPRISE (regional)
	ShareName  string
	CapacityGb int    // sizing (impl), default 1024 (BASIC_HDD minimum)
	Network    string // the VPC to attach (impl); default "default"
	KmsKey     string // CMEK, from impl; "" = provider-managed
}

// nfsProtocolOK accepts nfs/N and REFUSES smb/N (no managed GCP SMB filesystem).
func nfsProtocolOK(protocol string) error {
	engine, _, ok := strings.Cut(protocol, "/")
	switch {
	case !ok:
		return fmt.Errorf("protocol %q is not a protocol/version (e.g. nfs/4.1)", protocol)
	case strings.ToLower(engine) == "nfs":
		return nil
	case strings.ToLower(engine) == "smb":
		return fmt.Errorf(
			"protocol smb cannot be honored by Filestore (GCP has no managed SMB " +
				"filesystem — that is AWS FSx for Windows) — refusing rather than mis-provisioning")
	default:
		return fmt.Errorf("protocol %q has no Filestore mapping (nfs/N only)", protocol)
	}
}

// BuildFilestoreCreate maps capability.storage.filesystem attributes + the impl
// block to a Filestore create plan. Every error is a refusal apply surfaces in
// preflight, before any mutation — never a silently dropped attribute.
func BuildFilestoreCreate(project, environment, capability string,
	attrs, impl map[string]any, generation int) (FilestorePlan, error) {
	p := FilestorePlan{
		Name:       resourceName(project, environment, capability, generation, 63),
		Tier:       "BASIC_HDD", // zonal baseline unless availability says otherwise
		ShareName:  "share1",
		CapacityGb: 1024,
		Network:    "default",
	}
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Location, _ = raw.(string)
		case "protocol":
			proto, _ := raw.(string)
			if err := nfsProtocolOK(proto); err != nil {
				return FilestorePlan{}, err
			}
		case "availability.class":
			switch raw {
			case "zonal":
				p.Tier = "BASIC_HDD"
			case "regional":
				p.Tier = "ENTERPRISE"
			default:
				return FilestorePlan{}, fmt.Errorf(
					"availability.class %v has no Filestore mapping (zonal|regional)", raw)
			}
		case "encryption.atRest":
			if raw != true {
				return FilestorePlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored by Filestore (always encrypted at rest)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKey, _ = impl["kms_key_name"].(string)
				if p.KmsKey == "" {
					return FilestorePlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_name")
				}
			}
		case "service.managed":
			if raw != true {
				return FilestorePlan{}, fmt.Errorf("service.managed=false cannot be honored by Filestore")
			}
		default:
			return FilestorePlan{}, fmt.Errorf(
				"attribute %s has no Filestore mapping — refusing rather than silently dropping it "+
					"(capacity GiB, tier, mount network are implementation sizing/topology)", path)
		}
	}
	if p.Location == "" {
		return FilestorePlan{}, fmt.Errorf("filesystem requires location.region")
	}
	if !fsLocationOK.MatchString(p.Location) {
		return FilestorePlan{}, fmt.Errorf("location %q is not a valid region/zone", p.Location)
	}
	if !projectOK.MatchString(project) {
		return FilestorePlan{}, fmt.Errorf("project %q is invalid", project)
	}
	if n, ok := impl["network"].(string); ok && n != "" {
		p.Network = n
	}
	// capacity is sizing (impl); accept an override, default 1024GiB.
	if c, ok := impl["capacity_gb"]; ok {
		switch v := c.(type) {
		case float64:
			p.CapacityGb = int(v)
		case int:
			p.CapacityGb = v
		case string:
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				return FilestorePlan{}, fmt.Errorf("implementation.capacity_gb %q is not a positive integer", v)
			}
			p.CapacityGb = n
		}
	}
	if p.CapacityGb < 1 {
		p.CapacityGb = 1024
	}
	return p, nil
}

// createBody is the instances.create request body. Ownership is labels; the
// share is NFS and always encrypted at rest.
func (p FilestorePlan) createBody(capability, environment string) map[string]any {
	body := map[string]any{
		"tier": p.Tier,
		"fileShares": []any{
			map[string]any{"name": p.ShareName, "capacityGb": p.CapacityGb},
		},
		"networks": []any{
			map[string]any{"network": p.Network, "modes": []any{"MODE_IPV4"}},
		},
		"labels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	if p.KmsKey != "" {
		body["kmsKeyName"] = p.KmsKey
	}
	return body
}
