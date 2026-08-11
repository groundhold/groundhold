// AMI network shell (D370): auth, HTTP and the reverse mapping. No semantics
// here — those are in ami.go.
//
// There is no mutation shell, because there is nothing to mutate: this is a
// witness driver (D177). The usual D29 create/delete honesty rules therefore have
// nothing to apply to, and the adversarial mutation harness has no operations to
// fault-inject. What replaces them is the read discipline, which is the only
// discipline a witness has: every fact is either MEASURED from the API or
// reported UNREAD, and nothing in between.
//
// Two reads are needed for one image. DescribeImages gives the sharing state and
// names the backing snapshot; the encryption pair lives on the SNAPSHOT, not on
// the image. When the second read fails, the encryption attributes are unread —
// not `false`, which would fail a CMK constraint reality may satisfy, and not
// `true`, which would pass one reality violates.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"groundhold/internal/provider"
)

// amiIDOK bounds an image id before it reaches a request.
var amiIDOK = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)

// amiProviderID is region-scoped: an AMI id is unique per region, and the same
// image copied to another region is a DIFFERENT AMI with its own id and its own
// sharing state — which is exactly why the region belongs in the identity.
func amiProviderID(region, account, id string) string {
	return "ami:" + region + ":" + account + ":" + id
}

func splitAMIProviderID(providerID string) (region, account, id string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "ami" {
		return "", "", "", fmt.Errorf("providerId %q is not an ami id (want ami:<region>:<account>:<ami-...>)", providerID)
	}
	region, account, id = parts[1], parts[2], parts[3]
	if region == "" || !amiIDOK.MatchString(id) {
		return "", "", "", fmt.Errorf("providerId %q has no valid region/image id", providerID)
	}
	return region, account, id, nil
}

// amiImage is the slice of DescribeImages this driver reads.
type amiImage struct {
	ImageID     string
	Public      bool
	SnapshotIDs []string
}

// describeAMIs runs a DescribeImages query. An empty result with no error means
// the API answered and the image is not there — different from "the read failed".
func (d *Driver) describeAMIs(region string, extra map[string]string) ([]amiImage, error) {
	params := map[string]string{"Action": "DescribeImages", "Version": ec2Version}
	for k, v := range extra {
		params[k] = v
	}
	st, body, err := d.ec2PostBase(region, encodeForm(params))
	if err != nil {
		return nil, readTransport("DescribeImages", err)
	}
	if st == http.StatusBadRequest && strings.Contains(ec2ErrCode(body), "NotFound") {
		return nil, nil
	}
	if st != http.StatusOK {
		return nil, readHTTP("DescribeImages", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			ImageID  string `xml:"imageId"`
			IsPublic bool   `xml:"isPublic"`
			Devices  []struct {
				SnapshotID string `xml:"ebs>snapshotId"`
			} `xml:"blockDeviceMapping>item"`
		} `xml:"imagesSet>item"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return nil, readBody("DescribeImages", st)
	}
	out := make([]amiImage, 0, len(resp.Items))
	for _, it := range resp.Items {
		img := amiImage{ImageID: it.ImageID, Public: it.IsPublic}
		for _, dev := range it.Devices {
			if dev.SnapshotID != "" {
				img.SnapshotIDs = append(img.SnapshotIDs, dev.SnapshotID)
			}
		}
		out = append(out, img)
	}
	return out, nil
}

// amiSnapshot is the slice of DescribeSnapshots the encryption attributes need.
type amiSnapshot struct {
	Encrypted bool
	KmsKeyID  string
}

func (d *Driver) describeAMISnapshot(region, snapshotID string) (amiSnapshot, bool, error) {
	st, body, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeSnapshots", "Version": ec2Version, "SnapshotId.1": snapshotID,
	}))
	if err != nil {
		return amiSnapshot{}, false, readTransport("DescribeSnapshots", err)
	}
	if st == http.StatusBadRequest && strings.Contains(ec2ErrCode(body), "NotFound") {
		return amiSnapshot{}, false, nil
	}
	if st != http.StatusOK {
		return amiSnapshot{}, false, readHTTP("DescribeSnapshots", st, awsErrCodeOf(body))
	}
	var resp struct {
		Items []struct {
			Encrypted bool   `xml:"encrypted"`
			KmsKeyID  string `xml:"kmsKeyId"`
		} `xml:"snapshotSet>item"`
	}
	if xml.Unmarshal(body, &resp) != nil {
		return amiSnapshot{}, false, readBody("DescribeSnapshots", st)
	}
	if len(resp.Items) == 0 {
		return amiSnapshot{}, false, nil
	}
	return amiSnapshot{Encrypted: resp.Items[0].Encrypted, KmsKeyID: resp.Items[0].KmsKeyID}, true, nil
}

// observeAMI is the whole driver. Every fact is measured or unread.
func (d *Driver) observeAMI(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, id, err := splitAMIProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	imgs, rerr := d.describeAMIs(region, map[string]string{"ImageId.1": id})
	if rerr != nil {
		return nil, nil, rerr
	}
	if len(imgs) == 0 {
		// F-LC3 (D521): a BOUND resource the API says is GONE. A diagnostic
		// alone leaves the binding a no-op forever (D513).
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"image not found — bound resource is gone (will re-create)"}, nil
	}
	img := imgs[0]
	obs := []provider.Observation{
		// Present: clear the marker (F-LC3), or a stale "gone" survives a re-create.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		// `isPublic` is the account-level sharing state: true means any AWS account
		// can launch it, and anything baked into the image is readable with it.
		{Path: "network.publicExposure", Value: img.Public, Derivation: "measured"},
	}
	// sourceProvenance has NO field in the EC2 API. Emitting false would state as
	// measured fact that the image has no attestation, when the truth is that this
	// driver cannot see one — so a constraint on it stays `unknown` and blocks,
	// which is the honest outcome.
	unread := []string{
		"sourceProvenance unread — the EC2 API exposes no build attestation for an AMI; " +
			"a constraint on it cannot be proven from here",
	}
	if len(img.SnapshotIDs) == 0 {
		unread = append(unread, "image reported no backing snapshot — encryption unread")
		return obs, unread, nil
	}
	snap, found, serr := d.describeAMISnapshot(region, img.SnapshotIDs[0])
	switch {
	case serr != nil:
		unread = append(unread, "image encryption unread: "+serr.Error())
	case !found:
		unread = append(unread, "backing snapshot "+img.SnapshotIDs[0]+" not found — encryption unread")
	default:
		obs = append(obs, provider.Observation{
			Path: "encryption.atRest", Value: snap.Encrypted, Derivation: "measured"})
		// An AWS-managed default key is NOT customer-managed: reporting true here
		// would certify a BYOK control the customer cannot revoke — and an image is
		// copied and shared far more readily than the disk it came from.
		obs = append(obs, provider.Observation{
			Path:       "encryption.customerManagedKeys",
			Value:      snap.Encrypted && snap.KmsKeyID != "" && !isAWSManagedKMSKey(snap.KmsKeyID, "ebs"),
			Derivation: "measured"})
	}
	return obs, unread, nil
}

// discoverAMIs enumerates the images this ACCOUNT owns. Owner=self is the whole
// filter and it is load-bearing: without it DescribeImages returns every public
// AMI on the internet, which is not an estate anybody is accountable for.
func (d *Driver) discoverAMIs(region string) ([]provider.Discovered, []string, error) {
	account, err := d.discoverAccount()
	if err != nil {
		return nil, nil, fmt.Errorf("ami: %v", err)
	}
	imgs, rerr := d.describeAMIs(region, map[string]string{"Owner.1": "self"})
	if rerr != nil {
		return nil, nil, rerr
	}
	var out []provider.Discovered
	var diags []string
	for _, img := range imgs {
		if img.ImageID == "" {
			continue
		}
		pid := amiProviderID(region, account, img.ImageID)
		obs, odiags, oerr := d.observeAMI("", pid)
		if oerr != nil {
			diags = append(diags, img.ImageID+": "+oerr.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, img.ImageID+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.compute.image",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}
