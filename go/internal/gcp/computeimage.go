// Compute Engine image observation (D370): the GCP half of
// capability.compute.image — the SAME vocabulary an AMI fulfils, and a WITNESS
// rather than an author (D177).
//
// There is no create here, and that is the design rather than a gap. Images are
// BUILT, and building is a pipeline concern with its own review. The contract
// states what must be TRUE of the image a machine boots; `observe` proves it
// against the image that exists; the compiler records the capability as
// `witnessed` and emits no action.
//
// Two things differ from the AWS twin, and both come from the cloud rather than
// from the vocabulary:
//
//   - Images are GLOBAL on GCP. There is no per-region copy with its own id and
//     its own sharing state, so the providerId carries no region and
//     `location.region` is reported from `storageLocations` — where the bytes
//     actually sit, which is the residency question the attribute asks.
//   - Public exposure is an IAM POLICY, not a field on the resource. Reading it
//     is a second call, and when that call fails the attribute is unread rather
//     than `false` — a silent false passes an "is our base image private?"
//     constraint on an image the whole internet can launch.
//
// sourceProvenance is DELIBERATELY NOT EMITTED, exactly as on AWS. Binary
// Authorization attestations exist, but they are attached to container images and
// evaluated at admission — not readable from a Compute image resource. Reporting
// `false` would state as measured fact that the image has no provenance when the
// truth is that this driver cannot see one.
package gcp

import (
	"fmt"

	"groundhold/internal/provider"
)

// gcpWitnessServices is the set of GCP service tokens that groundhold OBSERVES
// but never authors. A set rather than a bare comparison because the witness
// predicate is registered once for the whole provider (D177), and every future
// observe-only GCP service belongs in exactly this place.
var gcpWitnessServices = map[string]bool{
	"computeimage": true,
}

// init teaches the compiler which GCP services are WITNESS-only, so it emits no
// create for them and records them as `witnessed` instead (D177). Per-service and
// narrow: `computeimage` is a witness, every other GCP token still authors.
func init() {
	provider.RegisterWitnessPredicate("gcp", func(service string) bool {
		return gcpWitnessServices[service]
	})
}

// errWitnessOnlyGCP is the refusal every author-shaped entry point returns for a
// witness service. One function so the wording cannot drift between the create
// path, the delete path and validation.
func errWitnessOnlyGCP(service string) error {
	return fmt.Errorf(
		"gcp/%s is a WITNESS service: groundhold observes it and never authors it (D177). "+
			"Build the image in the pipeline that owns it and point the machine's "+
			"implementation at the result; the contract still verifies what must be true of it",
		service)
}

// classifyComputeImageChange (D46): PURE. Nothing here is patchable because
// nothing here is AUTHORED. `unsupported` rather than `immutable`: immutable
// would imply groundhold could have created the image differently, and it never
// creates one at all.
func classifyComputeImageChange(path string) (string, string) {
	switch path {
	case "location.region", "network.publicExposure", "encryption.atRest",
		"encryption.customerManagedKeys", "sourceProvenance", "service.managed":
		return "unsupported", "an image is witnessed, not authored (D177) — groundhold observes it and never changes it; build a new image and point the machine at it"
	}
	return "", ""
}
