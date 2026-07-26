// AMI observation (D370): the AWS half of capability.compute.image — a machine
// image as a governed capability, and the first CLOUD driver that is a WITNESS
// rather than an author (D177).
//
// There is no create here, and that is the design rather than a gap. Images are
// BUILT, and building is a pipeline concern with its own review — Packer, a CI
// job, a golden-image process. A driver that "creates an image" would either be a
// thin wrapper over someone else's build or an invitation to move build logic
// into an infrastructure contract. So the contract states what must be TRUE of
// the image a machine boots, `observe` proves it against the image that exists,
// and the compiler records the capability as `witnessed` instead of emitting an
// action that would be refused at apply.
//
// That is not weaker governance. "Is our base image public?" is a question most
// estates cannot answer, and it is one `verify` answers deterministically. An AMI
// is a blob that outlives the pipeline that made it, gets copied between regions,
// and is shared by an account setting nobody re-reads.
//
// sourceProvenance is DELIBERATELY NOT EMITTED. The EC2 API has no field for a
// build attestation — none. Reporting `false` would state as measured fact that
// an image has no provenance when the truth is that this driver cannot see one,
// and reporting `true` would be an outright fabrication. So the attribute is left
// unobserved with a diagnostic saying why, which leaves any hard constraint on it
// `unknown` and BLOCKS the plan. Refusing to answer is the correct answer when
// the answer is not available, and a blocked plan is how the operator finds out.
package aws

import (
	"fmt"

	"groundhold/internal/provider"
)

// amiWitnessServices is the set of AWS service tokens that groundhold OBSERVES
// but never authors. It is a set rather than a bare comparison because the
// witness predicate is registered once for the whole provider (D177) and every
// future observe-only AWS service belongs in exactly this place.
var amiWitnessServices = map[string]bool{
	"ami": true,
}

// init teaches the compiler which AWS services are WITNESS-only, so it emits no
// create for them and records them as `witnessed` instead (D177).
//
// This is the FIRST time a cloud driver registers a predicate: until now the
// clouds relied on the fail-OPEN default (an unregistered provider authors
// everything), which was correct while everything they observed they also
// created. Registering makes the AWS answer explicit and per-service — `ami` is a
// witness, every other AWS token still authors — and the test below pins both
// halves, because a predicate that accidentally returned true for its whole
// provider would silently stop groundhold creating anything on AWS.
func init() {
	provider.RegisterWitnessPredicate("aws", func(service string) bool {
		return amiWitnessServices[service]
	})
}

// classifyAMIChange (D46): PURE — can a capability.compute.image transition be
// honored in place?
//
// Nothing here is patchable, because nothing here is AUTHORED. An image is
// witnessed: the way to change what a contract observes is to build a different
// image and point the machine at it, which is a pipeline action and a change to
// the machine's operands — not a mutation groundhold performs on this resource.
// Saying `unsupported` with that reason is more useful than `immutable`, which
// would imply groundhold could have created it differently.
func classifyAMIChange(path string) (string, string) {
	switch path {
	case "location.region", "network.publicExposure", "encryption.atRest",
		"encryption.customerManagedKeys", "sourceProvenance", "service.managed":
		return "unsupported", "an image is witnessed, not authored (D177) — groundhold observes it and never changes it; build a new image and point the machine at it"
	}
	return "", ""
}

// errWitnessOnly is the refusal every author-shaped entry point returns for a
// witness service. One function so the wording cannot drift between the create
// path, the delete path and validation — three places that must say the same
// thing, because an operator who hits one of them will not hit the others.
func errWitnessOnly(service, capType string) error {
	return fmt.Errorf(
		"aws/%s is a WITNESS service: groundhold observes %s and never authors it (D177). "+
			"Build the image in the pipeline that owns it and point the machine's "+
			"implementation at the result; the contract still verifies what must be true of it",
		service, capType)
}
