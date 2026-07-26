// Azure managed image observation (D370): the Azure third of
// capability.compute.image — the SAME vocabulary an AMI and a Compute Engine
// image fulfil, and a WITNESS rather than an author (D177).
//
// There is no create here, and that is the design rather than a gap. Images are
// BUILT, and building is a pipeline concern with its own review. The contract
// states what must be TRUE of the image a machine boots; `observe` proves it; the
// compiler records the capability as `witnessed` and emits no action.
//
// The interesting difference from both twins is `network.publicExposure`. An AMI
// carries an account-level sharing flag; a Compute Engine image carries an IAM
// policy. A Microsoft.Compute/images resource carries NEITHER, because it cannot
// be shared outside its subscription at all — cross-tenant sharing on Azure lives
// in a Compute Gallery, which is a different resource type.
//
// So the attribute is reported `false` with derivation CONFIG-INTENT, not
// `measured`. The distinction is the whole point of having derivations: `measured`
// would claim this driver looked at a sharing setting and found it off, when what
// actually happened is that the resource has no such setting to look at. The
// value is true of the platform; it is not a reading. An operator who later asks
// "how do we know?" gets an honest answer either way, and only one of them
// survives the question.
//
// sourceProvenance is DELIBERATELY NOT EMITTED, exactly as on the other two
// clouds. A gallery image VERSION can be signed; a managed image cannot, and this
// driver reads managed images.
package azure

import (
	"fmt"

	"groundhold/internal/provider"
)

// azureWitnessServices is the set of Azure service tokens that groundhold
// OBSERVES but never authors. A set rather than a bare comparison because the
// witness predicate is registered once for the whole provider (D177), and every
// future observe-only Azure service belongs in exactly this place.
var azureWitnessServices = map[string]bool{
	"azimage": true,
}

// init teaches the compiler which Azure services are WITNESS-only, so it emits no
// create for them and records them as `witnessed` instead (D177). Per-service and
// narrow: `azimage` is a witness, every other Azure token still authors.
func init() {
	provider.RegisterWitnessPredicate("azure", func(service string) bool {
		return azureWitnessServices[service]
	})
}

// errWitnessOnlyAzure is the refusal every author-shaped entry point returns for
// a witness service. One function so the wording cannot drift between the create
// path, the delete path and validation.
func errWitnessOnlyAzure(service string) error {
	return fmt.Errorf(
		"azure/%s is a WITNESS service: groundhold observes it and never authors it (D177). "+
			"Build the image in the pipeline that owns it and point the machine's "+
			"implementation at the result; the contract still verifies what must be true of it",
		service)
}

// classifyAzureImageChange (D46): PURE. Nothing here is patchable because nothing
// here is AUTHORED. `unsupported` rather than `immutable`: immutable would imply
// groundhold could have created the image differently, and it never creates one.
func classifyAzureImageChange(path string) (string, string) {
	switch path {
	case "location.region", "network.publicExposure", "encryption.atRest",
		"encryption.customerManagedKeys", "sourceProvenance", "service.managed":
		return "unsupported", "an image is witnessed, not authored (D177) — groundhold observes it and never changes it; build a new image and point the machine at it"
	}
	return "", ""
}
