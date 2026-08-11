package azure

import "testing"

// D526: four places in the drivers assert that a resource "at our name is ours by
// construction". That holds only if nobody else can compute the name — so this
// pins what actually goes into it.
//
// `azResourceName` hashes prefix|environment|capability[|gN] and nothing else. No
// subscription, no ledger, no deployment identity. Two independent groundhold
// deployments managing the same subscription, with the same capability id and
// environment, compute the SAME name — so a create that writes at that name
// without reading can overwrite the other one's resource, and the comment saying
// otherwise is an over-claim.
//
// The name is a good COLLISION-AVOIDANCE device and a poor ownership proof. This
// test exists so that if the inputs ever gain an estate identity, someone has to
// come here and say so deliberately.
func TestResourceNameCarriesNoEstateIdentity(t *testing.T) {
	const want = "pv-al-audit-prod-407f9735"
	if got := azResourceName("pv-al", "prod", "audit", 1); got != want {
		t.Fatalf("azResourceName = %q, want %q — the naming inputs changed. If an "+
			"estate identity was added, the 'ours by construction' claims in the "+
			"drivers may now be true; re-read them before updating this pin.", got, want)
	}
}
