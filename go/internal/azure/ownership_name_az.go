// D458 — ownership by NAME, for the Azure resources that have nowhere else to carry it.
//
// Most Azure resources take ARM tags, so a delete reads the resource and compares
// groundhold-capability/environment. A few do not: a subscription-scope diagnostic
// setting (activity-log export) and an EventGrid event subscription are name-only
// objects. For those the deterministic name IS the ownership evidence — the same answer
// AWS reached for budgets, IAM policies, metric filters, receipt rules and dashboards
// (D444-D449), and GCP for custom roles and asset feeds (D451).
//
// The Azure version can be exact rather than heuristic. azResourceName is
// content-addressed: prefix + slug + the first 8 hex of sha256(prefix|environment|
// capability[|gN]). So instead of pattern-matching a tail, this RE-DERIVES the name for
// each generation and demands an equality. A stranger's setting cannot collide unless
// they independently chose our prefix, our slug and our hash.
package azure

// azOwnedNameGenerations bounds the replacement generations (D48's -gN discriminator) a
// delete will recognise as its own. Past it the delete refuses rather than proceeds,
// which is the correct direction to fail: an unrecognised name is treated as someone
// else's, never as ours.
const azOwnedNameGenerations = 64

// azNameLooksOurs answers whether name is one this runtime would have minted for
// (prefix, environment, capability) at some generation.
func azNameLooksOurs(name, prefix, environment, capability string) bool {
	for g := 1; g <= azOwnedNameGenerations; g++ {
		if name == azResourceName(prefix, environment, capability, g) {
			return true
		}
	}
	return false
}
