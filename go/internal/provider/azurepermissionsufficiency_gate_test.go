package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1014. The AWS permission-sufficiency gate (D846-D853) confronts the permissions the
// drivers DECLARE against the operations they actually CALL, so an operation whose
// permission is declared NOWHERE cannot pass the preflight and wall mid-apply. GCP and
// Azure had no such gate — their declarations rested on hand-tracing, and the azurecdn
// Front Door composite writes five child ARM types (afdEndpoints, routes, originGroups,
// origins, customDomains) whose permissions are declared nowhere, so an identity without
// them passes the preflight and leaves a half-built, non-serving Front Door.
//
// Azure needs no external authority table: an ARM permission is a pure function of the
// request's (method, resource-type path). A PUT to
// .../Microsoft.Cdn/profiles/{}/afdEndpoints/{} needs Microsoft.Cdn/profiles/afdEndpoints/
// write; a DELETE needs .../delete; a POST action .../{}/lock needs .../lock/action. The
// subject is the SAME captured route file the reality gate uses (D1014,
// internal/azure/testdata/azure-routes.txt), so a driver that starts calling a new ARM
// type is covered the moment the capture records it.
//
// Like the AWS gate this asks only whether a needed permission is declared SOMEWHERE in
// the Azure tables (a global set), not on the exactly-right arm — the arm-precision half
// is D1013's concern. A mutation whose permission is in NEITHER the tables NOR the
// recorded-gap register is an undeclared operation the preflight would pass.
func TestAzureDeclaredPermissionsCoverTheMutationsTheDriversCall(t *testing.T) {
	root := repoRoot(t)

	// --- the mutations the drivers call (captured) -> the permission each needs ---
	blob, err := os.ReadFile(filepath.Join(root, "go", "internal", "azure", "testdata", "azure-routes.txt"))
	if err != nil {
		t.Fatalf("read azure-routes.txt: %v (refresh with "+
			"GROUNDHOLD_ROUTE_CAPTURE=testdata/azure-routes.txt go test ./internal/azure/)", err)
	}
	needed := map[string]string{} // permission -> the route that needs it (for the message)
	mutations := 0
	for _, line := range strings.Split(strings.TrimSpace(string(blob)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			continue
		}
		method, typePath := parts[0], parts[1]
		perm, ok := azurePermissionFor(method, typePath)
		if !ok {
			continue // GET/read — not a mutation; observe/ownership reads fail closed
		}
		mutations++
		if _, seen := needed[perm]; !seen {
			needed[perm] = method + " " + typePath
		}
	}
	// The gate stops meaning anything if the capture shrinks to nothing (D328).
	if mutations < 60 {
		t.Fatalf("only %d mutation routes derived from azure-routes.txt — the capture or the "+
			"derivation stopped matching its subject", mutations)
	}

	// --- the permissions the Azure tables DECLARE (a global set, like AWS) ---
	// Two Azure-specific shapes the extraction must honour, or it invents false gaps:
	//   - WILDCARD: the dnsrecord arm declares Microsoft.Network/dnsZones/*/write, one
	//     grant for every record type; it covers the concrete .../CNAME/write a driver
	//     builds. Kept as a pattern and matched by segment.
	//   - BASE CONCATENATION: the dnszone arm builds `base + "delete"` from a base literal
	//     that ends in "/", so no full "...dnsZones/delete" string exists to scrape. Every
	//     "Microsoft.X/.../"-suffixed literal is a base; expand it with the verbs.
	// Matching is CASE-INSENSITIVE because ARM permissions are (the tables spell one type
	// "Microsoft.Cache/Redis" and another "Microsoft.Cache/redis"; RBAC treats them alike).
	src, err := os.ReadFile(filepath.Join(root, "go", "internal", "provider", "provider.go"))
	if err != nil {
		t.Fatalf("read provider.go: %v", err)
	}
	declaredExact := map[string]bool{} // lowercased full permissions (may contain *)
	var declaredWild [][]string        // lowercased wildcard perms, pre-split by /
	add := func(perm string) {
		p := strings.ToLower(perm)
		declaredExact[p] = true
		if strings.Contains(p, "*") {
			declaredWild = append(declaredWild, strings.Split(p, "/"))
		}
	}
	for _, m := range regexp.MustCompile(`"(Microsoft\.[A-Za-z0-9]+/[A-Za-z0-9/*]+/(?:read|write|delete|action))"`).
		FindAllStringSubmatch(string(src), -1) {
		add(m[1])
	}
	// base prefixes: "Microsoft.X/type/.../" (ends in a slash) -> base+{read,write,delete}
	for _, m := range regexp.MustCompile(`"(Microsoft\.[A-Za-z0-9]+(?:/[A-Za-z0-9]+)+/)"`).
		FindAllStringSubmatch(string(src), -1) {
		for _, verb := range []string{"read", "write", "delete"} {
			add(m[1] + verb)
		}
	}
	if len(declaredExact) < 40 {
		t.Fatalf("only %d Azure permissions found in provider.go — the extraction stopped "+
			"matching its subject", len(declaredExact))
	}
	covers := func(perm string) bool {
		p := strings.ToLower(perm)
		if declaredExact[p] {
			return true
		}
		want := strings.Split(p, "/")
		for _, w := range declaredWild {
			if len(w) != len(want) {
				continue
			}
			match := true
			for i := range w {
				if w[i] != "*" && w[i] != want[i] {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
		return false
	}

	// --- recorded-gap register: mutations whose permission is knowingly undeclared, each
	// a fail-loud gap (the op 403s and apply reports failed, so it is not the dangerous
	// silent-success class the freeze admits), banked for the next unfreeze. The gate
	// asserts the uncovered set EQUALS this register — a new gap fails, and a gap that is
	// fixed and left here fails too. ---
	recordedGaps := map[string]string{
		"Microsoft.Cdn/profiles/afdEndpoints/write":         "D1014: azurecdn Front Door endpoint write, undeclared (fail-loud, half-built Front Door)",
		"Microsoft.Cdn/profiles/afdEndpoints/routes/write":  "D1014: azurecdn Front Door route write, undeclared",
		"Microsoft.Cdn/profiles/originGroups/write":         "D1014: azurecdn Front Door origin-group write, undeclared",
		"Microsoft.Cdn/profiles/originGroups/origins/write": "D1014: azurecdn Front Door origin write, undeclared",
		"Microsoft.Cdn/profiles/customDomains/write":        "D1014: azurecdn Front Door custom-domain write, undeclared",
		// D1017: the 6th child type, reached ONLY on the BYO Key Vault certificate branch a
		// managed cert never takes. A completeness-critic found it uncaptured (the gate was
		// blind); TestCreateAzureCDNBYOCertWritesSecret now drives the branch so the route is
		// captured and this gap is visible and held.
		"Microsoft.Cdn/profiles/secrets/write": "D1017: azurecdn Front Door BYO-cert secret write, undeclared",
	}

	var uncovered []string
	for perm, route := range needed {
		if covers(perm) {
			continue
		}
		if _, known := recordedGaps[perm]; known {
			continue
		}
		uncovered = append(uncovered, perm+"  (called by "+route+")")
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Errorf("%d Azure mutation permission(s) declared NOWHERE in the tables and not in the "+
			"recorded-gap register:\n  %s\n\nThe preflight passes and the denial lands mid-apply. "+
			"Declare the permission on the capability's arm, or (if it is a fail-loud gap that the "+
			"freeze does not admit fixing yet) register it with its reason.",
			len(uncovered), strings.Join(uncovered, "\n  "))
	}
	// A register entry that no captured route needs any more is stale — drop it.
	for perm := range recordedGaps {
		if _, ok := needed[perm]; !ok {
			t.Errorf("recorded-gap register entry %q covers no captured mutation any more — drop it", perm)
		}
	}
}

// azurePermissionFor derives the ARM permission a (method, resource-type path) needs.
// The type path keeps type segments and marks instance names {} (azureRouteRecord). A
// path ending in {} is an INSTANCE operation (write/delete/read); a POST whose last
// segment is a bare verb after a {} is an ACTION (.../verb/action). GET is a read and is
// reported not-a-mutation (ok=false) — an undeclared read fails closed at observe, not
// the dangerous mid-apply-mutation class this gate covers.
func azurePermissionFor(method, typePath string) (string, bool) {
	segs := strings.Split(typePath, "/")
	// resourceType drops the {} name markers.
	rt := func(ss []string) string {
		var keep []string
		for _, s := range ss {
			if s != "{}" {
				keep = append(keep, s)
			}
		}
		return strings.Join(keep, "/")
	}
	last := segs[len(segs)-1]
	switch method {
	case "PUT", "PATCH":
		if last == "{}" {
			return rt(segs) + "/write", true
		}
		// a PUT/PATCH ending in a bare type (a collection) is still a write on that type
		return rt(segs) + "/write", true
	case "DELETE":
		return rt(segs) + "/delete", true
	case "POST":
		if last != "{}" && len(segs) >= 2 && segs[len(segs)-2] == "{}" {
			// .../{name}/<action> — an action on a named instance
			return rt(segs[:len(segs)-1]) + "/" + last + "/action", true
		}
		// a POST to a collection (create-or-list) — treat as a write on the type
		return rt(segs) + "/write", true
	default:
		return "", false // GET / HEAD — a read
	}
}
