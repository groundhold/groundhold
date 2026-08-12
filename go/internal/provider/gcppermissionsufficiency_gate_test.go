package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1015. The last of the three permission-sufficiency gates (AWS D846-D853, Azure D1014).
// GCP declares permissions as "<service>.<resource>.<verb>" and preflights them before the
// lease; a mutation whose permission is declared NOWHERE passes the preflight and walls
// mid-apply. This confronts the mutations the drivers CALL (the captured gcp-routes.txt,
// D718) against what they DECLARE.
//
// GCP's route file cannot name the SERVICE cleanly the way Azure's ARM path does: the
// capture records a path plus the base-URL FIELD, and the drivers share a fixture host, so
// ~75 mutation routes come back AMBIGUOUS across two dozen fields; worse, one resource name
// is several services (locations/{}/instances is BOTH memorystore and filestore). So this
// gate matches on the (RESOURCE, VERB) pair rather than the full triple. That is exactly
// the power the AWS and Azure gates already have — "declared somewhere" — because a GCP
// resource name is 1:1 with its service for every resource but the shared `instances`, and
// a mutation on a resource/verb no service declares is the drift this catches (a driver
// that starts writing a new child type nobody granted).
func TestGCPDeclaredPermissionsCoverTheMutationsTheDriversCall(t *testing.T) {
	root := repoRoot(t)

	// --- declared: index every "<svc>.<resource>.<verb>" by its (resource, verb) ---
	src, err := os.ReadFile(filepath.Join(root, "go", "internal", "provider", "provider.go"))
	if err != nil {
		t.Fatalf("read provider.go: %v", err)
	}
	declaredRV := map[string]bool{} // "resource\tverb"
	for _, m := range regexp.MustCompile(`"([a-z][a-z0-9]+(?:\.[a-zA-Z0-9]+)+)"`).FindAllStringSubmatch(string(src), -1) {
		p := strings.Split(m[1], ".")
		if len(p) < 3 {
			continue // not a service.resource.verb permission
		}
		resource, verb := p[len(p)-2], p[len(p)-1]
		declaredRV[resource+"\t"+verb] = true
	}
	if len(declaredRV) < 40 {
		t.Fatalf("only %d GCP (resource,verb) pairs found in provider.go — the extraction stopped "+
			"matching its subject", len(declaredRV))
	}

	// --- the mutations the drivers call -> the (resource, verb) each needs ---
	blob, err := os.ReadFile(filepath.Join(root, "go", "internal", "gcp", "testdata", "gcp-routes.txt"))
	if err != nil {
		t.Fatalf("read gcp-routes.txt: %v", err)
	}
	needed := map[string]string{} // "resource\tverb" -> the route that needs it
	seenCustom := map[string]bool{}
	mutations := 0
	for _, line := range strings.Split(strings.TrimSpace(string(blob)), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "\t")
		if len(parts) != 3 {
			continue
		}
		method, rawpath := parts[1], parts[2]
		resource, verb, custom, ok := gcpResourceVerb(method, rawpath)
		if custom != "" {
			seenCustom[custom] = true
		}
		if !ok {
			continue // a read, or a path with no resource to name
		}
		mutations++
		key := resource + "\t" + verb
		if _, seen := needed[key]; !seen {
			needed[key] = method + " " + rawpath
		}
	}
	// D1018: the skip register is audited like AWS discoveryOnly — every exemption carries a
	// reason and is still exercised by a route; a dead one is dropped, so it cannot linger as
	// a channel that silently swallows a future write.
	for cv, reason := range gcpSkipVerbs {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("skip-verb %q has no reason — an unreasoned exemption is worse than none", cv)
		}
		if !seenCustom[cv] {
			t.Errorf("skip-verb %q is exercised by no captured route — a dead exemption, drop it", cv)
		}
	}
	if mutations < 50 {
		t.Fatalf("only %d GCP mutation routes derived from gcp-routes.txt — the capture or the "+
			"derivation stopped matching its subject", mutations)
	}

	// recorded-gap register: (resource,verb) a driver mutates but no permission declares —
	// each a fail-loud gap banked for the next unfreeze (empty today; GCP was clean).
	recordedGaps := map[string]string{}

	var uncovered []string
	for key, route := range needed {
		if declaredRV[key] {
			continue
		}
		if _, known := recordedGaps[key]; known {
			continue
		}
		rv := strings.Split(key, "\t")
		uncovered = append(uncovered, rv[0]+"."+rv[1]+"  (called by "+route+")")
	}
	sort.Strings(uncovered)
	if len(uncovered) > 0 {
		t.Errorf("%d GCP mutation (resource.verb) pair(s) no declared permission covers, and not "+
			"in the recorded-gap register:\n  %s\n\nThe preflight passes and the denial lands "+
			"mid-apply. Declare the permission, or register the gap with its reason.",
			len(uncovered), strings.Join(uncovered, "\n  "))
	}
	for key := range recordedGaps {
		if _, ok := needed[key]; !ok {
			t.Errorf("recorded-gap register entry %q covers no captured mutation any more — drop it", key)
		}
	}
}

// gcpWriteVerbs maps a GCP custom method (the ":verb" suffix, or a trailing action segment)
// to the permission verb the MUTATION needs.
var gcpWriteVerbs = map[string]string{
	"setIamPolicy":        "setIamPolicy",
	"destroy":             "destroy", // cloudkms key version
	"pause":               "pause",   // cloudscheduler job
	"enable":              "enable",  // serviceusage service
	"setAddons":           "update",  // gke cluster addon toggle
	"lockRetentionPolicy": "update",  // gcs bucket retention lock
}

// gcpSkipVerbs is the AUDITED counterpart (D1018): custom methods this gate deliberately
// does NOT treat as a plan-action mutation, each with the reason it is exempt. A "" mapping
// buried in the write table would silently swallow a real write; here a skip is a named
// decision, and the gate asserts every entry is BOTH reasoned AND still called by some route
// (a dead exemption is dropped) — the discipline the AWS discoveryOnly register already has.
// A custom verb in NEITHER table is used verbatim and fails the gate: an unclassified verb is
// never silently skipped.
var gcpSkipVerbs = map[string]string{
	"getIamPolicy":       "a read of the IAM policy, not a write",
	"testIamPermissions": "the preflight's OWN probe (D75), never a plan mutation",
	"getEffectivePolicy": "a read of the effective org policy, not a write",
	"restoreBackup":      "the RTO probe's restore into a scratch instance — intrusive, double-consented (D59), outside any plan action; the scratch CREATE is declared separately",
}

// gcpResourceRemap fixes the resource names whose URL segment differs from the IAM
// permission's resource token: the GCS JSON API addresses a bucket as /b/{bucket} but the
// permission is storage.buckets.*; a Certificate Manager cert is /certificates/{} but
// certificatemanager.certs.*; a log-based metric is /metrics/{} but logging.logMetrics.*.
var gcpResourceRemap = map[string]string{
	"b":            "buckets",
	"certificates": "certs",
	"metrics":      "logMetrics",
}

func remapGCPResource(r string) string {
	if rm, ok := gcpResourceRemap[r]; ok {
		return rm
	}
	return r
}

func gcpKnownCustom(v string) bool {
	if _, ok := gcpWriteVerbs[v]; ok {
		return true
	}
	_, ok := gcpSkipVerbs[v]
	return ok
}

// gcpResourceVerb derives the (resource, verb) a GCP mutation needs, or ok=false for a read
// or an unrecognisable path. It also returns the custom method it saw (":verb" or trailing
// action), "" if none, so the gate can assert the skip register has no dead entries. The path
// is /projects/{p}/.../<collection>[/{name}[:verb]] or a collection create; nested collections
// and zone/region/location prefixes are context. GET is a read; POST is a create unless it
// carries a custom verb, which must be classified in gcpWriteVerbs or gcpSkipVerbs — an
// unclassified one is used verbatim and fails the gate rather than being silently skipped.
func gcpResourceVerb(method, rawpath string) (resourceOut, verbOut, customOut string, ok bool) {
	path := rawpath
	if i := strings.Index(path, "://"); i >= 0 {
		if s := strings.IndexByte(path[i+3:], '/'); s >= 0 {
			path = path[i+3+s:]
		}
	}
	path = strings.SplitN(path, "?", 2)[0]
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) == 0 || segs[0] == "" {
		return "", "", "", false
	}
	// A trailing "iam" sub-resource is an IAM-policy op on its parent (GCS spells
	// setIamPolicy as PUT /b/{bucket}/iam, not a ":verb"): drop it and let the method
	// decide (PUT/POST -> setIamPolicy, GET -> read).
	if segs[len(segs)-1] == "iam" && len(segs) >= 3 {
		if method == "GET" {
			return "", "", "", false
		}
		return remapGCPResource(segs[len(segs)-3]), "setIamPolicy", "", true
	}

	custom := ""
	if last := segs[len(segs)-1]; strings.Contains(last, ":") {
		nv := strings.SplitN(last, ":", 2)
		segs[len(segs)-1] = nv[0]
		custom = nv[1]
	} else if gcpKnownCustom(last) && len(segs) >= 2 {
		// a trailing ACTION segment (lockRetentionPolicy, restoreBackup) — not a resource
		custom = last
		segs = segs[:len(segs)-1]
	}

	resource := func(i int) string {
		if i < 0 || i >= len(segs) {
			return ""
		}
		r := remapGCPResource(segs[i])
		// compute's global address / forwarding rule are distinct permission tokens from
		// their regional siblings; the /global/ scope segment before them is the tell.
		if (r == "addresses" || r == "forwardingRules") && i >= 1 && segs[i-1] == "global" {
			return "global" + strings.ToUpper(r[:1]) + r[1:]
		}
		return r
	}

	switch method {
	case "DELETE":
		return resource(len(segs) - 2), "delete", custom, true
	case "PATCH", "PUT":
		return resource(len(segs) - 2), "update", custom, true
	case "POST":
		if custom != "" {
			if v, ok := gcpWriteVerbs[custom]; ok {
				return resource(len(segs) - 2), v, custom, true
			}
			if _, ok := gcpSkipVerbs[custom]; ok {
				return "", "", custom, false // an audited read/probe
			}
			// an unclassified custom verb — verbatim, so the gate fails loudly on it
			return resource(len(segs) - 2), custom, custom, true
		}
		// a collection create: the last segment is the resource type
		return resource(len(segs) - 1), "create", "", true
	default:
		return "", "", custom, false // GET / HEAD — a read (custom carried for staleness)
	}
}
