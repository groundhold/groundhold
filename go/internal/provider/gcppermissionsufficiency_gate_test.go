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
	mutations := 0
	for _, line := range strings.Split(strings.TrimSpace(string(blob)), "\n") {
		parts := strings.Split(strings.TrimSpace(line), "\t")
		if len(parts) != 3 {
			continue
		}
		method, rawpath := parts[1], parts[2]
		resource, verb, ok := gcpResourceVerb(method, rawpath)
		if !ok {
			continue // a read, or a path with no resource to name
		}
		mutations++
		key := resource + "\t" + verb
		if _, seen := needed[key]; !seen {
			needed[key] = method + " " + rawpath
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

// gcpVerbFromCustom maps a GCP custom method (the ":verb" suffix, or a trailing action
// segment) to the permission verb it needs. A read-only probe returns "" (skip).
var gcpVerbFromCustom = map[string]string{
	"setIamPolicy":        "setIamPolicy",
	"getIamPolicy":        "",        // a read
	"testIamPermissions":  "",        // the preflight's own probe (D75)
	"getEffectivePolicy":  "",        // a read
	"destroy":             "destroy", // cloudkms key version
	"pause":               "pause",   // cloudscheduler job
	"enable":              "enable",  // serviceusage service
	"setAddons":           "update",  // gke cluster addon toggle
	"lockRetentionPolicy": "update",  // gcs bucket retention lock
	"restoreBackup":       "",        // the RTO probe's restore (double-consented, D59)
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

// gcpResourceVerb derives the (resource, verb) a GCP mutation needs, or ok=false for a read
// or an unrecognisable path. The path is /projects/{p}/.../<collection>[/{name}[:verb]] or a
// collection create /projects/{p}/.../<collection>; nested collections and zone/region/
// location prefixes are context. GET is a read; POST is a create unless it carries a custom
// verb (":verb" or a known trailing-action segment).
func gcpResourceVerb(method, rawpath string) (string, string, bool) {
	path := rawpath
	if i := strings.Index(path, "://"); i >= 0 {
		if s := strings.IndexByte(path[i+3:], '/'); s >= 0 {
			path = path[i+3+s:]
		}
	}
	path = strings.SplitN(path, "?", 2)[0]
	segs := strings.Split(strings.Trim(path, "/"), "/")
	if len(segs) == 0 || segs[0] == "" {
		return "", "", false
	}
	// A trailing "iam" sub-resource is an IAM-policy op on its parent (GCS spells
	// setIamPolicy as PUT /b/{bucket}/iam, not a ":verb"): drop it and let the method
	// decide (PUT/POST -> setIamPolicy, GET -> read).
	if segs[len(segs)-1] == "iam" && len(segs) >= 3 {
		if method == "GET" {
			return "", "", false
		}
		return remapGCPResource(segs[len(segs)-3]), "setIamPolicy", true
	}

	custom := ""
	if last := segs[len(segs)-1]; strings.Contains(last, ":") {
		nv := strings.SplitN(last, ":", 2)
		segs[len(segs)-1] = nv[0]
		custom = nv[1]
	} else if _, ok := gcpVerbFromCustom[last]; ok && len(segs) >= 2 {
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
		return resource(len(segs) - 2), "delete", true
	case "PATCH", "PUT":
		return resource(len(segs) - 2), "update", true
	case "POST":
		if custom != "" {
			verb, mapped := gcpVerbFromCustom[custom]
			if !mapped {
				verb = custom // an action we have not mapped: use it verbatim (fail loud in the gate)
			}
			if verb == "" {
				return "", "", false // a read/probe
			}
			return resource(len(segs) - 2), verb, true
		}
		// a collection create: the last segment is the resource type
		return resource(len(segs) - 1), "create", true
	default:
		return "", "", false // GET / HEAD — a read
	}
}
