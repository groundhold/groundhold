package gcp

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// D1009. A GCP create verb passes the new resource's id as a query parameter, and the API
// documents it in camelCase (`repositoryId`, `instanceId`, `keyRingId` …). One driver used
// snake_case `repository_id` — the lone exception among thirteen — and if the API ignored it
// and auto-named the resource, the create would land under a name the providerId (built from
// the intended id) does not match, so observe would read a live resource as ABSENT. An
// adversarial confrontation of the drivers against Google's own discovery docs found it. The
// convention is the discovery docs' own casing; this pins it so a new driver cannot
// reintroduce the snake_case that slipped through the whole driver set.
func TestGCPCreateQueryIdParamsAreCamelCase(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	idParam := regexp.MustCompile(`[?&]([A-Za-z_]+[Ii][dD])=%s`)
	var snake []string
	camel := 0
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, "_net.go") {
			continue
		}
		src, err := os.ReadFile(n)
		if err != nil {
			continue
		}
		for _, m := range idParam.FindAllStringSubmatch(string(src), -1) {
			if strings.Contains(m[1], "_") {
				snake = append(snake, n+": "+m[1])
			} else {
				camel++
			}
		}
	}
	// D328: a scan that matched nothing would pass over a convention it never checked.
	if camel < 8 {
		t.Fatalf("only %d camelCase id query params found across gcp *_net.go — the scan is "+
			"broken, not the drivers", camel)
	}
	if len(snake) > 0 {
		t.Errorf("gcp create verbs pass a resource id as a snake_case query param: %v\nThe API "+
			"and every sibling use camelCase (repositoryId, instanceId …). A snake_case name the "+
			"API ignores auto-names the resource under a name the providerId does not match — "+
			"observe then reads a live resource as absent (D1009).", snake)
	}
}
