package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	_ "groundhold/internal/aws"
	_ "groundhold/internal/azure"
	_ "groundhold/internal/cloudflare"
	_ "groundhold/internal/gcp"
	_ "groundhold/internal/hetzner"
	_ "groundhold/internal/k8s"
	"groundhold/internal/provider"
	_ "groundhold/internal/upstash"
)

// D732. A driver whose Create/Update/Delete all refuse is a WITNESS: it observes and it
// never authors. D177 built that concept and said why emitting a create for one would
// lie — "the driver refuses it at apply". Three read-only drivers were never entered in
// the register, so `CanAuthor` returned its permissive default for them, the compiler
// planned a create, the plan SEALED, and only apply discovered that nothing could be
// written.
//
// The gate derives its subject rather than listing it: a driver package whose Create
// returns the package's not-implemented sentinel is read-only BY CONSTRUCTION, and must
// declare itself a witness. That way a fourth read-only driver cannot join without
// either authoring or saying it does not.
func TestEveryReadOnlyDriverDeclaresItselfAWitness(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "go", "internal"))
	if err != nil {
		t.Fatalf("read internal/: %v", err)
	}
	// A Create whose whole body is an unconditional failure — the read-only shape,
	// however the reason is spelled. The first version of this gate matched one exact
	// spelling (`Reason: notImplemented`) and silently skipped the driver that wrote its
	// reason inline. A gate that recognises one dialect of the thing it hunts is the
	// defect it hunts (D732).
	refuses := regexp.MustCompile(`(?s)func \(d \*Driver\) Create\(.{0,200}?\{\s*return provider\.CreateResult\{Status: "failed",[^}]*\}\s*\}`)

	readOnly, checked := []string{}, 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, "go", "internal", e.Name(), e.Name()+".go"))
		if err != nil {
			continue // not a single-file driver package; the cloud drivers are checked below
		}
		checked++
		if refuses.Match(src) {
			readOnly = append(readOnly, e.Name())
		}
	}
	if checked < 3 || len(readOnly) == 0 {
		t.Fatalf("the sweep examined %d packages and found %d read-only drivers — it has "+
			"lost its subject and would pass over any driver at all", checked, len(readOnly))
	}

	for _, name := range readOnly {
		// Whatever service string it is asked about, a read-only driver must not claim
		// authorability: the compiler would emit a create the driver refuses at apply.
		for _, svc := range []string{"dnsrecord", "redis", "server", "anything-at-all"} {
			if provider.CanAuthor(name, svc) {
				t.Errorf("%s refuses every write verb but CanAuthor(%s, %q) is true — the "+
					"compiler will plan a create, seal the plan, and apply will discover "+
					"there is nothing to write (D732)", name, name, svc)
			}
		}
	}
	t.Logf("read-only drivers, all declared witnesses: %s", strings.Join(readOnly, ", "))
}
