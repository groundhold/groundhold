package provider_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// D1120. The quickstart now opens with a download rather than a build, because the
// first instruction a curious reader met was `git clone` and `make check` — a Go
// toolchain and a full conformance run before they could see anything. The fastest
// honest path is a binary, two scaffolded documents and one command run twice.
//
// Writing that section introduced a drift risk the rest of this file exists to
// prevent: a version number in a SECOND place. The README's download line is the one
// the release workflow checks — it refuses a tag the README does not name — and a
// copy of `v0.1.x` on the quickstart would be pinned by nothing, so the day a release
// is cut the page starts handing out a stale binary while every gate stays green.
//
// So the page deliberately carries no version, and this holds it to that. The
// alternative — teaching the release workflow about a second file — buys a copy
// nobody needs: the releases page is always current by construction.
func TestQuickstartPinsNoVersionOfItsOwn(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "website", "pages", "quickstart.md"))
	if err != nil {
		t.Skipf("no quickstart here: %v", err)
	}
	page := string(raw)

	if !strings.Contains(page, "github.com/groundhold/groundhold/releases") {
		t.Error("the quickstart no longer points at the releases page — that link is " +
			"what lets this page stay version-free")
	}

	// A release tag anywhere on the page. The README may name one (it is gated);
	// this page may not.
	if m := regexp.MustCompile(`v0\.\d+\.\d+`).FindString(page); m != "" {
		t.Errorf("the quickstart pins %s. Only the README's download line names a tag, "+
			"and the release workflow refuses a release the README does not name — a "+
			"second copy here is checked by nothing and goes stale on the next release, "+
			"handing readers an old binary while every gate stays green.", m)
	}

	// `/releases/latest` resolves only to a NON-prerelease, and every release so far
	// is a prerelease — the README says so explicitly. A "latest" download URL on
	// this page would 404 for every reader, today.
	if strings.Contains(page, "releases/latest/download") {
		t.Error("the quickstart uses a /releases/latest/download URL. GitHub excludes " +
			"prereleases from `latest`, and every release so far is one, so that link " +
			"404s — verified by fetching it. The README documents this; the quickstart " +
			"must not undo it.")
	}
}

// D1122. Reordering the page so it opens with a download (D1120) left every later
// section calling `bin/groundhold-go` — the name the BUILD produces, and the build
// moved to the bottom. A reader following the new opening ran two minutes of working
// commands and then met one naming a file they never made.
//
// Nothing was wrong when either half was written. The opening is correct, the build
// section is correct, and the sequence between them stopped working the moment the
// order changed — the shape D1063 is about, this time introduced by my own edit and
// found by walking the page rather than by any gate.
//
// So the rule is the page's own coherence: an invocation must use the name the page
// told THAT reader to produce. The build section is the one place `bin/groundhold-go`
// belongs, because producing it is what that section does.
func TestQuickstartCallsTheBinaryItToldYouToGet(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "website", "pages", "quickstart.md"))
	if err != nil {
		t.Skipf("no quickstart here: %v", err)
	}
	page := string(raw)

	build := strings.Index(page, "## Build from source")
	if build < 0 {
		t.Fatal("the quickstart no longer has a build-from-source section — this gate " +
			"cannot tell which invocations are allowed to name the built binary")
	}
	buildEnd := strings.Index(page[build:], "\n## ")
	if buildEnd < 0 {
		buildEnd = len(page) - build
	}

	// Invocations of the built name anywhere except inside that one section.
	lines := strings.Split(page, "\n")
	offset, stale := 0, []string{}
	for i, line := range lines {
		start := offset
		offset += len(line) + 1
		if !regexp.MustCompile(`^\s*(\./)?bin/groundhold-go\s`).MatchString(line) {
			continue
		}
		if start >= build && start < build+buildEnd {
			continue // the section that produces it
		}
		stale = append(stale, fmt.Sprintf("line %d: %s", i+1, strings.TrimSpace(line)))
	}
	if len(stale) > 0 {
		t.Errorf("these commands name the built binary outside the build section:\n  %s\n\n"+
			"The page opens by telling a reader to download `./groundhold`. A command "+
			"naming `bin/groundhold-go` sends them to a file they never produced — the "+
			"sequence reads fine and does not run.", strings.Join(stale, "\n  "))
	}

	// Vacuity: if the page stops using the downloaded name entirely, the check above
	// passes over a page that tells nobody to run anything.
	if n := len(regexp.MustCompile(`(?m)^\s*\./groundhold\s`).FindAllString(page, -1)); n < 4 {
		t.Errorf("only %d invocations use the downloaded name — the page was rewritten "+
			"and this gate would now pass on almost anything", n)
	}
}
