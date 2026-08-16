package provider_test

import (
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
