package main

import (
	"strings"
	"testing"
)

// D687. A `mappings:` key names a provider, and a reader takes that as support.
// `dns.proxied` lists exactly one — `cloudflare.dnsrecord` — and the cloudflare
// driver is read-only discovery: no candidate can ever carry the attribute, and a
// contract requiring it cannot be satisfied. The vocabulary says so in a COMMENT
// that `explain` does not print; it printed the mapping and stopped.
//
// The check is about the PROVIDER and SERVICE, not the attribute — which is why it
// is statable where D686's attribute-liveness rule was not.
func TestExplainSaysWhenNothingCanAuthorAnAttribute(t *testing.T) {
	if anyMappingCanAuthor(map[string]any{
		"cloudflare.dnsrecord": "the record's proxied flag",
	}) {
		t.Error("a mapping to a discovery-only driver reads as authorable — " +
			"provider.CanAuthor defaults to true for a provider it has never heard " +
			"of, and cloudflare is one")
	}
	if anyMappingCanAuthor(map[string]any{"google.something": "x", "okta": "y"}) {
		t.Error("a mapping to a provider with no driver at all reads as authorable")
	}

	// The control: a real cloud service must read as authorable, or every attribute
	// grows the warning and it stops meaning anything.
	if !anyMappingCanAuthor(map[string]any{
		"aws.s3": "ServerSideEncryptionConfiguration",
	}) {
		t.Error("an authoring cloud service does not read as authorable")
	}
	// And a WITNESS service inside an authoring driver is not authorable either.
	if anyMappingCanAuthor(map[string]any{"k8s.flux-kustomization": "spec.source"}) {
		t.Error("a witness-only service reads as authorable — the compiler emits no " +
			"mutating action for it (D177/D640)")
	}
}

// The rendered line, so the sentence an operator reads is pinned rather than only
// the predicate behind it.
func TestTheNotAuthorableLineNamesTheConsequence(t *testing.T) {
	out := captureStdout(t, func() {
		run([]string{"explain", "dns.proxied", "--vocab",
			repoRootFromCmd(t) + "/spec/vocab"})
	})
	if !strings.Contains(out, "NOT AUTHORABLE") {
		t.Fatalf("explain does not warn about an attribute nothing can author:\n%s", out)
	}
	if !strings.Contains(out, "cannot be satisfied by any candidate") {
		t.Errorf("the warning does not say what it costs the reader:\n%s", out)
	}
}
