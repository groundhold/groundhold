package provider_test

import (
	"strings"
	"testing"

	"groundhold/internal/provider"
)

func TestSecretValuesInFindsCredentialsAndSkipsKeyIdentifiers(t *testing.T) {
	impl := map[string]any{
		"masterPassword":  "hunter2-not-in-a-receipt",
		"admin_password":  "another-one-entirely",
		"kms_key_arn":     "arn:aws:kms:eu-central-1:000000000000:key/abc",
		"key_vault_key":   "https://v.vault.azure.net/keys/k/1",
		"secretName":      "app-db-credential",
		"region":          "eu-central-1",
		"shortPassword":   "abc", // below minRedactableLen — unprotectable by substring
		"nested":          map[string]any{"auth": map[string]any{"token": "nested-bearer-value"}},
		"listed":          []any{map[string]any{"apiKey": "listed-api-key-value"}},
		"manageMasterPwd": true,
	}
	got := provider.SecretValuesIn(impl)
	want := map[string]bool{
		"hunter2-not-in-a-receipt": true,
		"another-one-entirely":     true,
		"nested-bearer-value":      true,
		"listed-api-key-value":     true,
		// secretName's VALUE is a name, but the key says "secret" — redacting a
		// name is harmless and the alternative (guessing which "secret*" keys hold
		// material) is the kind of cleverness that eventually leaks one.
		"app-db-credential": true,
	}
	if len(got) != len(want) {
		t.Fatalf("collected %v, want exactly %d values (%v)", got, len(want), want)
	}
	for _, g := range got {
		if !want[g] {
			t.Errorf("collected %q, which is not a credential value", g)
		}
	}
}

func TestScrubRemovesEveryRememberedCredential(t *testing.T) {
	var r provider.Redactor
	r.Remember(map[string]any{"masterPassword": "hunter2-not-in-a-receipt"})
	in := "CreateDBCluster HTTP 400 (InvalidParameterValue): Invalid value for " +
		"MasterUserPassword=hunter2-not-in-a-receipt in request"
	out := r.Scrub(in)
	if strings.Contains(out, "hunter2-not-in-a-receipt") {
		t.Fatalf("credential survived the scrub: %s", out)
	}
	if !strings.Contains(out, provider.RedactionMark) {
		t.Errorf("redaction must be VISIBLE (an operator can tell it from truncation): %s", out)
	}
	// the diagnosis itself must survive
	for _, keep := range []string{"CreateDBCluster", "400", "InvalidParameterValue"} {
		if !strings.Contains(out, keep) {
			t.Errorf("scrub destroyed the diagnosis (%q missing): %s", keep, out)
		}
	}
}

// A credential from one action must never leak into — or redact — the next.
func TestForgetClearsBetweenActions(t *testing.T) {
	var r provider.Redactor
	r.Remember(map[string]any{"password": "action-one-credential"})
	r.Forget()
	if got := r.Scrub("action-one-credential appears here"); !strings.Contains(got, "action-one-credential") {
		t.Fatalf("Forget must clear the set; got %q", got)
	}
}
