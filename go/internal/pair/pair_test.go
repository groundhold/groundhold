package pair

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseCredentialRef(t *testing.T) {
	cases := map[string]CredentialRef{
		"env:GOOGLE_APPLICATION_CREDENTIALS": {Kind: "env", Name: "GOOGLE_APPLICATION_CREDENTIALS"},
		"aws-profile:example-preprod":        {Kind: "aws-profile", Name: "example-preprod"},
		"gcloud-config:example-project":      {Kind: "gcloud-config", Name: "example-project"},
		"kubeconfig:/etc/kube/config":        {Kind: "kubeconfig", Path: "/etc/kube/config"},
		"kubeconfig:/etc/kube/config#prod":   {Kind: "kubeconfig", Path: "/etc/kube/config", Context: "prod"},
	}
	for spec, want := range cases {
		got, err := ParseCredentialRef(spec)
		if err != nil || got != want {
			t.Fatalf("%s -> %+v (err %v), want %+v", spec, got, err, want)
		}
	}
	for _, bad := range []string{"noSeparator", "unknown:x", "env:", ":name"} {
		if _, err := ParseCredentialRef(bad); err == nil {
			t.Fatalf("%q must be rejected", bad)
		}
	}
}

func TestResolvesEnv(t *testing.T) {
	t.Setenv("GROUNDHOLD_TEST_CRED", "the-secret-value")
	if err := (CredentialRef{Kind: "env", Name: "GROUNDHOLD_TEST_CRED"}).Resolves(); err != nil {
		t.Fatalf("a present env var must resolve: %v", err)
	}
	err := CredentialRef{Kind: "env", Name: "GROUNDHOLD_TEST_ABSENT"}.Resolves()
	if err == nil {
		t.Fatal("an absent env var must not resolve")
	}
	// the error must name the variable, never leak a value
	if strings.Contains(err.Error(), "the-secret-value") {
		t.Fatalf("resolve error leaked a value: %v", err)
	}
}

func TestOAuthProvidersRefused(t *testing.T) {
	for _, p := range []string{"github", "slack", "jira", "notion", "linear"} {
		err := Connection{Provider: p, Credential: CredentialRef{Kind: "env", Name: "X"}}.Validate()
		if err == nil || !strings.Contains(err.Error(), "D141") {
			t.Fatalf("%s must be refused with the D141 deferral, got %v", p, err)
		}
	}
	for _, p := range []string{"gcp", "aws", "azure", "k8s"} {
		if err := (Connection{Provider: p, Credential: CredentialRef{Kind: "aws-profile", Name: "x"}}).Validate(); err != nil {
			t.Fatalf("%s must be pairable: %v", p, err)
		}
	}
}

// TestRegistryStoresNoSecretValue pins the core safety property: a saved registry
// contains the credential's NAME, never its value — even though the value is set
// in the environment at save time.
func TestRegistryStoresNoSecretValue(t *testing.T) {
	t.Setenv("GROUNDHOLD_SECRET_ENV", "hunter2-do-not-persist")
	dir := t.TempDir()
	path := filepath.Join(dir, ".groundhold", "pairings.yaml")
	reg := &Registry{}
	reg.Upsert(Connection{Provider: "gcp", Scope: "example-project",
		Credential: CredentialRef{Kind: "env", Name: "GROUNDHOLD_SECRET_ENV"}, PairedAt: "2026-07-17T00:00:00Z"})
	if err := reg.Save(path); err != nil {
		t.Fatal(err)
	}
	back, err := Load(path)
	if err != nil || len(back.Pairings) != 1 {
		t.Fatalf("reload: %v / %+v", err, back)
	}
	raw := readFile(t, path)
	if strings.Contains(raw, "hunter2-do-not-persist") {
		t.Fatalf("the registry persisted a SECRET VALUE:\n%s", raw)
	}
	if !strings.Contains(raw, "GROUNDHOLD_SECRET_ENV") {
		t.Fatalf("the registry must carry the env-var NAME:\n%s", raw)
	}
}

// TestCredentialRefIsReferenceOnly is the structural guard: CredentialRef may carry
// only pointers (kind/name/path/context). Adding a field that could hold a secret
// value (Token, Secret, Value, Password...) breaks this test on purpose.
func TestCredentialRefIsReferenceOnly(t *testing.T) {
	allowed := map[string]bool{"Kind": true, "Name": true, "Path": true, "Context": true}
	rt := reflect.TypeOf(CredentialRef{})
	for i := 0; i < rt.NumField(); i++ {
		if !allowed[rt.Field(i).Name] {
			t.Fatalf("CredentialRef.%s is not an allowed reference field — a pairing must "+
				"never hold a secret value (D141/D53)", rt.Field(i).Name)
		}
	}
}

func TestUpsertAndRemove(t *testing.T) {
	reg := &Registry{}
	reg.Upsert(Connection{Provider: "aws", Scope: "preprod", Credential: CredentialRef{Kind: "aws-profile", Name: "a"}})
	reg.Upsert(Connection{Provider: "aws", Scope: "preprod", Credential: CredentialRef{Kind: "aws-profile", Name: "b"}})
	if len(reg.Pairings) != 1 || reg.Pairings[0].Credential.Name != "b" {
		t.Fatalf("upsert must replace by (provider,scope): %+v", reg.Pairings)
	}
	if !reg.Remove("aws", "preprod") || len(reg.Pairings) != 0 {
		t.Fatalf("remove must delete the pairing: %+v", reg.Pairings)
	}
	if reg.Remove("aws", "preprod") {
		t.Fatal("removing an absent pairing must report false")
	}
}
