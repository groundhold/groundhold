// Package pair is the pairing registry (D141): a machine-local list of credential
// REFERENCES the gentle crawler iterates. A pairing NEVER holds a secret — only a
// pointer (an env-var name, an aws profile, a gcloud config, a kubeconfig
// path+context) resolved on the crawling host at crawl time, exactly as the cloud
// drivers already source credentials. The type has nowhere to put a secret value
// (the D53 discipline made structural). It lives in .groundhold/pairings.yaml, not the
// ledger (D52: discovery never writes the ledger). Only DELEGATED-credential
// providers are pairable today; OAuth providers are deferred (D141) until a
// custodian that is not groundhold exists.
package pair

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// pairableProviders is the set of DELEGATED-credential providers — each holds its
// secret externally (a cloud profile/kubeconfig, or a static API token the operator
// provisioned into an env var / secret store), so a pairing is an honest REFERENCE.
// This is the line D141 draws: static-token providers belong here; OAuth providers
// that would make groundhold MINT and custody a refresh token stay deferred. Crawling a
// provider also needs a Discoverer — upstash/hetzner are pairable now; their crawl
// drivers are a follow-up (until then a crawl records their scope as incomplete).
var pairableProviders = map[string]bool{
	"gcp": true, "aws": true, "azure": true, "k8s": true,
	"upstash": true, "hetzner": true, "cloudflare": true,
	"fake": true,
}

// credKinds maps a credential kind to whether it names a resource (env/profile/
// config) or points at a file (kubeconfig).
var credKinds = map[string]bool{
	"env": true, "aws-profile": true, "gcloud-config": true, "kubeconfig": true,
}

// CredentialRef is a POINTER to a credential, never the credential. There is no
// field that could hold a secret value.
type CredentialRef struct {
	Kind    string `yaml:"kind"`              // env | aws-profile | gcloud-config | kubeconfig
	Name    string `yaml:"name,omitempty"`    // env-var / profile / config name
	Path    string `yaml:"path,omitempty"`    // kubeconfig path
	Context string `yaml:"context,omitempty"` // kubeconfig context
}

// ParseCredentialRef reads a `kind:value` spec (kubeconfig value may be
// `path#context`). It carries only names and paths — never a secret.
func ParseCredentialRef(spec string) (CredentialRef, error) {
	i := strings.Index(spec, ":")
	if i <= 0 || i == len(spec)-1 {
		return CredentialRef{}, fmt.Errorf("--cred-ref %q is not <kind>:<value> "+
			"(env:NAME | aws-profile:NAME | gcloud-config:NAME | kubeconfig:PATH[#context])", spec)
	}
	kind, val := spec[:i], spec[i+1:]
	if !credKinds[kind] {
		return CredentialRef{}, fmt.Errorf("unknown credential kind %q (env | aws-profile | gcloud-config | kubeconfig)", kind)
	}
	if kind == "kubeconfig" {
		path, ctx := val, ""
		if h := strings.Index(val, "#"); h >= 0 {
			path, ctx = val[:h], val[h+1:]
		}
		return CredentialRef{Kind: kind, Path: path, Context: ctx}, nil
	}
	return CredentialRef{Kind: kind, Name: val}, nil
}

// Resolves reports whether the reference points at something present — WITHOUT
// reading the secret into any output. An env var is checked for existence, a
// kubeconfig for a readable file; a named profile/config is the vendor CLI's to
// resolve at crawl time (refused loudly there if absent), so its presence is only
// name-validated here.
func (r CredentialRef) Resolves() error {
	switch r.Kind {
	case "env":
		if r.Name == "" {
			return fmt.Errorf("env ref needs a variable name")
		}
		if _, ok := os.LookupEnv(r.Name); !ok {
			return fmt.Errorf("env var %s is not set", r.Name)
		}
	case "kubeconfig":
		p := r.Path
		if strings.HasPrefix(p, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				p = filepath.Join(home, p[2:])
			}
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("kubeconfig %s: %v", r.Path, err)
		}
	case "aws-profile", "gcloud-config":
		if r.Name == "" {
			return fmt.Errorf("%s ref needs a name", r.Kind)
		}
	default:
		return fmt.Errorf("unknown credential kind %q", r.Kind)
	}
	return nil
}

// String renders the reference compactly for display (names/paths only).
func (r CredentialRef) String() string {
	if r.Kind == "kubeconfig" {
		if r.Context != "" {
			return "kubeconfig:" + r.Path + "#" + r.Context
		}
		return "kubeconfig:" + r.Path
	}
	return r.Kind + ":" + r.Name
}

// Connection is one paired provider+scope and the reference used to reach it.
type Connection struct {
	Provider   string        `yaml:"provider"`
	Scope      string        `yaml:"scope,omitempty"` // project / region / org
	Credential CredentialRef `yaml:"credentialRef"`
	PairedAt   string        `yaml:"pairedAt"`
}

// Registry is the whole pairing file.
type Registry struct {
	Pairings []Connection `yaml:"pairings"`
}

// Validate refuses an unpairable provider (OAuth deferred, D141) and a malformed ref.
// StampPairedAt records WHEN the pairing was registered, and records nothing when
// there is no clock to record. D588: `pair` takes no `--at`, so the CLI handed it the
// evaluation-time default — the epoch — and `connections` published a credential
// reference "registered" on 1 January 1970. Nothing reads the field, so no decision
// turned on it; it was simply untrue, in a document an auditor reads.
//
// Same rule D230 applies to a suggested command's echoed `--at`: a value the operator
// did not supply is OMITTED, never defaulted. An empty pairedAt says "not recorded",
// which is what happened; the epoch says "1970", which did not.
func (c *Connection) StampPairedAt(at string) {
	if at == "" || at == epochRFC3339 {
		c.PairedAt = ""
		return
	}
	c.PairedAt = at
}

// epochRFC3339 is the zero clock every unset --at collapses to.
const epochRFC3339 = "1970-01-01T00:00:00Z"

func (c Connection) Validate() error {
	if !pairableProviders[c.Provider] {
		pairable := make([]string, 0, len(pairableProviders))
		for p := range pairableProviders {
			pairable = append(pairable, p)
		}
		sort.Strings(pairable)
		return fmt.Errorf("provider %q is not pairable yet — only delegated-credential "+
			"providers (%s) are supported; OAuth providers "+
			"(github/slack/jira/notion/linear) are deferred until a non-groundhold "+
			"credential custodian exists (D141)", c.Provider, strings.Join(pairable, ", "))
	}
	if !credKinds[c.Credential.Kind] {
		return fmt.Errorf("connection %s: unknown credential kind %q", c.Provider, c.Credential.Kind)
	}
	return nil
}

// Load reads the registry; a missing file is an empty registry, not an error.
func Load(path string) (*Registry, error) {
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Registry{}, nil
	}
	if err != nil {
		return nil, err
	}
	var r Registry
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("pairings: %w", err)
	}
	return &r, nil
}

// Save writes the registry, creating the parent directory. Pairings are sorted by
// (provider, scope) for a stable file.
func (r *Registry) Save(path string) error {
	sort.Slice(r.Pairings, func(i, j int) bool {
		if r.Pairings[i].Provider != r.Pairings[j].Provider {
			return r.Pairings[i].Provider < r.Pairings[j].Provider
		}
		return r.Pairings[i].Scope < r.Pairings[j].Scope
	})
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	out, err := yaml.Marshal(r)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

// Upsert adds or replaces the pairing for a (provider, scope).
func (r *Registry) Upsert(c Connection) {
	for i := range r.Pairings {
		if r.Pairings[i].Provider == c.Provider && r.Pairings[i].Scope == c.Scope {
			r.Pairings[i] = c
			return
		}
	}
	r.Pairings = append(r.Pairings, c)
}

// Remove deletes the pairing for a (provider, scope); reports whether one was found.
func (r *Registry) Remove(provider, scope string) bool {
	for i := range r.Pairings {
		if r.Pairings[i].Provider == provider && r.Pairings[i].Scope == scope {
			r.Pairings = append(r.Pairings[:i], r.Pairings[i+1:]...)
			return true
		}
	}
	return false
}

// DefaultPath is where the registry lives unless overridden.
func DefaultPath() string {
	if p := os.Getenv("GROUNDHOLD_PAIRINGS"); p != "" {
		return p
	}
	return filepath.Join(".groundhold", "pairings.yaml")
}
