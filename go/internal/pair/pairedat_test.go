package pair

import "testing"

// D588. `connections` published this for a pairing made today:
//
//	"pairedAt": "1970-01-01T00:00:00Z"
//
// `pair` takes no `--at`, so the CLI passed its evaluation-time default, which is the
// epoch. Nothing READS the field — it is written once and printed — so no decision
// turned on it. What it is, is a false statement in a published record: an auditor
// reading `connections` is told the credential reference was registered in 1970.
//
// The project already decided this case. D230 echoes the operator's `--at` back into
// a refusal's suggested command "only when the operator actually supplied it (never
// the epoch default)", because a command builder that needs a clock must omit itself
// rather than fabricate one. A record is held to the same rule: say nothing rather
// than say 1970.
//
// Validate does not require the field, so omitting is structurally safe.
func TestPairedAtIsOmittedRatherThanFabricated(t *testing.T) {
	c := Connection{Provider: "k8s", Scope: "default",
		Credential: CredentialRef{Kind: "kubeconfig", Path: "/x"}}
	c.StampPairedAt("") // no clock supplied
	if c.PairedAt != "" {
		t.Errorf("with no clock supplied the record carries %q — a time nobody "+
			"observed, published as fact", c.PairedAt)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("a connection without pairedAt must still validate: %v", err)
	}
}

// The epoch specifically, since that is what the CLI default produces.
func TestPairedAtRejectsTheEpochDefault(t *testing.T) {
	c := Connection{Provider: "k8s", Scope: "default",
		Credential: CredentialRef{Kind: "kubeconfig", Path: "/x"}}
	c.StampPairedAt("1970-01-01T00:00:00Z")
	if c.PairedAt != "" {
		t.Errorf("the epoch was recorded as a pairing time: %q", c.PairedAt)
	}
}

// A real clock is recorded verbatim — the point is to stop fabricating, not to stop
// recording.
func TestPairedAtKeepsARealClock(t *testing.T) {
	c := Connection{Provider: "k8s", Scope: "default",
		Credential: CredentialRef{Kind: "kubeconfig", Path: "/x"}}
	c.StampPairedAt("2026-07-31T19:00:00Z")
	if c.PairedAt != "2026-07-31T19:00:00Z" {
		t.Errorf("a supplied clock was not recorded: %q", c.PairedAt)
	}
}
