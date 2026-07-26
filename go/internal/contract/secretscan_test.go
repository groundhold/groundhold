package contract

import (
	"strings"
	"testing"
)

func candWithImpl(impl map[string]any) *Candidate {
	return &Candidate{
		ContractID: "c",
		Extras:     map[string]map[string]any{"api": {"implementation": impl}},
	}
}

func TestScanFindsCredentialShapes(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"pem private key", "-----BEGIN PRIVATE KEY-----\nMIGH...", "PEM private key"},
		{"pem rsa private key", "-----BEGIN RSA PRIVATE KEY-----\nMIIE...", "PEM private key"},
		{"openssh private key", "-----BEGIN OPENSSH PRIVATE KEY-----", "private key"},
		{"certificate", "-----BEGIN CERTIFICATE-----\nMIID...", "certificate"},
		{"postgres url with password", "postgres://user:s3cr3t@aurora.eu-central-1:5432/acme", "inline password"},
		{"aws access key", "AKIAIOSFODNN7EXAMPLE", "AWS access key"},
		{"google oauth secret", "GOCSPX-abcdefghijklmnop", "Google OAuth"},
		{"sendgrid key", "SG.abcdefghijklmnopq.rstuvwxyz0123456", "SendGrid"},
		{"brevo key", "xkeysib-" + strings.Repeat("a", 40), "Brevo"},
		{"slack token", "xoxb-1234567890-abcdefghij", "Slack"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ScanForPlaintextSecrets(candWithImpl(map[string]any{
				"environment": map[string]any{"VALUE": tc.value},
			}))
			if len(got) != 1 {
				t.Fatalf("expected exactly one finding, got %d: %+v", len(got), got)
			}
			if !strings.Contains(got[0].Kind, tc.want) {
				t.Errorf("Kind = %q, want it to mention %q", got[0].Kind, tc.want)
			}
			if got[0].Pointer != "capabilities.api.implementation.environment.VALUE" {
				t.Errorf("Pointer = %q", got[0].Pointer)
			}
			// A warning that quotes the secret defeats itself.
			if strings.Contains(got[0].Kind+got[0].Advice, tc.value) {
				t.Error("the finding carries the value itself — a warning must never quote the secret")
			}
			if got[0].Advice == "" {
				t.Error("no advice — a warning that only alarms leaves the operator where they were")
			}
		})
	}
}

// The reporter's actual outage: a placeholder that was never substituted reached
// a Lambda's environment verbatim, and the API lost its database for 13 minutes.
// The tool could see it and said nothing.
func TestScanFindsUnsubstitutedPlaceholders(t *testing.T) {
	for _, v := range []string{
		"{{secret:acme/database-url}}",
		"${DATABASE_URL}",
		"<your-api-key-here>",
	} {
		got := ScanForPlaintextSecrets(candWithImpl(map[string]any{
			"environment": map[string]any{"DATABASE_URL": v},
		}))
		if len(got) != 1 {
			t.Fatalf("%q produced %d findings, want 1", v, len(got))
		}
		if !strings.Contains(got[0].Advice, "literally") {
			t.Errorf("%q: advice does not say the string is applied verbatim: %q", v, got[0].Advice)
		}
	}
}

// The negative control, and the more important half of the test: a pattern that
// fires on ordinary configuration trains people to ignore the warning, which is
// worse than not having one.
func TestScanIsQuietOnOrdinaryConfiguration(t *testing.T) {
	quiet := map[string]any{
		"instance_type":        "m6i.large",
		"image_id":             "ami-0123456789abcdef0",
		"subnet_id":            "subnet-0abc123456789def0",
		"kms_key_id":           "arn:aws:kms:eu-central-1:000000000000:key/abc-123",
		"resource_group":       "rg-production",
		"ssh_public_key":       "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij ops@example",
		"source_image":         "projects/debian-cloud/global/images/debian-12",
		"endpoint":             "https://api.example.com/v1",
		"database_url_no_pass": "postgres://aurora.eu-central-1:5432/acme",
		"log_level":            "info",
		"replicas":             3,
		"tags":                 []any{"prod", "eu"},
	}
	if got := ScanForPlaintextSecrets(candWithImpl(quiet)); len(got) != 0 {
		t.Errorf("ordinary configuration produced %d false warnings: %+v", len(got), got)
	}
}

func TestScanWalksNestedShapesAndIsDeterministic(t *testing.T) {
	c := candWithImpl(map[string]any{
		"environment": map[string]any{
			"B_KEY": "-----BEGIN PRIVATE KEY-----",
			"A_KEY": "AKIAIOSFODNN7EXAMPLE",
		},
		"extra_args": []any{"--fine", "GOCSPX-abcdefghijklmnop"},
	})
	got := ScanForPlaintextSecrets(c)
	if len(got) != 3 {
		t.Fatalf("expected 3 findings across nested shapes, got %d: %+v", len(got), got)
	}
	// Sorted by pointer, so repeated runs print the same thing.
	for i := 1; i < len(got); i++ {
		if got[i-1].Pointer > got[i].Pointer {
			t.Errorf("findings are not sorted: %q before %q", got[i-1].Pointer, got[i].Pointer)
		}
	}
	if got[2].Pointer != "capabilities.api.implementation.extra_args[1]" {
		t.Errorf("list element pointer = %q", got[2].Pointer)
	}
}

func TestScanHandlesNilCandidate(t *testing.T) {
	if got := ScanForPlaintextSecrets(nil); got != nil {
		t.Errorf("nil candidate produced %+v", got)
	}
}
