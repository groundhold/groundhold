package aws

import (
	"net/url"
	"strings"
	"testing"
)

// The canonical AWS SigV4 test vector (get-vanilla from the official
// aws-sig-v4-test-suite): GET / on example.amazonaws.com, service "service",
// region us-east-1, at 20150830T123600Z, with the documented example key.
// The expected signature is published by AWS, so this pins our implementation
// against the reference rather than against ourselves.
func TestSignGetVanilla(t *testing.T) {
	u, _ := url.Parse("https://example.amazonaws.com/")
	creds := Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	got := Sign("GET", u, nil, emptyPayloadHash, "us-east-1", "service",
		"20150830T123600Z", creds)

	auth := got["Authorization"]
	// Credential + SignedHeaders are deterministic; assert them exactly.
	if !strings.Contains(auth, "Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request") {
		t.Fatalf("bad credential scope in %q", auth)
	}
	if !strings.Contains(auth, "SignedHeaders=host;x-amz-date") {
		t.Fatalf("bad signed headers in %q", auth)
	}
	// The published signature for get-vanilla:
	const official = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if !strings.Contains(auth, "Signature="+official) {
		t.Fatalf("signature mismatch against the AWS reference vector\n got: %q\nwant Signature=%s", auth, official)
	}
}

// D880: an ARN-in-path read (backup ListTags) exercises the SigV4 double-encoding of the
// canonical path — the rule that broke every backup vault/plan delete. The expected
// signature is computed by botocore for the SAME request (single-encoded %3A on the wire,
// double-encoded %253A in the canonical, the model's trailing slash), so this pins our
// signer against the reference SDK, not against ourselves. A signer that single-encodes
// the canonical (the bug) produces 0afd0307…; only the double-encode yields this value.
func TestSignArnInPathDoubleEncodes(t *testing.T) {
	u, _ := url.Parse("https://backup.us-east-1.amazonaws.com/tags/" +
		"arn%3Aaws%3Abackup%3Aus-east-1%3A000000000000%3Abackup-vault%3Av/")
	creds := Credentials{
		AccessKeyID:     "AKIDEXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	got := Sign("GET", u, nil, emptyPayloadHash, "us-east-1", "backup",
		"20150830T123600Z", creds)
	const official = "a6e0e541da052b24aeb34053a3e70fafca060ed253848d3b5f6e058733bf5db4"
	if !strings.Contains(got["Authorization"], "Signature="+official) {
		t.Fatalf("ARN-in-path signature mismatch (canonical must double-encode the path)\n"+
			" got: %q\nwant Signature=%s", got["Authorization"], official)
	}
}

func TestRfc3986Encoding(t *testing.T) {
	cases := map[string]string{
		"a b":   "a%20b",
		"a/b":   "a%2Fb",
		"~-_.":  "~-_.",
		"A1z9":  "A1z9",
		"k=v&x": "k%3Dv%26x",
	}
	for in, want := range cases {
		if got := rfc3986(in); got != want {
			t.Errorf("rfc3986(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSessionTokenSigned(t *testing.T) {
	u, _ := url.Parse("https://example.amazonaws.com/")
	creds := Credentials{AccessKeyID: "AKID", SecretAccessKey: "secret", SessionToken: "tok"}
	got := Sign("GET", u, nil, emptyPayloadHash, "us-east-1", "service", "20150830T123600Z", creds)
	if got["X-Amz-Security-Token"] != "tok" {
		t.Fatal("session token must be emitted as a header")
	}
	if !strings.Contains(got["Authorization"], "x-amz-security-token") {
		t.Fatal("session token must be a SIGNED header (in SignedHeaders)")
	}
}
