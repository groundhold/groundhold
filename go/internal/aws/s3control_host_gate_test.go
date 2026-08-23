package aws

import (
	"net"
	"os"
	"strings"
	"testing"
)

// D1230. The account-level S3 Control endpoint carries the ACCOUNT ID as a DNS
// PREFIX: `<account>.s3-control.<region>.amazonaws.com`. The bare
// `s3-control.<region>.amazonaws.com` this driver used since D240 does not resolve —
// in any region — so every account-level Block Public Access read failed against real
// AWS with a DNS error for as long as the code existed.
//
// Nothing caught it, and the reasons are worth keeping because they are a recipe:
//
//   - the read is LAZY, so it only fires when a bucket policy already reads public;
//   - its failure keeps the CONSERVATIVE public verdict, so the damage was an
//     over-report, never a false-green — the safe direction hid the breakage;
//   - every unit test overrides S3ControlBaseURL for hermeticity, so the real
//     hostname was never once constructed under test;
//   - the live endpoint-reality gate asks about PATHS, and this path is recorded
//     under service "s3", so it was asked at the s3 host and answered there.
//
// A read that always fails in the safe direction is invisible. The gate below is
// therefore about the SHAPE of the host, which is checkable without a network.

func TestS3ControlHostCarriesTheAccountPrefix(t *testing.T) {
	d := NewDriver("eu-central-1")
	got := d.s3ControlBase("eu-central-1", "123456789012")
	const want = "https://123456789012.s3-control.eu-central-1.amazonaws.com"
	if got != want {
		t.Fatalf("the account id is a DNS prefix on S3 Control, not a header-only operand.\n"+
			" got: %s\nwant: %s", got, want)
	}
	// The bare form is the bug, stated so a "simplification" cannot reintroduce it.
	if strings.HasPrefix(got, "https://s3-control.") {
		t.Fatalf("https://s3-control.<region>.amazonaws.com does not resolve; it is not a "+
			"shorter spelling of the endpoint, it is a different (nonexistent) host: %s", got)
	}
}

// The test override must still win, or every httptest fixture in the package starts
// talking to AWS.
func TestS3ControlBaseHonorsTheTestOverride(t *testing.T) {
	d := NewDriver("eu-central-1")
	d.S3ControlBaseURL = "http://127.0.0.1:1"
	if got := d.s3ControlBase("eu-central-1", "123456789012"); got != "http://127.0.0.1:1" {
		t.Fatalf("S3ControlBaseURL must override the derived host, got %s", got)
	}
}

// The claim this fix rests on, asked of DNS rather than believed: the bare host does
// not exist and the account-prefixed shape is the real one. Skipped without network,
// because a gate that fails on an offline machine teaches people to skip gates.
func TestS3ControlBareHostDoesNotResolve(t *testing.T) {
	if os.Getenv("GROUNDHOLD_LIVE_AWS_SMOKE") != "1" {
		t.Skip("needs network egress (set GROUNDHOLD_LIVE_AWS_SMOKE=1)")
	}
	if _, err := net.LookupHost("s3.eu-central-1.amazonaws.com"); err != nil {
		t.Skipf("no usable DNS in this environment: %v", err)
	}
	if addrs, err := net.LookupHost("s3-control.eu-central-1.amazonaws.com"); err == nil {
		t.Fatalf("the bare s3-control host RESOLVES (%v) — re-check D1230's premise before "+
			"trusting the account-prefixed form", addrs)
	}
}

// D1230, second half. parsePABFlag decides whether a 404 is a DEFINITIVE "no
// configuration set" or an unreadable answer BY THE ERROR CODE — deliberately, so a
// NoSuchBucket / wrong-account 404 keeps its error. That decision needs the code to
// actually be extracted, and S3 Control wraps its error one level deeper than S3
// does. Both envelopes, in one table, with the live-confirmed body verbatim.
func TestAWSErrCodeReadsBothS3AndS3ControlEnvelopes(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"plain S3 (root Error)": {
			`<?xml version="1.0"?><Error><Code>NoSuchBucket</Code><Message>x</Message></Error>`,
			"NoSuchBucket",
		},
		"S3 Control (ErrorResponse wrapper, verbatim from AWS)": {
			`<?xml version="1.0" encoding="UTF-8"?>` +
				`<ErrorResponse><Error><Code>NoSuchPublicAccessBlockConfiguration</Code>` +
				`<Message>The public access block configuration was not found</Message>` +
				`<AccountId>123456789012</AccountId></Error><RequestId>R</RequestId></ErrorResponse>`,
			"NoSuchPublicAccessBlockConfiguration",
		},
		"unrecognised shape yields nothing, never the raw body": {
			`<Something><Else>x</Else></Something>`, "",
		},
	} {
		if got := awsErrCode([]byte(tc.body)); got != tc.want {
			t.Errorf("%s: awsErrCode = %q, want %q", name, got, tc.want)
		}
	}
}

// The consequence, end to end: an account with NO Block Public Access configuration
// is a definitive not-set, not an unreadable read. Getting this wrong is safe and
// therefore silent, which is why it survived.
func TestAccountPABNotSetIsDefinitiveNotUnreadable(t *testing.T) {
	const body = `<?xml version="1.0" encoding="UTF-8"?>` +
		`<ErrorResponse><Error><Code>NoSuchPublicAccessBlockConfiguration</Code>` +
		`<Message>The public access block configuration was not found</Message>` +
		`</Error></ErrorResponse>`
	enforced, err := parsePABFlag("GetAccountPublicAccessBlock", 404, []byte(body), nil,
		func(c pabConfig) string { return c.IgnorePublicAcls })
	if err != nil {
		t.Fatalf("a NoSuchPublicAccessBlockConfiguration 404 is a definitive not-set, got err=%v", err)
	}
	if enforced {
		t.Fatalf("not-set cannot be enforced")
	}
	// and a 404 WITHOUT that code stays unreadable, or the definitive branch would
	// swallow a wrong-account answer.
	if _, err := parsePABFlag("GetAccountPublicAccessBlock", 404,
		[]byte(`<ErrorResponse><Error><Code>NoSuchBucket</Code></Error></ErrorResponse>`), nil,
		func(c pabConfig) string { return c.IgnorePublicAcls }); err == nil {
		t.Fatalf("a 404 carrying a DIFFERENT code must stay unreadable")
	}
}
