package aws

import (
	"strings"
	"testing"
)

// The garbled-200 honesty invariant reduces to a property of the pure parsers:
// they must be TOTAL (never panic on a hostile body) and must never FABRICATE a
// value not present in the input (a confident wrong answer is worse than none).
// These fuzz targets run their seed corpus under `go test` and deep-fuzz under
// `go test -fuzz`.

var parserSeeds = []string{
	``,
	`<Error><Code>NoSuchBucket</Code></Error>`,
	`<Error><Code>InternalError</Code></Error>`,
	`<Response><Errors><Error><Code>InvalidVpcID.NotFound</Code></Error></Errors></Response>`,
	`<ErrorResponse><Error><Code>DBInstanceNotFound</Code></Error></ErrorResponse>`,
	`<Tagging><TagSet><Tag><Key>groundhold-capability</Key><Value>assets</Value></Tag></TagSet></Tagging>`,
	`<trunc`,
	`{"__type":"InvalidParameterException","message":"boom"}`,
	`not xml at all`,
	`<Code>x</Code>`,
}

// codeExtractorProperty: never panic; a non-empty extracted code must be a
// substring of the input (never invented); deterministic.
func codeExtractorProperty(t *testing.T, name string, fn func([]byte) string, in []byte) {
	t.Helper()
	got := fn(in)
	if got != fn(in) {
		t.Fatalf("%s not deterministic on %q", name, in)
	}
	if got != "" && !strings.Contains(string(in), got) {
		t.Fatalf("%s FABRICATED code %q not present in input %q", name, got, in)
	}
}

func FuzzAwsErrCode(f *testing.F) {
	for _, s := range parserSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		codeExtractorProperty(t, "awsErrCode", awsErrCode, in)
	})
}

func FuzzRdsErrCode(f *testing.F) {
	for _, s := range parserSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		codeExtractorProperty(t, "rdsErrCode", rdsErrCode, in)
	})
}

func FuzzEc2ErrCode(f *testing.F) {
	for _, s := range parserSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		codeExtractorProperty(t, "ec2ErrCode", ec2ErrCode, in)
	})
}

// parseS3Tags is tri-state (map | empty | error). Property: never panic;
// deterministic; on success every returned value must appear in the input (never
// a fabricated ownership tag from non-tag XML).
func FuzzParseS3Tags(f *testing.F) {
	for _, s := range parserSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		m, err := parseS3Tags(in)
		m2, err2 := parseS3Tags(in)
		if (err == nil) != (err2 == nil) || len(m) != len(m2) {
			t.Fatalf("parseS3Tags not deterministic on %q", in)
		}
		if err == nil {
			for k, v := range m {
				if !strings.Contains(string(in), k) || !strings.Contains(string(in), v) {
					t.Fatalf("parseS3Tags FABRICATED tag %q=%q not in input %q", k, v, in)
				}
			}
		}
	})
}

// ecsErr joins __type + message; both must come from the input (or it echoes the
// raw body). Property: never panic; deterministic; the trimmed result is either a
// substring-composed value or the raw body itself.
func FuzzEcsErr(f *testing.F) {
	for _, s := range parserSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		got := ecsErr(in)
		if got != ecsErr(in) {
			t.Fatalf("ecsErr not deterministic on %q", in)
		}
		// each whitespace-separated token must appear in the input, unless ecsErr
		// fell back to echoing the whole (unparseable) body.
		if got != strings.TrimSpace(string(in)) {
			for _, tok := range strings.Fields(got) {
				if !strings.Contains(string(in), tok) {
					t.Fatalf("ecsErr FABRICATED token %q not in input %q", tok, in)
				}
			}
		}
	})
}
