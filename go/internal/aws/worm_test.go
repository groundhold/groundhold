package aws

import "testing"

// retention.locked (Slice B): S3 REFUSES WORM. Object Lock must be enabled at
// bucket birth and its retention set by a separate call the idempotent
// 409-continue path cannot re-assert — an honest one-cloud refusal (GCS honors
// it), never a half-apply.

func TestBuildS3RetentionLockedRefused(t *testing.T) {
	a := s3Attrs()
	a["retention.locked"] = true
	if _, err := BuildS3Requests("000000000000", "prod", "assets", a, nil, 1); err == nil {
		t.Fatal("retention.locked (WORM) must be refused on S3 (Object Lock is create-time-only)")
	}
}

func TestBuildS3RetentionLockedFalseIsNoop(t *testing.T) {
	a := s3Attrs()
	a["retention.locked"] = false
	if _, err := BuildS3Requests("000000000000", "prod", "assets", a, nil, 1); err != nil {
		t.Fatalf("retention.locked=false must be accepted (no WORM requested): %v", err)
	}
}
