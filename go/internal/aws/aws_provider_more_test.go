package aws

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// This file exercises aws_provider.go's dispatch-by-service-token routing
// itself (Validate/Observe/Update/Delete/ClassifyChange) — previously the
// weakest functions in the file (Validate 15%, Observe 14.8%, update 25.9%,
// ClassifyChange 40.7%) because almost every capability's own test file calls
// the lower-level d.xxxService(...) function directly rather than going
// through the top-level dispatcher. That leaves the switch statements
// themselves — the part that actually wires a service token to its
// implementation — mostly unexercised. A regression here (a service listed in
// requireService but never wired into one of these switches) would silently
// fall through to a "not wired yet" refusal; these tests catch that directly.
//
// allDispatchServices mirrors requireService's exact list (aws_provider.go).
var allDispatchServices = []string{
	"s3", "rds", "ecs", "apprunner", "vpc", "sns", "sqs", "secretsmanager",
	"elasticache", "elasticache-serverless", "route53", "route53record",
	"rolepolicy", "custompolicy", "cloudwatch", "cloudwatchdash", "route53health",
	"cwlogfilter", "ecr", "efs", "dynamodb", "opensearch", "opensearch-serverless",
	"kinesis", "msk", "waf", "acm", "cloudfront", "apigateway", "iam",
	"redshiftserverless", "eventbridgescheduler", "kms", "vpngateway",
	"backupvault", "changefeed", "loadbalancer", "eks", "eks-addon",
	"eks-podidentity", "ses-sending", "ses-inbound", "aurora", "bedrock",
	"budgets", "cloudtrail", "backupplan", "guardduty", "cwlogs", "lambda",
}

// ---- Validate: every requireService token must reach a REAL builder --------

// TestValidateDispatchesEveryService: the default arm ALWAYS returns a non-nil
// "is not wired yet" error (see the switch above), so ANY outcome other than
// that exact phrasing — success OR a service-specific refusal — proves
// dispatch reached the real per-service builder rather than falling through.
// Some builders happily accept an empty candidate (nothing required attrs);
// that is a legitimate success, not a test bug.
func TestValidateDispatchesEveryService(t *testing.T) {
	d := NewDriver("eu-central-1")
	for _, svc := range allDispatchServices {
		t.Run(svc, func(t *testing.T) {
			attrs := map[string]any{}
			if !isGlobalService(svc) {
				attrs["location.region"] = "eu-central-1"
			}
			err := d.Validate(svc, "cap", "prod", attrs, map[string]any{}, 1)
			if err != nil && strings.Contains(err.Error(), "is not wired yet") {
				t.Fatalf("Validate(%s) fell through to the not-wired default — dispatch is missing this case", svc)
			}
		})
	}
}

// TestValidateRefusesMissingRegionBeforeDispatch: for every REGIONAL service,
// a missing location.region is caught before the per-service builder runs at
// all (refuse-before-mutate) — the region gate, not the dispatch switch.
func TestValidateRefusesMissingRegionBeforeDispatch(t *testing.T) {
	d := NewDriver("eu-central-1")
	for _, svc := range allDispatchServices {
		if isGlobalService(svc) {
			continue
		}
		t.Run(svc, func(t *testing.T) {
			err := d.Validate(svc, "cap", "prod", map[string]any{}, map[string]any{}, 1)
			if err == nil || !strings.Contains(err.Error(), "location.region") {
				t.Fatalf("Validate(%s) with no region must refuse naming location.region, got %v", svc, err)
			}
		})
	}
}

// TestValidateUnknownServiceFailsClosed: requireService gates dispatch itself.
func TestValidateUnknownServiceFailsClosed(t *testing.T) {
	d := NewDriver("eu-central-1")
	if err := d.Validate("__nope__", "cap", "prod", nil, nil, 1); err == nil {
		t.Fatal("an unknown service must refuse closed")
	}
}

// ---- Observe: every wired token must reach a REAL observer -----------------

// observeDispatchServices mirrors the Observe switch's case list exactly
// (aws_provider.go) — every requireService token EXCEPT the ones Observe has
// no case for (there are none today; Observe covers the full set).
var observeDispatchServices = allDispatchServices

// TestObserveDispatchesEveryService: a garbage providerId fails EVERY
// service's own split*ProviderID parse before any network call — so this
// sweep is fast and safe, and it still proves dispatch reaches the per-service
// observer (never "observe is not wired yet").
func TestObserveDispatchesEveryService(t *testing.T) {
	d := NewDriver("eu-central-1")
	d.HTTP = &http.Client{Timeout: 300 * time.Millisecond} // bound any dispatch that does reach the network
	for _, svc := range observeDispatchServices {
		t.Run(svc, func(t *testing.T) {
			_, _, err := d.Observe(svc, "cap", "not-a-valid-providerid")
			if err == nil {
				t.Fatalf("Observe(%s, garbage-pid) unexpectedly succeeded", svc)
			}
			if strings.Contains(err.Error(), "observe is not wired yet") {
				t.Fatalf("Observe(%s) fell through to the not-wired default — dispatch is missing this case", svc)
			}
		})
	}
}

func TestObserveUnknownServiceFailsClosed(t *testing.T) {
	d := NewDriver("eu-central-1")
	if _, _, err := d.Observe("__nope__", "cap", "x"); err == nil {
		t.Fatal("an unknown service must refuse closed")
	}
}

// ---- Update: every wired token must reach a REAL patcher --------------------

// updateDispatchServices mirrors update's explicit case list (aws_provider.go)
// — services with NO in-place patch route to the default "not wired yet"
// refusal by design (a replacement, not a bug), so they are excluded here.
var updateDispatchServices = []string{
	"acm", "apprunner", "s3", "route53record", "sns", "sqs", "rds",
	"secretsmanager", "loadbalancer", "eks", "eks-addon", "ses-sending",
	"ses-inbound", "ecr", "aurora", "budgets", "cloudtrail", "backupplan",
	"guardduty", "cwlogs", "lambda",
}

// TestUpdateDispatchesEveryWiredService: with credentials present (so the
// hasCreds gate does not short-circuit before dispatch) and a garbage
// providerId, every wired service's own parse fails before any network call —
// dispatch must reach the per-service updater, never "loadbalancer" being the
// sole exception (an explicit read-only refusal, asserted separately).
func TestUpdateDispatchesEveryWiredService(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.HTTP = &http.Client{Timeout: 300 * time.Millisecond}
	for _, svc := range updateDispatchServices {
		t.Run(svc, func(t *testing.T) {
			res := d.Update(svc, "cap", "prod", "not-a-valid-providerid", map[string]any{}, map[string]any{}, nil, "k")
			if res.Status != "failed" && res.Status != "unknown" {
				t.Fatalf("Update(%s, garbage-pid) = %+v, want failed or unknown", svc, res)
			}
			if strings.Contains(res.Reason, "is not wired yet") {
				t.Fatalf("Update(%s) fell through to the not-wired default — dispatch is missing this case", svc)
			}
		})
	}
}

// TestUpdateLoadBalancerAlwaysRefusesInPlace: loadbalancer is a DELIBERATE
// read-only exception — every governed attribute routes to a replacement.
func TestUpdateLoadBalancerAlwaysRefusesInPlace(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	res := d.Update("loadbalancer", "cap", "prod", "elbv2:eu-central-1:x", map[string]any{}, nil, nil, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not supported") {
		t.Fatalf("loadbalancer update must refuse in-place, got %+v", res)
	}
}

// TestUpdateNoCredsRefusesBeforeDispatch: the credential gate runs BEFORE the
// switch — no service-specific parse error leaks through it.
func TestUpdateNoCredsRefusesBeforeDispatch(t *testing.T) {
	d := &Driver{Region: "eu-central-1", Now: time.Now}
	res := d.Update("s3", "cap", "prod", "s3:eu-central-1:bucket", map[string]any{}, nil, nil, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "credentials") {
		t.Fatalf("Update with no credentials must refuse before dispatch, got %+v", res)
	}
}

// TestUpdateUnwiredServiceIsHonestlyNotWired: a service with genuinely no
// in-place update path (e.g. vpc) reaches the default arm honestly.
func TestUpdateUnwiredServiceIsHonestlyNotWired(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	res := d.Update("vpc", "cap", "prod", "vpc:eu-central-1:vpc-0abc123", map[string]any{}, nil, []string{"network.publicExposure"}, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "is not wired yet") {
		t.Fatalf("an unwired service must honestly say so, got %+v", res)
	}
}

func TestUpdateUnknownServiceFailsClosed(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	res := d.Update("__nope__", "cap", "prod", "x", nil, nil, nil, "k")
	if res.Status != "failed" {
		t.Fatal("an unknown service must refuse closed")
	}
}

// ---- Delete: every wired token must reach a REAL deleter --------------------

// TestDeleteDispatchesEveryService: same discipline as Observe — a garbage pid
// fails every service's own parse before any network call.
func TestDeleteDispatchesEveryService(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.HTTP = &http.Client{Timeout: 300 * time.Millisecond}
	for _, svc := range allDispatchServices {
		t.Run(svc, func(t *testing.T) {
			res := d.Delete(svc, "cap", "prod", "not-a-valid-providerid", "k")
			if res.Status != "failed" && res.Status != "unknown" {
				t.Fatalf("Delete(%s, garbage-pid) = %+v, want failed or unknown", svc, res)
			}
			if strings.Contains(res.Reason, "is not wired yet") {
				t.Fatalf("Delete(%s) fell through to the not-wired default — dispatch is missing this case", svc)
			}
		})
	}
}

func TestDeleteUnknownServiceFailsClosed(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	res := d.Delete("__nope__", "cap", "prod", "x", "k")
	if res.Status != "failed" {
		t.Fatal("an unknown service must refuse closed")
	}
}

// ---- ClassifyChange: every explicitly-wired token routes to ITS classifier --

// classifyDispatchServices mirrors ClassifyChange's explicit case list
// (aws_provider.go) — every OTHER requireService token deliberately falls to
// the default "no in-place update path" (a replacement), asserted separately.
var classifyDispatchServices = []string{
	"s3", "apprunner", "elasticache-serverless", "opensearch-serverless",
	"route53record", "sns", "sqs", "rds", "secretsmanager", "loadbalancer",
	"eks", "eks-addon", "eks-podidentity", "ses-sending", "ses-inbound", "ecr",
	"aurora", "bedrock", "budgets", "cloudtrail", "backupplan", "guardduty",
	"cwlogs", "acm", "lambda",
}

// TestClassifyChangeDispatchesEveryWiredService: PURE, no network. The
// fallthrough default's reason text is a fixed, recognizable phrase — a wired
// service's own classifier must never produce exactly that phrase for an
// arbitrary path (each has its own wording), so its presence proves the
// dispatch reached the generic default instead of the intended case.
func TestClassifyChangeDispatchesEveryWiredService(t *testing.T) {
	d := NewDriver("eu-central-1")
	for _, svc := range classifyDispatchServices {
		t.Run(svc, func(t *testing.T) {
			_, reason := d.ClassifyChange(svc, "some.arbitrary.path", nil, nil, nil)
			if strings.Contains(reason, "has no in-place update path") {
				t.Fatalf("ClassifyChange(%s) fell through to the generic default — dispatch is missing this case", svc)
			}
		})
	}
}

// TestClassifyChangeUnwiredServiceIsTheHonestDefault: a service with no
// explicit ClassifyChange case (e.g. vpc, ecs — mostly-immutable composites)
// gets the D215 honest default: immutable, so a drift reconciles as a
// replacement rather than silently freezing.
func TestClassifyChangeUnwiredServiceIsTheHonestDefault(t *testing.T) {
	d := NewDriver("eu-central-1")
	for _, svc := range []string{"vpc", "ecs", "kms", "iam", "waf"} {
		got, reason := d.ClassifyChange(svc, "some.path", nil, nil, nil)
		if got != "immutable" {
			t.Errorf("ClassifyChange(%s) = %q, want immutable (the honest D215 default)", svc, got)
		}
		if !strings.Contains(reason, "has no in-place update path") {
			t.Errorf("ClassifyChange(%s) reason = %q, want the D215 default phrasing", svc, reason)
		}
	}
}

// ---- isGlobalService / requireService: pure invariants ----------------------

// TestRequireServiceAcceptsEveryDispatchToken: the exact set requireService
// gates must be the set every dispatcher above assumes.
func TestRequireServiceAcceptsEveryDispatchToken(t *testing.T) {
	d := NewDriver("eu-central-1")
	for _, svc := range allDispatchServices {
		if err := d.requireService(svc); err != nil {
			t.Errorf("requireService(%s) refused, but it is in the dispatch table: %v", svc, err)
		}
	}
}

func TestRequireServiceRefusesUnknown(t *testing.T) {
	d := NewDriver("eu-central-1")
	if err := d.requireService("__nope__"); err == nil {
		t.Fatal("an unlisted service must refuse")
	}
}

// TestRequireServiceRefusesInvalidPinnedRegion: a driver pinned to a malformed
// region refuses every KNOWN service too (D85: refuse-before-mutate on the
// driver's own configuration, not just the candidate's).
func TestRequireServiceRefusesInvalidPinnedRegion(t *testing.T) {
	d := NewDriver("not-a-region")
	if err := d.requireService("s3"); err == nil {
		t.Fatal("a driver pinned to an invalid region must refuse")
	}
}
