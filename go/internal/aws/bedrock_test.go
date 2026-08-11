package aws

import (
	"encoding/json"
	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
	"groundhold/internal/scalars"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	bedrockCap       = "capability.ai.inference"
	bedrockRegion    = "eu-central-1"
	bedrockProfile1  = "eu.anthropic.claude-sonnet-4-20250514-v1:0" // a SYSTEM profile — the ':0' version suffix (every real id carries one) is the D1000 regression case
	bedrockAppID     = "abcd1234efgh"                               // an AWS-assigned APPLICATION profile id
	bedrockModelBase = "anthropic.claude-3-5-sonnet-20241022-v2:0"
)

func bedrockModelArn(region string) string {
	return "arn:aws:bedrock:" + region + "::foundation-model/" + bedrockModelBase
}

// fakeBedrock is a stateful fake Bedrock control-plane (REST-JSON) endpoint. It
// serves GetInferenceProfile / ListInferenceProfiles / CreateInferenceProfile /
// DeleteInferenceProfile, records mutating order + captures the create body, and can
// inject an unreadable (500) profile read to exercise the unknown path.
type fakeBedrock struct {
	mu sync.Mutex

	profileID   string
	profileType string // SYSTEM_DEFINED | APPLICATION
	status      string
	modelArns   []string
	tags        []map[string]string
	exists      bool

	unreadable bool // 500 on GetInferenceProfile
	notFound   bool // 404 on GetInferenceProfile
	arnOnly    bool // CreateInferenceProfile returns ONLY the ARN (real AWS shape) — F18

	createBody string
	order      []string

	getEscapedPath string // D1000: the RAW request path the GET arrived on, to pin wire encoding
}

func newFakeBedrock() *fakeBedrock {
	return &fakeBedrock{
		profileID:   bedrockProfile1,
		profileType: "SYSTEM_DEFINED",
		status:      "ACTIVE",
		modelArns: []string{
			bedrockModelArn("eu-central-1"),
			bedrockModelArn("eu-west-1"),
			bedrockModelArn("eu-south-2"),
		},
		exists: true,
	}
}

func (f *fakeBedrock) profileJSON() []byte {
	models := make([]map[string]any, 0, len(f.modelArns))
	for _, a := range f.modelArns {
		models = append(models, map[string]any{"modelArn": a})
	}
	out, _ := json.Marshal(map[string]any{
		"inferenceProfileArn":  "arn:aws:bedrock:" + bedrockRegion + ":000000000000:inference-profile/" + f.profileID,
		"inferenceProfileId":   f.profileID,
		"inferenceProfileName": f.profileID,
		"status":               f.status,
		"type":                 f.profileType,
		"models":               models,
		"tags":                 f.tags,
	})
	return out
}

func (f *fakeBedrock) handler(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	getPath := bedrockProfilesPath + "/" + f.profileID
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		if rec != nil {
			rec.record(r, body)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		p, m := r.URL.Path, r.Method
		switch {
		case p == bedrockProfilesPath && m == http.MethodGet: // ListInferenceProfiles
			// mirror real AWS: the list is filtered by typeEquals and DEFAULTS to
			// SYSTEM_DEFINED when the filter is absent — so a driver that omits
			// typeEquals=APPLICATION (or misspells it as type=) never sees an
			// application profile it created (F20).
			want := r.URL.Query().Get("typeEquals")
			if want == "" {
				want = "SYSTEM_DEFINED"
			}
			summaries := []map[string]any{}
			if want == f.profileType {
				summaries = append(summaries, map[string]any{"inferenceProfileId": f.profileID})
			}
			out, _ := json.Marshal(map[string]any{"inferenceProfileSummaries": summaries})
			_, _ = w.Write(out)
		case p == getPath && m == http.MethodGet: // GetInferenceProfile
			f.getEscapedPath = r.URL.EscapedPath() // D1000: the wire encoding, undecoded
			if f.unreadable {
				http.Error(w, `{"message":"InternalServerError"}`, http.StatusInternalServerError)
				return
			}
			if f.notFound || !f.exists {
				http.Error(w, `{"message":"ResourceNotFoundException"}`, http.StatusNotFound)
				return
			}
			_, _ = w.Write(f.profileJSON())
		case p == bedrockProfilesPath && m == http.MethodPost: // CreateInferenceProfile
			f.order = append(f.order, "CreateInferenceProfile")
			f.createBody = body
			out := map[string]any{
				"inferenceProfileArn": "arn:aws:bedrock:" + bedrockRegion + ":000000000000:application-inference-profile/" + bedrockAppID,
			}
			if !f.arnOnly {
				out["inferenceProfileId"] = bedrockAppID
			}
			b, _ := json.Marshal(out)
			_, _ = w.Write(b)
		case strings.HasPrefix(p, bedrockProfilesPath+"/") && m == http.MethodDelete: // DeleteInferenceProfile
			f.order = append(f.order, "DeleteInferenceProfile")
			f.exists = false
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	}))
}

func bedrockDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver(bedrockRegion)
	d.BedrockBaseURL = srv.URL
	d.PollInterval = 0
	d.PollTimeout = 2 * time.Second
	return d
}

// TestBedrock_ObserveReverseMap is the D1 verifier-rule input: a profile routing to
// [eu-central-1, eu-west-1, eu-south-2] reverse-maps inference.destinationRegions to
// exactly those three SORTED — with eu-south-2 SURFACED so a subset-of contract can
// catch the residency trap deterministically. model.provider is anthropic.
func TestBedrock_ObserveReverseMap(t *testing.T) {
	f := newFakeBedrock()
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	obs, diags, err := d.observeBedrock(bedrockCap, bedrockProviderID(bedrockRegion, bedrockProfile1))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["location.region"] != bedrockRegion {
		t.Fatalf("region = %v, want %s", m["location.region"], bedrockRegion)
	}
	dr, ok := m["inference.destinationRegions"].([]string)
	if !ok {
		t.Fatalf("inference.destinationRegions must be a []string, got %T", m["inference.destinationRegions"])
	}
	want := []string{"eu-central-1", "eu-south-2", "eu-west-1"} // sorted, unique
	if strings.Join(dr, ",") != strings.Join(want, ",") {
		t.Fatalf("destinationRegions = %v, want %v (sorted, unique)", dr, want)
	}
	// the crux: eu-south-2 must be present so subset-of catches the trap.
	if !containsRegion(dr, "eu-south-2") {
		t.Fatalf("eu-south-2 (the residency trap) must be surfaced in %v", dr)
	}
	if m["model.provider"] != "anthropic" {
		t.Fatalf("model.provider = %v, want anthropic", m["model.provider"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed missing")
	}
	if rec.unsign != 0 {
		t.Fatalf("every Bedrock request must be SigV4-signed; %d were not", rec.unsign)
	}
	_ = diags
}

// TestBedrock_ColonIdSingleEncodedOnWire (D1000): a profile id carries a ':' version
// suffix (eu.anthropic...v1:0). The signer double-encodes the canonical path for every
// non-S3 service (%3A→%253A, D880), so the WIRE must carry the SINGLE-encoded %3A — then
// AWS re-encodes it to %253A and the signature matches. A raw ':' on the wire (AWS
// re-encodes to %3A) or a double-encoded %253A both 403. ACME-034 measured the raw-':'
// regression against real AWS. The fake decodes r.URL.Path, so only the raw request
// path (EscapedPath) reveals the wire encoding — which is why the old test, whose id had
// no ':', could not catch this.
func TestBedrock_ColonIdSingleEncodedOnWire(t *testing.T) {
	if !strings.Contains(bedrockProfile1, ":") {
		t.Fatal("this regression test needs a ':' in the profile id")
	}
	f := newFakeBedrock()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	if _, _, err := d.observeBedrock(bedrockCap, bedrockProviderID(bedrockRegion, bedrockProfile1)); err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := f.getEscapedPath
	if !strings.Contains(got, "%3A") {
		t.Fatalf("wire path %q must single-encode the colon as %%3A (the signer double-encodes to %%253A to match AWS)", got)
	}
	if strings.Contains(got, "%253A") {
		t.Fatalf("wire path %q double-encodes the colon — AWS would re-encode to %%25253A and 403", got)
	}
	if strings.Contains(got, "v1:0") {
		t.Fatalf("wire path %q carries a RAW colon — AWS re-encodes to %%3A while we signed %%253A (ACME-034 403)", got)
	}
}

// TestBedrock_ManualGateHonesty: model.access IS reported (never omitted), OBSERVED
// from the profile's ACTIVE status (never a fabricated constant), and a diagnostic
// states plainly it is a manual-gate groundhold does not provision.
func TestBedrock_ManualGateHonesty(t *testing.T) {
	f := newFakeBedrock()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	obs, diags, err := d.observeBedrock(bedrockCap, bedrockProviderID(bedrockRegion, bedrockProfile1))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	var sawAccess bool
	for _, o := range obs {
		if o.Path == "model.access" {
			sawAccess = true
			if o.Value != true { // ACTIVE profile -> access observed true
				t.Fatalf("ACTIVE profile must observe model.access=true, got %v", o.Value)
			}
			if o.Derivation != "measured" {
				t.Fatalf("model.access must be measured (observed), got %q", o.Derivation)
			}
		}
	}
	if !sawAccess {
		t.Fatal("model.access must be reported (a manual-gate observed, never omitted)")
	}
	var sawDiag bool
	for _, dg := range diags {
		if strings.Contains(dg, "manual-gate") && strings.Contains(dg, "model.access") {
			sawDiag = true
		}
	}
	if !sawDiag {
		t.Fatalf("a diagnostic must state model.access is a manual-gate groundhold does not provision; diags = %v", diags)
	}

	// never fabricated as a blind constant: a non-ACTIVE profile observes access=false.
	f.status = "CREATING"
	obs2, _, err := d.observeBedrock(bedrockCap, bedrockProviderID(bedrockRegion, bedrockProfile1))
	if err != nil {
		t.Fatalf("observe (non-active): %v", err)
	}
	for _, o := range obs2 {
		if o.Path == "model.access" && o.Value != false {
			t.Fatalf("a non-ACTIVE profile must observe model.access=false (not a fabricated constant), got %v", o.Value)
		}
	}
}

// TestBedrock_Discover enumerates the region's profiles as capability.ai.inference,
// each carrying the reverse-mapped destination regions.
func TestBedrock_Discover(t *testing.T) {
	f := newFakeBedrock()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	found, _, err := d.discoverBedrock(bedrockRegion)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("discover found %d profiles, want 1", len(found))
	}
	if found[0].ResourceType != "capability.ai.inference" {
		t.Fatalf("resource type = %q, want capability.ai.inference", found[0].ResourceType)
	}
	if found[0].ProviderID != bedrockProviderID(bedrockRegion, bedrockProfile1) {
		t.Fatalf("providerId = %q", found[0].ProviderID)
	}
	var sawDest bool
	for _, o := range found[0].Observations {
		if o.Path == "inference.destinationRegions" {
			sawDest = true
		}
	}
	if !sawDest {
		t.Fatal("discovered profile must carry inference.destinationRegions")
	}
}

// TestBedrock_DiscoverApplicationProfile pins the F20 sibling: an APPLICATION profile
// (the kind groundhold creates, the kind adopt takes over) MUST be discovered. The old
// discover issued a bare ListInferenceProfiles, which on real AWS defaults to
// SYSTEM_DEFINED and hid every application profile — so a brownfield adopt would find
// nothing to onboard. With the fake mirroring that default, this asserts the explicit
// APPLICATION sweep surfaces it.
func TestBedrock_DiscoverApplicationProfile(t *testing.T) {
	f := newFakeBedrock()
	f.profileType = "APPLICATION"
	f.profileID = bedrockAppID
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	found, _, err := d.discoverBedrock(bedrockRegion)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("an APPLICATION profile must be discovered, found %d", len(found))
	}
	if found[0].ProviderID != bedrockProviderID(bedrockRegion, bedrockAppID) {
		t.Fatalf("providerId = %q, want the application profile", found[0].ProviderID)
	}
}

// TestBedrock_ObserveNotFound: a vanished profile is nothing-to-observe (readable,
// empty observations + a diagnostic), NOT an error.
func TestBedrock_ObserveNotFound(t *testing.T) {
	f := newFakeBedrock()
	f.notFound = true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	obs, diags, err := d.observeBedrock(bedrockCap, bedrockProviderID(bedrockRegion, bedrockProfile1))
	if err != nil {
		t.Fatalf("not-found must not error, got %v", err)
	}
	// Corrected with D520: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if !absentMarked(obs) {
		t.Fatalf("not-found must mark the resource absent, got %v", obs)
	}
	if len(diags) == 0 || !strings.Contains(diags[0], "bound resource is gone") {
		t.Fatalf("not-found must carry a gone diagnostic, got %v", diags)
	}
}

// TestBedrock_ObserveUnreadableErrors: an unreadable (500) profile read is UNKNOWN —
// an error, never a fabricated absence.
func TestBedrock_ObserveUnreadableErrors(t *testing.T) {
	f := newFakeBedrock()
	f.unreadable = true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	if _, _, err := d.observeBedrock(bedrockCap, bedrockProviderID(bedrockRegion, bedrockProfile1)); err == nil {
		t.Fatal("an unreadable profile must return an error, not a fabricated absence")
	}
}

// TestBedrock_CreateManualGateRefuses: a create requiring model.access=true must
// HONEST-REFUSE (a manual-gate groundhold does not provision), issuing no mutation.
func TestBedrock_CreateManualGateRefuses(t *testing.T) {
	f := newFakeBedrock()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	attrs := map[string]any{
		"location.region": bedrockRegion,
		"model.access":    true,
		"service.managed": true,
	}
	impl := map[string]any{
		"inferenceProfileName": "acme-eu-sonnet",
		"modelSource":          "arn:aws:bedrock:eu-central-1:000000000000:inference-profile/" + bedrockProfile1,
	}
	res := d.createBedrock(bedrockRegion, "prod", bedrockCap, attrs, impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "MANUAL gate") {
		t.Fatalf("model.access=true create must honest-refuse the manual gate, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("a manual-gate refusal must issue no Bedrock mutation; saw %v", f.order)
	}

	// D378, and the half that matters: the refusal must come from VALIDATE, which
	// apply runs as an up-front preflight over every action (D43). Raised only at
	// create time it fires mid-DAG, after sibling actions have already mutated —
	// which is how a field partner deployed a bad image and lost production while
	// the run reported nothing but this refusal.
	//
	// Validate takes no network and no fake: if it refuses, the whole run refuses
	// before the first mutation.
	if err := NewDriver(bedrockRegion).Validate("bedrock", bedrockCap, "prod", attrs, impl, 1); err == nil {
		t.Fatal("Validate accepted a create that can only ever be refused — apply would " +
			"mutate every sibling action first and discover this half-way through the plan")
	} else if !strings.Contains(err.Error(), "MANUAL gate") {
		t.Errorf("Validate refusal = %q, want the manual-gate reason", err)
	}
}

// TestBedrock_CreateApplicationProfile: a create WITHOUT the model.access manual-gate
// stands up an application profile and returns the AWS-assigned id in the pid, with
// ownership tags in the create body.
func TestBedrock_CreateApplicationProfile(t *testing.T) {
	f := newFakeBedrock()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	attrs := map[string]any{"location.region": bedrockRegion, "service.managed": true}
	impl := map[string]any{
		"inferenceProfileName": "acme-eu-sonnet",
		"modelSource":          "arn:aws:bedrock:eu-central-1:000000000000:inference-profile/" + bedrockProfile1,
	}
	res := d.createBedrock(bedrockRegion, "prod", bedrockCap, attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != bedrockProviderID(bedrockRegion, bedrockAppID) {
		t.Fatalf("create providerId = %q, want the AWS-assigned application id", res.ProviderID)
	}
	var cb map[string]any
	if err := json.Unmarshal([]byte(f.createBody), &cb); err != nil {
		t.Fatalf("create body not JSON: %v", err)
	}
	tags, _ := cb["tags"].([]any)
	if len(tags) != 2 {
		t.Fatalf("create must carry two ownership tags, got %v", cb["tags"])
	}
}

// TestBedrock_CreateArnOnlyResponse pins F18: AWS's CreateInferenceProfile returns
// the ARN, not a bare inferenceProfileId. A create that required the id
// false-negatived a real success as "unknown" and aborted the apply into a partial.
// The driver now derives the id from the ARN and reports succeeded.
func TestBedrock_CreateArnOnlyResponse(t *testing.T) {
	f := newFakeBedrock()
	f.arnOnly = true // real AWS shape: ARN only, no inferenceProfileId
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	attrs := map[string]any{"location.region": bedrockRegion, "service.managed": true}
	impl := map[string]any{
		"inferenceProfileName": "acme-eu-sonnet",
		"modelSource":          "arn:aws:bedrock:eu-central-1:000000000000:inference-profile/" + bedrockProfile1,
	}
	res := d.createBedrock(bedrockRegion, "prod", bedrockCap, attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("an ARN-only create response must succeed (id derived from the ARN), got %q (%s)", res.Status, res.Reason)
	}
	if res.ProviderID != bedrockProviderID(bedrockRegion, bedrockAppID) {
		t.Fatalf("providerId = %q, want the id derived from the ARN", res.ProviderID)
	}
}

// TestBedrock_DeleteSystemProfileRefuses: a SYSTEM (eu.anthropic.*) profile is
// AWS-managed — the delete must honest-refuse before any mutation.
func TestBedrock_DeleteSystemProfileRefuses(t *testing.T) {
	f := newFakeBedrock()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	res := d.deleteBedrock(bedrockCap, "prod", bedrockProviderID(bedrockRegion, bedrockProfile1))
	if res.Status != "failed" || !strings.Contains(res.Reason, "AWS-managed") {
		t.Fatalf("a system inference profile delete must honest-refuse, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("no delete may touch an AWS-managed system profile; saw %v", f.order)
	}
}

// TestBedrock_DeleteApplicationOwnershipGated: an application profile with matching
// ownership tags deletes; a foreign one refuses.
func TestBedrock_DeleteApplicationOwnershipGated(t *testing.T) {
	f := newFakeBedrock()
	f.profileID = bedrockAppID
	f.profileType = "APPLICATION"
	f.tags = []map[string]string{
		{"key": "groundhold-capability", "value": sanitizeTag(bedrockCap)},
		{"key": "groundhold-environment", "value": sanitizeTag("prod")},
	}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	res := d.deleteBedrock(bedrockCap, "prod", bedrockProviderID(bedrockRegion, bedrockAppID))
	if res.Status != "succeeded" {
		t.Fatalf("owned application profile delete = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if strings.Join(f.order, ",") != "DeleteInferenceProfile" {
		t.Fatalf("delete order = %v, want [DeleteInferenceProfile]", f.order)
	}

	// foreign tags -> refuse.
	f2 := newFakeBedrock()
	f2.profileID = bedrockAppID
	f2.profileType = "APPLICATION"
	f2.tags = []map[string]string{{"key": "team", "value": "someone-else"}}
	srv2 := f2.handler(t, nil)
	defer srv2.Close()
	d2 := bedrockDriver(t, srv2)
	res2 := d2.deleteBedrock(bedrockCap, "prod", bedrockProviderID(bedrockRegion, bedrockAppID))
	if res2.Status != "failed" || !strings.Contains(res2.Reason, "not ours") {
		t.Fatalf("a foreign application profile must refuse the delete, got %+v", res2)
	}
	for _, o := range f2.order {
		if o == "DeleteInferenceProfile" {
			t.Fatal("no delete may touch a foreign profile")
		}
	}
}

// TestBedrock_ClassifyChange: routing (destinationRegions, provider) is immutable; the
// manual-gate model.access + service.managed are unsupported. Every path has a reason.
func TestBedrock_ClassifyChange(t *testing.T) {
	want := map[string]string{
		"inference.destinationRegions": "immutable",
		"model.provider":               "immutable",
		"model.access":                 "unsupported",
		"service.managed":              "unsupported",
	}
	for p, w := range want {
		got, reason := classifyBedrockChange(p)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// TestBedrock_BuildRefusesUnmapped: an attribute with no ai.inference mapping is
// REFUSED (never silently dropped).
func TestBedrock_BuildRefusesUnmapped(t *testing.T) {
	attrs := map[string]any{"location.region": bedrockRegion, "encryption.atRest": true}
	impl := map[string]any{"inferenceProfileName": "x", "modelSource": "arn:aws:bedrock:eu-central-1::foundation-model/anthropic.claude"}
	if _, err := BuildBedrock("prod", bedrockCap, attrs, impl, 1); err == nil {
		t.Fatal("an unmapped attribute must be refused, not silently dropped")
	}
}

func containsRegion(rs []string, r string) bool {
	for _, x := range rs {
		if x == r {
			return true
		}
	}
	return false
}

// TestBedrock_ReconcilePendingCreate pins F19: the AWS driver concludes a pending
// bedrock create receipt read-only by ownership tags — a live ACTIVE profile with
// our tags => succeeded WITH the id (unblocks resume/apply); no owned profile in a
// complete, readable list => failed.
func TestBedrock_ReconcilePendingCreate(t *testing.T) {
	f := newFakeBedrock()
	f.profileType = "APPLICATION"
	f.profileID = bedrockAppID
	f.status = "ACTIVE"
	f.tags = []map[string]string{
		{"key": "groundhold-capability", "value": sanitizeTag(bedrockCap)},
		{"key": "groundhold-environment", "value": "prod"},
	}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	receipt := map[string]any{"target": "aws.bedrock/xyz", "operation": "create"}
	res := d.Reconcile(bedrockCap, "prod", receipt)
	if res.Status != "succeeded" {
		t.Fatalf("a live ACTIVE profile with our tags must conclude succeeded, got %+v", res)
	}
	if res.ProviderID != bedrockProviderID(bedrockRegion, bedrockAppID) {
		t.Fatalf("providerId = %q, want the found profile's id", res.ProviderID)
	}

	f.tags = nil // no owned profile in a readable list -> the create never landed
	if res2 := d.Reconcile(bedrockCap, "prod", receipt); res2.Status != "failed" {
		t.Fatalf("no owned profile must conclude failed, got %+v", res2)
	}
	// a non-bedrock target fails closed to unknown, never a fabricated conclusion.
	if u := d.Reconcile(bedrockCap, "prod", map[string]any{"target": "aws.eks/x"}); u.Status != "unknown" {
		t.Fatalf("an unwired service must reconcile unknown, got %+v", u)
	}
}

// TestBedrock_ReconcileEmptyRegion pins the honest-refusal guard: a driver built
// with NO region (the CLI bug where resume/converge/adopt/probe constructed
// aws.NewDriver("") and discarded the operator's region) must refuse a bedrock
// reconcile with a region-naming reason — NOT attempt a malformed endpoint and
// report an opaque "unreadable". This is the regression the fake could never catch:
// bedrockDriver overrides BedrockBaseURL, so an empty region was invisible in tests
// while it broke every real run. The guard fires before any URL is built.
func TestBedrock_ReconcileEmptyRegion(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AWS_REGION", "")         // D269 added AWS_REGION as the first fallback
	t.Setenv("AWS_DEFAULT_REGION", "") // no ambient region either
	d := NewDriver("")                 // the CLI-discarded-region bug, reproduced
	res := d.Reconcile(bedrockCap, "prod", map[string]any{"target": "aws.bedrock/xyz", "operation": "create"})
	if res.Status != "unknown" {
		t.Fatalf("a region-less reconcile must be unknown, got %+v", res)
	}
	if !strings.Contains(res.Reason, "region") {
		t.Fatalf("the refusal must name the missing region (not opaque 'unreadable'), got %q", res.Reason)
	}
}

// TestBedrock_CreateAdoptsExisting pins D252: when CreateInferenceProfile reports
// the name already exists AND a profile with that name carries our ownership tags,
// create BINDS it (succeeded + pid) — a lost-ledger converge re-adopts reality
// instead of stranding an unknown. Ownership is tags, never candidate attributes.
// bedrockExistingServer is the create-adoption fixture: the profile already exists and
// carries our ownership tags, so the create POST is answered 409 and the driver must
// list, recognise and bind it. Shared by the per-driver test and the D391 class gate.
func bedrockExistingServer(t *testing.T, profID, profName string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, m := r.URL.Path, r.Method
		switch {
		case p == bedrockProfilesPath && m == http.MethodPost: // create -> already exists
			http.Error(w, `{"message":"Conflict: inference profile already exists"}`, http.StatusConflict)
		case p == bedrockProfilesPath && m == http.MethodGet: // list APPLICATION -> ours
			if r.URL.Query().Get("typeEquals") == "APPLICATION" {
				out, _ := json.Marshal(map[string]any{"inferenceProfileSummaries": []map[string]any{{"inferenceProfileId": profID}}})
				_, _ = w.Write(out)
			} else {
				_, _ = w.Write([]byte(`{"inferenceProfileSummaries":[]}`))
			}
		case p == bedrockProfilesPath+"/"+profID && m == http.MethodGet: // get -> name + our tags
			out, _ := json.Marshal(map[string]any{
				"inferenceProfileArn":  "arn:aws:bedrock:" + bedrockRegion + ":000000000000:inference-profile/" + profID,
				"inferenceProfileId":   profID,
				"inferenceProfileName": profName,
				"type":                 "APPLICATION",
				"status":               "ACTIVE",
				"tags": []map[string]any{
					{"key": "groundhold-capability", "value": sanitizeTag(bedrockCap)},
					{"key": "groundhold-environment", "value": sanitizeTag("prod")},
				},
			})
			_, _ = w.Write(out)
		default:
			w.WriteHeader(400)
		}
	}))
}

func TestBedrock_CreateAdoptsExisting(t *testing.T) {
	const profID = "oxw790j932py"
	const profName = "acme-eu-sonnet"
	srv := bedrockExistingServer(t, profID, profName)
	defer srv.Close()
	d := bedrockDriver(t, srv)

	attrs := map[string]any{"location.region": bedrockRegion, "service.managed": true}
	impl := map[string]any{"inferenceProfileName": profName,
		"modelSource": "arn:aws:bedrock:eu-central-1:000000000000:inference-profile/" + bedrockProfile1}
	res := d.createBedrock(bedrockRegion, "prod", bedrockCap, attrs, impl, 1)
	if res.Status != "succeeded" || res.ProviderID != bedrockProviderID(bedrockRegion, profID) {
		t.Fatalf("create-adoption must bind the existing owned profile, got %+v", res)
	}
}

// D376. Every observation this driver emits must survive the SAME parse `adopt`
// puts it through. Reported from the field: adopting a Bedrock inference profile
// refused with `inference.destinationRegions: observation unparseable`, because
// the driver emits a Go []string and the scalar parser accepted only []any.
//
// The driver's own tests all passed — they compare the Value directly and never
// parse it. This assertion closes that gap where it was found: observe, then run
// every value through the parser, exactly as adoption does.
func TestBedrock_ObservationsSurviveTheAdoptParse(t *testing.T) {
	f := newFakeBedrock()
	srv := f.handler(t, newCapture())
	defer srv.Close()
	d := bedrockDriver(t, srv)

	obs, _, err := d.observeBedrock(bedrockCap, bedrockProviderID(bedrockRegion, bedrockProfile1))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	if len(obs) == 0 {
		t.Fatal("no observations — this assertion would be vacuous")
	}
	for _, o := range obs {
		if _, perr := scalars.Parse(o.Value); perr != nil {
			t.Errorf("%s carries a value adopt cannot parse (%T): %v", o.Path, o.Value, perr)
		}
	}
}

// bedrockRole classifies the Bedrock REST surface: GET is the ownership read, anything
// else changes the world.
func bedrockRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingBedrock enrols Bedrock in the D391 gate. Bedrock adopts REACTIVELY —
// it sends the create, AWS answers 409, and the driver then lists and binds the owned
// profile. So one mutation is the mechanism, not a duplicate, and the load-bearing proof
// here is the PID: it must be the EXISTING profile's id, never a freshly minted one.
func TestAdoptsExistingBedrock(t *testing.T) {
	const profID = "oxw790j932py"
	const profName = "acme-eu-sonnet"
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/bedrock",
		Classify: bedrockRole,
		ExistingServer: func() *httptest.Server {
			return bedrockExistingServer(t, profID, profName)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(bedrockRegion)
			d.HTTP = &http.Client{Transport: rt}
			d.BedrockBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.PollInterval = 0
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("bedrock", bedrockCap, "prod",
				map[string]any{"location.region": bedrockRegion, "service.managed": true},
				map[string]any{"inferenceProfileName": profName,
					"modelSource": "arn:aws:bedrock:eu-central-1:000000000000:inference-profile/" + bedrockProfile1},
				"inf", 1)
		},
		PID:              bedrockProviderID(bedrockRegion, profID),
		AllowedMutations: 1, // the create POST AWS answers 409 — the detection itself
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// absentMarked reports whether an observation set carries the F-LC3 marker set
// true — the one way a driver says a BOUND resource is authoritatively gone.
func absentMarked(obs []provider.Observation) bool {
	for _, o := range obs {
		if o.Path == provider.ResourceAbsentPath {
			gone, _ := o.Value.(bool)
			return gone
		}
	}
	return false
}
