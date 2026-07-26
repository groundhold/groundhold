package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	sesInbCap       = "capability.email.inbound"
	sesInbRegion    = "eu-central-1"
	sesInbRuleSet   = "pv-deals-set"
	sesInbRuleNm    = "pv-deals-rule"
	sesInbRecipient = "in.acme.example"
	sesInbBucket    = "acme-deal-mailbox"
	sesInbTopic     = "arn:aws:sns:eu-central-1:000000000000:deal-mail-landed"
)

// fakeSESInb is a stateful fake SES v1 (receiving, Query-protocol) endpoint. It
// records the ORDER of mutating actions, tracks the rule set / rule / active-set as
// they land and are torn down, captures the CreateReceiptRule params, and can
// inject a SetActiveReceiptRuleSet failure to exercise the inactive-rule -> unknown
// path (the four-valued crux: a rule that receives nothing until activated).
type fakeSESInb struct {
	ruleSet string
	rule    string

	ruleSetExists bool
	ruleExists    bool
	scanEnabled   bool
	hasS3         bool
	active        string // name of the active rule set ("" = none)

	failSetActive bool

	ruleParams url.Values // captured CreateReceiptRule / UpdateReceiptRule params
	order      []string
}

func newFakeSESInb() *fakeSESInb {
	return &fakeSESInb{ruleSet: sesInbRuleSet, rule: sesInbRuleNm}
}

func sesInbErrXML(code string) string {
	return `<ErrorResponse><Error><Type>Sender</Type><Code>` + code + `</Code><Message>x</Message></Error></ErrorResponse>`
}

func (f *fakeSESInb) ruleXML() string {
	actions := ""
	if f.hasS3 {
		actions = `<Actions><member><S3Action><BucketName>` + sesInbBucket + `</BucketName><ObjectKeyPrefix>raw/</ObjectKeyPrefix></S3Action></member></Actions>`
	}
	scan := "false"
	if f.scanEnabled {
		scan = "true"
	}
	return `<DescribeReceiptRuleResponse><DescribeReceiptRuleResult><Rule>` +
		`<Name>` + f.rule + `</Name><Enabled>true</Enabled><TlsPolicy>Require</TlsPolicy>` +
		`<ScanEnabled>` + scan + `</ScanEnabled>` +
		`<Recipients><member>` + sesInbRecipient + `</member></Recipients>` +
		actions +
		`</Rule></DescribeReceiptRuleResult></DescribeReceiptRuleResponse>`
}

func (f *fakeSESInb) handler(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body := string(b)
		if rec != nil {
			rec.record(r, body)
		}
		vals, _ := url.ParseQuery(body)
		action := vals.Get("Action")
		switch action {
		case "CreateReceiptRuleSet":
			f.order = append(f.order, "CreateReceiptRuleSet")
			f.ruleSetExists = true
			_, _ = w.Write([]byte(`<CreateReceiptRuleSetResponse/>`))
		case "CreateReceiptRule":
			f.order = append(f.order, "CreateReceiptRule")
			f.ruleParams = vals
			f.ruleExists = true
			f.scanEnabled = vals.Get("Rule.ScanEnabled") == "true"
			f.hasS3 = vals.Get("Rule.Actions.member.1.S3Action.BucketName") != ""
			_, _ = w.Write([]byte(`<CreateReceiptRuleResponse/>`))
		case "UpdateReceiptRule":
			f.order = append(f.order, "UpdateReceiptRule")
			f.ruleParams = vals
			f.scanEnabled = vals.Get("Rule.ScanEnabled") == "true"
			f.hasS3 = vals.Get("Rule.Actions.member.1.S3Action.BucketName") != ""
			_, _ = w.Write([]byte(`<UpdateReceiptRuleResponse/>`))
		case "SetActiveReceiptRuleSet":
			if f.failSetActive {
				http.Error(w, sesInbErrXML("InvalidParameterValue"), http.StatusBadRequest)
				return
			}
			f.order = append(f.order, "SetActiveReceiptRuleSet")
			f.active = vals.Get("RuleSetName")
			_, _ = w.Write([]byte(`<SetActiveReceiptRuleSetResponse/>`))
		case "DescribeReceiptRule":
			if !f.ruleExists {
				http.Error(w, sesInbErrXML("RuleDoesNotExist"), http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(f.ruleXML()))
		case "DescribeActiveReceiptRuleSet":
			_, _ = w.Write([]byte(`<DescribeActiveReceiptRuleSetResponse><DescribeActiveReceiptRuleSetResult><Metadata><Name>` +
				f.active + `</Name></Metadata></DescribeActiveReceiptRuleSetResult></DescribeActiveReceiptRuleSetResponse>`))
		case "DescribeReceiptRuleSet":
			if !f.ruleSetExists {
				http.Error(w, sesInbErrXML("RuleSetDoesNotExist"), http.StatusBadRequest)
				return
			}
			members := ""
			if f.ruleExists {
				members = `<member><Name>` + f.rule + `</Name></member>`
			}
			_, _ = w.Write([]byte(`<DescribeReceiptRuleSetResponse><DescribeReceiptRuleSetResult><Rules>` +
				members + `</Rules></DescribeReceiptRuleSetResult></DescribeReceiptRuleSetResponse>`))
		case "DeleteReceiptRule":
			f.order = append(f.order, "DeleteReceiptRule")
			f.ruleExists = false
			_, _ = w.Write([]byte(`<DeleteReceiptRuleResponse/>`))
		case "DeleteReceiptRuleSet":
			f.order = append(f.order, "DeleteReceiptRuleSet")
			f.ruleSetExists = false
			_, _ = w.Write([]byte(`<DeleteReceiptRuleSetResponse/>`))
		case "ListReceiptRuleSets":
			member := ""
			if f.ruleSetExists {
				member = `<member><Name>` + f.ruleSet + `</Name></member>`
			}
			_, _ = w.Write([]byte(`<ListReceiptRuleSetsResponse><ListReceiptRuleSetsResult><RuleSets>` +
				member + `</RuleSets></ListReceiptRuleSetsResult></ListReceiptRuleSetsResponse>`))
		default:
			http.Error(w, sesInbErrXML("InvalidAction"), http.StatusBadRequest)
		}
	}))
}

func sesInbDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver(sesInbRegion)
	d.SESBaseURL = srv.URL // SES receiving shares the SESv2 endpoint host
	d.PollInterval = 0
	d.PollTimeout = 2 * time.Second
	return d
}

func sesInbCandidate() (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region": sesInbRegion,
		"spam.filtered":   true,
		"delivery.sink":   true,
		"service.managed": true,
	}
	impl = map[string]any{
		"recipientDomain":   sesInbRecipient,
		"ruleSetName":       sesInbRuleSet,
		"ruleName":          sesInbRuleNm,
		"s3BucketName":      sesInbBucket,
		"s3ObjectKeyPrefix": "raw/",
		"snsTopicArn":       sesInbTopic,
	}
	return
}

// TestSESInbound_FullCreateSucceeds: CreateReceiptRuleSet -> CreateReceiptRule
// (recipients + scanning + the S3 sink) -> SetActiveReceiptRuleSet -> succeeded
// WITH the pid. Every request is SigV4-signed.
func TestSESInbound_FullCreateSucceeds(t *testing.T) {
	f := newFakeSESInb()
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := sesInbDriver(t, srv)
	attrs, impl := sesInbCandidate()

	res := d.createSESInbound(sesInbRegion, "prod", sesInbCap, attrs, impl, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm) {
		t.Fatalf("create providerId = %q", res.ProviderID)
	}
	joined := strings.Join(f.order, ",")
	if joined != "CreateReceiptRuleSet,CreateReceiptRule,SetActiveReceiptRuleSet" {
		t.Fatalf("create order = %v, want rule set -> rule -> activate", f.order)
	}
	if f.ruleParams.Get("Rule.ScanEnabled") != "true" {
		t.Fatalf("spam.filtered=true must set Rule.ScanEnabled=true, got %q", f.ruleParams.Get("Rule.ScanEnabled"))
	}
	if f.ruleParams.Get("Rule.Actions.member.1.S3Action.BucketName") != sesInbBucket {
		t.Fatalf("delivery.sink=true must attach the S3 action bucket, got %q", f.ruleParams.Get("Rule.Actions.member.1.S3Action.BucketName"))
	}
	if f.ruleParams.Get("Rule.Recipients.member.1") != sesInbRecipient {
		t.Fatalf("recipient must ride in the rule, got %q", f.ruleParams.Get("Rule.Recipients.member.1"))
	}
	if f.ruleParams.Get("Rule.TlsPolicy") != "Require" {
		t.Fatalf("inbound mail must require TLS, got %q", f.ruleParams.Get("Rule.TlsPolicy"))
	}
	if rec.unsign != 0 {
		t.Fatalf("every SES request must be SigV4-signed; %d were not", rec.unsign)
	}
}

// TestSESInbound_InactiveIsUnknown: the four-valued crux — the rule set + rule land
// but SetActiveReceiptRuleSet fails. The result must be unknown WITH the providerId
// (a rule that receives nothing until activated — reconcile), never "failed".
func TestSESInbound_InactiveIsUnknown(t *testing.T) {
	f := newFakeSESInb()
	f.failSetActive = true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)
	attrs, impl := sesInbCandidate()

	res := d.createSESInbound(sesInbRegion, "prod", sesInbCap, attrs, impl, 1)
	if res.Status != "unknown" {
		t.Fatalf("rule created + activation failed must be unknown, got %q (%s)", res.Status, res.Reason)
	}
	if res.ProviderID != sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm) {
		t.Fatalf("inactive-rule unknown must carry the providerId, got %q", res.ProviderID)
	}
	if !f.ruleExists {
		t.Fatal("the rule should have landed before the activation failure")
	}
}

// TestSESInbound_ObserveReverseMap: a scanning rule with an S3 action, in the
// ACTIVE rule set, reverse-maps to spam.filtered=true and delivery.sink=true, with
// EU residency and service.managed.
func TestSESInbound_ObserveReverseMap(t *testing.T) {
	f := newFakeSESInb()
	f.ruleSetExists, f.ruleExists = true, true
	f.scanEnabled, f.hasS3 = true, true
	f.active = sesInbRuleSet
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)

	obs, _, err := d.observeSESInbound(sesInbCap, sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["location.region"] != sesInbRegion {
		t.Fatalf("region = %v, want %s (EU residency)", m["location.region"], sesInbRegion)
	}
	if m["spam.filtered"] != true {
		t.Fatalf("ScanEnabled must map to spam.filtered=true, got %v", m["spam.filtered"])
	}
	if m["delivery.sink"] != true {
		t.Fatalf("an S3 action in the active rule set must map to delivery.sink=true, got %v", m["delivery.sink"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed missing")
	}
}

// TestSESInbound_ObserveInactiveSinkIsFalse: an S3 action in a rule set that is NOT
// the active one delivers nothing — delivery.sink=false (honest: an inactive rule
// receives no mail).
func TestSESInbound_ObserveInactiveSinkIsFalse(t *testing.T) {
	f := newFakeSESInb()
	f.ruleSetExists, f.ruleExists = true, true
	f.scanEnabled, f.hasS3 = true, true
	f.active = "someone-elses-set" // ours is NOT active
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)

	obs, _, err := d.observeSESInbound(sesInbCap, sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "delivery.sink" && o.Value != false {
			t.Fatalf("an inactive rule set must map to delivery.sink=false, got %v", o.Value)
		}
	}
}

// TestSESInbound_DeleteSucceeds: delete removes the rule (ownership by deterministic
// name), and succeeds.
func TestSESInbound_DeleteSucceeds(t *testing.T) {
	f := newFakeSESInb()
	f.ruleSetExists, f.ruleExists = true, true
	f.active = sesInbRuleSet // active -> the rule set is left standing (SES refuses)
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)

	res := d.deleteSESInbound(sesInbCap, "prod",
		sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm))
	if res.Status != "succeeded" {
		t.Fatalf("delete status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if f.order[0] != "DeleteReceiptRule" {
		t.Fatalf("delete must issue DeleteReceiptRule first, got %v", f.order)
	}
	if f.ruleExists {
		t.Fatal("the rule should be gone after delete")
	}
}

// TestSESInbound_DeleteIdempotent: a rule already gone is an idempotent success
// (no mutation).
func TestSESInbound_DeleteIdempotent(t *testing.T) {
	f := newFakeSESInb()
	f.ruleExists = false
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)

	res := d.deleteSESInbound(sesInbCap, "prod",
		sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm))
	if res.Status != "succeeded" {
		t.Fatalf("idempotent delete must succeed, got %+v", res)
	}
	for _, o := range f.order {
		if strings.HasPrefix(o, "Delete") {
			t.Fatalf("an already-gone rule must issue no delete, saw %v", f.order)
		}
	}
}

// TestSESInbound_RefuseBeforeMutate: delivery.sink=true with no s3BucketName must
// refuse at Build AND createSESInbound — before any SES call.
func TestSESInbound_RefuseBeforeMutate(t *testing.T) {
	f := newFakeSESInb()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)

	attrs, impl := sesInbCandidate()
	delete(impl, "s3BucketName")
	if _, err := BuildSESInbound("prod", sesInbCap, attrs, impl, 1); err == nil || !strings.Contains(err.Error(), "s3BucketName") {
		t.Fatalf("delivery.sink with no bucket must refuse at Build with an s3BucketName reason, got %v", err)
	}
	res := d.createSESInbound(sesInbRegion, "prod", sesInbCap, attrs, impl, 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "s3BucketName") {
		t.Fatalf("delivery.sink with no bucket must refuse create, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("refuse-before-mutate must issue no SES call; saw %v", f.order)
	}
}

// TestSESInbound_SinkOperandWithoutSinkRefuses: an s3BucketName given while
// delivery.sink is not true is an ambiguous shape — refused.
func TestSESInbound_SinkOperandWithoutSinkRefuses(t *testing.T) {
	attrs, impl := sesInbCandidate()
	attrs["delivery.sink"] = false
	if _, err := BuildSESInbound("prod", sesInbCap, attrs, impl, 1); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("a sink operand without delivery.sink must refuse as ambiguous, got %v", err)
	}
}

// TestSESInbound_UnmappedAttributeRefuses: an attribute with no email.inbound
// mapping is REFUSED (never silently dropped).
func TestSESInbound_UnmappedAttributeRefuses(t *testing.T) {
	attrs, impl := sesInbCandidate()
	attrs["encryption.atRest"] = true
	if _, err := BuildSESInbound("prod", sesInbCap, attrs, impl, 1); err == nil {
		t.Fatal("an unmapped attribute must be refused, not silently dropped")
	}
}

// TestSESInbound_ClassifyChange: spam.filtered + delivery.sink are mutable in
// place; location.region is unsupported (SES receiving is region-bound). Every path
// carries a reason.
func TestSESInbound_ClassifyChange(t *testing.T) {
	want := map[string]string{
		"spam.filtered":   "mutable",
		"delivery.sink":   "mutable",
		"location.region": "unsupported",
		"service.managed": "unsupported",
	}
	for p, w := range want {
		got, reason := classifySESInboundChange(p)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// TestSESInbound_UpdateDeliverySink: turning delivery.sink ON in place re-puts the
// rule (with the S3 action) and re-asserts activation.
func TestSESInbound_UpdateDeliverySink(t *testing.T) {
	f := newFakeSESInb()
	f.ruleSetExists, f.ruleExists = true, true
	f.scanEnabled, f.hasS3 = true, false // no sink yet
	f.active = sesInbRuleSet
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)
	attrs, impl := sesInbCandidate()

	res := d.updateSESInbound(sesInbCap, "prod",
		sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm),
		attrs, impl, []string{"delivery.sink"})
	if res.Status != "succeeded" || res.ProviderID != sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm) {
		t.Fatalf("delivery.sink update must succeed with the pid, got %+v", res)
	}
	if !f.hasS3 {
		t.Fatalf("update must have attached the S3 action; order = %v", f.order)
	}
	if strings.Join(f.order, ",") != "UpdateReceiptRule,SetActiveReceiptRuleSet" {
		t.Fatalf("update order = %v, want UpdateReceiptRule then SetActiveReceiptRuleSet", f.order)
	}
}

// TestSESInbound_Discover: ListReceiptRuleSets -> DescribeReceiptRuleSet -> observe
// surfaces the receiving pipeline as capability.email.inbound for adoption.
func TestSESInbound_Discover(t *testing.T) {
	f := newFakeSESInb()
	f.ruleSetExists, f.ruleExists = true, true
	f.scanEnabled, f.hasS3 = true, true
	f.active = sesInbRuleSet
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesInbDriver(t, srv)

	found, _, err := d.discoverSESInbound(sesInbRegion)
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("discover found %d, want 1", len(found))
	}
	if found[0].ResourceType != "capability.email.inbound" {
		t.Fatalf("discovered type = %q", found[0].ResourceType)
	}
	if found[0].ProviderID != sesInboundProviderID(sesInbRegion, sesInbRuleSet, sesInbRuleNm) {
		t.Fatalf("discovered pid = %q", found[0].ProviderID)
	}
}

// TestSESInbound_DeterministicNames: with no name operands the driver derives
// pv-prefixed, valid SES names (the ownership marker — there are no tags).
func TestSESInbound_DeterministicNames(t *testing.T) {
	attrs, impl := sesInbCandidate()
	delete(impl, "ruleSetName")
	delete(impl, "ruleName")
	p, err := BuildSESInbound("prod", sesInbCap, attrs, impl, 1)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.HasPrefix(p.RuleSetName, sesInboundGeneratedPrefix) || !sesInboundNameOK.MatchString(p.RuleSetName) {
		t.Fatalf("derived rule-set name %q is not a valid pv- name", p.RuleSetName)
	}
	if !strings.HasPrefix(p.RuleName, sesInboundGeneratedPrefix) || !sesInboundNameOK.MatchString(p.RuleName) {
		t.Fatalf("derived rule name %q is not a valid pv- name", p.RuleName)
	}
}
