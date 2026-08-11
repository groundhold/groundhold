package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

const (
	sesCap    = "capability.email.sending"
	sesDomain = "mail.acme.example.com"
	sesRegion = "eu-central-1"
	sesTopic  = "arn:aws:sns:eu-central-1:000000000000:acme-bounces"
)

// fakeSES is a stateful fake SESv2 (REST-JSON) endpoint. It records the ORDER of
// mutating actions, tracks the identity + configuration set + event destination as
// they land and are torn down, captures the CreateEmailIdentity body, and can inject
// an event-destination failure to exercise the partial-composite -> unknown path.
type fakeSES struct {
	mu sync.Mutex

	domain    string
	configSet string

	identityExists bool
	tags           []map[string]string
	dkimSigning    bool
	dkimStatus     string
	// D746: the identity's default configuration set, set by the create.
	defaultConfigSet string
	configSetExists  bool
	eventDestExists  bool

	productionAccess bool // SESv2 GetAccount ProductionAccessEnabled (sandbox exit)
	failGetAccount   bool // inject a 500 on GetAccount to exercise the unreadable path

	failEventDest bool // inject a 400 on the event-destination POST

	identityBody string // captured CreateEmailIdentity JSON
	order        []string
}

func newFakeSES() *fakeSES {
	return &fakeSES{
		domain:    sesDomain,
		configSet: sesConfigSetName(sesCap, sesDomain),
		tags: []map[string]string{
			{"Key": "groundhold-capability", "Value": sanitizeTag(sesCap)},
			{"Key": "groundhold-environment", "Value": sanitizeTag("prod")},
		},
		dkimStatus: "PENDING",
	}
}

func (f *fakeSES) handler(t *testing.T, rec *capture) *httptest.Server {
	t.Helper()
	idPath := sesIdentitiesPath + "/" + f.domain
	csPath := sesConfigSetsPath + "/" + f.configSet
	edPath := csPath + "/event-destinations"
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
		case p == sesIdentitiesPath && m == http.MethodPost: // CreateEmailIdentity
			f.order = append(f.order, "CreateEmailIdentity")
			f.identityExists = true
			f.identityBody = body
			f.dkimSigning, f.dkimStatus = true, "PENDING" // Easy DKIM default-on
			_, _ = w.Write([]byte(`{}`))
		case p == idPath && m == http.MethodGet: // GetEmailIdentity
			if !f.identityExists {
				http.Error(w, `{"message":"NotFoundException"}`, http.StatusNotFound)
				return
			}
			out, _ := json.Marshal(map[string]any{
				"DkimAttributes": map[string]any{"SigningEnabled": f.dkimSigning, "Status": f.dkimStatus},
				"Tags":           f.tags,
				// D746: the identity's DEFAULT configuration set. Absent until the
				// create associates one — which it did not do until this entry, so a
				// set nothing routed through reported bounce.tracked: true.
				"ConfigurationSetName": f.defaultConfigSet,
			})
			_, _ = w.Write(out)
		case p == idPath+"/configuration-set" && m == http.MethodPut: // D746
			f.order = append(f.order, "PutIdentityConfigurationSet")
			var in struct{ ConfigurationSetName string }
			_ = json.Unmarshal(b, &in)
			f.defaultConfigSet = in.ConfigurationSetName
			_, _ = w.Write([]byte(`{}`))
		case p == idPath+"/dkim" && m == http.MethodPut: // PutEmailIdentityDkimAttributes
			f.order = append(f.order, "PutDkim")
			var in struct{ SigningEnabled bool }
			_ = json.Unmarshal(b, &in)
			f.dkimSigning = in.SigningEnabled
			_, _ = w.Write([]byte(`{}`))
		case p == idPath && m == http.MethodDelete: // DeleteEmailIdentity
			f.order = append(f.order, "DeleteEmailIdentity")
			f.identityExists = false
			_, _ = w.Write([]byte(`{}`))
		case p == sesConfigSetsPath && m == http.MethodPost: // CreateConfigurationSet
			f.order = append(f.order, "CreateConfigurationSet")
			f.configSetExists = true
			_, _ = w.Write([]byte(`{}`))
		case p == edPath && m == http.MethodPost: // CreateConfigurationSetEventDestination
			if f.failEventDest {
				http.Error(w, `{"message":"BadRequestException"}`, http.StatusBadRequest)
				return
			}
			f.order = append(f.order, "CreateEventDestination")
			f.eventDestExists = true
			_, _ = w.Write([]byte(`{}`))
		case p == edPath && m == http.MethodGet: // GetConfigurationSetEventDestinations
			if !f.configSetExists {
				http.Error(w, `{"message":"NotFoundException"}`, http.StatusNotFound)
				return
			}
			if f.eventDestExists {
				_, _ = w.Write([]byte(`{"EventDestinations":[{"MatchingEventTypes":["BOUNCE","COMPLAINT"],"SnsDestination":{"TopicArn":"` + sesTopic + `"}}]}`))
			} else {
				_, _ = w.Write([]byte(`{"EventDestinations":[]}`))
			}
		case p == sesAccountPath && m == http.MethodGet: // GetAccount (manual-gate)
			if f.failGetAccount {
				http.Error(w, `{"message":"InternalServiceException"}`, http.StatusInternalServerError)
				return
			}
			out, _ := json.Marshal(map[string]any{
				"ProductionAccessEnabled": f.productionAccess,
				"EnforcementStatus":       "HEALTHY",
			})
			_, _ = w.Write(out)
		case p == csPath && m == http.MethodDelete: // DeleteConfigurationSet
			f.order = append(f.order, "DeleteConfigurationSet")
			f.configSetExists, f.eventDestExists = false, false
			_, _ = w.Write([]byte(`{}`))
		default:
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
		}
	}))
}

func sesDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver(sesRegion)
	d.SESBaseURL = srv.URL
	d.PollInterval = 0
	d.PollTimeout = 2 * time.Second
	return d
}

func sesCandidate() (attrs, impl map[string]any) {
	attrs = map[string]any{
		"location.region":     sesRegion,
		"authentication.dkim": true,
		"bounce.tracked":      true,
		"service.managed":     true,
	}
	impl = map[string]any{
		"domain":         sesDomain,
		"bounceTopicArn": sesTopic,
	}
	return
}

// TestSESSending_FullCreateSucceeds: CreateEmailIdentity (domain + ownership tags) ->
// DKIM ensure -> CreateConfigurationSet -> CreateConfigurationSetEventDestination ->
// succeeded WITH the pid. Every request is SigV4-signed.
func TestSESSending_FullCreateSucceeds(t *testing.T) {
	f := newFakeSES()
	rec := newCapture()
	srv := f.handler(t, rec)
	defer srv.Close()
	d := sesDriver(t, srv)
	attrs, impl := sesCandidate()

	res := d.Create("ses-sending", sesCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if res.ProviderID != sesSendingProviderID(sesRegion, sesDomain) {
		t.Fatalf("create providerId = %q", res.ProviderID)
	}
	// order: identity, then the bounce composite (config set before the destination).
	joined := strings.Join(f.order, ",")
	if !strings.HasPrefix(joined, "CreateEmailIdentity,") ||
		!strings.Contains(joined, "CreateConfigurationSet,CreateEventDestination") {
		t.Fatalf("create order = %v, want identity then config set then event destination", f.order)
	}
	// CreateEmailIdentity body carries the domain + ownership tags.
	var cb map[string]any
	if err := json.Unmarshal([]byte(f.identityBody), &cb); err != nil {
		t.Fatalf("CreateEmailIdentity body not JSON: %v", err)
	}
	if cb["EmailIdentity"] != sesDomain {
		t.Fatalf("body EmailIdentity = %v, want %s", cb["EmailIdentity"], sesDomain)
	}
	tags, _ := cb["Tags"].([]any)
	if len(tags) != 2 {
		t.Fatalf("CreateEmailIdentity must carry two ownership tags, got %v", cb["Tags"])
	}
	sawCap := false
	for _, tv := range tags {
		tm, _ := tv.(map[string]any)
		if tm["Key"] == "groundhold-capability" && tm["Value"] == sanitizeTag(sesCap) {
			sawCap = true
		}
	}
	if !sawCap {
		t.Fatalf("ownership capability tag missing: %v", cb["Tags"])
	}
	if rec.unsign != 0 {
		t.Fatalf("every SES request must be SigV4-signed; %d were not", rec.unsign)
	}
}

// TestSESSending_ObserveReverseMap: a verified, DKIM-signed identity with a
// BOUNCE+COMPLAINT SNS event destination reverse-maps to authentication.dkim=true and
// bounce.tracked=true, with EU residency and service.managed.
func TestSESSending_ObserveReverseMap(t *testing.T) {
	f := newFakeSES()
	f.identityExists = true
	f.dkimSigning, f.dkimStatus = true, "SUCCESS"
	f.configSetExists, f.eventDestExists = true, true
	// D746: the set is the identity's DEFAULT, which is what routes messages through
	// it. A set with the right destinations and nothing routing to it captures nothing,
	// and this fixture used to describe exactly that while asserting tracking.
	f.defaultConfigSet = sesConfigSetName(sesCap, sesDomain)
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)

	obs, _, err := d.Observe("ses-sending", sesCap, sesSendingProviderID(sesRegion, sesDomain))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	m := map[string]any{}
	for _, o := range obs {
		m[o.Path] = o.Value
	}
	if m["location.region"] != sesRegion {
		t.Fatalf("region = %v, want %s (EU residency)", m["location.region"], sesRegion)
	}
	if m["authentication.dkim"] != true {
		t.Fatalf("SigningEnabled+SUCCESS must map to authentication.dkim=true, got %v", m["authentication.dkim"])
	}
	if m["bounce.tracked"] != true {
		t.Fatalf("BOUNCE+COMPLAINT SNS destination must map to bounce.tracked=true, got %v", m["bounce.tracked"])
	}
	if m["service.managed"] != true {
		t.Fatalf("service.managed missing")
	}
}

// TestSESSending_ObserveDkimPendingIsFalse: signing enabled but Status!=SUCCESS is an
// UNVERIFIED domain — authentication.dkim=false (honest: the DNS records are the
// operator's to publish).
func TestSESSending_ObserveDkimPendingIsFalse(t *testing.T) {
	f := newFakeSES()
	f.identityExists = true
	f.dkimSigning, f.dkimStatus = true, "PENDING"
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)

	obs, _, err := d.observeSESSending(sesCap, sesSendingProviderID(sesRegion, sesDomain))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	for _, o := range obs {
		if o.Path == "authentication.dkim" && o.Value != false {
			t.Fatalf("PENDING DKIM must map to authentication.dkim=false, got %v", o.Value)
		}
		if o.Path == "bounce.tracked" && o.Value != false {
			t.Fatalf("no configuration set must map to bounce.tracked=false, got %v", o.Value)
		}
	}
}

// TestSESSending_ObserveProductionAccess: the MANUAL-GATE observe. SESv2 GetAccount
// ProductionAccessEnabled reverse-maps to sending.productionAccess (measured), true
// when the account is out of the sandbox, false when sandboxed — never fabricated. An
// unreadable GetAccount OMITS the attribute with a diagnostic (never a fake "sandboxed").
func TestSESSending_ObserveProductionAccess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		prod  bool
		fail  bool
		want  any    // expected sending.productionAccess value, or nil when it must be omitted
		diagS string // substring expected in a diagnostic
	}{
		{name: "production", prod: true, want: true, diagS: "manual-gate"},
		{name: "sandbox", prod: false, want: false, diagS: "manual-gate"},
		{name: "unreadable", fail: true, want: nil, diagS: "not derivable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSES()
			f.identityExists = true
			f.dkimSigning, f.dkimStatus = true, "SUCCESS"
			f.productionAccess = tc.prod
			f.failGetAccount = tc.fail
			srv := f.handler(t, nil)
			defer srv.Close()
			d := sesDriver(t, srv)

			obs, diags, err := d.observeSESSending(sesCap, sesSendingProviderID(sesRegion, sesDomain))
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			var got any
			present := false
			for _, o := range obs {
				if o.Path == "sending.productionAccess" {
					got, present = o.Value, true
					if o.Derivation != "measured" {
						t.Fatalf("sending.productionAccess must be measured, got %q", o.Derivation)
					}
				}
			}
			if tc.want == nil {
				if present {
					t.Fatalf("unreadable GetAccount must OMIT sending.productionAccess, got %v", got)
				}
			} else {
				if !present {
					t.Fatalf("sending.productionAccess must be observed, diags=%v", diags)
				}
				if got != tc.want {
					t.Fatalf("sending.productionAccess = %v, want %v", got, tc.want)
				}
			}
			sawDiag := false
			for _, dg := range diags {
				if strings.Contains(dg, tc.diagS) {
					sawDiag = true
				}
			}
			if !sawDiag {
				t.Fatalf("expected a diagnostic containing %q, got %v", tc.diagS, diags)
			}
		})
	}
}

// TestSESSending_ProductionAccessNotProvisioned: the manual-gate is a VERIFY TARGET,
// never a build input. A candidate that asserts sending.productionAccess=true must NOT
// cause the create to try to provision it (there is no API) — the create proceeds and
// issues no extra mutation for it. groundhold observes the gate, it does not open it.
func TestSESSending_ProductionAccessNotProvisioned(t *testing.T) {
	f := newFakeSES()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)
	attrs, impl := sesCandidate()
	attrs["sending.productionAccess"] = true // a verify target, not a build operand

	// BuildSESSending must accept it without refusing and without turning it into work.
	if _, err := BuildSESSending("prod", sesCap, attrs, impl, 1); err != nil {
		t.Fatalf("sending.productionAccess must be accepted as a verify target, got %v", err)
	}
	res := d.Create("ses-sending", sesCap, "prod", attrs, impl, "k", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create must succeed (productionAccess is not provisioned), got %q (%s)", res.Status, res.Reason)
	}
	// no GetAccount PUT/POST — the fake exposes GetAccount as GET-only; any attempt to
	// mutate account posture would 404 in the handler. The order must carry only the
	// identity + bounce composite mutations.
	for _, o := range f.order {
		if strings.Contains(o, "Account") {
			t.Fatalf("create must not touch account posture; saw %v", f.order)
		}
	}
}

// TestSESSending_PartialEventDestFails: the four-valued crux — the identity + config
// set land but the bounce event destination POST fails. The result must be unknown
// WITH the providerId (a sender that claims tracking with no sink — reconcile), never
// a bare "failed" that implies nothing was created.
func TestSESSending_PartialEventDestFails(t *testing.T) {
	f := newFakeSES()
	f.failEventDest = true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)
	attrs, impl := sesCandidate()

	res := d.Create("ses-sending", sesCap, "prod", attrs, impl, "k", 1)
	if res.Status != "unknown" {
		t.Fatalf("identity created + event dest failed must be unknown, got %q (%s)", res.Status, res.Reason)
	}
	if res.ProviderID != sesSendingProviderID(sesRegion, sesDomain) {
		t.Fatalf("partial-failure unknown must carry the providerId, got %q", res.ProviderID)
	}
	if !f.identityExists {
		t.Fatal("the identity should have landed before the event-destination failure")
	}
}

// TestSESSending_CreateForeignRefuses: an identity already at our domain whose
// ownership tags are NOT ours must not be adopted — refuse (failed), issue no mutation.
func TestSESSending_CreateForeignRefuses(t *testing.T) {
	f := newFakeSES()
	f.identityExists = true
	f.tags = []map[string]string{{"Key": "groundhold-capability", "Value": "someone-else"}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)
	attrs, impl := sesCandidate()

	res := d.Create("ses-sending", sesCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign identity create must refuse, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("no mutation may touch a foreign identity; saw %v", f.order)
	}
}

// TestSESSending_DeleteReverseOrder: delete tears the composite down in REVERSE order
// — DeleteConfigurationSet then DeleteEmailIdentity — ownership-guarded, and succeeds.
func TestSESSending_DeleteReverseOrder(t *testing.T) {
	f := newFakeSES()
	f.identityExists = true
	f.configSetExists, f.eventDestExists = true, true
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)

	res := d.Delete("ses-sending", sesCap, "prod", sesSendingProviderID(sesRegion, sesDomain), "k")
	if res.Status != "succeeded" {
		t.Fatalf("delete status = %q (%s), want succeeded", res.Status, res.Reason)
	}
	if strings.Join(f.order, ",") != "DeleteConfigurationSet,DeleteEmailIdentity" {
		t.Fatalf("delete order = %v, want [DeleteConfigurationSet DeleteEmailIdentity] (reverse)", f.order)
	}
}

// TestSESSending_DeleteForeignRefuses: a foreign identity at our domain must refuse
// the delete before any mutation.
func TestSESSending_DeleteForeignRefuses(t *testing.T) {
	f := newFakeSES()
	f.identityExists = true
	f.tags = []map[string]string{{"Key": "team", "Value": "someone-else"}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)

	res := d.Delete("ses-sending", sesCap, "prod", sesSendingProviderID(sesRegion, sesDomain), "k")
	if res.Status != "failed" {
		t.Fatalf("a foreign identity must refuse the delete, got %+v", res)
	}
	for _, o := range f.order {
		if strings.HasPrefix(o, "Delete") {
			t.Fatalf("no delete may touch a foreign identity; saw %v", f.order)
		}
	}
}

// TestSESSending_RefuseBeforeMutate: bounce.tracked=true with no bounceTopicArn must
// refuse at BOTH Create and Validate — before any SES call.
func TestSESSending_RefuseBeforeMutate(t *testing.T) {
	f := newFakeSES()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)

	attrs, impl := sesCandidate()
	delete(impl, "bounceTopicArn")
	res := d.Create("ses-sending", sesCap, "prod", attrs, impl, "k", 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "bounceTopicArn") {
		t.Fatalf("bounce.tracked with no topic must refuse with a bounceTopicArn reason, got %+v", res)
	}
	if len(f.order) != 0 {
		t.Fatalf("refuse-before-mutate must issue no SES call; saw %v", f.order)
	}
	if err := d.Validate("ses-sending", sesCap, "prod", attrs, impl, 1); err == nil || !strings.Contains(err.Error(), "bounceTopicArn") {
		t.Fatalf("Validate must refuse bounce.tracked with no topic, got %v", err)
	}
}

// TestSESSending_UnmappedAttributeRefuses: an attribute with no email.sending mapping
// is REFUSED (never silently dropped).
func TestSESSending_UnmappedAttributeRefuses(t *testing.T) {
	attrs, impl := sesCandidate()
	attrs["encryption.atRest"] = true // not an email.sending attribute
	if _, err := BuildSESSending("prod", sesCap, attrs, impl, 1); err == nil {
		t.Fatal("an unmapped attribute must be refused, not silently dropped")
	}
}

// TestSESSending_ClassifyChange: authentication.dkim + bounce.tracked are mutable in
// place; location.region is unsupported (an identity is region-bound). Every path
// carries a reason.
func TestSESSending_ClassifyChange(t *testing.T) {
	d := NewDriver(sesRegion)
	want := map[string]string{
		"authentication.dkim":      "mutable",
		"bounce.tracked":           "mutable",
		"sending.productionAccess": "unsupported",
		"location.region":          "unsupported",
		"service.managed":          "unsupported",
	}
	for p, w := range want {
		got, reason := d.ClassifyChange("ses-sending", p, nil, nil, nil)
		if got != w {
			t.Errorf("classify %s = %q, want %q", p, got, w)
		}
		if reason == "" {
			t.Errorf("classify %s must carry an honest reason", p)
		}
	}
}

// TestSESSending_UpdateBounceTracked: turning bounce tracking ON in place ensures the
// configuration set + the BOUNCE+COMPLAINT event destination, ownership-guarded.
func TestSESSending_UpdateBounceTracked(t *testing.T) {
	f := newFakeSES()
	f.identityExists = true
	f.dkimSigning, f.dkimStatus = true, "SUCCESS"
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)
	attrs, impl := sesCandidate()

	res := d.Update("ses-sending", sesCap, "prod", sesSendingProviderID(sesRegion, sesDomain),
		attrs, impl, []string{"bounce.tracked"}, "k")
	if res.Status != "succeeded" || res.ProviderID != sesSendingProviderID(sesRegion, sesDomain) {
		t.Fatalf("bounce.tracked update must succeed with the pid, got %+v", res)
	}
	if !f.eventDestExists {
		t.Fatalf("update must have created the bounce event destination; order = %v", f.order)
	}
}

// TestSESSending_UpdateForeignRefuses: an in-place update on an identity whose tags
// are not ours is refused before any patch.
func TestSESSending_UpdateForeignRefuses(t *testing.T) {
	f := newFakeSES()
	f.identityExists = true
	f.tags = []map[string]string{{"Key": "team", "Value": "someone-else"}}
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)
	attrs, impl := sesCandidate()

	res := d.Update("ses-sending", sesCap, "prod", sesSendingProviderID(sesRegion, sesDomain),
		attrs, impl, []string{"authentication.dkim"}, "k")
	if res.Status != "failed" {
		t.Fatalf("a foreign identity must refuse the update, got %+v", res)
	}
	for _, o := range f.order {
		if o == "PutDkim" {
			t.Fatal("no patch may touch a foreign identity")
		}
	}
}

func sesRESTRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet {
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingSESSending enrols ses-sending in the D391 gate. It is a COMPOSITE
// (email identity plus configuration set plus event destination) and the identity is
// name-addressed by domain, so an estate that already sends mail is exactly what a
// converge meets. The foreign case had a test; ours did not.
func TestAdoptsExistingSESSending(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	attrs, impl := sesCandidate()
	p := &certifynet.ExistingProbe{
		Name:     "aws/ses-sending",
		Classify: sesRESTRole,
		ExistingServer: func() *httptest.Server {
			f := newFakeSES()
			f.identityExists = true
			f.configSetExists, f.eventDestExists = true, true
			f.tags = []map[string]string{
				{"Key": "groundhold-capability", "Value": sanitizeTag(sesCap)},
				{"Key": "groundhold-environment", "Value": sanitizeTag("prod")},
			}
			return f.handler(t, nil)
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver(sesRegion)
			d.HTTP = &http.Client{Transport: rt}
			d.SESBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.PollInterval = 0
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("ses-sending", sesCap, "prod", attrs, impl, "k", 1)
		},
		PID:              sesSendingProviderID(sesRegion, sesDomain),
		AllowedMutations: 3, // convergence onto the standing identity/config set
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D746: a configuration set captures nothing unless something routes messages through
// it. AWS applies one when the sender names it per send, or when it is the identity's
// DEFAULT. The driver built the set and its BOUNCE+COMPLAINT destination and stopped —
// so `bounce.tracked` reported true for a set nothing pointed at, while the vocabulary's
// promise for that attribute is "a failed demand returns to the record, never the void".
func TestBounceTrackedNeedsSomethingRoutingThroughTheSet(t *testing.T) {
	cases := []struct {
		name         string
		destinations bool
		defaultSet   string
		want         any // nil => withheld
	}{
		{"no destination at all", false, "", false},
		{"destination, and the identity routes through it", true, "DEFAULT", true},
		{"destination, but nothing routes through it", true, "", nil},
		{"destination, and a DIFFERENT set is the default", true, "someone-elses", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeSES()
			f.identityExists = true
			f.dkimSigning, f.dkimStatus = true, "SUCCESS"
			f.configSetExists, f.eventDestExists = true, c.destinations
			if c.defaultSet == "DEFAULT" {
				f.defaultConfigSet = sesConfigSetName(sesCap, sesDomain)
			} else {
				f.defaultConfigSet = c.defaultSet
			}
			srv := f.handler(t, nil)
			defer srv.Close()
			d := sesDriver(t, srv)

			obs, diags, err := d.Observe("ses-sending", sesCap, sesSendingProviderID(sesRegion, sesDomain))
			if err != nil {
				t.Fatal(err)
			}
			var got any
			for _, o := range obs {
				if o.Path == "bounce.tracked" {
					got = o.Value
				}
			}
			if got != c.want {
				t.Fatalf("bounce.tracked = %v, want %v", got, c.want)
			}
			if c.want == nil {
				var saidWhy bool
				for _, dg := range diags {
					if strings.Contains(dg, "not the identity's default set") {
						saidWhy = true
					}
				}
				if !saidWhy {
					t.Fatalf("withholding without saying why is its own defect: %v", diags)
				}
			}
		})
	}
}

// D746: and the create now makes that association itself, so the guarantee is one the
// infrastructure provides rather than one every caller must remember.
func TestSESCreateAssociatesTheConfigurationSetWithTheIdentity(t *testing.T) {
	f := newFakeSES()
	srv := f.handler(t, nil)
	defer srv.Close()
	d := sesDriver(t, srv)

	attrs, impl := sesCandidate()
	res := d.Create("ses-sending", sesCap, "prod", attrs, impl, "k1", 1)
	if res.Status != "succeeded" {
		t.Fatalf("create: %+v", res)
	}
	if f.defaultConfigSet != sesConfigSetName(sesCap, sesDomain) {
		t.Fatalf("the identity's default configuration set is %q — a set nothing routes "+
			"through captures nothing, and the create claimed tracking", f.defaultConfigSet)
	}
}
