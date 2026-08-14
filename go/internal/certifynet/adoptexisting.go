package certifynet

import (
	"net/http"
	"net/http/httptest"

	"groundhold/internal/adoptcheck"
	"groundhold/internal/provider"
)

// D391: the mirror of CertifyNoDuplicate, and the more expensive half.
//
// D252/D253 built create-time adoption: a create that finds an OWNED resource already
// standing binds it instead of minting a second one. That is what makes a converge
// against a lost ledger safe, and D253 named the damage when it is absent — "a second
// VPC, a second paid key", because a server-assigned id with no idempotency token means
// a second create never collides, it silently duplicates.
//
// D253 proved the property for a roster of 18 AWS services, per driver. The roster is
// now 54 creates, and no gate ever asserted the property as a CLASS — so the proof
// covers a third of the services it is claimed for, and nothing notices when a new
// driver lands without it. That is the D338 shape (a property proven once against a
// roster that then tripled) applied to behaviour rather than to a registry.
//
// The gate asks the driver rather than reading it (D317): drive a create against a fake
// in which the owned resource ALREADY EXISTS, and require both halves of the property —
// the result binds that resource's providerId, and ZERO create mutations went out. The
// second half is the real proof; a driver can report a plausible binding while having
// already sent the duplicating POST.
type ExistingProbe struct {
	Name string
	// ExistingServer is a fake in which the resource this create targets already
	// exists AND carries this runtime's ownership tags/markers.
	ExistingServer func() *httptest.Server
	New            func(happyURL string, rt http.RoundTripper) provider.Provider
	Classify       Classifier
	Create         func(p provider.Provider) provider.CreateResult
	// PID is the providerId the create must bind to — the identity of the resource
	// that already exists. Left empty, the gate checks only that SOME id came back.
	PID string
	// AllowedMutations is for creates that legitimately mutate while adopting (for
	// example a tag write that stamps ownership on a resource being taken over).
	// Default 0: an adoption that sends nothing is the property in its strongest form.
	AllowedMutations int
	// IdentityFromContent marks a create whose resource id is DERIVED from the
	// request — Azure hashes (scope|principal|role) into the assignment GUID — so
	// a write at that id can only ever land on the resource those inputs name.
	// Such a create need not read to be safe, and the gate must not demand it
	// (D525). Declaring it while the create DOES read is itself a failure: a
	// create that reads can check what it found.
	IdentityFromContent bool
	// ConcludesUnknown marks a driver that deliberately does NOT bind inline: it
	// answers unknown-WITH-pid and leaves ownership to reconcile (cloudtrail does
	// this). That is honest and it still cannot duplicate — the create was refused —
	// so the no-duplicate half of the property holds unchanged. It must be declared
	// per driver rather than tolerated globally, because the difference between
	// "defers by design" and "silently stopped adopting" is exactly what this gate
	// exists to notice.
	ConcludesUnknown bool
	// MissingControl (D1062) proves the CONTROL-COMPLETENESS half of adoption: a
	// create that adopts a resource LACKING a declared control (its create body set
	// the control inline, so it never applied to the pre-existing resource) must NOT
	// report succeeded. Each case serves the owned resource STRIPPED of one declared
	// control; the driver must return WantStatus (failed for an immutable control it
	// cannot fix, unknown for a mutable one converge can patch) and send no more than
	// WantMutations. Without this, an adopt silently certifies a security control that
	// is not there (the 23-driver systemic finding).
	MissingControl []ControlCase
	// MoreSecure serves the owned resource EXCEEDING the declaration (a control ON
	// though not required). Adoption must still SUCCEED — the safe direction is not a
	// lie, and false-failing it would block a legitimate takeover. Pins the safe
	// direction as a regression test, not a review comment.
	MoreSecure func() *httptest.Server
	// AdoptControls is the driver's OWN runtime adopt-critical control table (the same
	// one it passes to adoptcheck.Compare), so the gate's expectations cannot drift
	// from what the driver actually enforces. A driver that declares controls here MUST
	// prove every one with a MissingControl case and pin the safe direction with
	// MoreSecure — that is what turns the control-completeness invariant from a
	// convention into an enforced gate (D1062). A driver with no controls leaves it nil.
	AdoptControls []adoptcheck.Control
}

// ControlCase is one missing-control scenario for the adopt control-completeness
// check (D1062): the estate serves the owned resource without a declared control.
type ControlCase struct {
	Path   string // the declared control the served resource LACKS
	Server func() *httptest.Server
	// Create overrides the probe's Create for this case — a control is only
	// exercised when the candidate DECLARES it, so a case for a control the base
	// candidate leaves permissive supplies a candidate that requires it. Falls back
	// to the probe's Create when nil.
	Create        func(provider.Provider) provider.CreateResult
	WantStatus    string // "failed" (immutable) | "unknown" (mutable, converge patches)
	WantMutations int    // adopting must not half-fix; default 0
}

func CertifyCreateAdoptsExisting(t TestingT, p *ExistingProbe) {
	t.Helper()
	srv := p.ExistingServer()
	defer srv.Close()
	rt := &countRT{inner: http.DefaultTransport, classify: p.Classify}

	res := p.Create(p.New(srv.URL, rt))

	want := "succeeded"
	if p.ConcludesUnknown {
		want = "unknown"
	}
	if res.Status != want {
		t.Errorf("%s: a create that finds its OWNED resource already standing must bind "+
			"it and succeed (D252/D253 create-time adoption — this is what makes a converge "+
			"against a lost ledger safe; this driver declares status %q). Got status=%q reason=%q.",
			p.Name, want, res.Status, res.Reason)
	}
	if res.ProviderID == "" {
		t.Errorf("%s: adoption returned no providerId — nothing was bound, so the next "+
			"converge repeats the create.", p.Name)
	} else if p.PID != "" && res.ProviderID != p.PID {
		t.Errorf("%s: adoption bound %q, want the EXISTING resource %q — binding the wrong "+
			"identity is worse than duplicating, because the duplicate is now unmanaged.",
			p.Name, res.ProviderID, p.PID)
	}
	// The estate must actually CONTAIN the resource being adopted. With a fixture
	// that 404s the read, the driver simply CREATES one, succeeds, returns a
	// providerId — and this gate reports adoption as verified while nothing was
	// adopted (D524). It is the mirror of the foreign-refusal hole: there the
	// refusal was for the wrong reason, here the success is.
	// Two different things look identical here and must not be conflated (D525).
	// A probe whose fixture is EMPTY is debt: the adopt path was never exercised.
	// A create that legitimately does not READ is not debt at all — Azure's role
	// assignment and custom role definition derive their identity by hashing
	// (scope|principal|role), so a PUT at that id can only ever land on the
	// assignment that grants exactly that principal exactly that role. There is no
	// other resource it could hit, which is the same reasoning as ForeignProbe's
	// OwnershipFromIDAlone.
	if p.IdentityFromContent && rt.readFound {
		t.Errorf("%s: declares IdentityFromContent but DID read the estate — if the create "+
			"reads, it can and must check what it found; the declaration is wrong.", p.Name)
	}
	if known := knownNoAdoptRead[p.Name] || p.IdentityFromContent; !rt.readFound && !known {
		t.Errorf("%s: no read of the estate returned the resource — every read 404'd or "+
			"failed, so the create did not ADOPT anything; it made one. This proves the "+
			"create path, not the adopt path. Make the fixture serve the existing resource.",
			p.Name)
	} else if knownNoAdoptRead[p.Name] && rt.readFound {
		t.Errorf("%s: listed in knownNoAdoptRead but its estate DOES serve the resource — "+
			"the fixture was fixed and the entry outlived it. Remove the entry; the debt "+
			"list must shrink when the debt does.", p.Name)
	}
	if rt.mutations > p.AllowedMutations {
		t.Errorf("%s: adopting an EXISTING owned resource sent %d mutation(s) (allowed %d) — "+
			"it stood up a duplicate rather than binding. D253's named cost: a second VPC, "+
			"a second paid key, and neither one in the ledger.",
			p.Name, rt.mutations, p.AllowedMutations)
	}

	// D1062: the CONTROL-COMPLETENESS half — an adopt of a resource missing a declared
	// control must not report succeeded. Two-way enforcement so the class cannot silently
	// reopen: a driver wired to the shared comparator declares AdoptControls (its own
	// runtime table) and must prove EVERY control with a MissingControl case + pin the
	// safe direction with MoreSecure, and must be OFF the debt list; an unwired driver
	// with a security control set inline stays on adoptControlDebt (documented, tracked)
	// until a campaign slice wires it. The list can only shrink.
	if len(p.AdoptControls) > 0 {
		if adoptControlDebt[p.Name] {
			t.Errorf("%s: declares AdoptControls (wired to the comparator) but is still on "+
				"adoptControlDebt — remove it; the debt list only shrinks.", p.Name)
		}
		covered := map[string]bool{}
		for _, cc := range p.MissingControl {
			covered[cc.Path] = true
		}
		for _, c := range p.AdoptControls {
			if !covered[c.Path] {
				t.Errorf("%s: adopt-critical control %q has no MissingControl case — every "+
					"declared control must be proven to block an adopt that lacks it, or the "+
					"gate certifies a control it never tested.", p.Name, c.Path)
			}
		}
		if p.MoreSecure == nil {
			t.Errorf("%s: declares AdoptControls but no MoreSecure case — the safe direction "+
				"(a resource more secure than declared) must be pinned so a fix cannot start "+
				"false-failing a legitimate adopt.", p.Name)
		}
	} else if adoptControlDebt[p.Name] && len(p.MissingControl) > 0 {
		t.Errorf("%s: on adoptControlDebt but declares MissingControl cases — it is wired; "+
			"remove it from the debt list.", p.Name)
	}

	for _, cc := range p.MissingControl {
		cs := cc.Server()
		crt := &countRT{inner: http.DefaultTransport, classify: p.Classify}
		create := p.Create
		if cc.Create != nil {
			create = cc.Create
		}
		cres := create(p.New(cs.URL, crt))
		cs.Close()
		if cres.Status != cc.WantStatus {
			t.Errorf("%s: adopting a resource missing declared control %q must be %q — a "+
				"create must never claim a control the live resource lacks; got %q reason=%q",
				p.Name, cc.Path, cc.WantStatus, cres.Status, cres.Reason)
		}
		if cc.WantStatus == "failed" && cres.ProviderID != "" {
			t.Errorf("%s: an immutable missing control (%q) must not bind an unusable "+
				"resource (a replacement may be needed), got pid %q", p.Name, cc.Path, cres.ProviderID)
		}
		if cc.WantStatus == "unknown" && cres.ProviderID == "" {
			t.Errorf("%s: a mutable missing control (%q) must keep the handle so converge "+
				"reconciles it, got no pid", p.Name, cc.Path)
		}
		if crt.mutations > cc.WantMutations {
			t.Errorf("%s: adopting a resource missing control %q sent %d mutation(s) (allowed "+
				"%d) — fail-loud must not half-fix; remediation is converge's job.",
				p.Name, cc.Path, crt.mutations, cc.WantMutations)
		}
	}

	if p.MoreSecure != nil {
		ms := p.MoreSecure()
		mrt := &countRT{inner: http.DefaultTransport, classify: p.Classify}
		mres := p.Create(p.New(ms.URL, mrt))
		ms.Close()
		if mres.Status != "succeeded" {
			t.Errorf("%s: adopting a resource MORE secure than declared must succeed — the "+
				"safe direction is not a lie; false-failing it blocks a legitimate takeover. "+
				"Got %q reason=%q", p.Name, mres.Status, mres.Reason)
		}
	}
}

// knownNoAdoptRead names the adopt probes where NO successful read happened, so
// `CertifyCreateAdoptsExisting` exercised the CREATE path and called it adoption
// (D524). The first name for this was knownEmptyEstate, and it was WRONG for some
// entries: there are two causes and they are not the same thing (D525).
//
//   - the FIXTURE is empty, so there was nothing to find (azDashServer started
//     with `stored == nil`, so the first GET 404'd);
//   - the DRIVER never reads — `PutDashboard` writes at a deterministic name
//     without looking, so the estate could serve the resource all day and the
//     create would not notice.
//
// D546 measured which cause each entry has, because a register that names a cause
// it did not measure is the error D525 had already made once here. All five
// remaining entries are the SECOND cause: their creates issue no read at all.
// Seeding a fixture cannot fix them, and whether such a create SHOULD read is the
// open question D526 raised (a deterministic name is computable by anyone, so it
// does not prove ownership) — so they wait on a decision, not on effort.
//
// The sixth was neither: `gcp/pubsub-queue` reads on 409, but its adopt probe
// shared a POST-only create predicate while Pub/Sub creates its topic with PUT, so
// the conflict never fired and the probe exercised a clean create. A per-case
// predicate fixed it.
//
// The second is not automatically a defect (an idempotent write at an identity
// derived from the request cannot land elsewhere — that is IdentityFromContent),
// but it is not adoption either, and calling it adoption is what this register
// exists to stop.
//
// This is the D463/D472 exemption idiom, not an allowlist: the check runs BOTH
// ways. An entry whose fixture starts serving the resource FAILS, so a fixed
// probe must be removed from this list and the list can only shrink. It cannot
// rot into a set of stale excuses the way a one-directional skip would.
//
// Each needs its fixture pre-seeded with the resource carrying OUR ownership
// markers — per-service work, since each speaks its own API.
// D804 emptied it. The four entries that remained after D700 were closed one by one:
// three drivers (aws/cwlogfilter, azure/activitylog, azure/consumptionbudget) now READ
// before writing at a name anyone can compute, and the fourth (aws/cloudtrail) had been
// reading since D391 — its probe modelled a RACE rather than the ownership question,
// which is the register naming a cause it never measured, the very error its own comment
// says was made here once before.
//
// The register stays, empty, because it is the shape of the check rather than a list:
// an entry can only be added deliberately, and the two-way rule means it can only ever
// shrink again.
var knownNoAdoptRead = map[string]bool{}

// adoptControlDebt (D1062) named the drivers that set a security control INLINE in
// their create body — so a 409-adopt never applied it — and whose control-completeness
// was NOT YET proven by this gate. It was the campaign's remaining work made VISIBLE and
// two-way: the moment a driver declared AdoptControls, `CertifyCreateAdoptsExisting`
// FAILED ("remove it from the debt list"), so wiring a driver forced its removal and the
// list could only shrink. The systemic 409-adopt false-success audit found 23 drivers.
//
// The map is now EMPTY: every driver is wired to the shared comparator with
// MissingControl gate cases, so the class is fully enforced rather than remembered. The
// last to land was aws/kms, which needed a new `Ceiling` Direction for rotation.period (a
// duration whose safe direction is shorter-is-more-secure) plus a `rotation.enabled`
// observation so a non-rotating key is a MEASURED miss, not an invisible absence.
//
// The map STAYS as the shape of the check, not a leftover: an entry can only be added
// deliberately (a new driver that sets a control inline before its gate cases exist), and
// the two-way rule means it can only shrink again. An empty map is the closed state.
var adoptControlDebt = map[string]bool{}
