package certifynet

import (
	"net/http"
	"net/http/httptest"
	"strings"

	"groundhold/internal/provider"
)

// D439: the mirror of CertifyCreateAdoptsExisting, and the half where being wrong is
// irreversible.
//
// The adoption sweep (D391-D438) asked, for all 143 creates on three clouds: when the
// resource is ALREADY THERE and it is OURS, does the driver bind it? This asks the
// opposite question of the opposite verb: when the resource is there and it is NOT ours,
// does the driver refuse to delete it?
//
// Those are not the same property and neither implies the other. A create that adopts
// correctly can still have a delete that trusts the providerId it was handed — and the
// providerId comes from the ledger, which a mistaken adoption, a hand-edited plan, or a
// stale binding can populate with a stranger's resource. Every driver in this repo already
// carries an ownership check on delete; what has never existed is a statement that ALL of
// them do, or a test that drives each one to prove it.
//
// The asymmetry with create is the point. A create that gets ownership wrong duplicates —
// wasteful, recoverable, visible on the next bill. A delete that gets it wrong destroys
// something that was not ours, and no amount of subsequent correctness brings it back.
// This is the one property in the sweep where a gate that finds nothing is still worth
// its cost, because the failure it guards against cannot be undone.
type ForeignProbe struct {
	Name string
	// ForeignServer is a fake in which the resource at our providerId EXISTS but carries
	// ownership markers that are NOT ours.
	ForeignServer func() *httptest.Server
	New           func(happyURL string, rt http.RoundTripper) provider.Provider
	Classify      Classifier
	// Delete runs the driver's delete against the foreign resource.
	Delete func(p provider.Provider) provider.CreateResult
	// Update runs the driver's update against the foreign resource (D459).
	Update func(p provider.Provider) provider.CreateResult
	// AllowedMutations defaults to 0 and should almost always stay there: a refusal that
	// sends a mutation first has already done the damage. Raise it only where the driver
	// must write to LEARN ownership, and say why.
	AllowedMutations int
	// OwnershipFromIDAlone marks a driver whose providerId is CONTENT-ADDRESSED, so a
	// foreign resource is recognisable without reading anything (GCP firestore: the
	// database id is derived from project+environment+capability). Everyone else must
	// have asked the estate, and this gate insists on it: twice on AWS a probe "passed"
	// because the fixture's providerId had the wrong prefix and the driver refused at
	// parsing, having never looked at the resource at all. A refusal that never read is
	// not evidence that the ownership check works.
	OwnershipFromIDAlone bool
}

func CertifyDeleteRefusesForeign(t TestingT, p *ForeignProbe) {
	t.Helper()
	certifyForeign(t, p, "delete", p.Delete)
}

// CertifyUpdateRefusesForeign is the same property on the middle verb (D459). An update
// that lands on a resource which is not ours is not milder than a delete — it is a
// TAKEOVER: the resource keeps running under someone else's name with our configuration
// in it, and on Azure the mutation is literally a PUT that overwrites. Unlike a delete
// the damage is quiet, so nobody looks for it.
//
// The probe takes p.Update instead of p.Delete; everything else — zero mutations, a
// stated reason, and evidence that the refusal READ something — is identical, because
// the question is identical.
func CertifyUpdateRefusesForeign(t TestingT, p *ForeignProbe) {
	t.Helper()
	certifyForeign(t, p, "update", p.Update)
}

func certifyForeign(t TestingT, p *ForeignProbe, verb string,
	mutate func(provider.Provider) provider.CreateResult) {
	t.Helper()
	srv := p.ForeignServer()
	defer srv.Close()
	rt := &countRT{inner: http.DefaultTransport, classify: p.Classify}

	res := mutate(p.New(srv.URL, rt))

	if res.Status == "succeeded" {
		t.Errorf("%s: %s of a resource whose ownership markers are NOT ours reported "+
			"success — the driver either mutated a stranger's resource or claimed to. "+
			"Reason: %q", p.Name, strings.ToUpper(verb), res.Reason)
	}
	if rt.mutations > p.AllowedMutations {
		t.Errorf("%s: refusing to %s a FOREIGN resource still sent %d mutation(s) "+
			"(allowed %d). A refusal that mutates first has already done the damage: the "+
			"write landed on someone else's resource and the refusal is only a report.",
			p.Name, verb, rt.mutations, p.AllowedMutations)
	}
	if !p.OwnershipFromIDAlone && rt.requests == 0 {
		t.Errorf("%s: [reason=%q] the %s refused WITHOUT reading the estate — it never looked at "+
			"the resource, so this proves nothing about the ownership check. Either the "+
			"fixture's providerId is malformed (the driver refused at parsing) or ownership "+
			"is derivable from the id alone, which must be declared.", p.Name, res.Reason, verb)
	}
	// The estate must actually CONTAIN the foreign resource. A fixture that 404s
	// every read still satisfies "the driver looked" (D455), and the driver then
	// refuses because the thing is not there — a different path, proving a
	// different property, while the gate reports the ownership check as verified
	// (D524). Same shape as every finding in the F-LC3 series: the instrument
	// unable to express the condition it claims to test.
	if !p.OwnershipFromIDAlone && !rt.readFound {
		t.Errorf("%s: [reason=%q] no read of the foreign estate returned a resource — every "+
			"read 404'd or failed, so the %s refused an ABSENT resource, not a foreign one. "+
			"The ownership check is unproven; make the fixture serve the resource with "+
			"markers that are not ours.", p.Name, res.Reason, verb)
	}
	if res.Reason == "" {
		t.Errorf("%s: the refusal carries no reason — an operator who meets this needs to "+
			"be told the resource is not ours, not left with an unexplained failure.",
			p.Name)
	}
}
