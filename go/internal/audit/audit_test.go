package audit

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"groundhold/internal/contract"
	"groundhold/internal/ledger"
	"groundhold/internal/vocab"
)

// seedObs populates the per-source projection audit reads (D191), keyed by
// each record's Source — mirroring what projectObservations builds on replay.
func seedObs(led *ledger.Ledger, capID string, byPath map[string]ledger.ObsRecord) {
	led.ObservationsBySource[capID] = map[string]map[string]ledger.ObsRecord{}
	for path, rec := range byPath {
		led.ObservationsBySource[capID][path] = map[string]ledger.ObsRecord{rec.Source: rec}
	}
}

// Non-negotiable #1: unknown OR UNVERIFIABLE on a hard constraint
// blocks — with no bypass. audit's machine surface (exit code + status)
// is what monitoring routes on, so a hard unverifiable must make audit
// report violations-found / exit 2, matching the BLOCKED banner. The
// reviewer's scenario: a hard cost constraint in USD, reality recorded
// in EUR -> currency mismatch -> unverifiable -> must NOT be status
// clean / exit 0 (found by the pre-GA review; previously escaped).
func TestAuditHardUnverifiableBlocks(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: money, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-cost
      subject: db
      path: cost.monthly
      op: lte
      value: "100 USD"
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	// reality recorded in a DIFFERENT currency — incomparable, not false
	led := ledger.New()
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"cost.monthly": {Value: "90 EUR", ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "measured", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != "unverifiable" {
		t.Fatalf("currency mismatch must be unverifiable, got %+v", res.Verdicts)
	}
	// Violations>0 is what main maps to exit 2 — the machine surface
	// (exit + status) now matches the BLOCKED banner
	if res.Status != "violations-found" || res.Violations != 1 {
		t.Fatalf("a hard unverifiable MUST block the machine surface, "+
			"got status=%q violations=%d", res.Status, res.Violations)
	}
}

// TestAuditSecurityPathRejectsDeclaredIntent pins the systemic cure for the D1003/
// D1040/D1041/D1069/D1070 false-secure class. A hard SECURITY constraint declared at
// the default `static` bar: adopt filled a MISSING observation with the candidate's
// own declared value (source candidate-declared, derivation declared — what
// adopt.go writes when a driver's observe emitted nothing for the path). Without a
// security-path floor that declared intent SATISFIES the static bar, certifying a
// control the live resource may lack — the silent false-SECURE. A security control must
// be WITNESSED (>= provider-api), so declared intent must BLOCK, not satisfy.
func TestAuditSecurityPathRejectsDeclaredIntent(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: sec, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-cmek
      subject: db
      path: encryption.customerManagedKeys
      op: equals
      value: true
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	// the adopt-fill: the candidate's declared true, recorded as intent because the
	// driver's observe emitted nothing for the path (the one-state defect).
	led := ledger.New()
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"encryption.customerManagedKeys": {Value: true, ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "declared", Source: "candidate-declared"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 || (res.Verdicts[0].Verdict != "unknown" && res.Verdicts[0].Verdict != "unverifiable") {
		t.Fatalf("declared intent on a hard SECURITY path must NOT satisfy — a security "+
			"control must be witnessed; got %+v", res.Verdicts)
	}
	if res.Status != "violations-found" || res.Violations != 1 {
		t.Fatalf("a hard security control witnessed only by declared intent MUST block, "+
			"got status=%q violations=%d", res.Status, res.Violations)
	}
}

// TestSecurityFloorCoversEverySecurityPostureAttr is the forcing function the
// hand-maintained securityNamespaces list needed (D1072 and D1074 were the SAME
// omission defect twice — a list that shadows the vocabulary by hand drifts from it).
// It reads every vocabulary attribute and, when the path or its description signals a
// security posture, requires the path to be floored by isSecurityPath OR explicitly
// waived here as reviewed-non-security. So a NEW security attribute fails the build
// until someone classifies it — the omission can no longer be silent.
func TestSecurityFloorCoversEverySecurityPostureAttr(t *testing.T) {
	all, err := vocab.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	signal := regexp.MustCompile(`(?i)encrypt|customer.?managed.?key|\btls\b|plaintext|` +
		`public.*(expos|internet|reachable|read path|network path|publish path)|api.?exposure|` +
		`\brotat|retention.?lock|\bworm\b|immutab|\bhsm\b|deletion.?protect|privileg|\bmfa\b|` +
		`second factor|sso.*enforc|password.?bypass|password auth|redirect|\bpkce\b|dkim|` +
		`signed|provenance|refresh.?token|replay|implicit grant|confidential.*client|` +
		`envelope.?encrypt|byok|exportable|downloadable|audience`)
	// reviewed and NOT a floored security control (matched a keyword incidentally). Each
	// entry is a deliberate decision — config/tuning/durability/naming/cost, not a
	// dangerous-direction control witnessing would protect. The set only shrinks by
	// fixing a real classifier.
	allow := map[string]bool{
		"capability.messaging.queue::reliability.deadLetter":       true, // delivery reliability, not security
		"capability.messaging.queue::ordering.enabled":             true, // message ordering
		"capability.authorization.role::cost.monthly":              true, // cost projection
		"capability.key.encryption::cost.monthly":                  true, // cost projection
		"capability.key.encryption::location.region":               true, // residency (matched "HSM/vault" in prose)
		"capability.dns.record::dns.proxied":                       true, // CDN/proxy routing toggle, not a compliance control
		"capability.storage.object::replication.enabled":           true, // durability/DR, not security
		"capability.backup.plan::retention.duration":               true, // a retention floor (S3-precedent: no floor to witness)
		"capability.cdn.distribution::origin.domain":               true, // an origin hostname
		"capability.streaming.pipe::retention.window":              true, // a retention window (durability)
		"capability.identity.oauth-client::refreshToken.lifetime":  true, // a token-lifetime duration (tuning)
		"capability.identity.oauth-client::refreshToken.issued":    true, // whether refresh tokens are issued at all
		"capability.identity.podidentity::workload.serviceAccount": true, // which SA (an identity binding, not a toggle)
		"capability.authorization.grant::cost.monthly":             true, // cost projection
		"capability.identity.serviceaccount::display.name":         true, // a display name
		"capability.gitops.application::source.repoURL":            true, // a repository URL
	}
	count := 0
	for capType, v := range all {
		for path, attr := range v.Attributes {
			desc, _ := attr["description"].(string)
			if !signal.MatchString(path + " " + desc) {
				continue
			}
			count++
			if isSecurityPath(path) || allow[capType+"::"+path] {
				continue
			}
			t.Errorf("%s::%s reads as a security-posture attribute but is NOT floored by "+
				"isSecurityPath and NOT allowlisted — classify it (add to securityNamespaces) "+
				"or waive it here as reviewed-non-security. An unfloored security path is a "+
				"silent false-secure (D1072/D1074).", capType, path)
		}
	}
	if count < 20 {
		t.Fatalf("the security-signal scan matched only %d attributes — the regex or the vocab "+
			"load broke, and this gate would pass over an unfloored set (D328)", count)
	}
}

// TestAuditIdentitySecurityPathRejectsDeclaredIntent pins the identity-vocab gap the
// D323/D325-class hunt found: the identity capabilities (sso, oauth-client) are
// declared-ONLY (no observer driver), so a hard identity security control could ONLY
// ever be witnessed by the candidate's declared word — the worst false-secure, because
// there is no measured path at all. mfa.required declared and recorded as intent must
// BLOCK, exactly like the encryption case, now that the floor covers identity paths.
func TestAuditIdentitySecurityPathRejectsDeclaredIntent(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: idp, environment: test, version: 1 }
capabilities:
  - id: sso
    type: capability.identity.sso
constraints:
  hard:
    - id: c-mfa
      subject: sso
      path: mfa.required
      op: equals
      value: true
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	seedObs(led, "sso", map[string]ledger.ObsRecord{
		"mfa.required": {Value: true, ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "declared", Source: "candidate-declared"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "violations-found" || res.Violations != 1 {
		t.Fatalf("a hard identity security control witnessed only by declared intent MUST "+
			"block (no observer can ever measure it), got status=%q violations=%d verdicts=%+v",
			res.Status, res.Violations, res.Verdicts)
	}
}

// TestAuditNonSecurityPathStillSatisfiesAtStatic proves the security floor does NOT
// over-fire: a NON-security path (cost.monthly) with a declared-intent observation
// still satisfies the static bar exactly as before — the floor bites security paths
// only, so the F-LC3 intent-is-not-a-lie rule survives for genuinely non-observable
// attributes like cost.
func TestAuditNonSecurityPathStillSatisfiesAtStatic(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: cost, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-cost
      subject: db
      path: cost.monthly
      op: lte
      value: "100 USD"
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"cost.monthly": {Value: "90 USD", ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "declared", Source: "candidate-declared"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != "satisfied" {
		t.Fatalf("a non-security path at the static bar must still accept declared intent, got %+v", res.Verdicts)
	}
}

// TestIsSecurityPath pins the fail-closed security classifier — a regression fence so
// a rename or a new namespace does not silently drop a control out of the floor.
func TestIsSecurityPath(t *testing.T) {
	for _, p := range []string{
		"encryption.customerManagedKeys", "encryption.atRest", "encryption.inTransit",
		"network.publicExposure", "tls.enforced", "rotation.enabled", "rotation.period",
		"retention.locked", "protection.level", "deletion.protection", "access.privileged",
		// identity.sso / identity.oauth-client (D55) — declared-only, so a hard
		// constraint on these could ONLY ever be satisfied by intent; flooring them is
		// what stops audit certifying an unwitnessed MFA/SSO/redirect control as proven.
		"sso.enforced", "mfa.required", "assertions.signed",
		"pkce.required", "client.authentication", "redirects.exactMatch",
		"redirects.wildcardsAllowed", "token.asymmetricSigning", "grants.implicit",
		// D1190. Siblings inside a block the keyword lint had floored only in part:
		// `access.privileged` and `grants.implicit` above matched a keyword, these did
		// not. Pinned beside them on purpose — the pairing is the finding.
		"grant.principal", "grant.role", "access.scope",
		"grants.clientCredentials", "grants.authorizationCode",
		"refreshToken.rotation", "sourceProvenance", "network.apiExposure",
		"authentication.dkim", "retention.lockMode",
		// D1075 (found by the keyword lint):
		"security.podSecurity", "dnssec.enabled", "image.signedProvenance",
		"ingress.public", "egress.internet", "serviceAccess.private", "interconnect.private",
		"access.mutating", "role.permissions", "immutable.tags", "viewer.protocol",
		"integrity.logValidation", "key.exportable", "audience.restricted",
	} {
		if !isSecurityPath(p) {
			t.Errorf("%q must classify as a security path (it carries a security posture)", p)
		}
	}
	for _, p := range []string{
		"cost.monthly", "location.region", "service.managed", "availability.class",
		"engine.protocol", "retention.minimum", "display.name",
	} {
		if isSecurityPath(p) {
			t.Errorf("%q must NOT classify as a security path (no dangerous-direction posture, or the floor would over-fire)", p)
		}
	}
}

// TestAuditSoftSecurityPathAcceptsIntent proves the escape: the witnessed-evidence
// floor bites HARD constraints only. A SOFT security constraint with declared intent is
// recorded and does not block — the honest path for a control genuinely unobservable on
// a provider (declare it advisory), so the floor never bricks a legitimate gap.
func TestAuditSoftSecurityPathAcceptsIntent(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: sec, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  soft:
    - id: c-cmek
      subject: db
      path: encryption.customerManagedKeys
      op: equals
      value: true
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"encryption.customerManagedKeys": {Value: true, ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "declared", Source: "candidate-declared"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	// soft never blocks the machine surface, whatever the verdict.
	if res.Status == "violations-found" || res.Violations != 0 {
		t.Fatalf("a SOFT security constraint must not block, got status=%q violations=%d", res.Status, res.Violations)
	}
}

// TestAuditFutureDatedObservationIsUnverifiable pins D188 Finding 1: an
// observation whose observedAt is AFTER the evaluation --at has negative age,
// which slips past the `age > TTL` staleness test and would read as fresh — a
// fail-open reachable by time-travel evaluation (--at earlier than a recorded
// observation). A future observation that would SATISFY a hard constraint must
// instead be unverifiable and BLOCK. Fails before the fix (satisfied / clean).
func TestAuditFutureDatedObservationIsUnverifiable(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: money, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-cost
      subject: db
      path: cost.monthly
      op: lte
      value: "100 USD"
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	// the observation SATISFIES the constraint (90 <= 100 USD) but is dated
	// SIX HOURS AFTER the evaluation --at — it did not exist at the evaluated
	// instant, so it is invalid evidence, not fresh proof
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"cost.monthly": {Value: "90 USD", ObservedAt: "2026-07-15T18:00:00Z",
			TTLSeconds: 86400, Derivation: "measured", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:00:00Z", false, nil) // eval BEFORE the observation
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != "unverifiable" {
		t.Fatalf("a future-dated observation must be unverifiable, not fresh, got %+v",
			res.Verdicts)
	}
	if res.Status != "violations-found" || res.Violations != 1 {
		t.Fatalf("a hard unverifiable MUST block, got status=%q violations=%d",
			res.Status, res.Violations)
	}
}

// TestAuditEnforcesVerifyMethodEvidence pins D190: a hard constraint declaring
// verify.method=probe (an OUTCOME the author says must be measured) must NOT be
// satisfied by a provider-api config read, even one whose value matches. The
// author's evidence bar is honored at the runtime gate — insufficient source is
// unknown (probe first), which blocks. Fails before the fix (satisfied on the
// weaker provider-api evidence — the false PASS the method field was meant to
// prevent).
func TestAuditEnforcesVerifyMethodEvidence(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: ev, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-rto
      subject: db
      path: recovery.rto
      op: lte
      value: 1h
      verify: { method: probe }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	// the value SATISFIES (35m <= 1h) and is fresh, but its SOURCE is a
	// provider-api read (config-intent / observe), not a probe — insufficient
	// evidence for an outcome the contract says must be measured
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"recovery.rto": {Value: "35m", ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
		"2026-07-15T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].Verdict != "unknown" {
		t.Fatalf("a probe-method constraint with only provider-api evidence must "+
			"be unknown, got %+v", res.Verdicts)
	}
	if res.Status != "violations-found" || res.Violations != 1 {
		t.Fatalf("insufficient evidence on a hard constraint MUST block, "+
			"got status=%q violations=%d", res.Status, res.Violations)
	}

	// and a probe-sourced observation of the same value DOES satisfy it
	seedObs(led, "db", map[string]ledger.ObsRecord{
		"recovery.rto": {Value: "35m", ObservedAt: "2026-07-15T12:00:00Z",
			TTLSeconds: 86400, Derivation: "measured", Source: "probe"}})
	res, err = Run(c, led, filepath.Join(td, "l.jsonl"), "2026-07-15T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdicts[0].Verdict != "satisfied" {
		t.Fatalf("a probe-sourced measurement must satisfy the probe-method "+
			"constraint, got %+v", res.Verdicts[0])
	}
}

// TestAuditRetainsProbeEvidenceOverNewerObserve pins D191: a probe measurement
// must survive a later provider-api observe of the SAME path. The single-slot
// projection is newest-time-wins, so the newer (insufficient, here also
// violating) observe would erase the probe and flip the probe-method verdict to
// unknown/violated; per-source retention keeps the probe, which still satisfies.
func TestAuditRetainsProbeEvidenceOverNewerObserve(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: ret, environment: test, version: 1 }
capabilities:
  - id: db
    type: capability.database.relational
constraints:
  hard:
    - id: c-rto
      subject: db
      path: recovery.rto
      op: lte
      value: 1h
      verify: { method: probe }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	// a probe measured 35m at 12:00; a LATER provider-api observe read 2h (a
	// config value that would VIOLATE) at 13:00. Per-source retention keeps
	// both; audit judges the probe-method constraint on the probe record.
	led.ObservationsBySource["db"] = map[string]map[string]ledger.ObsRecord{
		"recovery.rto": {
			"probe": {Value: "35m", ObservedAt: "2026-07-15T12:00:00Z",
				TTLSeconds: 86400, Derivation: "measured", Source: "probe"},
			"provider-api": {Value: "2h", ObservedAt: "2026-07-15T13:00:00Z",
				TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
		},
	}
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"), "2026-07-15T13:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdicts[0].Verdict != "satisfied" {
		t.Fatalf("the retained probe measurement must satisfy the probe-method "+
			"constraint despite a newer provider-api observe, got %+v", res.Verdicts[0])
	}
}

// D722, from the field, on a live account with a hard EU-residency requirement:
//
//	{"path":"egress.restricted","value":true,"derivation":"config-intent"}
//
// The contract's HARD constraint `egress.restricted == true` read SATISFIED. Measured
// independently, both security groups in that network allowed `-1` to `0.0.0.0/0` —
// default-allow, the exact opposite of the vocabulary's "default-deny egress
// allow-list". The reporter's sentence: "Narzędzie ma znacznik `derivation` i go nie
// używa przy ocenie ograniczeń."
//
// `config-intent` means the resource STORES the value and does not itself enforce it.
// It is a rung below a provider-api MEASUREMENT, and the evidence ladder ranked it the
// same, because it keyed on `source` alone.
func TestConfigIntentCannotSatisfyAProviderAPIConstraint(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: net, environment: test, version: 1 }
capabilities:
  - id: vpc
    type: capability.network.private
constraints:
  hard:
    - id: c-egress
      subject: vpc
      path: egress.restricted
      op: equals
      value: true
      verify: { method: provider-api }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	seedObs(led, "vpc", map[string]ledger.ObsRecord{
		"egress.restricted": {Value: true, ObservedAt: "2026-08-03T12:00:00Z",
			TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"), "2026-08-03T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Verdicts) != 1 {
		t.Fatalf("expected one verdict, got %+v", res.Verdicts)
	}
	if got := res.Verdicts[0].Verdict; got != "unknown" {
		t.Fatalf("a hard constraint asking for provider-api evidence was ruled %q on a "+
			"config-intent reading — the marker exists and the judgement ignores it; "+
			"the estate that produced this had default-allow egress", got)
	}
}

// The other side, so the rule is not a blanket downgrade: an author who declares
// `verify: {method: static}` has accepted the document's own word, and a config-intent
// reading is exactly that. It must still satisfy.
func TestConfigIntentStillSatisfiesAStaticConstraint(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: net, environment: test, version: 1 }
capabilities:
  - id: vpc
    type: capability.network.private
constraints:
  hard:
    - id: c-egress
      subject: vpc
      path: egress.restricted
      op: equals
      value: true
      verify: { method: static }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	led := ledger.New()
	seedObs(led, "vpc", map[string]ledger.ObsRecord{
		"egress.restricted": {Value: true, ObservedAt: "2026-08-03T12:00:00Z",
			TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"), "2026-08-03T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Verdicts[0].Verdict; got != "satisfied" {
		t.Fatalf("a static-method constraint accepts the configuration's own word; got %q", got)
	}
}

// D728: the whole point of the two bars is that they are consulted by different
// commands. This is the audit half — the same constraint that passes `verify` on the
// candidate's declaration must be judged against its RUNTIME bar here, so a
// config-intent reading does not satisfy it.
func TestAuditJudgesAgainstTheRuntimeBarNotTheDesignBar(t *testing.T) {
	td := t.TempDir()
	cpath := filepath.Join(td, "c.yaml")
	if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: net, environment: test, version: 1 }
capabilities:
  - id: vpc
    type: capability.network.private
constraints:
  hard:
    - id: c-egress
      subject: vpc
      path: egress.restricted
      op: equals
      value: true
      verify: { design: static, runtime: provider-api }
`), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := contract.LoadContract(cpath)
	if err != nil {
		t.Fatal(err)
	}
	if c.Constraints[0].VerifyMethod != "static" ||
		c.Constraints[0].RuntimeMethod != "provider-api" {
		t.Fatalf("the two bars did not survive loading: design=%q runtime=%q",
			c.Constraints[0].VerifyMethod, c.Constraints[0].RuntimeMethod)
	}
	led := ledger.New()
	seedObs(led, "vpc", map[string]ledger.ObsRecord{
		"egress.restricted": {Value: true, ObservedAt: "2026-08-03T12:00:00Z",
			TTLSeconds: 86400, Derivation: "config-intent", Source: "provider-api"},
	})
	res, err := Run(c, led, filepath.Join(td, "l.jsonl"), "2026-08-03T12:05:00Z", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Verdicts[0].Verdict; got != "unknown" {
		t.Fatalf("audit ruled %q — it judged against the DESIGN bar (static, which any "+
			"declaration meets) instead of the runtime bar the contract wrote for it", got)
	}
}

// D759. A third derivation, because the set had two values and reality has three.
// Measured across the drivers: 65 of 72 `config-intent` observations were BARE CONSTANTS
// — `encryption.atRest: true` on a service that always encrypts — and the published
// definition of that label is "a value the resource STORES but does not itself enforce".
// The resource stores nothing of the kind. The values are true; the provenance was not.
//
// It earns the SAME bar as config-intent, and that is the load-bearing half. A provider
// guarantee is tempting to rank high — it cannot be otherwise — and three entries in one
// day were an author asserting a guarantee that was not one (D752, D753, D754). Nothing
// about THIS resource was read, so the static bar is what it earns. The new value buys
// honest provenance, never more trust.
func TestPlatformInvariantIsHonestProvenanceNotMoreTrust(t *testing.T) {
	contractFor := func(t *testing.T, method string) *contract.Contract {
		t.Helper()
		cpath := filepath.Join(t.TempDir(), "c.yaml")
		if err := os.WriteFile(cpath, []byte(`
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: net, environment: test, version: 1 }
capabilities:
  - id: vpc
    type: capability.network.private
constraints:
  hard:
    - id: c-egress
      subject: vpc
      path: egress.restricted
      op: equals
      value: true
      verify: { method: `+method+` }
`), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := contract.LoadContract(cpath)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	verdictFor := func(t *testing.T, method, derivation string) string {
		t.Helper()
		led := ledger.New()
		seedObs(led, "vpc", map[string]ledger.ObsRecord{
			"egress.restricted": {Value: true, ObservedAt: "2026-08-03T12:00:00Z",
				TTLSeconds: 86400, Derivation: derivation, Source: "provider-api"},
		})
		res, err := Run(contractFor(t, method), led, filepath.Join(t.TempDir(), "l.jsonl"),
			"2026-08-03T12:05:00Z", false, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Verdicts) != 1 {
			t.Fatalf("expected one verdict, got %+v", res.Verdicts)
		}
		return res.Verdicts[0].Verdict
	}

	if got := verdictFor(t, "provider-api", "platform-invariant"); got != "unknown" {
		t.Errorf("a hard constraint asking for a provider-api READING was ruled %q on a "+
			"platform guarantee — nothing was read about this resource, and an author who "+
			"asserted a guarantee wrongly is exactly how D752/D753/D754 happened", got)
	}
	if got := verdictFor(t, "static", "platform-invariant"); got != "satisfied" {
		t.Errorf("a static-bar constraint was ruled %q on a platform guarantee — the "+
			"author accepted a claim, and this is one", got)
	}
	// The control: the new value must not be the old one under another name, nor
	// silently rejected as an unknown basis.
	if got := verdictFor(t, "static", "measured"); got != "satisfied" {
		t.Errorf("measured at the static bar = %q, want satisfied", got)
	}
	if got := verdictFor(t, "provider-api", "measured"); got != "satisfied" {
		t.Errorf("measured at the provider-api bar = %q, want satisfied — the fix must "+
			"not demote real readings", got)
	}
}

// D1190. The same proof as TestAuditSecurityPathRejectsDeclaredIntent, aimed at the
// paths that were NOT floored — and it is written as a table with a CONTROL, because
// the finding is not "one path was missing" but "the lint floored part of a block and
// left its siblings".
//
// `access.privileged` is the control: it was already floored, because the keyword regex
// contains "privileg". `grant.principal` and `grant.role` live in the same capability
// and matched nothing, so until this slice an audit witnessed "this grant is not
// privileged" and accepted "the principal is a named user, not allUsers" on the
// candidate's own word. That is the D1179 public-access shape one attribute over,
// reached without anyone doing anything wrong.
func TestAuditFloorsGrantIdentityNotJustPrivilege(t *testing.T) {
	for _, tc := range []struct {
		path, note string
	}{
		{"access.privileged", "the CONTROL — floored before this slice (regex: privileg)"},
		{"grant.principal", "allUsers vs a named principal — the same shape as D1179"},
		{"grant.role", "owner vs viewer — the least-privilege crown"},
		{"access.scope", "how wide the grant reaches"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			td := t.TempDir()
			cpath := filepath.Join(td, "c.yaml")
			doc := `
apiVersion: contract/v0.1
kind: InfrastructureContract
meta: { id: sec, environment: test, version: 1 }
capabilities:
  - id: g
    type: capability.authorization.grant
constraints:
  hard:
    - id: c-grant
      subject: g
      path: ` + tc.path + `
      op: equals
      value: false
      verify: { method: static }
`
			if err := os.WriteFile(cpath, []byte(doc), 0o600); err != nil {
				t.Fatal(err)
			}
			c, err := contract.LoadContract(cpath)
			if err != nil {
				t.Fatal(err)
			}
			// The adopt-fill: the driver observed nothing for this path, so the
			// candidate's own claim was recorded as intent.
			led := ledger.New()
			seedObs(led, "g", map[string]ledger.ObsRecord{
				tc.path: {Value: false, ObservedAt: "2026-07-15T12:00:00Z",
					TTLSeconds: 86400, Derivation: "declared", Source: "candidate-declared"},
			})
			res, err := Run(c, led, filepath.Join(td, "l.jsonl"),
				"2026-07-15T12:05:00Z", false, nil)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Verdicts) != 1 {
				t.Fatalf("expected one verdict, got %+v", res.Verdicts)
			}
			if v := res.Verdicts[0].Verdict; v != "unknown" && v != "unverifiable" {
				t.Fatalf("%s (%s): declared intent SATISFIED a hard security constraint — "+
					"the audit certified a control nobody measured; got %q",
					tc.path, tc.note, v)
			}
			if res.Status != "violations-found" {
				t.Fatalf("%s: a hard security control backed only by intent must BLOCK, "+
					"got status=%q", tc.path, res.Status)
			}
		})
	}
}
