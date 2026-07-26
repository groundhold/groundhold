// Event signatures (D102): an OPT-IN detached ed25519 signature in the
// event envelope. The signature attests identity, it is not part of it
// — canonical.HashEvent excludes the `sig` key, so signed and unsigned
// copies of one event share one hash and unsigned history stays valid
// forever. What is signed is the domain-separated canonical hash
// string, never raw JSON bytes: canonicalization is the cross-
// implementation truth, byte layouts of lines are not.
//
// Threat model, stated honestly: a verified chain proves "these events,
// in this order, were authored by the holder of this key". It does NOT
// prove freshness or completeness-of-knowledge — a signer can withhold
// a newer suffix. Countering omission is the anchor's job (D70):
// receivers hold anchors off-host and check them positionally.
package ledger

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"

	"groundhold/internal/canonical"
)

// SigScheme separates event signatures from any other ed25519 use of
// the same key — signing a hash from a different domain can never be
// replayed as an event attestation. v2 (D134): the signed message also
// binds the LEDGER's identity (the genesis event's canonical hash), so
// the same event verbatim cannot be presented as attesting some other
// ledger's history: message = scheme + ledgerId + ":" + eventHash.
const SigScheme = "groundhold/sig/v2"

func sigMessage(ledgerID, eventHash string) []byte {
	return []byte(SigScheme + ":" + ledgerID + ":" + eventHash)
}

var (
	signKey ed25519.PrivateKey // nil: appends stay unsigned (the default)
	// trustSet (D133): rotation is receiver policy, not ledger history —
	// --trust is repeatable and every signed line must verify by ANY key
	// in the set (exact match). Revocation = the receiver removes a key
	// from THEIR set; the ledger does not get a vote.
	trustSet []ed25519.PublicKey
	// trustFrom (D133): canonical hash of the event where signing
	// becomes mandatory (inclusive). Receiver-held, out-of-band — a
	// boundary an attacker cannot slide. Empty: the whole file must be
	// signed (when trustSet is armed).
	trustFrom string
)

// LoadSignKey arms signing for every subsequent append in this process
// (--sign-key). The file holds a hex-encoded 32-byte ed25519 seed.
func LoadSignKey(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("%s: expected a hex-encoded 32-byte ed25519 seed", path)
	}
	signKey = ed25519.NewKeyFromSeed(seed)
	return nil
}

// AddTrust arms replay verification (--trust, repeatable): every event
// in the file must carry a signature by SOME key in the set — an
// unsigned or foreign-signed line is tamper evidence, same channel as
// a broken hash chain. Accepts the 64-char hex public key.
func AddTrust(hexPub string) error {
	pub, err := hex.DecodeString(strings.TrimSpace(hexPub))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("--trust expects a hex-encoded 32-byte ed25519 public key")
	}
	trustSet = append(trustSet, ed25519.PublicKey(pub))
	return nil
}

// SetTrustFrom arms the signing boundary (--trust-from): the canonical
// hash of the event where signing becomes mandatory, inclusive.
func SetTrustFrom(h string) error {
	h = strings.TrimSpace(h)
	if !strings.HasPrefix(h, "sha256:") || len(h) != len("sha256:")+64 {
		return fmt.Errorf("--trust-from expects a canonical event hash " +
			"(sha256:<64 hex>) — the id column of `groundhold export`")
	}
	trustFrom = h
	return nil
}

// SigningArmed reports whether a --sign-key is loaded (D137 needs it to
// refuse an unsignable trust snapshot up front).
func SigningArmed() bool { return signKey != nil }

// ResetSigning disarms everything (tests).
func ResetSigning() { signKey, trustSet, trustFrom = nil, nil, "" }

// TrustChecker carries the per-stream state of one verification pass
// (a replay, an export fold, a capsule): whether the --trust-from
// boundary has been reached, and which ledger the stream's signatures
// claim (D134). The trust SET is process config; both of these are
// properties of the stream being read — never global.
type TrustChecker struct {
	reached  bool
	ledgerID string // expected (set by the stream) or first claimed
}

// TrustError marks a failure of the SIGNATURE/TRUST contract, as opposed to
// structural corruption of the chain. The distinction is machine-readable —
// `restore --partial` reports capsule-trust-refused vs capsule-tampered — and it
// used to be recovered by substring-matching the message for "key", "signed",
// "trust"... Several verification messages embed the CAPABILITY NAME, which the
// contract author chooses, so a capability called "api-keys" made every
// structural corruption report as a trust refusal (D312). This repo already ruled
// once (D62/D73) that classifying on substrings of text carrying user-controlled
// ids is spoofable; the class is carried by the type now.
type TrustError struct{ Err error }

func (e *TrustError) Error() string { return e.Err.Error() }
func (e *TrustError) Unwrap() error { return e.Err }

func trustErrf(format string, a ...any) error {
	return &TrustError{Err: fmt.Errorf(format, a...)}
}

// IsTrustError reports whether err (or anything it wraps) is a trust/signature
// failure. Callers MUST use this rather than reading the message.
func IsTrustError(err error) bool {
	var t *TrustError
	return errors.As(err, &t)
}

func NewTrustChecker() *TrustChecker { return &TrustChecker{} }

// SeedBoundaryHonored marks the --trust-from boundary as already
// reached — used ONLY when a snapshot's verifiedUnder receipt records
// that the rotation replay honored EXACTLY this boundary (D137): the
// boundary event lives in the archive now, and the receipt is the
// proof the obligation was enforced.
func (tc *TrustChecker) SeedBoundaryHonored() { tc.reached = true }

// ExpectLedger pins the stream's actual identity (its genesis event
// hash) once the stream knows it. If a signature already claimed a
// different ledger, that claim was a lie — refuse.
func (tc *TrustChecker) ExpectLedger(id string) error {
	if tc.ledgerID != "" && tc.ledgerID != id {
		return trustErrf("a signature claims ledger %s… but this "+
			"stream's genesis is %s… — signed for a FOREIGN ledger",
			trunc(tc.ledgerID), trunc(id))
	}
	tc.ledgerID = id
	return nil
}

// LedgerID reports the identity this stream's signatures consistently
// claimed (capsules: provenance the receiver can compare out-of-band).
// Empty when nothing signed was seen.
func (tc *TrustChecker) LedgerID() string { return tc.ledgerID }

// Check enforces the trust contract on one line. Before an armed
// --trust-from boundary, lines are the tolerated unsigned era; the
// boundary event itself must verify (inclusive — a tolerant boundary
// would be a sliding one).
func (tc *TrustChecker) Check(doc map[string]any, line int) error {
	if len(trustSet) == 0 {
		return nil
	}
	if trustFrom != "" && !tc.reached {
		h, err := canonical.HashEvent(doc)
		if err != nil {
			return fmt.Errorf("ledger line %d: %v", line, err)
		}
		if h != trustFrom {
			return nil // pre-boundary era
		}
		tc.reached = true // fall through: the boundary must verify
	}
	return tc.verifySig(doc, line)
}

// Finish refuses a stream that never contained the armed boundary: a
// file that lacks the boundary cannot claim it — otherwise truncation
// would erase the obligation to be signed.
func (tc *TrustChecker) Finish() error {
	if len(trustSet) > 0 && trustFrom != "" && !tc.reached {
		return trustErrf("--trust-from boundary %s… absent from the "+
			"verified input — the boundary is checked against what is "+
			"actually being read, never a parent ledger (truncated, "+
			"filtered or foreign)", trunc(trustFrom))
	}
	return nil
}

// signDoc attaches the detached envelope. Must run AFTER the event is
// final — any later mutation would invalidate the signature (the hash
// itself is immune, it excludes `sig`). ledgerID is the genesis event's
// hash; for the genesis line itself it is the line's own hash (D134 —
// computable pre-signing precisely because the hash excludes `sig`).
func signDoc(doc map[string]any, ledgerID string) error {
	if signKey == nil {
		return nil
	}
	h, err := canonical.HashEvent(doc)
	if err != nil {
		return err
	}
	if ledgerID == "" {
		ledgerID = h // this line IS the genesis
	}
	sig := ed25519.Sign(signKey, sigMessage(ledgerID, h))
	doc["sig"] = map[string]any{
		"alg":    "ed25519",
		"pub":    hex.EncodeToString(signKey.Public().(ed25519.PublicKey)),
		"sig":    hex.EncodeToString(sig),
		"ledger": ledgerID,
	}
	return nil
}

// ArmedTrustFrom exposes the armed --trust-from boundary (export needs
// it to credit a compacted boundary from the snapshot receipt, D137).
func ArmedTrustFrom() string { return trustFrom }

// ArmedPolicy exposes the process's trust policy for anchors to embed
// (D135) — an anchor may carry only what its emitter actually verified.
func ArmedPolicy() (keys []string, from string) {
	for _, k := range trustSet {
		keys = append(keys, hex.EncodeToString(k))
	}
	return keys, trustFrom
}

// MergeAnchorPolicy applies a trust policy carried by a receiver-held
// anchor (D135). When the CLI also armed a policy, the two must AGREE
// — no silent union, no precedence: two sources of trust policy that
// disagree are an operator error to resolve, never a choice the tool
// makes quietly.
func MergeAnchorPolicy(scheme string, keys []string, from string) error {
	if scheme != SigScheme {
		return fmt.Errorf("the anchor's trust policy is for signature "+
			"scheme %q; this runtime implements %q — refusing to apply a "+
			"policy to an incompatible scheme", scheme, SigScheme)
	}
	if len(trustSet) == 0 && trustFrom == "" {
		for _, k := range keys {
			if err := AddTrust(k); err != nil {
				return fmt.Errorf("anchor trust policy: %v", err)
			}
		}
		if from != "" {
			if err := SetTrustFrom(from); err != nil {
				return fmt.Errorf("anchor trust policy: %v", err)
			}
		}
		return nil
	}
	armed, armedFrom := ArmedPolicy()
	if !sameKeySet(armed, keys) || armedFrom != from {
		return fmt.Errorf("the anchor's trust policy and the command " +
			"line's disagree (keys or boundary) — resolve which one is " +
			"true; the tool will not pick")
	}
	return nil
}

// sameKeySet is true multiset-insensitive equality: dedupe both sides
// (case-insensitive) and compare — {K1,K2} vs {K1,K1} must be UNequal
// (review fix: a length-plus-membership check passed it asymmetrically).
func sameKeySet(a, b []string) bool {
	sa, sb := map[string]bool{}, map[string]bool{}
	for _, k := range a {
		sa[strings.ToLower(k)] = true
	}
	for _, k := range b {
		sb[strings.ToLower(k)] = true
	}
	if len(sa) != len(sb) {
		return false
	}
	for k := range sa {
		if !sb[k] {
			return false
		}
	}
	return true
}

// verifySig checks one line against the trust set (any-of, D133) and
// the stream's ledger identity (D134).
func (tc *TrustChecker) verifySig(doc map[string]any, line int) error {
	sig, ok := doc["sig"].(map[string]any)
	if !ok {
		return trustErrf("ledger line %d: unsigned event but --trust "+
			"was given — the whole file must be authored by the trusted "+
			"key (tampered, or history predates signing)", line)
	}
	// the ledger claim binds first (D134): a valid signature for the
	// wrong ledger is not partial credit, it is someone else's history
	claim, _ := sig["ledger"].(string)
	if !strings.HasPrefix(claim, "sha256:") || len(claim) != len("sha256:")+64 {
		return trustErrf("ledger line %d: malformed ledger claim in the "+
			"signature envelope", line)
	}
	if tc.ledgerID == "" {
		tc.ledgerID = claim
	} else if claim != tc.ledgerID {
		return trustErrf("ledger line %d: signature claims ledger %s… "+
			"but this stream is %s… — signed for a FOREIGN ledger "+
			"(transplanted, or two histories spliced)",
			line, trunc(claim), trunc(tc.ledgerID))
	}
	pubHex, _ := sig["pub"].(string)
	pub, err := hex.DecodeString(pubHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return trustErrf("ledger line %d: malformed signature public key", line)
	}
	inSet := false
	for _, t := range trustSet {
		if t.Equal(ed25519.PublicKey(pub)) {
			inSet = true
			break
		}
	}
	if !inSet {
		return trustErrf("ledger line %d: event signed by a FOREIGN key "+
			"%s… — not among the trusted keys", line, pubHex[:16])
	}
	sigHex, _ := sig["sig"].(string)
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return trustErrf("ledger line %d: malformed signature", line)
	}
	h, err := canonical.HashEvent(doc) // excludes `sig` (D102)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), sigMessage(claim, h), sigBytes) {
		return trustErrf("ledger line %d: signature does not verify — "+
			"the event was altered after signing, or the signature was "+
			"transplanted from another event", line)
	}
	return nil
}

// trunc renders a hash prefix for error text without assuming shape —
// a MALFORMED claim must produce a clean refusal, never a slice panic
// (review fix).
func trunc(s string) string {
	if len(s) > 23 {
		return s[:23]
	}
	if s == "" {
		return "<empty>"
	}
	return s
}
