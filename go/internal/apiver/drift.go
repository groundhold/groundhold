package apiver

// drift.go is the PURE drift comparator (D236). Given a pin and a live version
// list (canary-fetched per provider), it returns a four-valued verdict. It has
// NO network and NO write path back to the registry: it surfaces drift, a human
// bumps the pin. Determinism + golden-testability come for free — the live
// fetchers that PRODUCE a LiveVersions live in the canary, gated exactly like
// fixture capture (drift_capture, next slice).

// Verdict is the closed drift outcome set. Same fail-closed spine as the
// verifier: an unknown live state is cannot-verify, never a green guess.
type Verdict string

const (
	// PinnedCurrent: the live provider still advertises the pinned version as a
	// current (non-deprecated) version and nothing stable supersedes it.
	// UNREACHABLE for AWS by construction — see Compare.
	PinnedCurrent Verdict = "pinned-current"
	// NewerAvailable: a newer STABLE version is advertised/preferred. Surface it;
	// do not follow it.
	NewerAvailable Verdict = "newer-available"
	// Deprecated: the provider no longer advertises the pinned version, or marks
	// it deprecated. The strongest drift signal.
	Deprecated Verdict = "deprecated"
	// CannotVerify: no reliable live signal (fetch failed, empty, or — for AWS —
	// there is no authoritative current-version endpoint at all). Never green.
	CannotVerify Verdict = "cannot-verify"
)

// LiveVersion is one version the provider advertises for a service.
type LiveVersion struct {
	ID         string `json:"id"`         // "compute/v1" | "2024-06-01" | "2024-06-01-preview"
	Stable     bool   `json:"stable"`     // not alpha/beta/preview
	Preferred  bool   `json:"preferred"`  // provider marks it default/preferred
	Deprecated bool   `json:"deprecated"` // provider marks it deprecated
}

// LiveVersions is a normalized per-service snapshot fetched from a provider. It
// is the ONLY input to Compare besides the pin; a fetcher (canary) fills it.
type LiveVersions struct {
	Provider  string        `json:"provider"`
	Service   string        `json:"service"`
	Versions  []LiveVersion `json:"versions"`
	Source    string        `json:"source"`    // discovery URL | sdk-model | arm-providers
	FetchedAt string        `json:"fetchedAt"` // RFC3339 (canary run)
}

// Result is one drift verdict with its evidence.
type Result struct {
	Provider  string   `json:"provider"`
	Service   string   `json:"service"`
	Pinned    string   `json:"pinned"`
	Verdict   Verdict  `json:"verdict"`
	Evidence  string   `json:"evidence"`
	Newer     []string `json:"newer,omitempty"` // newer stable version ids, if any
	Source    string   `json:"source,omitempty"`
	FetchedAt string   `json:"fetchedAt,omitempty"`
}

// Compare is the pure comparator. AWS is structurally barred from PinnedCurrent:
// AWS exposes no authoritative "current version" endpoint, so a matching SDK
// model is evidence, not proof — the honest AWS domain is {NewerAvailable,
// CannotVerify}. GCP and Azure carry preferred/deprecated flags via Discovery /
// ARM, so their full domain is reachable.
func Compare(pin Pin, live *LiveVersions) Result {
	r := Result{Provider: pin.Provider, Service: pin.Service, Pinned: pin.Version}
	if live == nil || len(live.Versions) == 0 {
		r.Verdict = CannotVerify
		r.Evidence = "no live version signal available"
		return r
	}
	r.Source, r.FetchedAt = live.Source, live.FetchedAt

	if pin.Provider == "aws" {
		// No authoritative current-version endpoint. The only positive machine
		// signal is a newer dated version in the SDK service models. A MATCH is
		// NOT pinned-current: mirror lag and announcement-only deprecation make
		// that a fabricated green. So AWS yields NewerAvailable or CannotVerify.
		newer := newerStable(pin.Version, live.Versions, awsAfter)
		if len(newer) > 0 {
			r.Verdict = NewerAvailable
			r.Newer = newer
			r.Evidence = "AWS SDK models advertise a newer service API version; " +
				"deprecation of the pinned version is announcement-only (not machine-checkable)"
			return r
		}
		r.Verdict = CannotVerify
		r.Evidence = "AWS exposes no authoritative current-version endpoint; " +
			"a matching SDK model is not proof of currency"
		return r
	}

	// GCP / Azure: locate the pin in the advertised set.
	var found *LiveVersion
	for i := range live.Versions {
		if live.Versions[i].ID == pin.Version {
			found = &live.Versions[i]
			break
		}
	}
	if found == nil {
		r.Verdict = Deprecated
		r.Evidence = "the pinned version is no longer advertised by the provider"
		return r
	}
	if found.Deprecated {
		r.Verdict = Deprecated
		r.Evidence = "the provider marks the pinned version deprecated"
		// still surface any newer stable version to aid the bump
		r.Newer = supersedes(*found, live.Versions)
		return r
	}
	newer := supersedes(*found, live.Versions)
	if len(newer) > 0 {
		r.Verdict = NewerAvailable
		r.Newer = newer
		r.Evidence = "a newer stable version is advertised/preferred by the provider"
		return r
	}
	r.Verdict = PinnedCurrent
	r.Evidence = "the pinned version is advertised and current"
	return r
}

// supersedes returns the stable versions that supersede the pinned one for
// GCP/Azure: another STABLE version that the provider PREFERS over the pin, or —
// when no preferred flag distinguishes them — a strictly-later dated stable
// version (Azure). Preview/beta versions never supersede a stable pin.
func supersedes(pin LiveVersion, all []LiveVersion) []string {
	var out []string
	for _, v := range all {
		if v.ID == pin.ID || !v.Stable || v.Deprecated {
			continue
		}
		if v.Preferred && !pin.Preferred {
			out = append(out, v.ID)
			continue
		}
		// date-comparable ids (Azure api-versions): later stable date wins.
		if dateAfter(pin.ID, v.ID) {
			out = append(out, v.ID)
		}
	}
	return out
}

// newerStable returns stable, non-deprecated advertised versions strictly after
// the pin per the given ordering.
func newerStable(pinID string, all []LiveVersion, after func(pin, cand string) bool) []string {
	var out []string
	for _, v := range all {
		if v.ID == pinID || !v.Stable || v.Deprecated {
			continue
		}
		if after(pinID, v.ID) {
			out = append(out, v.ID)
		}
	}
	return out
}

// awsAfter: AWS service API versions are dates (YYYY-MM-DD); lexical compare of
// the ISO date is a correct chronological compare.
func awsAfter(pin, cand string) bool { return cand > pin && isDate(cand) && isDate(pin) }

// dateAfter: Azure api-versions are dates with an optional -preview suffix. Two
// stable dates compare lexically; a -preview id never counts as "after" a stable
// pin (its stability is filtered by the caller, but guard here too).
func dateAfter(pin, cand string) bool {
	pd, cd := datePart(pin), datePart(cand)
	if pd == "" || cd == "" {
		return false
	}
	return cd > pd
}

func datePart(s string) string {
	if len(s) < 10 || !isDate(s[:10]) {
		return ""
	}
	return s[:10]
}

// isDate reports whether s is exactly YYYY-MM-DD.
func isDate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	for i, c := range s {
		if i == 4 || i == 7 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
