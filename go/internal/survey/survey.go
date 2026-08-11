// Package survey compares a code survey (spec/survey.md — the
// commit-pinned evidence table an agent's crawl produces) against a
// contract. Deterministic comparator, no LLM, no network: the code is
// a witness, not an author, and a survey never becomes a contract
// (the D53 hints precedent). Absence of evidence is never drift
// unless the survey set is declared complete.
package survey

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"groundhold/internal/contract"
)

const apiVersion = "survey/v0.1"

type Doc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Repo       struct {
		Name   string `json:"name"`
		Remote string `json:"remote"`
		Commit string `json:"commit"`
	} `json:"repo"`
	Service     string    `json:"service"`
	GeneratedAt string    `json:"generatedAt"`
	Findings    []Finding `json:"findings"`
}

type Finding struct {
	Dependency     string   `json:"dependency"`
	Class          string   `json:"class"`
	CapabilityHint string   `json:"capabilityHint,omitempty"`
	Evidence       []string `json:"evidence"`
	Note           string   `json:"note,omitempty"`
}

var validClass = map[string]bool{
	"required": true, "optional": true, "dev-test": true, "unknown": true,
}

// Load refuses loudly: an unpinned survey (no commit) or an unknown
// finding class is a structural error, never a guess.
func Load(path string) (*Doc, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var d Doc
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if d.APIVersion != apiVersion {
		return nil, fmt.Errorf("%s: apiVersion %q is not %q",
			path, d.APIVersion, apiVersion)
	}
	if d.Kind != "CodeSurvey" {
		return nil, fmt.Errorf("%s: kind %q is not CodeSurvey", path, d.Kind)
	}
	if d.Repo.Name == "" || d.Repo.Commit == "" {
		return nil, fmt.Errorf("%s: survey must be pinned — repo.name and "+
			"repo.commit are mandatory (findings are true AT a commit, "+
			"never in general)", path)
	}
	for _, f := range d.Findings {
		if f.Dependency == "" {
			return nil, fmt.Errorf("%s: finding without a dependency", path)
		}
		if !validClass[f.Class] {
			return nil, fmt.Errorf("%s: finding %q: class %q is not in "+
				"required|optional|dev-test|unknown", path, f.Dependency, f.Class)
		}
		if len(f.Evidence) == 0 {
			return nil, fmt.Errorf("%s: finding %q cites no evidence — a "+
				"finding that cannot say where it saw something is not a "+
				"finding", path, f.Dependency)
		}
	}
	return &d, nil
}

type CoverageRow struct {
	Repo           string `json:"repo"`
	Dependency     string `json:"dependency"`
	Class          string `json:"class"`
	CapabilityHint string `json:"capabilityHint,omitempty"`
	// covered | uncovered | gap | ignored
	Status     string `json:"status"`
	Capability string `json:"capability,omitempty"`
}

type OrphanRow struct {
	Capability string `json:"capability"`
	Type       string `json:"type"`
	// unwitnessed (information) | orphaned (drift, --complete only) |
	// witnessed-by-type (information, D707: a sibling of the same type was
	// witnessed and a type-level finding cannot say which one)
	Status string `json:"status"`
}

type Source struct {
	Repo    string `json:"repo"`
	Commit  string `json:"commit"`
	Service string `json:"service,omitempty"`
}

type Report struct {
	Contract string        `json:"contract"`
	Surveys  []Source      `json:"surveys"`
	Complete bool          `json:"complete"`
	Coverage []CoverageRow `json:"coverage"`
	Orphans  []OrphanRow   `json:"orphans"`
	Drift    bool          `json:"drift"`
	Code     string        `json:"code,omitempty"` // survey-drift
	Exit     int           `json:"-"`
}

// Run computes coverage both ways. required+hint → covered/uncovered;
// required without a hint, optional, unknown → gap (a question, never
// silent drift); dev-test → ignored but reported. A capability no
// survey witnesses is unwitnessed information — another repo may be
// the consumer — and hardens into orphaned drift only under complete.
func Run(c *contract.Contract, docs []*Doc, complete bool) *Report {
	rep := &Report{Contract: c.ID, Complete: complete,
		Coverage: []CoverageRow{}, Orphans: []OrphanRow{}}

	capsByType := map[string][]string{}
	for id, raw := range c.Capabilities {
		t, _ := raw["type"].(string)
		capsByType[t] = append(capsByType[t], id)
	}
	for t := range capsByType {
		sort.Strings(capsByType[t])
	}

	witnessed := map[string]bool{} // capability id -> has a required finding
	// byTypeOnly: witnessed only through a sibling of the same type (D707). Not
	// drift — a type-level finding is real evidence that SOMETHING of that type is
	// used — but not a sighting of this capability either, and `--complete` exists
	// to find capabilities nobody uses. Reported so the silence is visible.
	byTypeOnly := map[string]bool{}
	for _, d := range docs {
		rep.Surveys = append(rep.Surveys, Source{
			Repo: d.Repo.Name, Commit: d.Repo.Commit, Service: d.Service})
		for _, f := range d.Findings {
			row := CoverageRow{Repo: d.Repo.Name, Dependency: f.Dependency,
				Class: f.Class, CapabilityHint: f.CapabilityHint}
			switch {
			case f.Class == "dev-test":
				row.Status = "ignored"
			case f.Class != "required" || f.CapabilityHint == "":
				row.Status = "gap"
			case len(capsByType[f.CapabilityHint]) > 0:
				row.Status = "covered"
				row.Capability = capsByType[f.CapabilityHint][0]
				for _, id := range capsByType[f.CapabilityHint] {
					witnessed[id] = true
					// D707: a finding names a TYPE, so with several capabilities of
					// that type it cannot say which one this repo uses. Remember that
					// the answer was an inference, not a sighting.
					if len(capsByType[f.CapabilityHint]) > 1 {
						byTypeOnly[id] = true
					}
				}
			default:
				row.Status = "uncovered"
				rep.Drift = true
			}
			rep.Coverage = append(rep.Coverage, row)
		}
	}

	ids := make([]string, 0, len(c.Capabilities))
	for id := range c.Capabilities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		typ, _ := c.Capabilities[id]["type"].(string)
		if witnessed[id] {
			// D707: witnessed, but only because a SIBLING of the same type was. The
			// report used to say nothing at all about these, so an operator running
			// --complete to find a capability nobody uses got silence about the one
			// case the evidence cannot settle. Information, never drift: turning it
			// into drift would accuse every contract with two capabilities of one
			// type and a single witnessing repo.
			if byTypeOnly[id] {
				rep.Orphans = append(rep.Orphans, OrphanRow{
					Capability: id, Type: typ, Status: "witnessed-by-type"})
			}
			continue
		}
		t := typ
		status := "unwitnessed"
		if complete {
			status = "orphaned"
			rep.Drift = true
		}
		rep.Orphans = append(rep.Orphans, OrphanRow{
			Capability: id, Type: t, Status: status})
	}

	if rep.Drift {
		rep.Code = "survey-drift"
		rep.Exit = 2
	}
	return rep
}
