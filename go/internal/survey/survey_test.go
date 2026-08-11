package survey

import (
	"os"
	"path/filepath"
	"testing"

	"groundhold/internal/contract"
)

// ---- Load ----------------------------------------------------------------

// a minimal well-formed survey JSON, mutated per case.
const goodSurvey = `{
  "apiVersion": "survey/v0.1",
  "kind": "CodeSurvey",
  "repo": {"name": "app", "remote": "git@x", "commit": "abc123"},
  "service": "api",
  "generatedAt": "2026-07-24T00:00:00Z",
  "findings": [
    {"dependency": "mysql", "class": "required",
     "capabilityHint": "capability.database.relational",
     "evidence": ["cmd/main.go:12"]}
  ]
}`

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "survey.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	d, err := Load(writeTmp(t, goodSurvey))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d.Repo.Name != "app" || d.Repo.Commit != "abc123" {
		t.Errorf("repo not parsed: %+v", d.Repo)
	}
	if d.Service != "api" {
		t.Errorf("service = %q, want api", d.Service)
	}
	if len(d.Findings) != 1 || d.Findings[0].Dependency != "mysql" {
		t.Fatalf("findings not parsed: %+v", d.Findings)
	}
}

func TestLoadErrors(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"bad json", `{not json`},
		{"wrong apiVersion", `{"apiVersion":"survey/v9","kind":"CodeSurvey",
			"repo":{"name":"a","commit":"c"},"findings":[]}`},
		{"wrong kind", `{"apiVersion":"survey/v0.1","kind":"Nope",
			"repo":{"name":"a","commit":"c"},"findings":[]}`},
		{"unpinned: no name", `{"apiVersion":"survey/v0.1","kind":"CodeSurvey",
			"repo":{"name":"","commit":"c"},"findings":[]}`},
		{"unpinned: no commit", `{"apiVersion":"survey/v0.1","kind":"CodeSurvey",
			"repo":{"name":"a","commit":""},"findings":[]}`},
		{"finding without dependency", `{"apiVersion":"survey/v0.1","kind":"CodeSurvey",
			"repo":{"name":"a","commit":"c"},
			"findings":[{"dependency":"","class":"required","evidence":["x"]}]}`},
		{"invalid class", `{"apiVersion":"survey/v0.1","kind":"CodeSurvey",
			"repo":{"name":"a","commit":"c"},
			"findings":[{"dependency":"d","class":"maybe","evidence":["x"]}]}`},
		{"no evidence", `{"apiVersion":"survey/v0.1","kind":"CodeSurvey",
			"repo":{"name":"a","commit":"c"},
			"findings":[{"dependency":"d","class":"required","evidence":[]}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Load(writeTmp(t, tc.body)); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}

// every class in validClass must load (the accept side of TestLoadErrors).
func TestLoadAcceptsAllClasses(t *testing.T) {
	for _, cls := range []string{"required", "optional", "dev-test", "unknown"} {
		body := `{"apiVersion":"survey/v0.1","kind":"CodeSurvey",
			"repo":{"name":"a","commit":"c"},
			"findings":[{"dependency":"d","class":"` + cls + `","evidence":["x"]}]}`
		if _, err := Load(writeTmp(t, body)); err != nil {
			t.Errorf("class %q: unexpected error: %v", cls, err)
		}
	}
}

// ---- Run -----------------------------------------------------------------

func cap(t string) map[string]any { return map[string]any{"type": t} }

func contractWith(id string, caps map[string]map[string]any) *contract.Contract {
	return &contract.Contract{ID: id, Capabilities: caps}
}

func doc(repo, commit, service string, fs ...Finding) *Doc {
	d := &Doc{APIVersion: apiVersion, Kind: "CodeSurvey", Service: service,
		Findings: fs}
	d.Repo.Name = repo
	d.Repo.Commit = commit
	return d
}

func find(dep, class, hint string) Finding {
	return Finding{Dependency: dep, Class: class, CapabilityHint: hint,
		Evidence: []string{"x"}}
}

// findByDep locates a coverage row by its dependency name.
func findRow(rep *Report, dep string) *CoverageRow {
	for i := range rep.Coverage {
		if rep.Coverage[i].Dependency == dep {
			return &rep.Coverage[i]
		}
	}
	return nil
}

func TestRunStatuses(t *testing.T) {
	c := contractWith("c1", map[string]map[string]any{
		"db": cap("capability.database.relational"),
	})
	d := doc("app", "sha", "api",
		find("req-covered", "required", "capability.database.relational"),
		find("req-uncovered", "required", "capability.cache.redis"),
		find("req-nohint", "required", ""),
		find("opt", "optional", "capability.database.relational"),
		find("unk", "unknown", ""),
		find("dev", "dev-test", "capability.database.relational"),
	)
	rep := Run(c, []*Doc{d}, false)

	want := map[string]string{
		"req-covered":   "covered",
		"req-uncovered": "uncovered",
		"req-nohint":    "gap",
		"opt":           "gap",
		"unk":           "gap",
		"dev":           "ignored",
	}
	for dep, status := range want {
		row := findRow(rep, dep)
		if row == nil {
			t.Fatalf("no coverage row for %q", dep)
		}
		if row.Status != status {
			t.Errorf("%q: status = %q, want %q", dep, row.Status, status)
		}
	}
	// covered pins the concrete capability id.
	if r := findRow(rep, "req-covered"); r.Capability != "db" {
		t.Errorf("covered capability = %q, want db", r.Capability)
	}
	// uncovered is the only drift trigger here (optional/gap/dev do not drift).
	if !rep.Drift {
		t.Error("expected drift from the uncovered required finding")
	}
	if rep.Code != "survey-drift" || rep.Exit != 2 {
		t.Errorf("drift code/exit = %q/%d, want survey-drift/2", rep.Code, rep.Exit)
	}
}

// gaps and dev-test alone never drift.
func TestRunNoDriftWithoutUncoveredOrOrphan(t *testing.T) {
	c := contractWith("c1", map[string]map[string]any{
		"db": cap("capability.database.relational"),
	})
	d := doc("app", "sha", "",
		find("req-covered", "required", "capability.database.relational"),
		find("opt", "optional", ""),
		find("dev", "dev-test", ""),
	)
	rep := Run(c, []*Doc{d}, false)
	if rep.Drift {
		t.Errorf("unexpected drift: %+v", rep)
	}
	if rep.Code != "" || rep.Exit != 0 {
		t.Errorf("code/exit = %q/%d, want empty/0", rep.Code, rep.Exit)
	}
}

// A covered finding marks EVERY capability of that type witnessed, and the
// concrete id is the lexicographically-first (sorted) one.
func TestRunCoveredWitnessesAllOfType(t *testing.T) {
	c := contractWith("c1", map[string]map[string]any{
		"db-b": cap("capability.database.relational"),
		"db-a": cap("capability.database.relational"),
	})
	d := doc("app", "sha", "",
		find("mysql", "required", "capability.database.relational"))
	rep := Run(c, []*Doc{d}, false)
	if r := findRow(rep, "mysql"); r.Capability != "db-a" {
		t.Errorf("capability = %q, want db-a (sorted first)", r.Capability)
	}
	// D707: both are witnessed, so neither is drift — but a type-level finding
	// cannot say WHICH of the two this repo uses, and `--complete` is the mode an
	// operator runs to find a capability nobody uses. The report used to be silent
	// about exactly that case; it now says so, as information.
	repC := Run(c, []*Doc{d}, true)
	if repC.Drift {
		t.Error("unexpected drift: a type-level witness is real evidence, and " +
			"accusing every contract with two capabilities of one type would be " +
			"a confident accusation")
	}
	got := map[string]string{}
	for _, o := range repC.Orphans {
		got[o.Capability] = o.Status
	}
	for _, id := range []string{"db-a", "db-b"} {
		if got[id] != "witnessed-by-type" {
			t.Errorf("%s: status %q, want witnessed-by-type — one finding named the "+
				"TYPE, so neither capability was individually sighted", id, got[id])
		}
	}
}

// D707: with exactly ONE capability of the type, the witness is unambiguous and
// nothing extra is reported — the new row must not become noise on every contract.
func TestRunSingleCapabilityOfTypeIsNotAmbiguous(t *testing.T) {
	c := contractWith("c1", map[string]map[string]any{
		"db": cap("capability.database.relational"),
	})
	d := doc("app", "sha", "",
		find("mysql", "required", "capability.database.relational"))
	rep := Run(c, []*Doc{d}, true)
	if len(rep.Orphans) != 0 {
		t.Errorf("one capability of the type was witnessed directly; nothing is "+
			"ambiguous, got %+v", rep.Orphans)
	}
	if rep.Drift {
		t.Error("unexpected drift")
	}
}

// An unwitnessed capability is information (no drift) unless --complete.
func TestRunOrphanCompleteGate(t *testing.T) {
	c := contractWith("c1", map[string]map[string]any{
		"cache": cap("capability.cache.redis"),
	})
	d := doc("app", "sha", "") // no findings witness anything

	incomplete := Run(c, []*Doc{d}, false)
	if incomplete.Drift {
		t.Error("unwitnessed under !complete must not drift")
	}
	if len(incomplete.Orphans) != 1 || incomplete.Orphans[0].Status != "unwitnessed" {
		t.Fatalf("orphans = %+v, want one unwitnessed", incomplete.Orphans)
	}
	if incomplete.Orphans[0].Type != "capability.cache.redis" {
		t.Errorf("orphan type = %q", incomplete.Orphans[0].Type)
	}

	complete := Run(c, []*Doc{d}, true)
	if !complete.Drift || complete.Exit != 2 {
		t.Error("unwitnessed under --complete must drift with exit 2")
	}
	if complete.Orphans[0].Status != "orphaned" {
		t.Errorf("orphan status = %q, want orphaned", complete.Orphans[0].Status)
	}
	if !complete.Complete {
		t.Error("Complete flag not reflected in report")
	}
}

// Orphans are emitted in sorted capability-id order (determinism).
func TestRunOrphansSorted(t *testing.T) {
	c := contractWith("c1", map[string]map[string]any{
		"zeta":  cap("t"),
		"alpha": cap("t"),
		"mid":   cap("t"),
	})
	rep := Run(c, nil, false)
	got := []string{}
	for _, o := range rep.Orphans {
		got = append(got, o.Capability)
	}
	want := []string{"alpha", "mid", "zeta"}
	if len(got) != len(want) {
		t.Fatalf("orphans = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orphans = %v, want %v", got, want)
		}
	}
}

// Multiple surveys: sources recorded in order, coverage merged.
func TestRunMultiRepoSources(t *testing.T) {
	c := contractWith("c1", map[string]map[string]any{
		"db": cap("capability.database.relational"),
	})
	d1 := doc("app-a", "sha-a", "api",
		find("mysql", "required", "capability.database.relational"))
	d2 := doc("app-b", "sha-b", "worker",
		find("redis", "optional", ""))
	rep := Run(c, []*Doc{d1, d2}, false)

	if len(rep.Surveys) != 2 {
		t.Fatalf("surveys = %+v", rep.Surveys)
	}
	if rep.Surveys[0].Repo != "app-a" || rep.Surveys[0].Commit != "sha-a" ||
		rep.Surveys[0].Service != "api" {
		t.Errorf("survey[0] = %+v", rep.Surveys[0])
	}
	if rep.Surveys[1].Repo != "app-b" {
		t.Errorf("survey[1] = %+v", rep.Surveys[1])
	}
	// db is witnessed by app-a, so no orphan even under complete.
	repC := Run(c, []*Doc{d1, d2}, true)
	if repC.Drift {
		t.Errorf("db is witnessed; unexpected drift: %+v", repC)
	}
}

// Empty inputs: no findings, no capabilities -> clean, non-nil slices.
func TestRunEmpty(t *testing.T) {
	c := contractWith("c-empty", map[string]map[string]any{})
	rep := Run(c, nil, true)
	if rep.Contract != "c-empty" {
		t.Errorf("contract id = %q", rep.Contract)
	}
	if rep.Drift || rep.Exit != 0 {
		t.Errorf("empty must be clean, got drift=%v exit=%d", rep.Drift, rep.Exit)
	}
	if rep.Coverage == nil || rep.Orphans == nil {
		t.Error("Coverage/Orphans must be non-nil (empty) slices for JSON")
	}
	if len(rep.Coverage) != 0 || len(rep.Orphans) != 0 {
		t.Errorf("expected empty coverage/orphans: %+v", rep)
	}
}

// A capability whose doc has no "type" key degrades to an empty-string type
// rather than panicking, and can only be witnessed by an empty hint.
func TestRunCapabilityWithoutType(t *testing.T) {
	c := contractWith("c1", map[string]map[string]any{
		"weird": {}, // no "type"
	})
	rep := Run(c, nil, false)
	if len(rep.Orphans) != 1 || rep.Orphans[0].Type != "" {
		t.Fatalf("orphans = %+v, want one with empty type", rep.Orphans)
	}
}
