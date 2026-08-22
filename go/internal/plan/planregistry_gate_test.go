package plan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/apply"
	"groundhold/internal/compiler"
)

// D1171. The sealed plan is the document that gets EXECUTED, and its closed sets were
// held by nothing. Two gates here, both against the same principle: the loader must
// accept exactly what our own compiler emits, and every copy of a closed set must say
// the same thing.
//
// What that principle would have caught, all of it live when this was written:
//
//	`claim`             emitted by the compiler (D52 takeover), executed by apply,
//	                    rendered by planview — MISSING from the reference's operation
//	                    set and from the published prose. Our reference implementation
//	                    refused a plan our own compiler produces.
//	`pricingCatalog`    in the shipped example plan; read by nothing, anywhere.
//	`provider.region`   in the shipped example AND the prose, inside the block D28
//	                    calls the pinned identity. A reader consults a plan to learn
//	                    WHERE it will act and finds a region that pins nothing.
//	`blocked`,          emitted (D249/D388/D699/D1034), documented nowhere — two of
//	`unverified`,       them are CONSENTS, which is what someone auditing a plan for
//	`advisories`,       what was authorised goes looking for.
//	`fieldReclaim`,
//	`emissionAdopt`

// TestPlanKeySetsMatchWhatTheCompilerEmits derives the truth from the compiler's
// struct tags rather than restating it. A hand-typed list in a test is one more copy
// to drift, which is the defect this whole family is about.
func TestPlanKeySetsMatchWhatTheCompilerEmits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		typ   any
		known map[string]bool
	}{
		{"plan body", compiler.Body{}, planBodyKeys},
		{"action", compiler.Action{}, planActionKeys},
		{"reads", compiler.Reads{}, planReadsKeys},
		{"risk", compiler.Risk{}, planRiskKeys},
		{"change", compiler.Change{}, planChangeKeys},
		{"witness record", compiler.WitnessRecord{}, planWitnessKeys},
		{"precondition", compiler.Precondition{}, planPreconditionKeys},
		{"pinned provider", compiler.Provider{}, planProviderKeys},
		// D1172: the seven nested lists. They were admitted by NAME and never walked,
		// so their inner keys were as open as the whole document had been before
		// D1171 — inside the blocks that carry succession (`replaces`), operand
		// resolution (`references`), sealed literals (`folds`) and the D249 record
		// that stands between a held-back capability and being read as converged.
		{"replaces", compiler.ReplaceInfo{}, planReplacesKeys},
		{"reference", compiler.OperandRef{}, planReferenceKeys},
		{"fold", compiler.OperandFold{}, planFoldKeys},
		{"blocked capability", compiler.BlockedCapability{}, planBlockedKeys},
		{"unverified capability", compiler.UnverifiedCapability{}, planUnverifiedKeys},
		{"noop capability", compiler.NoOpCapability{}, planNoOpKeys},
		{"advisory", compiler.Advisory{}, planAdvisoryKeys},
	} {
		t.Run(tc.name, func(t *testing.T) {
			emitted := jsonTags(t, tc.typ)
			if len(emitted) == 0 {
				t.Fatal("the struct scan found NO json tags — the gate would compare " +
					"an empty set with an empty set and pass over anything (D328)")
			}
			accepted := sortedKeys(tc.known)
			if strings.Join(emitted, ",") != strings.Join(accepted, ",") {
				t.Errorf("the compiler emits\n  %v\nthis loader accepts\n  %v\n"+
					"A field emitted and not accepted makes our own compiler produce a "+
					"plan our own loader refuses; a field accepted and not emitted is a "+
					"key nothing writes and nothing reads, sitting in the document that "+
					"gets executed.", emitted, accepted)
			}
		})
	}
}

// TestTheOperationSetAgreesAcrossEveryCopy is the D1159 shape applied to the plan's
// other closed set. The operation decides which branch of apply runs, so a value one
// side does not recognize is not a formatting difference: it is a plan one
// implementation executes and the other calls malformed.
func TestTheOperationSetAgreesAcrossEveryCopy(t *testing.T) {
	sets := map[string][]string{
		"go/internal/plan/plan.go (Operations)":     sortedKeys(Operations),
		"ref/groundholdlib/plan.py (OPERATIONS)":    pyOperations(t),
		"spec/sealed-plan.md (the Operations rule)": specOperations(t),
	}

	names := make([]string, 0, len(sets))
	for n, v := range sets {
		if len(v) == 0 {
			t.Fatalf("%s parsed to ZERO operations — the scan lost its subject and "+
				"this gate would pass over anything (D328)", n)
		}
		names = append(names, n)
	}
	sort.Strings(names)

	want := sortedKeys(Operations)
	for _, n := range names {
		if strings.Join(sets[n], " ") != strings.Join(want, " ") {
			t.Errorf("%s publishes\n  %v\nthe runtime accepts\n  %v\n"+
				"An operation in one and not the other is a plan our compiler seals "+
				"and something downstream refuses to load.", n, sets[n], want)
		}
	}

	// The floor. Naming the members is not enough if the set could quietly shrink.
	if len(Operations) < 7 {
		t.Errorf("the operation set holds %d values; seven are published. A shrunken "+
			"set refuses a plan the compiler is right to emit.", len(Operations))
	}
}

// TestTheShippedExamplePlanLoads keeps the example this project publishes runnable
// from `go test`.
//
// CORRECTED (D1173): the first version of this comment said nothing had ever run the
// example through its own loader. That was false, and it was published. `examples/
// check.sh` has globbed `*.plan.yaml` and run `forecast` over each one — plus checked
// that the hashes it pins reproduce — since before D1171. The claim came from grepping
// for the FILENAME, which a glob does not contain: a negative grep taken as proof of
// absence.
//
// What was true is narrower and is the actual reason the drifts survived: the example
// LOADED, and loading admitted any key, so `pricingCatalog` and `provider.region` rode
// along unexamined. Loading is not scrutiny.
func TestTheShippedExamplePlanLoads(t *testing.T) {
	path := filepath.Join(repoRootFromTest(t), "spec", "examples", "plans",
		"orders-production.plan.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no shipped example plan in this tree: %v", err)
	}
	if _, err := LoadPlan(path); err != nil {
		t.Errorf("the example plan this project SHIPS does not load: %v\n"+
			"It is the document a reader copies to learn the execution IR. An example "+
			"nothing runs is not an example — it is prose that looks like a document.",
			err)
	}
}

func jsonTags(t *testing.T, v any) []string {
	t.Helper()
	rt := reflect.TypeOf(v)
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		out = append(out, strings.Split(tag, ",")[0])
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func repoRootFromTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "spec")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not find the repository root from the test's working directory")
	return ""
}

func readRepoFileForPlan(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{repoRootFromTest(t)}, parts...)...))
	if err != nil {
		t.Fatalf("reading %v: %v", parts, err)
	}
	return string(raw)
}

// pyOperations reads the `OPERATIONS = { ... }` literal out of the reference.
func pyOperations(t *testing.T) []string {
	t.Helper()
	raw := readRepoFileForPlan(t, "ref", "groundholdlib", "plan.py")
	m := regexp.MustCompile(`(?s)OPERATIONS = \{(.*?)\}`).FindStringSubmatch(raw)
	if m == nil {
		t.Fatal("could not find OPERATIONS in the reference implementation")
	}
	out := []string{}
	for _, v := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
		out = append(out, v[1])
	}
	sort.Strings(out)
	return out
}

// specOperations reads the members out of the published rule. They are backticked and
// bar-separated, and the members are taken from INSIDE the backticks on purpose: the
// sentence that follows names `claim` again while explaining it, and a scan that
// accepted the word would be satisfied by the paragraph about the word.
func specOperations(t *testing.T) []string {
	t.Helper()
	raw := readRepoFileForPlan(t, "spec", "sealed-plan.md")
	m := regexp.MustCompile("(?m)^- \\*\\*Operations\\*\\*: `([^`]+)`").FindStringSubmatch(raw)
	if m == nil {
		t.Fatal("could not find the Operations rule in spec/sealed-plan.md — it moved, " +
			"and this gate is reading nothing (D328)")
	}
	out := []string{}
	for _, w := range strings.Split(m[1], "|") {
		if w := strings.TrimSpace(w); w != "" {
			out = append(out, w)
		}
	}
	sort.Strings(out)
	return out
}

// TestAMisspelledActionKeyIsRefused is the enforcement itself, on the sharpest field.
// The registry gates above prove the copies agree; this proves the set is CONSULTED —
// a set everyone agrees on and nobody checks is the arrangement that lets a typo
// remove an edge from the graph apply executes.
func TestAMisspelledActionKeyIsRefused(t *testing.T) {
	const doc = `apiVersion: plan/v0
kind: SealedPlan
plan:
  contract: h1
  reads:
    contractHash: "sha256:c07bcf79091106cb2fc4b21306ae4a1f31fafe2134198a2e5c7bb6ac0c15a825"
    candidateHash: "sha256:eb5959117c0065812904b828078b0b1672bf6e99e7d2b724529b8ff61a1df2b8"
    heads: { db: genesis }
    toolchain: { compiler: groundhold-ref/0.1, spec: contract/v0.1 }
  writes: [db]
  actions:
    - id: a-create
      capability: db
      operation: create
      target: cloudsql.instance/primary
      idempotencyKey: db-create-1
      %s
      risk:
        reversibility: R2
        dataLoss: none
        downtime: none
        securityExposure: none
        costDelta: { amount: 0, currency: EUR }
        identityReplacement: false
  preconditions:
    - type: report-executable
`
	write := func(t *testing.T, field string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "p.yaml")
		if err := os.WriteFile(p, []byte(strings.Replace(doc, "%s", field, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// The control first: without it, a refusal below could mean the fixture is simply
	// malformed and this would be a gate over nothing (D328).
	if _, err := LoadPlan(write(t, "dependsOn: []")); err != nil {
		t.Fatalf("the well-formed fixture does not load, so the refusals below prove "+
			"nothing: %v", err)
	}
	if _, err := LoadPlan(write(t, `x-note: "not runtime data"`)); err != nil {
		t.Errorf("the `x-` escape was refused: %v — a plan is a document a reader "+
			"copies, and every other document here honours the hatch", err)
	}

	for _, bad := range []string{"dependson: []", "depends_on: []", "requiredPermission: []"} {
		_, err := LoadPlan(write(t, bad))
		if err == nil {
			t.Errorf("action key %q was ACCEPTED. `dependsOn` is read optionally, so "+
				"this is not a typo — it reads as `no dependencies`, and apply trusts "+
				"the graph verbatim for both the execution order and fail-isolation. "+
				"A D48 replace would destroy before it created.", bad)
			continue
		}
		if !strings.Contains(err.Error(), "unknown key") {
			t.Errorf("the refusal for %q says %q — it must name the key, or an author "+
				"cannot tell a typo from a malformed document", bad, err.Error())
		}
	}
}

// TestAMisspelledKeyInsideANestedBlockIsRefused is D1172's enforcement. The gate above
// proves the sets match what the compiler emits; this proves they are CONSULTED at the
// levels D1171 admitted by name and never walked.
//
// The subject is a REAL shipped fixture rather than a hand-typed document, because the
// question "does the loader walk this list" is only answerable over a document that
// actually has one — `conformance/testdata/show-four-ops.plan.json` carries both
// `replaces` and `references`. A synthetic fixture would let the walk quietly find
// nothing and this would pass over an empty list (D328).
func TestAMisspelledKeyInsideANestedBlockIsRefused(t *testing.T) {
	root := repoRootFromTest(t)
	raw, err := os.ReadFile(filepath.Join(root, "conformance", "testdata",
		"show-four-ops.plan.json"))
	if err != nil {
		t.Skipf("no four-ops fixture in this tree: %v", err)
	}

	load := func(t *testing.T, mutate func(map[string]any)) error {
		t.Helper()
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("the fixture does not parse: %v", err)
		}
		mutate(doc)
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "p.json")
		if err := os.WriteFile(p, out, 0o600); err != nil {
			t.Fatal(err)
		}
		_, lerr := LoadPlan(p)
		return lerr
	}

	// actionsWith finds the first action carrying `key` and hands it to f. It FAILS
	// when there is none: the fixture is the vacuity floor here, so a fixture that
	// stopped carrying these blocks must break this test rather than pass it.
	actionsWith := func(t *testing.T, doc map[string]any, key string, f func(map[string]any)) {
		t.Helper()
		body, _ := doc["plan"].(map[string]any)
		acts, _ := body["actions"].([]any)
		for _, it := range acts {
			a, _ := it.(map[string]any)
			if _, ok := a[key]; ok {
				f(a)
				return
			}
		}
		t.Fatalf("no action in the fixture carries %q — this test would be walking an "+
			"empty list and reporting that as proof (D328)", key)
	}

	t.Run("the fixture loads untouched", func(t *testing.T) {
		if err := load(t, func(map[string]any) {}); err != nil {
			t.Fatalf("the clean fixture does not load, so every refusal below proves "+
				"nothing: %v", err)
		}
	})

	t.Run("replaces", func(t *testing.T) {
		err := load(t, func(doc map[string]any) {
			actionsWith(t, doc, "replaces", func(a map[string]any) {
				rep := a["replaces"].(map[string]any)
				rep["providerid"] = rep["providerId"]
				delete(rep, "providerId")
			})
		})
		if err == nil {
			t.Error("a misspelled `providerId` inside `replaces` was ACCEPTED. apply " +
				"builds the binding's `lineage.replaces` from that field and nothing " +
				"else, so the record of what this resource SUCCEEDED is dropped — the " +
				"question an audit and a capsule are read for.")
		} else if !strings.Contains(err.Error(), "providerid") {
			t.Errorf("the refusal does not name the key: %v", err)
		}
	})

	t.Run("references", func(t *testing.T) {
		err := load(t, func(doc map[string]any) {
			actionsWith(t, doc, "references", func(a map[string]any) {
				ref := a["references"].([]any)[0].(map[string]any)
				ref["slott"] = ref["slot"]
				delete(ref, "slot")
			})
		})
		if err == nil {
			t.Error("a misspelled `slot` inside `references` was ACCEPTED — a " +
				"reference resolves an operand from another action's receipt at apply " +
				"(D226), so this is an operand silently unresolved in the document " +
				"that gets executed")
		}
	})

	t.Run("the x- escape still works inside a nested block", func(t *testing.T) {
		if err := load(t, func(doc map[string]any) {
			actionsWith(t, doc, "replaces", func(a map[string]any) {
				a["replaces"].(map[string]any)["x-note"] = "an author's marker"
			})
		}); err != nil {
			t.Errorf("the hatch was refused inside a nested block: %v — it is the same "+
				"hatch at every other level of every other document here", err)
		}
	})
}

// TestTheOperationSetIsClassifiedByBehaviour is D1174, and it is a correction to the
// gate above as much as an addition.
//
// `TestTheOperationSetAgreesAcrossEveryCopy` (D1171) holds three copies of
// `Operations` in agreement with EACH OTHER. That caught a real defect — `claim` was
// missing from two of them — and it also froze three members nothing has ever emitted
// and nothing can execute. Agreement is not correctness: three artefacts can say the
// same wrong thing, and a gate that only compares them will keep them saying it.
//
// D1171 derived the plan's KEY sets from what the compiler emits and then, in the same
// slice, held the OPERATION set to inter-copy agreement instead. This applies the same
// principle to the axis that was missed: what the executor can apply is a fact about
// behaviour, and every member of the accepted set must be classified as one this
// executor applies or one it only loads — with the second list carrying its reasons in
// the source, where a reader meets them.
func TestTheOperationSetIsClassifiedByBehaviour(t *testing.T) {
	// Every accepted operation is either applied or declared load-only. A new member
	// cannot join `Operations` without someone deciding which it is.
	for op := range Operations {
		applied := apply.SupportedOperations[op]
		loadOnly := LoadOnlyOperations[op]
		switch {
		case applied && loadOnly:
			t.Errorf("%q is declared both applied and load-only — the two lists must "+
				"partition the accepted set, or neither says anything", op)
		case !applied && !loadOnly:
			t.Errorf("%q is accepted by the loader, applied by nothing, and declared "+
				"nowhere. A closed set the executor cannot honour invites a producer "+
				"to write an action we turn away — say which it is in "+
				"LoadOnlyOperations, with the reason.", op)
		}
	}

	// The other direction: an operation the executor implements and the loader refuses
	// is a branch no document can reach.
	for op := range apply.SupportedOperations {
		if !Operations[op] {
			t.Errorf("the executor applies %q and this loader REFUSES it — a plan "+
				"carrying it never reaches the branch that would run it", op)
		}
	}

	// Floors. Both sets must be non-empty and the applied set must not have quietly
	// become the whole accepted set (which would make the partition vacuous).
	if len(apply.SupportedOperations) == 0 || len(LoadOnlyOperations) == 0 {
		t.Fatal("one of the two sets is EMPTY, so the partition above compares nothing " +
			"(D328)")
	}
	if len(apply.SupportedOperations)+len(LoadOnlyOperations) != len(Operations) {
		t.Errorf("applied(%d) + load-only(%d) != accepted(%d) — the classification has "+
			"drifted from the set it classifies",
			len(apply.SupportedOperations), len(LoadOnlyOperations), len(Operations))
	}
}

// TestTheRefusalNamesWhatTheExecutorActuallyApplies pins the sentence a user reads to
// the set the switch implements. It used to be typed by hand in the error itself, and
// it was the ONLY artefact in the project that named the four correctly — correct by
// luck, with nothing to keep it so.
func TestTheRefusalNamesWhatTheExecutorActuallyApplies(t *testing.T) {
	got := apply.SupportedOperationList()
	for op := range apply.SupportedOperations {
		if !strings.Contains(got, op) {
			t.Errorf("the refusal says %q and does not name %q, which the executor "+
				"applies — a user told the wrong set reconciles the wrong thing", got, op)
		}
	}
	for op := range LoadOnlyOperations {
		if strings.Contains(got, op) {
			t.Errorf("the refusal says %q, which names %q — an operation this executor "+
				"REFUSES. Naming it as supported is the advice failure the message "+
				"exists to prevent.", got, op)
		}
	}
}

// TestSupportedOperationsMatchTheExecutorsBranches closes the hole the previous gate
// left, and the hole was found by mutating it: moving `replace` from LoadOnly into
// SupportedOperations kept the partition perfectly consistent and the gate passed. A
// self-consistent classification can still be a lie about what the code does.
//
// This reads the SWITCH — the implementation — rather than the list beside it. That is
// a structural check, not a behavioural one, and the difference matters enough to name:
// D317's lesson is that a static scrape of an implementation is not the same as asking
// it. Asking means applying a one-action plan per operation and looking for
// `unsupported-operation`.
//
// That debt is PAID (D1177):
// `apply.TestTheExecutorReallyAppliesWhatItDeclares` does exactly that, and it catches
// what this scan cannot — a branch that exists and falls through, a branch guarded by a
// condition that is never true, a refusal routed to the wrong code. This check stays
// because it is cheap and it fails on a different thing: a name in the list with no
// branch at all, which the behavioural gate reports as a refusal rather than as a
// missing branch. Two failures, two messages, one for each way the two can disagree.
//
// What it does catch is the drift that actually happened here — a name in the list with
// no branch behind it, or a branch quietly removed while the list still promises it.
func TestSupportedOperationsMatchTheExecutorsBranches(t *testing.T) {
	src := readRepoFileForPlan(t, "go", "internal", "apply", "apply.go")

	// The vacuity floor first: this scan must find the switch it thinks it is reading.
	// A rename would otherwise leave every assertion below trivially true (D328).
	found := 0
	for op := range apply.SupportedOperations {
		if strings.Contains(src, "\t\tcase \""+op+"\":") {
			found++
		}
	}
	if found == 0 {
		t.Fatal("no `case \"<operation>\":` branch was found in apply.go at all — the " +
			"scan lost its subject, and every check below would pass over anything")
	}

	for op := range apply.SupportedOperations {
		if !strings.Contains(src, "\t\tcase \""+op+"\":") {
			t.Errorf("the executor DECLARES it applies %q and has no branch for it. The "+
				"refusal message is derived from this set, so a user is told an "+
				"operation is supported and then meets the default branch.", op)
		}
	}
	for op := range LoadOnlyOperations {
		if strings.Contains(src, "\t\tcase \""+op+"\":") {
			t.Errorf("%q is declared load-only and the executor HAS a branch for it — "+
				"either it is applied after all (move it, and say so in the spec) or "+
				"that branch is unreachable code wearing a real name", op)
		}
	}
}
