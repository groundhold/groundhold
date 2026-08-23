package provider_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// D1241. A delete that leaves the resource RECOVERABLE has succeeded in a weaker sense
// than the word suggests, and the reader — often an agent — decides what to do next
// from that word.
//
// The codebase already knew this. `CreateResult{Status: "succeeded"}` carries a Reason
// in exactly the places where the success is qualified: AWS KMS's pending window, GCP's
// custom-role undelete window, Azure's key-vault soft delete, an ECS retire that left a
// shared cluster standing. Twelve such Reasons, against six hundred bare successes —
// and the bare ones are right, because most successes mean what they say.
//
// Two did not. AWS Secrets Manager asked for `RecoveryWindowInDays: 7` and reported a
// bare success; the Azure secret vault is created with `enableSoftDelete: true` and its
// delete reported a bare success, while the vault for capability.key.encryption — the
// same shape, one file over — disclosed it.
//
// This gate is over the CLASS: any delete that asks the provider for a recovery window
// must say so in its result. It reads source because the property is which call site
// carries which literal; the behaviour is witnessed in the driver packages.
func TestARecoverableDeleteSaysTheResourceIsStillThere(t *testing.T) {
	root := filepath.Join("..", "..", "internal")
	// The parameters a driver passes to ASK for a recoverable delete. Each is a
	// provider's own name for "keep this around".
	recoveryParams := []string{
		"RecoveryWindowInDays", // AWS Secrets Manager
		"PendingWindowInDays",  // AWS KMS
	}
	// Drivers that CREATE with soft-delete on: their deletes leave a recoverable
	// resource even though the delete call itself names no window.
	softDeleteCreators := map[string]string{
		"azure/secret_kv_net.go": "azure/secret_kv.go",
		"azure/key_azure_net.go": "azure/key_azure.go",
	}

	// What this gate can and cannot do, stated because the first cut got it wrong.
	//
	// It checked whether the FILE mentions "recoverable" anywhere — and the mutants
	// that stripped the disclosure from BOTH drivers survived it, because the comment
	// explaining the fix still contained the word. A gate satisfied by the prose about
	// the thing is not a gate on the thing (D1225's marker rule, met again).
	//
	// Source cannot tell whether a sentence reaches the RESULT. So this is a
	// completeness check over the CLASS — every site that asks for a recovery window,
	// or whose create turns soft-delete on, must have a BEHAVIOURAL witness — and the
	// witnesses do the proving.
	witnesses := map[string]string{
		"aws/secretsmanager_net.go": "TestDeletingASecretSaysItIsStillRestorable",
		"aws/kms_aws_net.go":        "TestSchedulingAKeyForDeletionSaysSo",
		"azure/secret_kv_net.go":    "TestDeletingTheSecretVaultSaysItIsStillRecoverable",
		"azure/key_azure_net.go":    "TestDeletingTheKeyVaultSaysItIsStillRecoverable",
	}
	var bare []string
	sites := 0
	check := func(rel, src, why string) {
		sites++
		name, known := witnesses[rel]
		if !known {
			bare = append(bare, rel+" ("+why+") — a recoverable delete with no witness named "+
				"in this gate")
			return
		}
		if !testExistsIn(t, filepath.Dir(filepath.Join(root, rel)), name) {
			bare = append(bare, rel+" ("+why+") — witness "+name+" is missing")
		}
	}

	for _, pkg := range []string{"aws", "gcp", "azure"} {
		dir := filepath.Join(root, pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			blob, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				t.Fatalf("read %s/%s: %v", pkg, n, err)
			}
			src := string(blob)
			rel := pkg + "/" + n
			for _, p := range recoveryParams {
				// the PARAMETER being sent, not merely mentioned in prose
				if regexp.MustCompile(`"`+p+`"\s*:`).MatchString(src) ||
					strings.Contains(src, p+`":%d`) || strings.Contains(src, p+`":7`) {
					check(rel, src, "sends "+p)
					break
				}
			}
			if creator, ok := softDeleteCreators[rel]; ok {
				cblob, err := os.ReadFile(filepath.Join(root, creator))
				if err != nil {
					t.Fatalf("read %s: %v", creator, err)
				}
				if strings.Contains(string(cblob), `"enableSoftDelete":        true`) ||
					strings.Contains(string(cblob), `"enableSoftDelete": true`) {
					check(rel, src, "its create sets enableSoftDelete")
				}
			}
		}
	}

	// D328: the scan must have a subject. If no driver asks for a recovery window any
	// more, this gate is watching nothing and should be retired deliberately.
	if sites < 3 {
		t.Fatalf("found only %d recoverable-delete sites — the scan is broken, or the "+
			"drivers stopped asking for recovery windows and this gate should be retired",
			sites)
	}
	sort.Strings(bare)
	if len(bare) > 0 {
		t.Errorf("%d recoverable-delete site(s) have no behavioural witness:\n  %s\n\n"+
			"The resource still exists and can be restored; \"succeeded\" alone tells the "+
			"reader it is gone. Add the disclosure to the CreateResult's Reason AND a test "+
			"that asserts it — this gate reads source and cannot tell prose from an emission.",
			len(bare), strings.Join(bare, "\n  "))
	}
}

// testExistsIn reports whether any _test.go in dir declares the named test.
func testExistsIn(t *testing.T, dir, name string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if strings.Contains(string(blob), "func "+name+"(") {
			return true
		}
	}
	return false
}
