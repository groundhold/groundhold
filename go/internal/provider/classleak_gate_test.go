package provider_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// D875. deny-audit.sh is a maintained NAME denylist, and this session shipped proof
// that a name nobody added is a name nobody catches: `acme` (the second field tester)
// rode into the export as an example AWS profile because the denylist had no entry for
// it. class-leak-scan.sh is the backstop that does not depend on the list being
// complete — it detects a real AWS ACCOUNT ID by its ARN shape, a class no denylist
// entry could ever cover, because an account id is a number and a denylist holds names.
//
// This gate does two things at the price of one grep: it drives the scanner with an
// INVENTED account id to prove the control fires (a positive control, the discipline of
// denyaudit_gate_test), and it runs the scanner over the real tree so a real account id
// committed in an ARN fails `make check` at the desk, not months later at export time.
func TestClassLeakScanBacksTheDenylist(t *testing.T) {
	skipIfExported(t, "the export scripts")
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "class-leak-scan.sh")
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("the class-leak backstop is gone: %v — the export would then rest on the "+
			"name denylist alone, which acme proved can be incomplete", err)
	}

	run := func(t *testing.T, dir string) int {
		t.Helper()
		cmd := exec.Command("bash", script, dir)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		t.Logf("%s", out)
		return code
	}

	// Positive control: a real-SHAPED account id in an ARN. It is ASSEMBLED from two
	// fragments so no 12-digit ARN literal sits in this source file — otherwise the
	// "working tree is clean" scan below would flag the gate's own test data. Invented,
	// not a real account and not a placeholder.
	t.Run("a real-shaped account id in an ARN is caught", func(t *testing.T) {
		dir := t.TempDir()
		arn := "arn:aws:iam::" + "349281" + "047163" + ":role/x"
		os.WriteFile(filepath.Join(dir, "x.tf"), []byte(`role_arn = "`+arn+`"`), 0o600)
		if run(t, dir) == 0 {
			t.Error("an account id in an ARN was passed — the backstop does not fire")
		}
	})

	// A placeholder account id in an ARN is a fixture, not a leak: it must pass, or every
	// driver test's `000000000000` ARN would break the export.
	t.Run("a placeholder account id in an ARN passes", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "x.go"),
			[]byte(`const a = "arn:aws:sns:eu-central-1:000000000000:topic"`), 0o600)
		if run(t, dir) != 0 {
			t.Error("a placeholder-account ARN was refused — the allowlist is not working")
		}
	})

	// A 12-digit duration and a hash substring must NOT read as account ids — the shapes
	// the first calibration pass tripped on, pinned so a future widening reintroduces them.
	t.Run("a bare 12-digit run is not an account id", func(t *testing.T) {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "x.go"),
			[]byte("retentionPeriod = \"315360000000\"\nhash = \"deadbeef247812867374\""), 0o600)
		if run(t, dir) != 0 {
			t.Error("a bare 12-digit number was read as an account id — false positive")
		}
	})

	// The live gate: the tree as it stands carries no real account id in an ARN.
	t.Run("the working tree is clean", func(t *testing.T) {
		if run(t, root) != 0 {
			t.Error("a real account id in an ARN is committed — scrub it before it exports")
		}
	})
}
