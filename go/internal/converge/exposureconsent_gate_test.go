package converge

import (
	"bytes"
	"strings"
	"testing"
)

// D630. D628 made `securityExposure: certain` derivable — a boolean security attribute
// weakened, or public access switched on. Nothing consumed it. `converge`'s consent
// gate read exactly `dataLoss == "certain" || identityReplacement`, so an update that
// turns `network.publicExposure` ON rode through on plain `--yes`, and the line the
// operator read before consenting did not even print the field.
//
// It is a separate flag rather than a fold into `--allow-data-loss`: the two are
// different harms, and a consent flag whose name does not describe what it permits is
// not consent.
func TestAPlanThatOpensSomethingUpNeedsItsOwnConsent(t *testing.T) {
	planWith := func(exposure, dataLoss string) string {
		return `{"plan":{"actions":[{"id":"a1","operation":"update","risk":{` +
			`"reversibility":"R1","dataLoss":"` + dataLoss + `","downtime":"possible",` +
			`"securityExposure":"` + exposure + `","identityReplacement":false}}]}}`
	}
	run := func(planBody string, opts Options) (int, string) {
		var out bytes.Buffer
		o := opts
		o.Contract, o.Candidate, o.At = "c", "k", "2026-01-01T00:00:00Z"
		o.Out = &out
		o.Run = func(args ...string) (int, string, string) {
			switch args[0] {
			case "verify":
				return 0, `{"verdicts":[]}`, ""
			case "plan":
				return 0, planBody, ""
			case "forecast":
				return 0, `{"forecast":{"rollup":{}}}`, ""
			case "apply":
				return 0, `{"status":"applied","outcomes":[]}`, ""
			}
			return 0, "", ""
		}
		return Converge(o), out.String()
	}

	t.Run("certain exposure refuses under plain --yes", func(t *testing.T) {
		code, out := run(planWith("certain", "none"), Options{Yes: true})
		if code == 0 {
			t.Errorf("a plan that provably increases exposure applied under --yes:\n%s",
				out)
		}
	})

	t.Run("the operator sees the field before consenting", func(t *testing.T) {
		_, out := run(planWith("certain", "none"), Options{Yes: true})
		if !strings.Contains(out, "exposure=") {
			t.Errorf("the per-action line omits securityExposure — the operator is "+
				"asked to consent to something the summary does not mention:\n%s", out)
		}
	})

	t.Run("--allow-exposure is the consent that covers it", func(t *testing.T) {
		code, out := run(planWith("certain", "none"),
			Options{Yes: true, AllowExposure: true})
		if code != 0 {
			t.Errorf("explicit consent did not cover the exposure: exit %d\n%s", code, out)
		}
	})

	t.Run("--allow-data-loss does not cover exposure", func(t *testing.T) {
		code, _ := run(planWith("certain", "none"),
			Options{Yes: true, AllowDataLoss: true})
		if code == 0 {
			t.Error("a data-loss consent silently covered a security exposure — a flag " +
				"whose name does not describe what it permits is not consent")
		}
	})

	t.Run("possible exposure does not gate", func(t *testing.T) {
		code, out := run(planWith("possible", "none"), Options{Yes: true})
		if code != 0 {
			t.Errorf("`possible` is the honest default for an underivable change "+
				"(D628); gating on it would ask for consent on every update: exit %d\n%s",
				code, out)
		}
	})
}
