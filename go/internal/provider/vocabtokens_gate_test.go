package provider_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
	"groundhold/internal/k8s"
)

// D669. `mappings:` keys are `<provider>.<service-token>`, and the existing gate
// splits on the dot and keeps only the PREFIX — so `aws.wafv2`, `azure.portal` and
// `gcp.speechtotext` all satisfied it whether or not those tokens exist. The token
// half is the part D534 treats as authoritative: it names WHICH driver service
// realises the capability, and an operator following it writes that service into a
// candidate.
//
// Measured against the drivers themselves: of 155 distinct (capability, cloud key)
// pairs, 48 name a token that does not serve that capability — 8 of them name a
// token that serves a DIFFERENT one (`capability.monitoring.uptime → aws.route53`,
// which is `capability.dns.zone`; the uptime token is `route53health`).
//
// The harm is a wasted round trip rather than a wrong action: following the
// published mapping gives `preflight exit 2` with "attribute check.path has no
// Route 53 mapping". Loud, not silent — which is why this is a ratchet rather than
// a hard zero. The number can only fall.
const (
	// The count when this gate was written was 50, of which 8 named ANOTHER
	// capability's real token. The 8 are fixed — those are the ones that send an
	// operator to a service that exists and does the wrong thing — so the
	// cross-capability baseline is ZERO and stays there.
	//
	// D702 took the rest from 42 to 11 by asking the drivers what each capability's
	// token actually IS and renaming the key to it: `aws.backup` -> `aws.backupplan`,
	// `gcp.pubsub` -> `gcp.pubsub-queue`, `azure.monitor` -> `azure.metricalert`, and
	// 28 more. Every rename was verified against ServiceCapabilities(), never guessed.
	//
	// The 11 that remain are NOT the same kind of debt, and this is why the number
	// stops here rather than at zero. They sit on two capability types that NO driver
	// builds — `capability.ai.speech` (aws/gcp/azure all `unbuilt`) and
	// `capability.identity.sso` (gcp/azure unbuilt) — so there is no real token to
	// rename them to. `explain` already answers UNBUILT for such a type (D691), which
	// is the honest reading of those lines: a design intent, not a route an operator
	// can take. They come down when a driver does, and the number may only FALL.
	vocabTokenMissingBaseline = 11 // token does not serve this capability
	vocabTokenCrossBaseline   = 0  // token serves a DIFFERENT capability (subset)
)

func TestVocabularyMappingsNameARealServiceToken(t *testing.T) {
	root := repoRoot(t)

	// what the DRIVERS say: provider -> token -> capability type (D317: ask them)
	serves := map[string]map[string]string{}
	for prov, m := range map[string]map[string]string{
		"aws":   aws.NewDriver("eu-central-1").ServiceCapabilities(),
		"gcp":   gcp.NewDriver("p").ServiceCapabilities(),
		"azure": azure.NewDriver("00000000-0000-0000-0000-000000000001").ServiceCapabilities(),
		"k8s":   k8s.NewDriver("https://example.invalid", "t").ServiceCapabilities(),
	} {
		serves[prov] = m
	}
	total := 0
	for _, m := range serves {
		total += len(m)
	}
	if total < 100 {
		t.Fatalf("the four drivers report only %d service tokens between them — the "+
			"probe is broken and this gate would pass on anything", total)
	}

	files, err := filepath.Glob(filepath.Join(root, "spec", "vocab", "*.yaml"))
	if err != nil || len(files) < 40 {
		t.Fatalf("read %d vocabulary files (%v) — this gate would be vacuous",
			len(files), err)
	}

	pairs := map[string]bool{} // capability|key, deduped across attributes
	var missing, cross []string
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Capability string                            `yaml:"capability"`
			Attributes map[string]map[string]interface{} `yaml:"attributes"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("vocabulary %s is unparseable: %v", filepath.Base(f), err)
		}
		if doc.Capability == "" {
			continue
		}
		for _, spec := range doc.Attributes {
			m, _ := spec["mappings"].(map[string]interface{})
			for k := range m {
				prov, token, ok := strings.Cut(k, ".")
				if !ok {
					continue // a bare provider key names no token to check
				}
				byToken, known := serves[prov]
				if !known {
					continue // cloudflare/google/okta: honest "no driver here" markers
				}
				if pairs[doc.Capability+"|"+k] {
					continue
				}
				pairs[doc.Capability+"|"+k] = true
				got, exists := byToken[token]
				switch {
				case exists && got == doc.Capability:
					// the mapping is exactly right
				case exists:
					cross = append(cross, doc.Capability+" -> "+k+" (that token is "+got+")")
					missing = append(missing, doc.Capability+" -> "+k)
				default:
					missing = append(missing, doc.Capability+" -> "+k+" (no such token)")
				}
			}
		}
	}
	sort.Strings(missing)
	sort.Strings(cross)

	if len(pairs) < 100 {
		t.Fatalf("only %d cloud mapping pairs found — the parse broke and a shrinking "+
			"subject is not a passing gate (D328)", len(pairs))
	}
	if len(missing) > vocabTokenMissingBaseline {
		t.Errorf("%d mappings name a token that does not serve their capability "+
			"(baseline %d) — the count may only FALL:\n  %s",
			len(missing), vocabTokenMissingBaseline, strings.Join(missing, "\n  "))
	}
	if len(cross) > vocabTokenCrossBaseline {
		t.Errorf("%d mappings name a token that serves a DIFFERENT capability "+
			"(baseline %d):\n  %s", len(cross), vocabTokenCrossBaseline,
			strings.Join(cross, "\n  "))
	}
	// A ratchet that never tightens is a baseline nobody lowers. Say the slack out
	// loud so the next author sees the number moving.
	t.Logf("mapping tokens: %d pairs, %d not serving their capability (%d of those "+
		"naming another capability's token); baselines %d/%d",
		len(pairs), len(missing), len(cross),
		vocabTokenMissingBaseline, vocabTokenCrossBaseline)
}
