package provider_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
	"groundhold/internal/k8s"
	"groundhold/internal/provider"
	"groundhold/internal/vocab"
)

// D682. An enum value that NO serving driver accepts is a promise the vocabulary
// makes and cannot keep: a contract can hard-constrain it and no candidate can ever
// satisfy it. An audit found `availability.class: multi-regional` refused by all
// three services on `capability.database.nosql` and all four on
// `capability.cache.keyvalue`, and `dns.proxied` refused by every serving driver
// for BOTH of its values — the one attribute in 340 where no value at all is
// acceptable to anyone.
//
// The drivers are ASKED, through the refuse-before-mutate hook they already
// implement (D317: never scrape). The count is a ratchet — it may only fall — and
// it is logged every run so the number is visible rather than buried in a constant.
// Eleven today, listed by the gate on every run. They are NOT removed here: each
// is a spec decision about whether the value is unbuilt-but-intended or a mistake,
// and deleting an enum member changes what a published vocabulary means. The
// ratchet makes the number visible and stops it growing.
const deadEnumValueBaseline = 11

func TestNoVocabularyEnumValueIsDeadEverywhere(t *testing.T) {
	vocabs, err := vocab.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(vocabs) < 40 {
		t.Fatalf("only %d vocabularies — this gate is measuring nothing", len(vocabs))
	}

	type drv struct {
		name string
		p    provider.Provider
	}
	drivers := []drv{
		{"aws", aws.NewDriver("eu-central-1")},
		{"gcp", gcp.NewDriver("p")},
		{"azure", azure.NewDriver("00000000-0000-0000-0000-000000000001")},
		{"k8s", k8s.NewDriver("https://example.invalid", "t")},
	}
	// capability type -> the (driver, service) pairs that claim to realise it
	serving := map[string][]struct {
		drv drv
		svc string
	}{}
	for _, d := range drivers {
		sc, ok := d.p.(interface{ ServiceCapabilities() map[string]string })
		if !ok {
			t.Fatalf("%s no longer reports its service capabilities", d.name)
		}
		for svc, capType := range sc.ServiceCapabilities() {
			serving[capType] = append(serving[capType], struct {
				drv drv
				svc string
			}{d, svc})
		}
	}
	if len(serving) < 20 {
		t.Fatalf("only %d capability types are served — the probe is broken", len(serving))
	}

	probes := 0
	var dead []string
	for capType, voc := range vocabs {
		pairs := serving[capType]
		if len(pairs) == 0 {
			continue // an unimplemented capability is a different finding (D682 note)
		}
		for path, spec := range voc.Attributes {
			enum, ok := spec["enum"].([]any)
			if !ok || len(enum) == 0 {
				continue
			}
			for _, v := range enum {
				// A refusal only counts as EVIDENCE about this value when it
				// differs from what the same service says with no attributes at
				// all. Otherwise the driver is refusing something else — a missing
				// operand, an unsupported service — and reading that as "this value
				// is dead" would turn an incomplete probe into a finding. The first
				// version of this gate did exactly that and reported 76 dead values,
				// including all three members of enums that plainly work.
				evidence, accepted := false, false
				for _, p := range pairs {
					probes += 2 // the baseline call and the probed one
					base := p.drv.p.Validate(p.svc, capType, "test",
						map[string]any{}, map[string]any{}, 1)
					err := p.drv.p.Validate(p.svc, capType, "test",
						map[string]any{path: v}, map[string]any{}, 1)
					if err == nil {
						accepted = true
						break
					}
					if base == nil || err.Error() != base.Error() {
						evidence = true
					}
				}
				if !accepted && evidence {
					dead = append(dead, capType+" "+path+" = "+toStr(v))
				}
			}
		}
	}
	sort.Strings(dead)
	if probes < 400 {
		t.Fatalf("only %d validate probes ran — the sweep collapsed and a shrinking "+
			"subject is not a passing gate (D328)", probes)
	}
	if len(dead) > deadEnumValueBaseline {
		t.Errorf("%d enum value(s) are refused by EVERY driver that serves their "+
			"capability (baseline %d) — a contract can require them and no candidate "+
			"can ever satisfy them:\n  %s", len(dead), deadEnumValueBaseline,
			strings.Join(dead, "\n  "))
	}
	t.Logf("%d validate probes, %d dead enum values (baseline %d)",
		probes, len(dead), deadEnumValueBaseline)
}

func toStr(v any) string { return fmt.Sprint(v) }
