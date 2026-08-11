package policy

import (
	"testing"

	"groundhold/internal/vocab"
)

// D664. `stateful:` is what arms `autonomy.forbidden: [delete_stateful]`, and
// `StatefulOf` reads that flag and nothing else. `capability.cluster.namespace` was
// marked `stateful: false` with a comment claiming "a namespace with live workloads
// is a cascade the delete gate still guards". Measured: the plan SEALED an
// `a-delete-ns` action with `"dataLoss": "none"` under a contract forbidding
// delete_stateful, while the k8s driver issues `DELETE /api/v1/namespaces/<name>` —
// which the API server cascades to every namespaced object, PVCs included.
//
// The flag is a hand-written claim, so the ones whose deletion destroys OTHER
// capabilities' resources are named here, once, and checked against the shipped
// vocabulary. A new cascading kind has one place to be declared instead of relying
// on whoever writes the file remembering what a cascade is.
var cascadingCapabilities = map[string]string{
	"capability.cluster.namespace": "deleting a namespace cascades to every " +
		"namespaced object in it — workloads, secrets, PersistentVolumeClaims",
}

func TestACascadingDeleteIsMarkedStateful(t *testing.T) {
	vocabs, err := vocab.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(vocabs) < 40 {
		t.Fatalf("only %d vocabularies — this gate is measuring nothing (D328)",
			len(vocabs))
	}
	for typ, why := range cascadingCapabilities {
		voc, ok := vocabs[typ]
		if !ok {
			t.Errorf("%s is named as cascading and has no vocabulary — one of the "+
				"two moved", typ)
			continue
		}
		if !voc.Stateful {
			t.Errorf("%s is stateful: false, so autonomy.forbidden[delete_stateful] "+
				"does not stop its deletion. %s", typ, why)
		}
	}
}

// The control: the flag must still be able to be false. A gate that demanded
// `stateful: true` everywhere would make the consent gate fire on every retirement
// and teach operators to pass --allow-data-loss by reflex.
func TestStatelessCapabilitiesStillExist(t *testing.T) {
	vocabs, err := vocab.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	stateless := 0
	for _, voc := range vocabs {
		if !voc.Stateful {
			stateless++
		}
	}
	if stateless < 10 {
		t.Errorf("only %d stateless capabilities — if nearly everything is stateful "+
			"the consent gate stops carrying information", stateless)
	}
}
