// The k8s half of the SILENT-IGNORE GUARD (D563). Per service, the exact set of
// candidate `implementation:` operand KEYS this driver reads. The compiler refuses
// any top-level key outside it rather than dropping it quietly — the failure the
// pilot reported for AWS (D530), which reached this driver by a different route:
// the guard exempts a provider that declares no consumed set, an exemption written
// for the Fake test double, and the k8s driver silently qualified for it.
//
// Enumerated by reading every impl[...] read on the create/update path:
//
//	namespace   namespaceOf (rbacrole_write.go) — namespaced kinds only
//	name        createMapped (generic_write.go) — every kind; a cluster-scoped
//	            object's name IS its identity
//	issuerRef   writeLensCertmanagerPrimaryDomain
//	secretName  writeLensCertmanagerPrimaryDomain
//
// The scope half is derived from the mapping registry rather than restated here:
// `namespace` is only read when the kind is Namespaced, so declaring it for a
// cluster-scoped service would re-open the hole this closes for exactly the
// operands most likely to be wrong (a namespace on a ClusterRole does nothing, and
// an operator who wrote one meant something by it).
package k8s

import "groundhold/internal/provider"

// lensOperands are the extra keys a named write lens reads, keyed by lens name so
// a mapping that adopts the lens inherits them and nothing has to be updated twice.
var lensOperands = map[string][]string{
	"k8s.certmanager.primaryDomain": {"issuerRef", "secretName"},
}

func (d *Driver) ConsumedOperands(service string) []string {
	m := d.mappingFor(service)
	if m == nil {
		return nil
	}
	out := []string{"name"}
	if m.Resource.Scope == "Namespaced" {
		out = append(out, "namespace")
	}
	for _, lens := range m.Lenses {
		out = append(out, lensOperands[lens]...)
	}
	return out
}

var _ provider.OperandConsumer = (*Driver)(nil)
