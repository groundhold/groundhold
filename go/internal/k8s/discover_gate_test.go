package k8s

import (
	"testing"

	"groundhold/internal/provider"
)

// TestK8sDiscoverabilityComplete brings k8s under the same discoverability gate as
// the cloud drivers (spec/drivers.md §2), but keyed off the SCHEMA-MAPPING registry
// rather than a PermissionsFor certify list: every mapped kind (the k8s notion of a
// "service") must have a discoverer. A new mapping in internal/k8s/mappings/ grows
// MappedServiceTokens and fails this gate until serviceDiscoverers covers it — so a
// newly observed kind is discoverable immediately, never shadow-blind.
func TestK8sDiscoverabilityComplete(t *testing.T) {
	d := NewDriver("", "")
	provider.CertifyDiscoverability(t, d, d.MappedServiceTokens())
}
