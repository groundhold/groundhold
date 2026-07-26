// k8s Namespace -> capability.cluster.namespace: a governed tenancy boundary and
// the Pod Security Standard it ENFORCES. Namespace is a CORE-group, CLUSTER-scoped
// resource (/api/v1/namespaces/<name>, no namespace segment). observe/create/update/
// delete are now the schema-driven engine's (mappings/k8s.namespace.yaml +
// the k8s.namespace.podSecurity lens); what remains here is the identity helper and
// the enum shared with the read-only discovery path (discover is not mapped).
package k8s

const podSecurityEnforceLabel = "pod-security.kubernetes.io/enforce"

var validPodSecurity = map[string]bool{"restricted": true, "baseline": true, "privileged": true}

// namespaceDoc is the shape the discovery lister unmarshals.
type namespaceDoc struct {
	Metadata objectMeta `json:"metadata"`
}

func nsProviderID(name string) string {
	return rbacProviderID("core", "v1", "Namespace", "", name)
}
