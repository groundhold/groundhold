// Shared RBAC constants + the object-metadata shape. The Role read/write path is
// now the schema-driven engine's (mappings/k8s.role.yaml + k8s.clusterrole.yaml
// through the k8s.rbac.roleRules lens); what remains here is the API group and the
// metadata struct the ownership guard and the discovery lister both unmarshal.
package k8s

const rbacGroup = "rbac.authorization.k8s.io"

// objectMeta is the slice of an object's metadata groundhold reads (labels for the
// ownership guard, name/namespace for identity).
type objectMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
