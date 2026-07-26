// The (Cluster)RoleBinding read/write path is now the schema-driven engine's
// (mappings/k8s.rolebinding.yaml + k8s.clusterrolebinding.yaml through the
// k8s.rbac.grant lens). What remains is the object shape the read-only discovery
// lister unmarshals; observe/create/update/delete all route through the engine.
package k8s

type roleBindingDoc struct {
	Metadata objectMeta `json:"metadata"`
	RoleRef  roleRef    `json:"roleRef"`
	Subjects []subject  `json:"subjects"`
}
