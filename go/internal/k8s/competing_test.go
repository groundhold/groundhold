package k8s

import (
	"reflect"
	"testing"
)

func TestCompetingManagersOf(t *testing.T) {
	cases := []struct {
		name string
		meta competeMeta
		want []string
	}{
		{"clean", competeMeta{Labels: map[string]string{"team": "payments"}}, nil},
		{"kubectl-only-not-competing", competeMeta{Managed: []managedField{{Manager: "kubectl-client-side-apply"}}}, nil},
		{"terraform-not-competing", competeMeta{Managed: []managedField{{Manager: "terraform"}}}, nil},
		{"argocd-annotation", competeMeta{Annotations: map[string]string{"argocd.argoproj.io/tracking-id": "app:ns"}}, []string{"argocd"}},
		{"helm-label", competeMeta{Labels: map[string]string{"app.kubernetes.io/managed-by": "Helm"}}, []string{"helm"}},
		{"flux-managedfield", competeMeta{Managed: []managedField{{Manager: "kustomize-controller"}}}, []string{"kustomize-controller"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := competingManagersOf(c.meta)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("competingManagersOf = %v, want %v", got, c.want)
			}
		})
	}
}
