package k8s

import (
	"testing"

	"groundhold/internal/provider"
)

// TestGitopsLensesNormalizeToNeutral proves the vendor-agnostic core: ArgoCD and
// Flux — different controllers, different status shapes — project onto the SAME
// neutral sync/health enums. Neither is privileged; both are one lens.
func TestGitopsLensesNormalizeToNeutral(t *testing.T) {
	collect := func(obs []provider.Observation) map[string]any {
		m := map[string]any{}
		for _, o := range obs {
			m[o.Path] = o.Value
		}
		return m
	}

	// ArgoCD: Synced + Healthy -> synced + healthy.
	obs, _ := lensGitopsArgocdStatus(map[string]any{
		"status": map[string]any{
			"sync":   map[string]any{"status": "Synced"},
			"health": map[string]any{"status": "Healthy"},
		},
	})
	if got := collect(obs); got["sync.status"] != "synced" || got["health.status"] != "healthy" {
		t.Fatalf("argocd Synced/Healthy = %+v, want synced/healthy", got)
	}

	// ArgoCD: OutOfSync + Degraded -> drifted + degraded.
	obs, _ = lensGitopsArgocdStatus(map[string]any{
		"status": map[string]any{
			"sync":   map[string]any{"status": "OutOfSync"},
			"health": map[string]any{"status": "Degraded"},
		},
	})
	if got := collect(obs); got["sync.status"] != "drifted" || got["health.status"] != "degraded" {
		t.Fatalf("argocd OutOfSync/Degraded = %+v, want drifted/degraded", got)
	}

	// Flux: Ready=True -> synced + healthy (the SAME neutral values as ArgoCD).
	obs, _ = lensGitopsFluxStatus(map[string]any{
		"status": map[string]any{
			"conditions": []any{map[string]any{"type": "Ready", "status": "True"}},
		},
	})
	if got := collect(obs); got["sync.status"] != "synced" || got["health.status"] != "healthy" {
		t.Fatalf("flux Ready=True = %+v, want synced/healthy", got)
	}

	// Flux: Ready=False -> drifted + degraded.
	obs, _ = lensGitopsFluxStatus(map[string]any{
		"status": map[string]any{
			"conditions": []any{map[string]any{"type": "Ready", "status": "False"}},
		},
	})
	if got := collect(obs); got["sync.status"] != "drifted" || got["health.status"] != "degraded" {
		t.Fatalf("flux Ready=False = %+v, want drifted/degraded", got)
	}

	// Flux: Ready=Unknown (a reconcile in flight / indeterminate) -> NEUTRAL
	// unknown on BOTH axes, never a fabricated drifted/degraded. A k8s condition
	// is three-valued; collapsing Unknown into a definite measured verdict would
	// make a hard gitops constraint falsely VIOLATED and block execution — the
	// four-valued honesty the ArgoCD twin keeps must hold on the Flux path too.
	obs, _ = lensGitopsFluxStatus(map[string]any{
		"status": map[string]any{
			"conditions": []any{map[string]any{"type": "Ready", "status": "Unknown"}},
		},
	})
	if got := collect(obs); got["sync.status"] != "unknown" || got["health.status"] != "unknown" {
		t.Fatalf("flux Ready=Unknown = %+v, want unknown/unknown (not fabricated drifted/degraded)", got)
	}

	// Flux: Reconciling in flight -> progressing.
	obs, _ = lensGitopsFluxStatus(map[string]any{
		"status": map[string]any{
			"conditions": []any{
				map[string]any{"type": "Ready", "status": "False"},
				map[string]any{"type": "Reconciling", "status": "True"},
			},
		},
	})
	if got := collect(obs); got["health.status"] != "progressing" {
		t.Fatalf("flux Reconciling = %+v, want progressing", got)
	}

	// Honesty: no status yet -> nothing fabricated, a diagnostic instead.
	obs, diags := lensGitopsArgocdStatus(map[string]any{})
	if len(obs) != 0 || len(diags) == 0 {
		t.Fatalf("argocd empty status must yield no observation + a diagnostic, got obs=%v diags=%v", obs, diags)
	}
	obs, diags = lensGitopsFluxStatus(map[string]any{})
	if len(obs) != 0 || len(diags) == 0 {
		t.Fatalf("flux empty status must yield no observation + a diagnostic, got obs=%v diags=%v", obs, diags)
	}
}
