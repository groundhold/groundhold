// Azure Container Apps request building (D99): the semantic core of the Azure
// workload.container driver — the SAME vocabulary Cloud Run / ECS fulfil. ACI is
// disqualified (no replicas, no autoscaler, no managed TLS ingress); Container Apps
// maps almost one-to-one onto Cloud Run. The binding is a CONSTITUTIVE COMPOSITE:
// a managed environment (the ECS-cluster analog — created per binding, retired with
// it) + a container app. image.signedProvenance is refused (no Binary Authorization
// equivalent — parity with the ECS refusal).
package azure

import (
	"fmt"
	"sort"
)

const appAPIVersion = "2024-03-01"

type ContainerAppPlan struct {
	Env           string
	App           string
	Region        string
	Environment   string
	Capability    string
	Image         string
	Public        bool
	AllowInsecure bool // = NOT tls.enforced
	MinReplicas   int
	ZoneRedundant bool   // availability.class regional
	Subnet        string // impl.infrastructure_subnet_id (required for zoneRedundant)
}

func containerAppName(environment, capability string, generation int) string {
	return azResourceName("pv-app", environment, capability, generation)
}

// BuildContainerApp maps capability.workload.container attributes to a plan. Every
// error is a refusal apply surfaces in preflight.
func BuildContainerApp(environment, capability string,
	attrs, impl map[string]any, generation int) (ContainerAppPlan, error) {
	if generation < 1 {
		generation = 1
	}
	app := containerAppName(environment, capability, generation)
	p := ContainerAppPlan{
		Environment: environment, Capability: capability,
		App: app, Env: app + "-env", MinReplicas: 1,
	}
	p.Image, _ = impl["image"].(string)
	if p.Image == "" {
		return ContainerAppPlan{}, fmt.Errorf("azure container app requires implementation.image")
	}

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			p.Public, _ = raw.(bool)
		case "tls.enforced":
			enforced, _ := raw.(bool)
			p.AllowInsecure = !enforced
		case "replicas.minimum":
			switch v := raw.(type) {
			case int:
				p.MinReplicas = v
			case float64:
				p.MinReplicas = int(v)
			default:
				return ContainerAppPlan{}, fmt.Errorf("replicas.minimum must be a number")
			}
			if p.MinReplicas < 0 {
				return ContainerAppPlan{}, fmt.Errorf("replicas.minimum cannot be negative")
			}
		case "autoscaling.enabled":
			if raw != true {
				return ContainerAppPlan{}, fmt.Errorf(
					"autoscaling.enabled=false cannot be honored: Container Apps always " +
						"scales via KEDA — refusing rather than faking a fixed-size deployment")
			}
		case "availability.class":
			switch raw {
			case "zonal":
				p.ZoneRedundant = false
			case "regional":
				sn, _ := impl["infrastructure_subnet_id"].(string)
				if sn == "" {
					return ContainerAppPlan{}, fmt.Errorf(
						"availability.class regional requires implementation.infrastructure_subnet_id " +
							"— zone-redundant Container Apps need a VNet-injected environment " +
							"(an impl prerequisite, not an attribute-added resource)")
				}
				p.ZoneRedundant, p.Subnet = true, sn
			case "multi-regional":
				return ContainerAppPlan{}, fmt.Errorf(
					"availability.class multi-regional has no single-environment Container Apps mapping")
			default:
				return ContainerAppPlan{}, fmt.Errorf("availability.class %v has no Azure mapping", raw)
			}
		case "image.signedProvenance":
			return ContainerAppPlan{}, fmt.Errorf(
				"image.signedProvenance is not honored: Azure has no Binary Authorization " +
					"equivalent on the app (the nearest is subscription/management-group Azure " +
					"Policy — an account-level control, not a capability attribute); refused " +
					"(parity with the ECS refusal)")
		case "service.managed":
			if raw != true {
				return ContainerAppPlan{}, fmt.Errorf("service.managed=false cannot be honored by Container Apps")
			}
		default:
			return ContainerAppPlan{}, fmt.Errorf(
				"attribute %s has no Azure Container Apps mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}
	if p.Region == "" {
		return ContainerAppPlan{}, fmt.Errorf("azure container app requires location.region")
	}
	return p, nil
}
