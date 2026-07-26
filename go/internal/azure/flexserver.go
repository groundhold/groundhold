// Azure Database (Flexible Server) request building (D99): the Azure
// database.relational driver. NOT Azure SQL Database — that speaks TDS only and is
// evergreen (no version to pin), so it would refuse every postgresql/mysql contract
// in the corpus. PostgreSQL Flexible Server is a SINGLE ARM resource carrying
// version, network, backup, HA and CMK in one create body — a cleaner map than RDS
// or the server+db split. And TLS is enforced by default (require_secure_transport),
// so encryption.inTransit is HONORED where RDS had to refuse it (no parameter group,
// no second binding).
package azure

import (
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/scalars"
)

const pgAPIVersion = "2023-06-01-preview"

type FlexServerPlan struct {
	Name                string
	Region              string
	Environment         string
	Capability          string
	Version             string // e.g. "16"
	AdminUser           string
	AdminPassword       string
	PublicAccess        bool
	BackupRetentionDays int64 // recovery.rpo; 0 = provider default
	ZoneRedundant       bool  // availability.class regional
	KmsKeyURI           string
	KmsIdentity         string
}

func flexServerName(environment, capability string, generation int) string {
	return azResourceName("pv-pg", environment, capability, generation)
}

// BuildFlexServer maps capability.database.relational attributes to a PostgreSQL
// Flexible Server plan. Every error is a refusal apply surfaces in preflight.
func BuildFlexServer(environment, capability string,
	attrs, impl map[string]any, generation int) (FlexServerPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := FlexServerPlan{
		Environment: environment, Capability: capability,
		Name: flexServerName(environment, capability, generation),
	}
	p.AdminUser, _ = impl["admin_username"].(string)
	p.AdminPassword, _ = impl["admin_password"].(string)
	if p.AdminUser == "" || p.AdminPassword == "" {
		return FlexServerPlan{}, fmt.Errorf(
			"azure flexible server requires implementation.admin_username AND admin_password")
	}

	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "engine.protocol":
			proto, _ := raw.(string)
			parts := strings.SplitN(proto, "/", 2)
			if parts[0] != "postgresql" && parts[0] != "postgres" {
				return FlexServerPlan{}, fmt.Errorf(
					"engine.protocol %q has no PostgreSQL Flexible Server mapping — "+
						"this service is postgres-only (mysql is a separate Flexible Server service)", proto)
			}
			if len(parts) == 2 {
				p.Version = parts[1]
			}
		case "location.region":
			p.Region, _ = raw.(string)
		case "network.publicExposure":
			p.PublicAccess, _ = raw.(bool)
		case "encryption.atRest":
			if raw != true {
				return FlexServerPlan{}, fmt.Errorf(
					"encryption.atRest=false cannot be honored (Azure storage is always encrypted)")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.KmsKeyURI, _ = impl["key_vault_key_uri"].(string)
				p.KmsIdentity, _ = impl["user_assigned_identity"].(string)
				if p.KmsKeyURI == "" || p.KmsIdentity == "" {
					return FlexServerPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.key_vault_key_uri " +
							"AND implementation.user_assigned_identity")
				}
			}
		case "encryption.inTransit":
			if raw != true {
				return FlexServerPlan{}, fmt.Errorf(
					"encryption.inTransit=false cannot be honored: PostgreSQL Flexible Server " +
						"enforces TLS by default (require_secure_transport) — disabling it is not offered")
			}
			// true -> honored by default (config-intent, no field to set)
		case "recovery.rpo":
			sc, err := scalars.Parse(raw)
			if err != nil || sc.Kind != scalars.Duration {
				return FlexServerPlan{}, fmt.Errorf("recovery.rpo is not a duration")
			}
			days := int64(sc.Value.(float64)) / 86400000
			if days < 1 {
				days = 1
			}
			if days > 35 {
				return FlexServerPlan{}, fmt.Errorf(
					"recovery.rpo backup retention above 35 days is not supported by Flexible Server")
			}
			p.BackupRetentionDays = days
		case "availability.class":
			switch raw {
			case "zonal":
				p.ZoneRedundant = false
			case "regional":
				p.ZoneRedundant = true
			case "multi-regional":
				return FlexServerPlan{}, fmt.Errorf(
					"availability.class multi-regional has no single-server mapping " +
						"(a failover group is a second server = a second binding); refused")
			default:
				return FlexServerPlan{}, fmt.Errorf("availability.class %v has no Azure mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return FlexServerPlan{}, fmt.Errorf("service.managed=false cannot be honored by Flexible Server")
			}
		default:
			return FlexServerPlan{}, fmt.Errorf(
				"attribute %s has no Azure Flexible Server mapping — refusing rather than "+
					"silently dropping it", path)
		}
	}
	if p.Region == "" {
		return FlexServerPlan{}, fmt.Errorf("azure flexible server requires location.region")
	}
	if p.Version == "" {
		return FlexServerPlan{}, fmt.Errorf("azure flexible server requires engine.protocol (e.g. postgresql/16)")
	}
	return p, nil
}
