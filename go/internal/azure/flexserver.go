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
	Name          string
	Region        string
	Environment   string
	Capability    string
	Version       string // e.g. "16"
	AdminUser     string
	AdminPassword string
	PublicAccess  bool
	ZoneRedundant bool // availability.class regional
	KmsKeyURI     string
	KmsIdentity   string
	Sku           string // impl operand; default Standard_B1ms
	Tier          string // DERIVED from the sku family — never a constant (D942)
}

// flexServerTier maps a PostgreSQL Flexible Server sku to its compute tier. The tier
// MUST match the sku family or the create 400s ("SKU is not compatible with tier"),
// so it is derived, never hardcoded (D942).
func flexServerTier(sku string) (string, error) {
	switch {
	case strings.HasPrefix(sku, "Standard_B"):
		return "Burstable", nil
	case strings.HasPrefix(sku, "Standard_D"):
		return "GeneralPurpose", nil
	case strings.HasPrefix(sku, "Standard_E"):
		return "MemoryOptimized", nil
	default:
		return "", fmt.Errorf("implementation.sku %q is not a recognized PostgreSQL Flexible Server "+
			"size (expected Standard_B* Burstable, Standard_D* GeneralPurpose, or Standard_E* "+
			"MemoryOptimized)", sku)
	}
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
			// D796. This used to divide the requested RPO into DAYS and write it to
			// backupRetentionDays, so asking for a 15-minute data-loss window set backup
			// retention to its floor of one day: a tighter recovery requirement made the
			// estate's recoverability WORSE, silently. Retention is how far back a
			// restore reaches; the RPO is how much a failure loses, and on a server that
			// restores to any point in its window the second is a measurement.
			//
			// The other two clouds already refuse to pretend otherwise — neither writes
			// the requested VALUE anywhere; both read it as "automated backups must be
			// on". Flexible Server has them on always, so there is nothing to switch and
			// nothing honest to write. Refuse, and say where the two properties live.
			return FlexServerPlan{}, fmt.Errorf(
				"recovery.rpo has no Flexible Server mapping: backups and point-in-time " +
					"recovery are always on, and backupRetentionDays is how far BACK a " +
					"restore reaches, not the data-loss window a failure costs — writing " +
					"the RPO there would shorten retention to meet a tighter RPO, which " +
					"is backwards. The data-loss window of a PITR server is measured, not " +
					"configured: drop recovery.rpo from the capability and prove it with " +
					"a restore probe (recovery.rto carries evidence: probe for the same " +
					"reason)")
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
	// D942: the tier is DERIVED from the sku family, never the constant "Burstable" the
	// body used to send. Field-proven: Standard_D2s_v3 (GeneralPurpose) with the correct
	// tier reaches Ready, but the identical body with tier:Burstable rolls back — so any
	// GeneralPurpose/MemoryOptimized sku was uncreatable (Azure accepts the mismatched PUT
	// with a 202, then fails provisioning, which is why the golden fake never caught it).
	p.Sku, _ = impl["sku"].(string)
	if p.Sku == "" {
		p.Sku = "Standard_B1ms"
	}
	tier, terr := flexServerTier(p.Sku)
	if terr != nil {
		return FlexServerPlan{}, terr
	}
	p.Tier = tier
	return p, nil
}
