// The Azure half of the SILENT-IGNORE GUARD: per service, the exact set of
// candidate `implementation:` operand KEYS this driver reads. The block is
// free-form (D26), but an operand no driver consumes is refused at compile
// rather than silently dropped — the same fail-closed rule the per-attribute
// allowlists already enforce. Only TOP-LEVEL keys are declared: a map/list-
// valued operand (aks.nodePool, aks-addon.addon_config, vnet.service_endpoints,
// loadbalancer.backendFqdns/backendIps, consumptionbudget.contactEmails, ...)
// is one key whose subkeys/elements are read structurally, not by name. Keyed
// by the SERVICE token the candidate declares, parallel to PermissionsFor: pure
// and table-driven.
package azure

import "groundhold/internal/provider"

// azureConsumedOperands: enumerated by reading every impl[...] read (inline and
// via the helpers implStringAz/aoiImpl/azStr/sbIntOperand/asInt64/toStringSlice)
// on the create, update and ClassifyChange paths of each of the 41 Azure service
// tokens (Reconcile/Observe/Delete read only the providerId/path). A service
// that reads no operand declares the empty set — any operand on it then refuses.
// Naming trap kept verbatim: dnsrecord reads camelCase "resourceGroup" while
// every other service reads snake_case "resource_group".
var azureConsumedOperands = map[string][]string{
	"acr":                  {"key_vault_key", "resource_group"},
	"acsemail":             {"domain", "domain_management", "email_service_name", "resource_group"},
	"activitylog":          {"destination", "diagnosticSettingName", "kms_key_name", "log_categories"},
	"azvm":                 {"admin_username", "disk_encryption_set_id", "image_reference", "network_interface_id", "os_disk_size_gb", "resource_group", "ssh_public_key", "vm_size"},
	"aisearch":             {"resource_group"},
	"aks":                  {"authorizedIPRanges", "clusterName", "dnsPrefix", "identity", "kmsKeyId", "nodePool", "resource_group", "userAssignedIdentityId"},
	"aks-addon":            {"addon_config", "clusterName", "resource_group"},
	"aks-workloadidentity": {"oidcIssuer", "resource_group", "uamiName", "uamiResourceId"},
	"apim":                 {"publisher_email", "publisher_name", "resource_group"},
	"azkafka":              {"key_vault_key_uri", "resource_group", "user_assigned_identity"},
	"azurecdn":             {"aliases", "cache_policy", "certificate", "resource_group"},
	"azurefiles":           {"key_vault_key_uri", "quota_gib", "resource_group", "user_assigned_identity"},
	"azureopenai":          {"account_name", "deployment_model", "deployment_name", "deployment_sku", "deployment_version", "resource_group"},
	"backuppolicy":         {"backupType", "backupVaultName", "dataStoreType", "datasourceType", "resource_group", "scheduleInterval"},
	"backupvault":          {"key_vault_key_uri", "resource_group", "storage_redundancy"},
	"blob":                 {"key_vault_key_uri", "replication_destination_account_id", "replication_destination_container", "resource_group", "user_assigned_identity"},
	"changefeed":           {},
	"consumptionbudget":    {"actionGroups", "billingCurrency", "contactEmails", "resource_group"},
	"containerapps":        {"image", "infrastructure_subnet_id", "resource_group"},
	"containerappsjob":     {"cron_expression", "environment_id", "resource_group"},
	"cosmos":               {"key_vault_key_uri", "resource_group"},
	"customroledef":        {},
	"defender":             {"serversSubPlan"},
	"dnsrecord":            {"record_name", "resourceGroup", "zone"},
	"dnszone":              {"resource_group"},
	"eventhubs":            {"key_vault_key_uri", "resource_group", "user_assigned_identity"},
	"flexpostgres":         {"admin_password", "admin_username", "key_vault_key_uri", "resource_group", "sku", "user_assigned_identity"},
	"frontdoorwaf":         {"resource_group"},
	"keyvault":             {"resource_group", "tenant_id"},
	"keyvaultkey":          {"resource_group", "tenant_id"},
	"loadbalancer":         {"backendFqdns", "backendIps", "port", "publicIpId", "resource_group", "sku", "sslCertificateId", "subnetId"},
	"loganalytics":         {"resource_group", "sku"},
	"managedidentity":      {"location", "resource_group"},
	"metricalert":          {"notification_channel", "resource_group", "target_resource"},
	"portaldash":           {"resource_group", "target_resource"},
	"rediscache":           {"capacity", "resource_group"},
	"roleassignment":       {},
	"scheduledquery":       {"resource_group", "scope", "value_field"},
	"servicebusqueue":      {"max_delivery_count", "resource_group"},
	"servicebustopic":      {"resource_group"},
	"vnet":                 {"resource_group", "service_endpoints"},
	"webtest":              {"app_insights_id", "resource_group"},
}

// ConsumedOperands implements provider.OperandConsumer (the operand twin of the
// permission table): the compiler refuses any implementation operand not in the
// declared set.
func (d *Driver) ConsumedOperands(service string) []string {
	return azureConsumedOperands[service]
}

var _ provider.OperandConsumer = (*Driver)(nil)
