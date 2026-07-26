package gcp

// Read-only discovery sweeps (gap batch A): the brownfield LIST half for seven
// GCP services that already have a create+observe path. Each sweep mirrors the
// established shape in discover_gcp.go (discoverCloudRun / discoverGCS): call the
// service's REST List API through the driver's bearer-signed d.call plumbing,
// build each resource's providerId with the in-package constructor, then reuse
// the service's OWN observe reverse map so LIST supplies identity and observe
// supplies real attributes (two-step, never all-unknown records). A per-resource
// observe failure is a diagnostic + skip; a List/transport/parse failure returns
// an error (never a fabricated empty list). Strictly read-only.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// discoverBigQuery enumerates BigQuery datasets as capability.warehouse.analytics,
// reusing observeBigQuery. Datasets are project-scoped with a location; region,
// when given, filters on that location (multi-region "US"/"EU" simply will not
// match a single-region filter).
func (d *Driver) discoverBigQuery(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.bqBase()+"/projects/"+d.Project+"/datasets", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("datasets.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("datasets.list: HTTP %d", status)
	}
	var resp struct {
		Datasets []struct {
			DatasetReference struct {
				DatasetID string `json:"datasetId"`
			} `json:"datasetReference"`
			Location string `json:"location"`
		} `json:"datasets"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("datasets.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, ds := range resp.Datasets {
		id := ds.DatasetReference.DatasetID
		if id == "" {
			continue
		}
		if region != "" && !strings.EqualFold(ds.Location, region) {
			continue // another location — not this sweep
		}
		pid := bqProviderID(d.Project, id)
		obs, odiags, err := d.observeBigQuery("", pid)
		if err != nil {
			diags = append(diags, id+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, id+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.warehouse.analytics",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverCloudArmor enumerates global Cloud Armor security policies as
// capability.security.waf, reusing observeArmor. Security policies here are
// GLOBAL compute resources; region does not filter.
func (d *Driver) discoverCloudArmor(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/global/securityPolicies", d.computeBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("securityPolicies.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("securityPolicies.list: HTTP %d", status)
	}
	var resp struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("securityPolicies.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, p := range resp.Items {
		if p.Name == "" {
			continue
		}
		pid := armorProviderID(d.Project, p.Name)
		obs, odiags, err := d.observeArmor("", pid)
		if err != nil {
			diags = append(diags, p.Name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, p.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.security.waf",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// discoverCloudDNS enumerates Cloud DNS managed zones as capability.dns.zone,
// reusing observeCloudDNS. Managed zones are project-global; region does not
// filter (a private zone's scope is reported by the observe map itself).
func (d *Driver) discoverCloudDNS(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/managedZones", d.dnsBase(), d.Project), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("managedZones.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("managedZones.list: HTTP %d", status)
	}
	var resp struct {
		ManagedZones []struct {
			Name string `json:"name"`
		} `json:"managedZones"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("managedZones.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, z := range resp.ManagedZones {
		if z.Name == "" {
			continue
		}
		pid := gdnsProviderID(d.Project, z.Name)
		obs, odiags, err := d.observeCloudDNS("", pid)
		if err != nil {
			diags = append(diags, z.Name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, z.Name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.dns.zone",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// cfDiscoverLocationName pulls location and function name out of a Cloud
// Functions v2 resource name (projects/p/locations/<loc>/functions/<name>).
func cfDiscoverLocationName(resourceName string) (loc, name string, ok bool) {
	li := strings.Index(resourceName, "/locations/")
	fi := strings.Index(resourceName, "/functions/")
	if li < 0 || fi < 0 || fi < li {
		return "", "", false
	}
	loc = resourceName[li+len("/locations/") : fi]
	name = resourceName[fi+len("/functions/"):]
	if loc == "" || name == "" {
		return "", "", false
	}
	return loc, name, true
}

// discoverCloudFunctions enumerates Cloud Functions (Gen 2) as
// capability.workload.container, reusing observeCloudFunction. The aggregated
// list (locations/-) spans every region; region, when given, filters on the
// function's own location parsed from its resource name.
func (d *Driver) discoverCloudFunctions(region string) ([]provider.Discovered, []string, error) {
	status, body, err := d.call("GET", d.cfBase()+"/projects/"+d.Project+"/locations/-/functions", nil)
	if err != nil {
		return nil, nil, fmt.Errorf("functions.list: %v", err)
	}
	if status != http.StatusOK {
		return nil, nil, fmt.Errorf("functions.list: HTTP %d", status)
	}
	var resp struct {
		Functions []struct {
			Name string `json:"name"`
		} `json:"functions"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, nil, readBody("functions.list", status)
	}
	var out []provider.Discovered
	var diags []string
	for _, f := range resp.Functions {
		loc, name, ok := cfDiscoverLocationName(f.Name)
		if !ok {
			continue
		}
		if region != "" && loc != region {
			continue // another location — not this sweep
		}
		pid := functionProviderID(d.Project, loc, name)
		obs, odiags, err := d.observeCloudFunction("", pid)
		if err != nil {
			diags = append(diags, name+": "+err.Error())
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.workload.container",
			Observations: obs,
		})
	}
	return out, diags, nil
}

// certManagerDiscoverLocations lists the Certificate Manager locations available
// to the project. certificates.list requires a concrete location (no cross-
// location wildcard), so a full-estate sweep enumerates locations first.
func (d *Driver) certManagerDiscoverLocations() ([]string, error) {
	return d.discoverGCPLocations(d.certManagerBase(), "certManager")
}

// discoverCertManager enumerates Certificate Manager certificates as
// capability.certificate.tls, reusing observeCertManager. A given region is
// swept directly; an empty region enumerates the project's locations first (the
// list has no cross-location wildcard). A per-location list failure is a
// diagnostic — it never hides the certificates another location returned. D53:
// observeCertManager reads certificate metadata only; the private key never
// transits groundhold.
func (d *Driver) discoverCertManager(region string) ([]provider.Discovered, []string, error) {
	var locations []string
	var diags []string
	if region != "" {
		locations = []string{region}
	} else {
		locs, err := d.certManagerDiscoverLocations()
		if err != nil {
			return nil, nil, err
		}
		locations = locs
	}
	var out []provider.Discovered
	for _, loc := range locations {
		status, body, err := d.call("GET", fmt.Sprintf(
			"%s/projects/%s/locations/%s/certificates", d.certManagerBase(), d.Project, loc), nil)
		if err != nil {
			diags = append(diags, "certificates.list "+loc+": "+err.Error())
			continue
		}
		if status != http.StatusOK {
			diags = append(diags, fmt.Sprintf("certificates.list %s: HTTP %d", loc, status))
			continue
		}
		var resp struct {
			Certificates []struct {
				Name string `json:"name"`
			} `json:"certificates"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			diags = append(diags, loc+": "+readBody("certificates.list", status).Error())
			continue
		}
		for _, c := range resp.Certificates {
			certID := leafName(c.Name)
			if certID == "" {
				continue
			}
			pid := certManagerProviderID(d.Project, loc, certID)
			obs, odiags, err := d.observeCertManager("", pid)
			if err != nil {
				diags = append(diags, certID+": "+err.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, certID+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.certificate.tls",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}

// backupDRDiscoverLocations lists the Backup and DR locations available to the
// project. backupVaults.list requires a concrete location, so a full-estate
// sweep enumerates locations first.
func (d *Driver) backupDRDiscoverLocations() ([]string, error) {
	return d.discoverGCPLocations(d.backupDRBase(), "backupDR")
}

// discoverBackupVault enumerates Backup and DR backup vaults as
// capability.backup.vault, reusing observeBackupDR. A given region is swept
// directly; an empty region enumerates the project's locations first. A
// per-location list failure is a diagnostic — it never hides the vaults another
// location returned. Vaults are regional, so region filters on the swept
// location.
func (d *Driver) discoverBackupVault(region string) ([]provider.Discovered, []string, error) {
	var locations []string
	var diags []string
	if region != "" {
		locations = []string{region}
	} else {
		locs, err := d.backupDRDiscoverLocations()
		if err != nil {
			return nil, nil, err
		}
		locations = locs
	}
	var out []provider.Discovered
	for _, loc := range locations {
		status, body, err := d.call("GET", fmt.Sprintf(
			"%s/projects/%s/locations/%s/backupVaults", d.backupDRBase(), d.Project, loc), nil)
		if err != nil {
			diags = append(diags, "backupVaults.list "+loc+": "+err.Error())
			continue
		}
		if status != http.StatusOK {
			diags = append(diags, fmt.Sprintf("backupVaults.list %s: HTTP %d", loc, status))
			continue
		}
		var resp struct {
			BackupVaults []struct {
				Name string `json:"name"`
			} `json:"backupVaults"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			diags = append(diags, loc+": "+readBody("backupVaults.list", status).Error())
			continue
		}
		for _, v := range resp.BackupVaults {
			vaultID := leafName(v.Name)
			if vaultID == "" {
				continue
			}
			pid := backupDRProviderID(d.Project, loc, vaultID)
			obs, odiags, err := d.observeBackupDR("", pid)
			if err != nil {
				diags = append(diags, vaultID+": "+err.Error())
				continue
			}
			for _, dg := range odiags {
				diags = append(diags, vaultID+": "+dg)
			}
			out = append(out, provider.Discovered{
				ProviderID:   pid,
				ResourceType: "capability.backup.vault",
				Observations: obs,
			})
		}
	}
	return out, diags, nil
}

// kmsDiscoverLocations lists the Cloud KMS locations available to the project.
// keyRings.list requires a concrete location (no cross-location wildcard), so a
// full-estate sweep enumerates locations first.
func (d *Driver) kmsDiscoverLocations() ([]string, error) {
	return d.discoverGCPLocations(d.kmsBase(), "kms")
}

// discoverCloudKMS enumerates Cloud KMS cryptoKeys as capability.key.encryption,
// reusing observeKMS. A cryptoKey lives under (location, keyRing), so the sweep
// descends locations -> keyRings -> cryptoKeys. A given region is swept directly;
// an empty region enumerates the project's locations first. A list failure at any
// level is a diagnostic — it never hides the keys another branch returned.
func (d *Driver) discoverCloudKMS(region string) ([]provider.Discovered, []string, error) {
	var locations []string
	var diags []string
	if region != "" {
		locations = []string{region}
	} else {
		locs, err := d.kmsDiscoverLocations()
		if err != nil {
			return nil, nil, err
		}
		locations = locs
	}
	var out []provider.Discovered
	for _, loc := range locations {
		rings, ok := d.kmsListKeyRings(loc, &diags)
		if !ok {
			continue
		}
		for _, ring := range rings {
			ringID := leafName(ring)
			if ringID == "" {
				continue
			}
			keys, ok := d.kmsListCryptoKeys(loc, ringID, &diags)
			if !ok {
				continue
			}
			for _, keyName := range keys {
				keyID := leafName(keyName)
				if keyID == "" {
					continue
				}
				pid := gkmsProviderID(d.Project, loc, ringID, keyID)
				obs, odiags, err := d.observeKMS("", pid)
				if err != nil {
					diags = append(diags, keyID+": "+err.Error())
					continue
				}
				for _, dg := range odiags {
					diags = append(diags, keyID+": "+dg)
				}
				out = append(out, provider.Discovered{
					ProviderID:   pid,
					ResourceType: "capability.key.encryption",
					Observations: obs,
				})
			}
		}
	}
	return out, diags, nil
}

// kmsListKeyRings lists the keyRing resource names in a location. A list failure
// appends a diagnostic and returns ok=false so the caller skips that location
// without aborting the whole sweep.
func (d *Driver) kmsListKeyRings(location string, diags *[]string) ([]string, bool) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/locations/%s/keyRings", d.kmsBase(), d.Project, location), nil)
	if err != nil {
		*diags = append(*diags, "keyRings.list "+location+": "+err.Error())
		return nil, false
	}
	if status != http.StatusOK {
		*diags = append(*diags, fmt.Sprintf("keyRings.list %s: HTTP %d", location, status))
		return nil, false
	}
	var resp struct {
		KeyRings []struct {
			Name string `json:"name"`
		} `json:"keyRings"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		*diags = append(*diags, location+": "+readBody("keyRings.list", status).Error())
		return nil, false
	}
	var names []string
	for _, r := range resp.KeyRings {
		names = append(names, r.Name)
	}
	return names, true
}

// kmsListCryptoKeys lists the cryptoKey resource names in a keyRing. A list
// failure appends a diagnostic and returns ok=false so the caller skips that ring.
func (d *Driver) kmsListCryptoKeys(location, ringID string, diags *[]string) ([]string, bool) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/locations/%s/keyRings/%s/cryptoKeys", d.kmsBase(), d.Project, location, ringID), nil)
	if err != nil {
		*diags = append(*diags, "cryptoKeys.list "+ringID+": "+err.Error())
		return nil, false
	}
	if status != http.StatusOK {
		*diags = append(*diags, fmt.Sprintf("cryptoKeys.list %s: HTTP %d", ringID, status))
		return nil, false
	}
	var resp struct {
		CryptoKeys []struct {
			Name string `json:"name"`
		} `json:"cryptoKeys"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		*diags = append(*diags, ringID+": "+readBody("cryptoKeys.list", status).Error())
		return nil, false
	}
	var names []string
	for _, k := range resp.CryptoKeys {
		names = append(names, k.Name)
	}
	return names, true
}

// discoverGCPLocations enumerates the locationId values a location-scoped GCP
// service exposes for the project (GET {base}/projects/{p}/locations). label
// names the service in any error, so callers stay legible.
func (d *Driver) discoverGCPLocations(base, label string) ([]string, error) {
	status, body, err := d.call("GET", fmt.Sprintf(
		"%s/projects/%s/locations", base, d.Project), nil)
	if err != nil {
		return nil, fmt.Errorf("%s locations.list: %v", label, err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s locations.list: HTTP %d", label, status)
	}
	var resp struct {
		Locations []struct {
			LocationID string `json:"locationId"`
		} `json:"locations"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, readBody("locations.list", status)
	}
	var out []string
	for _, l := range resp.Locations {
		if l.LocationID != "" {
			out = append(out, l.LocationID)
		}
	}
	return out, nil
}
