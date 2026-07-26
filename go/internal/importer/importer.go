// Package importer translates terraform/pulumi state into ADOPTION
// HINTS (D53) — mapping suggestions and expected attributes, never a
// contract and never observations. State stores normalized, coerced,
// provider-defaulted values; live observations win every disagreement,
// which is why hint values carry the label "expected" and no
// derivation claim. PURE: no cloud calls, no ledger writes.
//
// Secrets are structurally excluded: values cross into hints only
// through the explicit per-path mapping below — nothing is ever copied
// from state wholesale.
package importer

import (
	"fmt"
	"sort"
	"strings"

	"groundhold/internal/gcp"
)

type Hint struct {
	Address      string         `json:"address"`
	ResourceType string         `json:"resourceType"`
	ProviderID   string         `json:"providerId"`
	Expected     map[string]any `json:"expected"`
	Notes        []string       `json:"notes,omitempty"`
}

type Source struct {
	Format  string `json:"format"` // tfstate | pulumi
	Version any    `json:"version,omitempty"`
	Serial  any    `json:"serial,omitempty"`
	Lineage string `json:"lineage,omitempty"`
}

type Result struct {
	Kind        string   `json:"kind"`
	APIVersion  string   `json:"apiVersion"`
	Source      Source   `json:"source"`
	Hints       []Hint   `json:"hints"`
	Diagnostics []string `json:"diagnostics,omitempty"`
}

// DetectFormat: tfstate v4 has top-level "version"+"resources"; a
// pulumi checkpoint has "deployment" (or "checkpoint"). Unknown shapes
// are an error, never a guess.
func DetectFormat(doc map[string]any) (string, error) {
	if _, ok := doc["deployment"]; ok {
		return "pulumi", nil
	}
	if _, ok := doc["checkpoint"]; ok {
		return "pulumi", nil
	}
	_, hasRes := doc["resources"]
	_, hasVer := doc["version"]
	if hasRes && hasVer {
		return "tfstate", nil
	}
	return "", fmt.Errorf("unrecognized state format — expected a " +
		"terraform state (version+resources) or a pulumi checkpoint " +
		"(deployment)")
}

func Map(doc map[string]any, format string) (*Result, error) {
	if format == "" || format == "auto" {
		f, err := DetectFormat(doc)
		if err != nil {
			return nil, err
		}
		format = f
	}
	switch format {
	case "tfstate":
		return mapTFState(doc)
	case "pulumi":
		return mapPulumi(doc)
	}
	return nil, fmt.Errorf("unknown format %q", format)
}

// ---- terraform ----

func mapTFState(doc map[string]any) (*Result, error) {
	res := &Result{Kind: "AdoptionHints", APIVersion: "hints/v0",
		Source: Source{Format: "tfstate", Version: doc["version"],
			Serial: doc["serial"]}, Hints: []Hint{}}
	if l, ok := doc["lineage"].(string); ok {
		res.Source.Lineage = l
	}
	resources, _ := doc["resources"].([]any)
	for _, r := range resources {
		rm, _ := r.(map[string]any)
		rtype, _ := rm["type"].(string)
		rname, _ := rm["name"].(string)
		if mode, _ := rm["mode"].(string); mode == "data" {
			res.Diagnostics = append(res.Diagnostics, fmt.Sprintf(
				"data.%s.%s: data source, skipped", rtype, rname))
			continue
		}
		addr := rtype + "." + rname
		switch rtype {
		case "google_sql_database_instance":
			instances, _ := rm["instances"].([]any)
			for i, inst := range instances {
				im, _ := inst.(map[string]any)
				attrs, _ := im["attributes"].(map[string]any)
				iaddr := addr
				// count/for_each instances get distinct addresses —
				// duplicate keys made hint order nondeterministic and
				// hints indistinguishable (review fix)
				if key, ok := im["index_key"]; ok {
					iaddr = fmt.Sprintf("%s[%v]", addr, key)
				} else if len(instances) > 1 {
					iaddr = fmt.Sprintf("%s[%d]", addr, i)
				}
				h, notes, ok := tfCloudSQL(iaddr, attrs)
				res.Diagnostics = append(res.Diagnostics, notes...)
				if ok {
					res.Hints = append(res.Hints, h)
				}
			}
		case "google_sql_database", "google_sql_user":
			res.Diagnostics = append(res.Diagnostics, fmt.Sprintf(
				"%s: composite child of an instance — adopt the "+
					"instance; children ride along", addr))
		default:
			res.Diagnostics = append(res.Diagnostics, fmt.Sprintf(
				"%s: no vocabulary mapping for %s, skipped", addr, rtype))
		}
	}
	sortHints(res.Hints)
	return res, nil
}

// cloudSQLIdentity composes project:region:name and cross-checks it
// against connection_name and self_link when state carries them. A
// disagreement REFUSES the identity (the caller drops the hint) —
// mis-seeded adoptions are worse than no suggestion, so we never guess
// which of the disagreeing fields is right.
func cloudSQLIdentity(addr, project, region, name string,
	connectionName, selfLink any) (string, []string, bool) {
	if project == "" || region == "" || name == "" {
		return "", []string{addr + ": project/region/name incomplete — " +
			"providerId suggestion unavailable"}, true
	}
	pid := project + ":" + region + ":" + name
	if cn, ok := connectionName.(string); ok && cn != "" && cn != pid {
		return "", []string{fmt.Sprintf(
			"%s: identity disagreement — connection_name %q vs composed "+
				"%q; hint refused, resolve the state manually", addr, cn,
			pid)}, false
	}
	if sl, ok := selfLink.(string); ok && sl != "" &&
		!(strings.Contains(sl, "/projects/"+project+"/") &&
			strings.HasSuffix(sl, "/instances/"+name)) {
		return "", []string{fmt.Sprintf(
			"%s: identity disagreement — self_link %q does not match "+
				"project %q + name %q; hint refused, resolve the state "+
				"manually", addr, sl, project, name)}, false
	}
	return pid, nil, true
}

// tfCloudSQL maps the FLATTENED tfstate attribute schema (settings and
// ip_configuration are lists) through the same enum tables the API
// observe mapper uses. ok=false means the hint is refused entirely.
func tfCloudSQL(addr string, attrs map[string]any) (Hint, []string, bool) {
	h := Hint{Address: addr,
		ResourceType: "capability.database.relational",
		Expected:     map[string]any{}}
	var notes []string

	project, _ := attrs["project"].(string)
	region, _ := attrs["region"].(string)
	name, _ := attrs["name"].(string)
	pid, idDiags, ok := cloudSQLIdentity(addr, project, region, name,
		attrs["connection_name"], attrs["self_link"])
	notes = append(notes, idDiags...)
	if !ok {
		return Hint{}, notes, false
	}
	h.ProviderID = pid

	if dv, ok := attrs["database_version"].(string); ok {
		if proto, ok := gcp.VersionToProtocol(dv); ok {
			h.Expected["engine.protocol"] = proto
		} else {
			notes = append(notes, fmt.Sprintf(
				"%s: database_version %q unknown, skipped", addr, dv))
		}
	}
	if region != "" {
		h.Expected["location.region"] = region
	}

	settings := firstBlock(attrs["settings"])
	if at, ok := settings["availability_type"].(string); ok {
		if class, ok := gcp.AvailabilityToClass(at); ok {
			h.Expected["availability.class"] = class
		} else {
			notes = append(notes, fmt.Sprintf(
				"%s: availability_type %q unknown, skipped", addr, at))
		}
	}
	ipConfig := firstBlock(settings["ip_configuration"])
	if ipv4, ok := ipConfig["ipv4_enabled"].(bool); ok {
		// config intent only — state has no address evidence; live
		// discovery is the authority
		h.Expected["network.publicExposure"] = ipv4
	}
	backup := firstBlock(settings["backup_configuration"])
	if enabled, ok := backup["enabled"].(bool); ok && enabled {
		if pitr, _ := backup["point_in_time_recovery_enabled"].(bool); pitr {
			notes = append(notes, addr+": PITR enabled — recovery.rpo "+
				"value requires a probe, no hint emitted")
		} else {
			h.Expected["recovery.rpo"] = "24h"
		}
	}
	h.Expected["service.managed"] = true

	if dp, ok := attrs["deletion_protection"].(bool); ok && !dp {
		h.Notes = append(h.Notes, "deletion_protection is OFF in state — "+
			"Groundhold defaults protection ON at first update/replace")
	}
	return h, notes, true
}

// firstBlock unwraps terraform's list-of-one block encoding.
func firstBlock(v any) map[string]any {
	if l, ok := v.([]any); ok && len(l) > 0 {
		m, _ := l[0].(map[string]any)
		return m
	}
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

// ---- pulumi ----

func mapPulumi(doc map[string]any) (*Result, error) {
	res := &Result{Kind: "AdoptionHints", APIVersion: "hints/v0",
		Source: Source{Format: "pulumi", Version: doc["version"]},
		Hints:  []Hint{}}
	dep, _ := doc["deployment"].(map[string]any)
	if dep == nil {
		if cp, ok := doc["checkpoint"].(map[string]any); ok {
			dep, _ = cp["latest"].(map[string]any)
		}
	}
	resources, _ := dep["resources"].([]any)
	for _, r := range resources {
		rm, _ := r.(map[string]any)
		rtype, _ := rm["type"].(string)
		urn, _ := rm["urn"].(string)
		switch rtype {
		case "gcp:sql/databaseInstance:DatabaseInstance":
			// pulumi OUTPUTS mirror the provider API response — the
			// last state pulumi saw; inputs are desires, outputs are
			// the closest thing state has to reality
			outputs, _ := rm["outputs"].(map[string]any)
			h, notes, ok := pulumiCloudSQL(urn, outputs)
			res.Diagnostics = append(res.Diagnostics, notes...)
			if ok {
				res.Hints = append(res.Hints, h)
			}
		case "gcp:sql/database:Database", "gcp:sql/user:User":
			res.Diagnostics = append(res.Diagnostics, fmt.Sprintf(
				"%s: composite child of an instance — adopt the "+
					"instance; children ride along", urn))
		default:
			if rtype != "" && !strings.HasPrefix(rtype, "pulumi:") {
				res.Diagnostics = append(res.Diagnostics, fmt.Sprintf(
					"%s: no vocabulary mapping for %s, skipped", urn, rtype))
			}
		}
	}
	sortHints(res.Hints)
	return res, nil
}

func pulumiCloudSQL(urn string,
	outputs map[string]any) (Hint, []string, bool) {
	h := Hint{Address: urn,
		ResourceType: "capability.database.relational",
		Expected:     map[string]any{}}
	var notes []string

	project, _ := outputs["project"].(string)
	region, _ := outputs["region"].(string)
	name, _ := outputs["name"].(string)
	pid, idDiags, ok := cloudSQLIdentity(urn, project, region, name,
		outputs["connectionName"], outputs["selfLink"])
	notes = append(notes, idDiags...)
	if !ok {
		return Hint{}, notes, false
	}
	h.ProviderID = pid

	if dv, ok := outputs["databaseVersion"].(string); ok {
		if proto, ok := gcp.VersionToProtocol(dv); ok {
			h.Expected["engine.protocol"] = proto
		} else {
			notes = append(notes, fmt.Sprintf(
				"%s: databaseVersion %q unknown, skipped", urn, dv))
		}
	}
	if region != "" {
		h.Expected["location.region"] = region
	}
	settings, _ := outputs["settings"].(map[string]any)
	if at, ok := settings["availabilityType"].(string); ok {
		if class, ok := gcp.AvailabilityToClass(at); ok {
			h.Expected["availability.class"] = class
		} else {
			notes = append(notes, fmt.Sprintf(
				"%s: availabilityType %q unknown, skipped", urn, at))
		}
	}
	ipConfig, _ := settings["ipConfiguration"].(map[string]any)
	if ipv4, ok := ipConfig["ipv4Enabled"].(bool); ok {
		h.Expected["network.publicExposure"] = ipv4
	}
	backup, _ := settings["backupConfiguration"].(map[string]any)
	if enabled, ok := backup["enabled"].(bool); ok && enabled {
		if pitr, _ := backup["pointInTimeRecoveryEnabled"].(bool); pitr {
			notes = append(notes, urn+": PITR enabled — recovery.rpo "+
				"value requires a probe, no hint emitted")
		} else {
			h.Expected["recovery.rpo"] = "24h"
		}
	}
	h.Expected["service.managed"] = true

	if dp, ok := outputs["deletionProtection"].(bool); ok && !dp {
		h.Notes = append(h.Notes, "deletionProtection is OFF in state — "+
			"Groundhold defaults protection ON at first update/replace")
	}
	return h, notes, true
}

func sortHints(hints []Hint) {
	sort.Slice(hints, func(i, j int) bool {
		return hints[i].Address < hints[j].Address
	})
}
