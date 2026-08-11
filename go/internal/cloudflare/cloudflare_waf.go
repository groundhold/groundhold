package cloudflare

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"groundhold/internal/provider"
)

// Cloudflare WAF -> capability.security.waf (D874).
//
// SCHEMA-DERIVED, FIELD-UNVALIDATED. The shapes here come from Cloudflare's public
// api-schemas (credential-free): the firewall-managed rulesets entrypoint and the zone
// bot_management config. They were NOT confirmed against a live response — the token this
// was built with is DNS-scoped and 403s on both endpoints — so this stays deliberately narrow
// (only what the schema pins) and the field-validation-pending caveat lives in DESIGN D874
// and the vocab mapping rather than in a per-zone diagnostic that would repeat on every zone. A WAF-scoped token is what closes it (the D872 lesson: fixtures agree with each
// other, not necessarily with reality).
//
// The signal is the zone's http_request_firewall_managed phase entrypoint: a rule that
// EXECUTES one of Cloudflare's managed rulesets is a deployed managed WAF. Its override
// action tells prevention (block/challenge, the default) from detection (log) — the same
// axis aws.waf reads off OverrideAction None-vs-Count.

// managedRulesetIDs are Cloudflare's own managed rulesets — the ones whose deployment means
// "a managed WAF is on", as opposed to a customer's custom rules. These IDs are stable and
// documented (the Cloudflare Managed Ruleset and the OWASP Core Ruleset).
var managedRulesetIDs = map[string]string{
	"efb7b8c949ac4650a09736fc376e9aee": "Cloudflare Managed Ruleset",
	"4814384a9e5d4991b9815dcfc25d2f1f": "Cloudflare OWASP Core Ruleset",
}

const firewallManagedPhase = "http_request_firewall_managed"

type wafRule struct {
	Action           string `json:"action"`
	Enabled          bool   `json:"enabled"`
	ActionParameters struct {
		ID        string `json:"id"`
		Overrides struct {
			Action string `json:"action"`
		} `json:"overrides"`
	} `json:"action_parameters"`
}

// readFirewallEntrypoint reads the zone's managed-firewall entrypoint ruleset. A 404 is an
// AUTHORITATIVE answer — the zone deploys no managed ruleset (a free-tier zone often has no
// such phase) — and becomes managed.ruleset=false, not an error. Any other non-200 is
// unknown (four-valued honesty): the caller omits the attribute with a diagnostic.
func (d *Driver) readFirewallEntrypoint(zoneID string) (rules []wafRule, found bool, err error) {
	st, body, gerr := d.get("/zones/" + zoneID + "/rulesets/phases/" + firewallManagedPhase + "/entrypoint")
	if gerr != nil {
		return nil, false, gerr
	}
	if st == http.StatusNotFound {
		return nil, false, nil // authoritative: no managed WAF phase on this zone
	}
	if st != http.StatusOK {
		return nil, false, fmt.Errorf("rulesets entrypoint: HTTP %d", st)
	}
	var doc struct {
		Success bool `json:"success"`
		Result  struct {
			Rules []wafRule `json:"rules"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &doc) != nil || !doc.Success {
		return nil, false, fmt.Errorf("rulesets entrypoint: unreadable or unsuccessful response")
	}
	return doc.Result.Rules, true, nil
}

// managedWAFPosture reduces the entrypoint rules to (deployed, mode). Deployed = an ENABLED
// rule executing one of Cloudflare's managed rulesets. Mode = detection when that rule's
// override action is "log", prevention otherwise (the managed default blocks/challenges).
func managedWAFPosture(rules []wafRule) (deployed bool, mode string) {
	for _, r := range rules {
		if !r.Enabled || r.Action != "execute" {
			continue
		}
		if _, ok := managedRulesetIDs[r.ActionParameters.ID]; !ok {
			continue
		}
		if strings.EqualFold(r.ActionParameters.Overrides.Action, "log") {
			return true, "detection"
		}
		return true, "prevention"
	}
	return false, ""
}

// botManagement holds the fields that, across Cloudflare's three bot tiers, mean "bot
// protection is doing something": Bot Fight Mode (free), Super Bot Fight Mode (Pro/Biz),
// and Enterprise Bot Management. Over-reporting is the safe side of a security attribute,
// so ANY of them being active reads as protection on.
type botManagement struct {
	FightMode      bool   `json:"fight_mode"`
	SBFMAuto       string `json:"sbfm_definitely_automated"`
	SBFMLikely     string `json:"sbfm_likely_automated"`
	SBFMStatic     string `json:"sbfm_static_resource_protection"`
	EnableJS       bool   `json:"enable_js"`
	AIBotsProtect  string `json:"ai_bots_protection"`
	CrawlerProtect string `json:"crawler_protection"`
}

func (b botManagement) protecting() bool {
	if b.FightMode || b.EnableJS {
		return true
	}
	for _, a := range []string{b.SBFMAuto, b.SBFMLikely, b.SBFMStatic} {
		if a != "" && !strings.EqualFold(a, "allow") {
			return true
		}
	}
	return strings.EqualFold(b.AIBotsProtect, "block") || strings.EqualFold(b.CrawlerProtect, "block")
}

// readBotManagement reads the zone bot_management config. Non-200 (including 403 on a plan
// without bot management, or 404) is UNKNOWN — the caller omits bot.protection with a
// diagnostic rather than fabricate a false "off".
func (d *Driver) readBotManagement(zoneID string) (bm botManagement, found bool, err error) {
	st, body, gerr := d.get("/zones/" + zoneID + "/bot_management")
	if gerr != nil {
		return botManagement{}, false, gerr
	}
	if st == http.StatusNotFound {
		return botManagement{}, false, nil // authoritative: no bot management configured
	}
	if st != http.StatusOK {
		// 403 (token/plan without bot read) and 5xx are UNKNOWN, not "off".
		return botManagement{}, false, fmt.Errorf("bot_management: HTTP %d", st)
	}
	var doc struct {
		Success bool          `json:"success"`
		Result  botManagement `json:"result"`
	}
	if json.Unmarshal(body, &doc) != nil || !doc.Success {
		return botManagement{}, false, fmt.Errorf("bot_management: unreadable or unsuccessful response")
	}
	return doc.Result, true, nil
}

// mapZoneWAF is the pure reverse-map for one zone's WAF posture, shared by discover and
// Observe. Every derived observation is `measured`; a read that could not answer omits its
// attribute with a diagnostic (D44 four-valued honesty), never a fabricated default.
func (d *Driver) mapZoneWAF(zoneID string) ([]provider.Observation, []string) {
	obs := []provider.Observation{{Path: "service.managed", Value: true, Derivation: "measured"}}
	var diags []string
	rules, found, err := d.readFirewallEntrypoint(zoneID)
	switch {
	case err != nil:
		diags = append(diags, "managed.ruleset/policy.mode not observed: "+err.Error())
	case !found:
		// authoritative absence: no managed firewall phase -> no managed ruleset deployed.
		obs = append(obs, provider.Observation{Path: "managed.ruleset", Value: false, Derivation: "measured"})
	default:
		deployed, mode := managedWAFPosture(rules)
		obs = append(obs, provider.Observation{Path: "managed.ruleset", Value: deployed, Derivation: "measured"})
		if deployed {
			obs = append(obs, provider.Observation{Path: "policy.mode", Value: mode, Derivation: "measured"})
		}
	}

	bm, bfound, berr := d.readBotManagement(zoneID)
	switch {
	case berr != nil:
		diags = append(diags, "bot.protection not observed: "+berr.Error())
	case !bfound:
		// authoritative absence: no bot management configured on this zone.
		obs = append(obs, provider.Observation{Path: "bot.protection", Value: false, Derivation: "measured"})
	default:
		obs = append(obs, provider.Observation{Path: "bot.protection", Value: bm.protecting(), Derivation: "measured"})
	}
	return obs, diags
}

// wafProviderID pins the WAF posture to its zone: cfwaf:<zoneId>. One WAF capability per
// zone (the zone is Cloudflare's WAF boundary), mirroring dns:<zoneId>:<recordId>.
func (d *Driver) wafProviderID(zoneID string) string { return "cfwaf:" + zoneID }

func parseWAFProviderID(id string) (zoneID string, ok bool) {
	parts := strings.Split(id, ":")
	if len(parts) != 2 || parts[0] != "cfwaf" || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}
