// Azure Communication Services Email request building (D76 fala 4): the Azure half
// of capability.email.sending — the SAME vocabulary AWS SES fulfils (aws.ses-sending),
// honored-or-refused per Azure's shape. Authenticated outbound email as a governed
// capability: residency (data location), the authentication posture (DKIM signing —
// the proof a domain may send), and whether bounces/complaints are tracked.
//
// The composite (D26): Microsoft.Communication/emailServices/{name} (the sending
// service, carrying the immutable dataLocation residency) + — iff DKIM is asked —
// an emailServices/{name}/domains/{domain} sub-resource (customer- or azure-managed),
// whose verificationStates.DKIM is the authentication proof. The domain is an
// OPERAND (the operator owns the FQDN, or Azure assigns an azure-managed subdomain);
// this driver never stands up DNS — like SES it does NOT block create on DKIM
// verification (the operator publishes the records; observe reports the status
// honestly).
//
// The honest divergences from SES (the same discipline as azacr.go's scanOnPush):
//   - location.region maps to the ACS dataLocation (a residency string like "Europe"),
//     NOT an Azure region — the emailService resource itself is always location=global.
//     dataLocation is FIXED at creation (immutable — a change is a replacement).
//   - bounce.tracked has NO clean per-emailService mapping. ACS Email delivery/bounce
//     reports are Event Grid events emitted by the LINKED Microsoft.Communication/
//     communicationServices resource (via a system topic + an operator event handler),
//     NOT a property of the emailService+domains composite this driver owns. There is
//     no SES-style "configuration set with a BOUNCE event destination" on the sending
//     service. So bounce.tracked=true is HONEST-REFUSED (nothing on this composite to
//     provision; directs the author to an Event Grid subscription on the comm-services
//     resource), classify marks it unsupported (deliberately-not-mutable — no updater
//     owed), and observe OMITS it with a diagnostic rather than fabricate "not tracked".
package azure

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const acsEmailAPIVersion = "2023-04-01"

// acsEmailNameOK bounds an emailService resource name: 1-63 of alnum, hyphen,
// underscore, period (the ARM Communication resource-name charset).
var acsEmailNameOK = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

// acsDomainOK bounds a customer sending domain (FQDN): alnum/hyphen labels, at
// least one dot, an alphabetic TLD. It is the ARM domain sub-resource name.
var acsDomainOK = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$`)

// azureManagedDomainName is the fixed ARM name of an azure-managed domain — Azure
// assigns the actual subdomain (of azurecomm.net); the operator names no FQDN.
const azureManagedDomainName = "AzureManagedDomain"

// acsDataLocations maps a lowercased residency input to the canonical ACS
// dataLocation ARM spelling. location.region is a RESIDENCY (where the sending
// service's data lives), not an Azure region — so an unknown value is REFUSED
// (never silently placed in the wrong jurisdiction). EU residency is "Europe".
var acsDataLocations = map[string]string{
	"africa":               "Africa",
	"asia pacific":         "Asia Pacific",
	"asiapacific":          "Asia Pacific",
	"australia":            "Australia",
	"brazil":               "Brazil",
	"canada":               "Canada",
	"europe":               "Europe",
	"france":               "France",
	"germany":              "Germany",
	"india":                "India",
	"japan":                "Japan",
	"korea":                "Korea",
	"norway":               "Norway",
	"switzerland":          "Switzerland",
	"uae":                  "UAE",
	"united arab emirates": "UAE",
	"uk":                   "UK",
	"united kingdom":       "UK",
	"united states":        "United States",
	"usa":                  "United States",
	"us":                   "United States",
}

// canonACSDataLocation resolves a residency input to the canonical ACS ARM
// spelling; ok=false when it is not a recognized ACS data location.
func canonACSDataLocation(region string) (string, bool) {
	v, ok := acsDataLocations[strings.ToLower(strings.TrimSpace(region))]
	return v, ok
}

// ACSEmailPlan is the attribute+operand-derived shape a create assembles. The SHAPE
// (residency, DKIM posture) is driven by CAPABILITY attributes; the placement
// operands (resource group, the emailService name, the sending domain) are OPERATOR
// input (implementation: block, D26).
type ACSEmailPlan struct {
	Name             string // emailService resource name (operand, else deterministic)
	ResourceGroup    string // operand, required
	DataLocation     string // location.region -> canonical ACS dataLocation (residency)
	DKIM             bool   // authentication.dkim -> a domain sub-resource with DKIM
	DomainName       string // the ARM domain resource name (FQDN or AzureManagedDomain)
	DomainManagement string // "CustomerManaged" | "AzureManaged" (empty iff !DKIM)
}

func acsEmailName(environment, capability string, generation int) string {
	return azResourceName("pv-acsem", environment, capability, generation)
}

// BuildACSEmail maps capability.email.sending attributes + implementation operands
// to a plan, or REFUSES. Every error is a preflight refusal (never a half-build): an
// unmapped attribute, an unmappable posture (bounce.tracked), or a missing/invalid
// required operand is refused here, before the first ARM mutation (D26).
func BuildACSEmail(environment, capability string,
	attrs, impl map[string]any, generation int) (ACSEmailPlan, error) {
	if generation < 1 {
		generation = 1
	}
	p := ACSEmailPlan{Name: acsEmailName(environment, capability, generation)}

	// an explicit emailService name operand overrides the deterministic one.
	if given := strings.TrimSpace(implStringAz(impl, "email_service_name")); given != "" {
		if !acsEmailNameOK.MatchString(given) {
			return ACSEmailPlan{}, fmt.Errorf("implementation.email_service_name %q is invalid (1-63 alnum, '.', '-', '_')", given)
		}
		p.Name = given
	}

	// --- CAPABILITY attributes drive the SHAPE (refuse any unmapped attribute) ---
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	for _, path := range paths {
		raw := attrs[path]
		switch path {
		case "location.region":
			s, _ := raw.(string)
			canon, ok := canonACSDataLocation(s)
			if !ok {
				return ACSEmailPlan{}, fmt.Errorf(
					"location.region %q is not a recognized ACS Email data location (residency) — "+
						"refusing rather than placing the sending service in an unknown jurisdiction "+
						"(e.g. \"Europe\", \"United States\", \"UK\", \"Australia\")", s)
			}
			p.DataLocation = canon
		case "authentication.dkim":
			b, ok := raw.(bool)
			if !ok {
				return ACSEmailPlan{}, fmt.Errorf("authentication.dkim must be a bool")
			}
			p.DKIM = b
		case "bounce.tracked":
			b, ok := raw.(bool)
			if !ok {
				return ACSEmailPlan{}, fmt.Errorf("bounce.tracked must be a bool")
			}
			if b {
				return ACSEmailPlan{}, fmt.Errorf(
					"bounce.tracked=true cannot be honored on the ACS Email service — Azure has no " +
						"SES-style bounce sink on the sending service (the honest divergence from ses-sending's " +
						"configuration-set event destination). ACS Email delivery/bounce reports are Event Grid " +
						"events (EmailDeliveryReportReceived) emitted by the LINKED Microsoft.Communication/" +
						"communicationServices resource via a system topic + an operator event handler — a separate " +
						"resource graph, not a property of the emailService+domains composite. Declare bounce tracking " +
						"as an Event Grid subscription on the communication-services resource, not on the sender. groundhold " +
						"will not provision a per-emailService field that does not exist, nor fake it")
			}
			// bounce.tracked=false/absent: nothing to provision on the sending service.
		case "service.managed":
			if raw != true {
				return ACSEmailPlan{}, fmt.Errorf("service.managed=false cannot be honored — groundhold manages the sending identity it stands up")
			}
		case "sending.productionAccess":
			// SES has an account-level sandbox gate; ACS Email has NO equivalent sandbox
			// (a verified domain sends to arbitrary recipients). This is not an ACS concept,
			// so it is neither provisioned nor observed here. Accept the type, then ignore.
			if _, ok := raw.(bool); !ok {
				return ACSEmailPlan{}, fmt.Errorf("sending.productionAccess must be a bool")
			}
		default:
			return ACSEmailPlan{}, fmt.Errorf(
				"attribute %s has no ACS Email mapping — refusing rather than silently dropping it "+
					"(the email.sending vocab governs location.region + authentication.dkim + bounce.tracked)", path)
		}
	}

	// --- OPERATOR operands supply the placement (implementation: block, D26) ---
	p.ResourceGroup = strings.TrimSpace(implStringAz(impl, "resource_group"))
	if !rgOK.MatchString(p.ResourceGroup) {
		return ACSEmailPlan{}, fmt.Errorf("azure ACS Email requires implementation.resource_group")
	}
	if p.DataLocation == "" {
		return ACSEmailPlan{}, fmt.Errorf("capability.email.sending requires location.region (the ACS Email data location / residency)")
	}

	// the domain (DKIM proof) is REQUIRED iff DKIM is asked — DKIM is intrinsic to an
	// ACS sending domain, so there is no DKIM without a domain. A domain given but
	// DKIM not asked is an ambiguous shape (parity with the ses-sending bounce operand).
	mgmt := strings.TrimSpace(implStringAz(impl, "domain_management"))
	domain := strings.TrimSpace(implStringAz(impl, "domain"))
	if p.DKIM {
		if mgmt == "" {
			mgmt = "AzureManaged" // default: Azure assigns a pre-verified azurecomm.net subdomain
		}
		switch mgmt {
		case "AzureManaged":
			if domain != "" && domain != azureManagedDomainName {
				return ACSEmailPlan{}, fmt.Errorf(
					"implementation.domain %q was given with domain_management=AzureManaged, but Azure assigns "+
						"the azure-managed subdomain — omit implementation.domain (or set it to %q)", domain, azureManagedDomainName)
			}
			p.DomainName = azureManagedDomainName
		case "CustomerManaged":
			if !acsDomainOK.MatchString(domain) {
				return ACSEmailPlan{}, fmt.Errorf(
					"authentication.dkim=true with domain_management=CustomerManaged requires a valid " +
						"implementation.domain (the FQDN you own — the DKIM records get published in its DNS)")
			}
			p.DomainName = domain
		default:
			return ACSEmailPlan{}, fmt.Errorf(
				"implementation.domain_management %q is invalid (AzureManaged | CustomerManaged)", mgmt)
		}
		p.DomainManagement = mgmt
	} else if domain != "" || mgmt != "" {
		return ACSEmailPlan{}, fmt.Errorf(
			"implementation.domain/domain_management was given but authentication.dkim is not true — " +
				"a sending domain only attaches to the DKIM posture; refusing an ambiguous shape")
	}
	return p, nil
}

// classifyACSEmailChange (D46): PURE — which capability.email.sending transitions can
// ACS Email honor in place? authentication.dkim is mutable via the domain sub-resource
// (add the domain to enable, remove it to disable) — so an updater is owed and wired.
// location.region (dataLocation) is FIXED at emailService creation (a residency change
// is a replacement, not a patch). bounce.tracked is unsupported — a subscription-level
// Event Grid concern on the linked comm-services resource, not a sender toggle
// (deliberately-not-mutable — NOT mutable-without-updater, so no updater owed).
func classifyACSEmailChange(path string) (string, string) {
	switch path {
	case "authentication.dkim":
		return "mutable", "in-place by adding (a domain sub-resource) or removing the DKIM sending domain"
	case "bounce.tracked":
		return "unsupported", "bounce tracking on ACS Email is not a sender property — delivery/bounce reports are " +
			"Event Grid events on the LINKED Microsoft.Communication/communicationServices resource (a system topic + " +
			"an operator event handler), not a per-emailService toggle groundhold can patch on the sending service"
	case "location.region":
		return "immutable", "an ACS Email service's dataLocation (residency) is fixed at creation — a change is a replacement"
	case "sending.productionAccess":
		return "unsupported", "ACS Email has no sandbox/production-access gate (not an ACS concept) — nothing to patch"
	case "service.managed":
		return "unsupported", "platform/projection property — nothing to patch"
	default:
		return "unsupported", "no ACS Email in-place mapping for " + path
	}
}
