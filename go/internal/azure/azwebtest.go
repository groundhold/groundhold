// Azure Application Insights availability test request building (D108): the Azure half
// of the capability.monitoring.uptime driver — the SAME vocabulary GCP uptime checks and
// AWS Route 53 health checks fulfil. An availability test probes a URL. Two honest
// Azure-specific gaps the domain exists to surface: it is HTTP(S)-ONLY, so
// check.protocol=tcp is REFUSED; and its Frequency is 300s/600s/900s only, so a
// check.period Azure cannot honor is refused, not rounded. A test links to an
// Application Insights component (implementation.app_insights_id).
package azure

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"groundhold/internal/scalars"
)

const webtestAPIVersion = "2022-06-15"

var webtestHostOK = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// xmlEscaper escapes the values interpolated into the WebTest XML blob (D902b);
// xmlUnescaper reverses it when observe reads the URL back out.
var xmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
var xmlUnescaper = strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'")

// azWebtestFrequencies is the closed set of frequencies (seconds) Azure permits.
var azWebtestFrequencies = map[int]bool{300: true, 600: true, 900: true}

// AzureWebtestPlan is the attribute-derived shape a create assembles.
type AzureWebtestPlan struct {
	Name          string
	URL           string
	FrequencySec  int
	AppInsightsID string
	Location      string // D902: a web test is REGIONAL — "global" is rejected by Azure
}

// BuildAzureWebtest maps capability.monitoring.uptime attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildAzureWebtest(environment, capability string,
	attrs, impl map[string]any, generation int) (AzureWebtestPlan, error) {
	p := AzureWebtestPlan{Name: azResourceName("pv-webtest", environment, capability, generation)}
	var host, path, proto string
	protoSet, periodSet := false, false
	paths := make([]string, 0, len(attrs))
	for k := range attrs {
		paths = append(paths, k)
	}
	sort.Strings(paths)

	for _, ap := range paths {
		raw := attrs[ap]
		switch ap {
		case "check.target":
			host, _ = raw.(string)
			if !webtestHostOK.MatchString(host) {
				return AzureWebtestPlan{}, fmt.Errorf("check.target %q is not a valid host", host)
			}
		case "check.protocol":
			switch raw {
			case "http", "https":
				proto, _ = raw.(string)
			case "tcp":
				return AzureWebtestPlan{}, fmt.Errorf(
					"check.protocol=tcp cannot be honored — an Azure availability test is HTTP(S)-only")
			default:
				return AzureWebtestPlan{}, fmt.Errorf("check.protocol %v has no mapping", raw)
			}
			protoSet = true
		case "check.path":
			path, _ = raw.(string)
		case "check.period":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Duration {
				return AzureWebtestPlan{}, fmt.Errorf("check.period is not a duration")
			}
			ms, _ := s.Value.(float64)
			p.FrequencySec = int(ms / 1000)
			periodSet = true
		case "service.managed":
			if raw != true {
				return AzureWebtestPlan{}, fmt.Errorf("service.managed=false cannot be honored by Azure Monitor")
			}
		default:
			return AzureWebtestPlan{}, fmt.Errorf(
				"attribute %s has no availability-test mapping — refusing rather than silently dropping it", ap)
		}
	}
	if host == "" {
		return AzureWebtestPlan{}, fmt.Errorf("availability test requires check.target")
	}
	if !protoSet {
		return AzureWebtestPlan{}, fmt.Errorf("availability test requires check.protocol")
	}
	if !periodSet {
		return AzureWebtestPlan{}, fmt.Errorf("availability test requires check.period")
	}
	if !azWebtestFrequencies[p.FrequencySec] {
		return AzureWebtestPlan{}, fmt.Errorf(
			"check.period=%ds cannot be honored — an Azure availability test frequency must be 300s, 600s or 900s "+
				"(refusing rather than rounding to a different real interval)", p.FrequencySec)
	}
	p.URL = proto + "://" + host + path
	p.AppInsightsID, _ = impl["app_insights_id"].(string)
	if p.AppInsightsID == "" {
		return AzureWebtestPlan{}, fmt.Errorf(
			"azure availability test requires implementation.app_insights_id (the App Insights component it links to)")
	}
	// D902: an Application Insights web test is REGIONAL — Azure rejects location
	// "global" ("Unsupported location: global"). The region must be supplied (it must
	// match the linked component's region), never defaulted to a location the platform
	// refuses. Refuse rather than hardcode a value that cannot be created.
	p.Location, _ = impl["location"].(string)
	if p.Location == "" {
		return AzureWebtestPlan{}, fmt.Errorf(
			"azure availability test requires implementation.location (the region it lives in — a web test is " +
				"regional, and Azure refuses the location \"global\"); it must match the App Insights component's region")
	}
	return p, nil
}

// webtestConfigXML builds the WebTest XML blob Azure requires under
// properties.Configuration.WebTest (D902b). A ping test is not fully specified by the
// structured Request/Locations fields alone — Azure rejects a create whose Configuration
// is absent ("'properties.Configuration.WebTest' must be specified"). The GUIDs are
// DETERMINISTIC (derived from the plan) so a re-created test is byte-identical rather than
// churning on every apply.
func (p AzureWebtestPlan) webtestConfigXML() string {
	esc := func(s string) string {
		return xmlEscaper.Replace(s)
	}
	testGUID := azAssignmentGUID(p.Name, p.URL, "webtest")
	reqGUID := azAssignmentGUID(p.URL, p.Name, "webtest-request")
	return `<WebTest Name="` + esc(p.Name) + `" Id="` + testGUID + `" Enabled="True" CssProjectStructure="" ` +
		`CssIteration="" Timeout="30" WorkItemIds="" xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010" ` +
		`Description="" CredentialUserName="" CredentialPassword="" PreAuthenticate="True" Proxy="default" ` +
		`StopOnError="False" RecordedResultFile="" ResultsLocale=""><Items>` +
		`<Request Method="GET" Guid="` + reqGUID + `" Version="1.1" Url="` + esc(p.URL) + `" ThinkTime="0" ` +
		`Timeout="30" ParseDependentRequests="False" FollowRedirects="True" RecordResult="True" Cache="False" ` +
		`ResponseTimeGoal="0" Encoding="utf-8" ExpectedHttpStatusCode="200" ExpectedResponseUrl="" ` +
		`ReportingName="" IgnoreHttpStatusCode="False" /></Items></WebTest>`
}

func (p AzureWebtestPlan) createBody(tags map[string]any) map[string]any {
	// link the test to its App Insights component (hidden-link tag).
	tags["hidden-link:"+p.AppInsightsID] = "Resource"
	return map[string]any{
		"location": p.Location,
		"kind":     "ping",
		"tags":     tags,
		"properties": map[string]any{
			"SyntheticMonitorId": p.Name,
			"Name":               p.Name,
			"Description":        "",
			"Enabled":            true,
			"Frequency":          p.FrequencySec,
			"Timeout":            30,
			"Kind":               "ping",
			"RetryEnabled":       true,
			"Locations":          []any{map[string]any{"Id": "us-tx-sn1-azr"}},
			// D902b: the request URL, status expectation and verb live in the WebTest XML
			// blob Azure requires here — a structured "Request"/"ValidationRules" pair is
			// rejected ("Value cannot be null. Parameter name: format"); the XML is the
			// authority the ping test is created from.
			"Configuration": map[string]any{"WebTest": p.webtestConfigXML()},
		},
	}
}
