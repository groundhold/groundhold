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

	"groundhold/internal/scalars"
)

const webtestAPIVersion = "2022-06-15"

var webtestHostOK = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// azWebtestFrequencies is the closed set of frequencies (seconds) Azure permits.
var azWebtestFrequencies = map[int]bool{300: true, 600: true, 900: true}

// AzureWebtestPlan is the attribute-derived shape a create assembles.
type AzureWebtestPlan struct {
	Name          string
	URL           string
	FrequencySec  int
	AppInsightsID string
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
	return p, nil
}

func (p AzureWebtestPlan) createBody(tags map[string]any) map[string]any {
	// link the test to its App Insights component (hidden-link tag).
	tags["hidden-link:"+p.AppInsightsID] = "Resource"
	return map[string]any{
		"location": "global",
		"kind":     "ping",
		"tags":     tags,
		"properties": map[string]any{
			"SyntheticMonitorId": p.Name,
			"Name":               p.Name,
			"Enabled":            true,
			"Frequency":          p.FrequencySec,
			"Timeout":            30,
			"Kind":               "ping",
			"Locations":          []any{map[string]any{"Id": "us-tx-sn1-azr"}},
			"Request":            map[string]any{"RequestUrl": p.URL},
			"ValidationRules":    map[string]any{"ExpectedHttpStatusCode": 200},
		},
	}
}
