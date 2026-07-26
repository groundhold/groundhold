// GCP Cloud Monitoring uptime check request building (D108): the semantic core of the
// GCP capability.monitoring.uptime driver — the SAME vocabulary AWS Route 53 health
// checks and Azure availability tests fulfil. A check probes an endpoint over
// HTTP/HTTPS/TCP on a fixed period. GCP permits periods of 60s/300s/600s/900s; a period
// it cannot honor is refused, not rounded. tcp uses a tcpCheck (port from impl); a path
// is refused for tcp. Ownership is userLabels; the config id is server-assigned.
package gcp

import (
	"fmt"
	"regexp"

	"groundhold/internal/scalars"
)

const uptimeBaseURL = "https://monitoring.googleapis.com/v3"

var uptimeHostOK = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// gcpUptimePeriods is the closed set of periods (seconds) GCP uptime checks permit.
var gcpUptimePeriods = map[int]bool{60: true, 300: true, 600: true, 900: true}

// UptimePlan is the attribute-derived shape a create assembles.
type UptimePlan struct {
	DisplayName string
	Host        string
	IsTCP       bool
	UseSsl      bool
	Path        string
	Port        int
	PeriodSec   int
}

// BuildUptimeCheck maps capability.monitoring.uptime attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildUptimeCheck(project, environment, capability string,
	attrs, impl map[string]any, generation int) (UptimePlan, error) {
	p := UptimePlan{DisplayName: resourceName(project, environment, capability, generation, 63)}
	protoSet, periodSet := false, false
	for _, path := range sortedKeysG(attrs) {
		raw := attrs[path]
		switch path {
		case "check.target":
			p.Host, _ = raw.(string)
			if !uptimeHostOK.MatchString(p.Host) {
				return UptimePlan{}, fmt.Errorf("check.target %q is not a valid host", p.Host)
			}
		case "check.protocol":
			switch raw {
			case "http":
				p.IsTCP, p.UseSsl = false, false
			case "https":
				p.IsTCP, p.UseSsl = false, true
			case "tcp":
				p.IsTCP = true
			default:
				return UptimePlan{}, fmt.Errorf("check.protocol %v has no mapping", raw)
			}
			protoSet = true
		case "check.path":
			p.Path, _ = raw.(string)
		case "check.period":
			s, err := scalars.Parse(raw)
			if err != nil || s.Kind != scalars.Duration {
				return UptimePlan{}, fmt.Errorf("check.period is not a duration")
			}
			ms, _ := s.Value.(float64)
			p.PeriodSec = int(ms / 1000)
			periodSet = true
		case "service.managed":
			if raw != true {
				return UptimePlan{}, fmt.Errorf("service.managed=false cannot be honored by Cloud Monitoring")
			}
		default:
			return UptimePlan{}, fmt.Errorf(
				"attribute %s has no uptime-check mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.Host == "" {
		return UptimePlan{}, fmt.Errorf("uptime check requires check.target")
	}
	if !protoSet {
		return UptimePlan{}, fmt.Errorf("uptime check requires check.protocol")
	}
	if !periodSet {
		return UptimePlan{}, fmt.Errorf("uptime check requires check.period")
	}
	if !gcpUptimePeriods[p.PeriodSec] {
		return UptimePlan{}, fmt.Errorf(
			"check.period=%ds cannot be honored — a GCP uptime check period must be 60s, 300s, 600s or 900s "+
				"(refusing rather than rounding to a different real interval)", p.PeriodSec)
	}
	if p.IsTCP {
		if p.Path != "" {
			return UptimePlan{}, fmt.Errorf("check.path cannot be honored for a tcp check — a bare port connect has no path")
		}
		port, ok := toIntPort(impl["port"])
		if !ok {
			return UptimePlan{}, fmt.Errorf("a tcp uptime check requires implementation.port")
		}
		p.Port = port
	} else {
		p.Port = 80
		if p.UseSsl {
			p.Port = 443
		}
	}
	if !projectOK.MatchString(project) {
		return UptimePlan{}, fmt.Errorf("project %q is invalid", project)
	}
	return p, nil
}

func toIntPort(raw any) (int, bool) {
	switch v := raw.(type) {
	case int:
		return v, v > 0 && v < 65536
	case int64:
		return int(v), v > 0 && v < 65536
	case float64:
		return int(v), v > 0 && v < 65536
	}
	return 0, false
}

func (p UptimePlan) createBody(project, capability, environment string) map[string]any {
	body := map[string]any{
		"displayName": p.DisplayName,
		"monitoredResource": map[string]any{
			"type":   "uptime_url",
			"labels": map[string]any{"host": p.Host, "project_id": project},
		},
		"period":  fmt.Sprintf("%ds", p.PeriodSec),
		"timeout": "10s",
		"userLabels": map[string]any{
			"groundhold-capability":  sanitizeLabel(capability),
			"groundhold-environment": sanitizeLabel(environment),
		},
	}
	if p.IsTCP {
		body["tcpCheck"] = map[string]any{"port": p.Port}
	} else {
		body["httpCheck"] = map[string]any{
			"path": p.Path, "port": p.Port, "useSsl": p.UseSsl, "requestMethod": "GET",
		}
	}
	return body
}
