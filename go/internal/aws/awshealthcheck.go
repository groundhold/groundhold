// Route 53 health check request building (D108): the semantic core of the AWS
// capability.monitoring.uptime driver — the SAME vocabulary GCP uptime checks and
// Azure availability tests fulfil. A health check probes an endpoint over HTTP/HTTPS/TCP.
// Route 53 permits ONLY a 10s or 30s RequestInterval, so a check.period it cannot honor
// is refused, not rounded. It is a GLOBAL, REST-XML service (like a hosted zone), and the
// health-check Id is server-assigned, so a deterministic CallerReference is the
// idempotency key. A path is refused for a tcp check.
package aws

import (
	"fmt"
	"regexp"
	"strings"

	"groundhold/internal/scalars"
)

var r53hcHostOK = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// r53HCIntervals is the closed set of RequestInterval values (seconds) Route 53 permits.
var r53HCIntervals = map[int]bool{10: true, 30: true}

// R53HCPlan is the attribute-derived shape a create assembles.
type R53HCPlan struct {
	Type            string // HTTP | HTTPS | TCP
	FQDN            string
	Port            int
	Path            string
	Interval        int
	CallerReference string
}

// BuildRoute53HealthCheck maps capability.monitoring.uptime attributes + impl to a plan.
// Every error is a preflight refusal, never a silent drop.
func BuildRoute53HealthCheck(environment, capability string,
	attrs, impl map[string]any, generation int) (R53HCPlan, error) {
	p := R53HCPlan{}
	protoSet, periodSet := false, false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "check.target":
			p.FQDN, _ = raw.(string)
			if !r53hcHostOK.MatchString(p.FQDN) {
				return R53HCPlan{}, fmt.Errorf("check.target %q is not a valid host", p.FQDN)
			}
		case "check.protocol":
			switch raw {
			case "http":
				p.Type = "HTTP"
			case "https":
				p.Type = "HTTPS"
			case "tcp":
				p.Type = "TCP"
			default:
				return R53HCPlan{}, fmt.Errorf("check.protocol %v has no mapping", raw)
			}
			protoSet = true
		case "check.path":
			p.Path, _ = raw.(string)
		case "check.period":
			sec, ok := durationSeconds(raw)
			if !ok {
				return R53HCPlan{}, fmt.Errorf("check.period is not a duration")
			}
			p.Interval = sec
			periodSet = true
		case "service.managed":
			if raw != true {
				return R53HCPlan{}, fmt.Errorf("service.managed=false cannot be honored by Route 53")
			}
		default:
			return R53HCPlan{}, fmt.Errorf(
				"attribute %s has no Route 53 health check mapping — refusing rather than silently dropping it", path)
		}
	}
	if p.FQDN == "" {
		return R53HCPlan{}, fmt.Errorf("health check requires check.target")
	}
	if !protoSet {
		return R53HCPlan{}, fmt.Errorf("health check requires check.protocol")
	}
	if !periodSet {
		return R53HCPlan{}, fmt.Errorf("health check requires check.period")
	}
	if !r53HCIntervals[p.Interval] {
		return R53HCPlan{}, fmt.Errorf(
			"check.period=%ds cannot be honored — a Route 53 health check interval must be 10s or 30s "+
				"(refusing rather than rounding to a different real interval)", p.Interval)
	}
	if p.Type == "TCP" {
		if p.Path != "" {
			return R53HCPlan{}, fmt.Errorf("check.path cannot be honored for a tcp check — a bare port connect has no path")
		}
		port, ok := intPort(impl["port"])
		if !ok {
			return R53HCPlan{}, fmt.Errorf("a tcp health check requires implementation.port")
		}
		p.Port = port
	} else {
		p.Port = 80
		if p.Type == "HTTPS" {
			p.Port = 443
		}
	}
	p.CallerReference = "groundhold-" + letterHash(environment+"|"+capability+genSuffix(generation), 20)
	return p, nil
}

func (p R53HCPlan) createXML() string {
	var b strings.Builder
	b.WriteString(`<CreateHealthCheckRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">`)
	b.WriteString("<CallerReference>" + xmlEscape(p.CallerReference) + "</CallerReference>")
	b.WriteString("<HealthCheckConfig>")
	b.WriteString("<Type>" + p.Type + "</Type>")
	b.WriteString("<FullyQualifiedDomainName>" + xmlEscape(p.FQDN) + "</FullyQualifiedDomainName>")
	b.WriteString(fmt.Sprintf("<Port>%d</Port>", p.Port))
	if p.Type != "TCP" {
		b.WriteString("<ResourcePath>" + xmlEscape(p.Path) + "</ResourcePath>")
	}
	b.WriteString(fmt.Sprintf("<RequestInterval>%d</RequestInterval>", p.Interval))
	b.WriteString("<FailureThreshold>3</FailureThreshold>")
	b.WriteString("</HealthCheckConfig></CreateHealthCheckRequest>")
	return b.String()
}

func durationSeconds(raw any) (int, bool) {
	s, err := scalars.Parse(raw)
	if err != nil || s.Kind != scalars.Duration {
		return 0, false
	}
	ms, ok := s.Value.(float64)
	if !ok {
		return 0, false
	}
	return int(ms / 1000), true
}

func intPort(raw any) (int, bool) {
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
