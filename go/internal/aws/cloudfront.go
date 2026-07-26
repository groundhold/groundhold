// CloudFront request building (D118): the semantic core of the AWS
// capability.cdn.distribution driver — the SAME vocabulary Azure CDN fulfils (GCP
// Cloud CDN is a backend-service flag, not a standalone resource, so the domain is
// honestly two-cloud). A CloudFront distribution is a global edge CDN. Invariant #4:
// only the origin and the viewer TLS posture are exposed; cache behaviors, TTLs,
// path patterns and header forwarding are OPAQUE config carried under implementation.
package aws

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// cfDomainOK bounds an origin domain (a FQDN).
var cfDomainOK = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// acmCertArnOK bounds an ACM certificate ARN (the ViewerCertificate reference — a
// NAME, never key material, safe to carry, D53). The us-east-1 requirement for a
// CloudFront viewer cert is enforced separately with an honest message.
var acmCertArnOK = regexp.MustCompile(`^arn:aws[A-Za-z0-9-]*:acm:[a-z0-9-]+:[0-9]{12}:certificate/.+$`)

// AWS-managed cache policy ids (region-agnostic, global). CachingOptimized caches
// aggressively keyed by URL — correct for a STATIC origin (S3/website). CachingDisabled
// forwards every request and caches nothing — the ONLY safe default for a DYNAMIC
// origin (a Lambda Function URL fronting an API/SSR app, the D316 OAC pattern), where
// caching a per-request/per-user response by URL would serve one viewer's response to
// another (stale / cross-user leak).
const (
	cachePolicyOptimized = "658327ea-f89d-4fab-a63d-7e88639e58f6" // CachingOptimized
	cachePolicyDisabled  = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad" // CachingDisabled
)

// CloudFrontPlan is the attribute-derived shape a create assembles into XML.
type CloudFrontPlan struct {
	CallerReference string // deterministic idempotency key
	OriginDomain    string
	ViewerProtocol  string // https-only | redirect-to-https | allow-all

	// OriginPending is set when the origin is supplied by an UNRESOLVED $ref
	// operand (validate/preflight only — apply resolves it to a host string
	// before the builder runs), so the empty-origin refusal is deferred.
	OriginPending bool

	// OACEnabled + GrantLambdaArn implement the edge pattern (D26 operands):
	// origin_access: oac creates an Origin Access Control (always/sigv4/lambda)
	// and attaches it to the origin so the edge SIGNS the origin request; the
	// distribution then grants ITSELF invoke on its origin lambda
	// (grant_invoke_lambda = {$ref: <fn>.functionArn}) with a SourceArn scoped to
	// this one distribution. Together they front a Function URL (AuthType=AWS_IAM)
	// publicly WITHOUT anonymous invoke. The OAC id is server-assigned at apply.
	OACEnabled     bool
	OACName        string // deterministic ownership marker
	GrantLambdaArn string // the origin lambda's ARN to AddPermission on (may be a
	// pending $ref at validate); "" when no grant is wired.
	GrantPending bool

	// CachePolicyID is the managed cache policy attached to the DefaultCacheBehavior.
	// The default is SAFE PER ORIGIN TYPE — CachingDisabled for a dynamic Lambda
	// Function URL origin (OACEnabled, the D316 pattern), CachingOptimized for a
	// static origin — and the cache_policy operand overrides it.
	CachePolicyID string

	// Aliases are the alternate domain names the distribution serves under (the
	// DistributionConfig Aliases / CNAMEs, e.g. api.acme.eu) — the custom public
	// front. Empty keeps the default *.cloudfront.net-only distribution.
	Aliases []string

	// CertACMArn is the ACM certificate ARN for the ViewerCertificate. A CloudFront
	// viewer cert MUST be an ACM cert in us-east-1 (CloudFront's global cert store),
	// even when the origin is elsewhere — it is a PUBLIC edge cert (no PII, no data
	// residency), so us-east-1 is an AWS infrastructural requirement, NOT a
	// data-residency choice. Empty = CloudFrontDefaultCertificate (the pre-existing
	// default, unchanged — a cert is never forced).
	CertACMArn string
	// CertPending is set when certificate is an UNRESOLVED $ref (validate/preflight;
	// apply resolves it to the ARN string before the builder runs, where the
	// us-east-1 region is then enforced).
	CertPending bool
}

// BuildCloudFront maps capability.cdn.distribution attributes to a plan. Every error
// is a preflight refusal, never a silent drop.
func BuildCloudFront(environment, capability string,
	attrs, impl map[string]any, generation int) (CloudFrontPlan, error) {
	p := CloudFrontPlan{
		CallerReference: "pv" + letterHash(environment+"|"+capability+genSuffix(generation), 24),
		ViewerProtocol:  "https-only",
		OACName:         "pv-oac-" + letterHash(environment+"|"+capability+genSuffix(generation), 20),
	}

	// ---- origin operands (D26). origin_domain supplies the origin by $ref (a
	// same-plan producer output, e.g. a lambda functionUrlDomain) — the ONLY way
	// to source the origin from a resource created in the same plan, since the
	// compiler wires $ref from the implementation block, never from an attribute.
	// It is the operand twin of the origin.domain attribute (the D279 loadbalancer
	// pattern: semantics carried, wired by operand); exactly ONE of the two. ----
	originFromOperand := false
	if raw, has := impl["origin_domain"]; has {
		originFromOperand = true
		switch v := raw.(type) {
		case string:
			p.OriginDomain = strings.ToLower(strings.TrimSpace(v))
			if !cfDomainOK.MatchString(p.OriginDomain) {
				return CloudFrontPlan{}, fmt.Errorf("implementation.origin_domain %q is not a valid FQDN", p.OriginDomain)
			}
		default:
			if isRefShape(raw) {
				p.OriginPending = true // resolved to a host string at apply
			} else {
				return CloudFrontPlan{}, fmt.Errorf(
					"implementation.origin_domain must be a host string or a $ref to a producer output, got %T", raw)
			}
		}
	}
	// ---- origin_access operand: enable an Origin Access Control. ----
	if raw, has := impl["origin_access"]; has {
		s, _ := raw.(string)
		switch strings.TrimSpace(strings.ToLower(s)) {
		case "oac":
			p.OACEnabled = true
		case "":
			// no-op
		default:
			return CloudFrontPlan{}, fmt.Errorf(
				"implementation.origin_access %q is not supported — use \"oac\" (Origin Access Control)", s)
		}
	}
	// ---- grant_invoke_lambda operand: the origin lambda ARN the distribution
	// grants ITSELF invoke on (Model 2). A $ref to the fn's functionArn. ----
	if raw, has := impl["grant_invoke_lambda"]; has {
		switch v := raw.(type) {
		case string:
			p.GrantLambdaArn = strings.TrimSpace(v)
			if !lambdaArnOK.MatchString(p.GrantLambdaArn) {
				return CloudFrontPlan{}, fmt.Errorf(
					"implementation.grant_invoke_lambda %q is not a Lambda function ARN", p.GrantLambdaArn)
			}
		default:
			if isRefShape(raw) {
				p.GrantPending = true // resolved to an ARN string at apply
			} else {
				return CloudFrontPlan{}, fmt.Errorf(
					"implementation.grant_invoke_lambda must be a Lambda ARN or a $ref, got %T", raw)
			}
		}
	}

	// ---- cache_policy operand: explicit override of the managed cache policy the
	// DefaultCacheBehavior uses (disabled | optimized). Unset = safe per origin type
	// (set below): CachingDisabled for a dynamic Function-URL/OAC origin, else
	// CachingOptimized. Closed vocabulary — an unrecognized value refuses. ----
	cacheOverride := ""
	if raw, has := impl["cache_policy"]; has {
		s, _ := raw.(string)
		switch strings.TrimSpace(strings.ToLower(s)) {
		case "disabled":
			cacheOverride = cachePolicyDisabled
		case "optimized":
			cacheOverride = cachePolicyOptimized
		case "":
			// no-op — fall through to the per-origin default
		default:
			return CloudFrontPlan{}, fmt.Errorf(
				"implementation.cache_policy %q is not supported — use \"disabled\" or \"optimized\"", s)
		}
	}

	// ---- aliases operand: the alternate domain names (DistributionConfig Aliases /
	// CNAMEs) the distribution serves under — the custom public front (api.acme.eu).
	// A custom domain served over TLS REQUIRES a matching ViewerCertificate (the
	// default CloudFrontDefaultCertificate only covers *.cloudfront.net), enforced
	// below. Each entry is a validated FQDN. ----
	if raw, has := impl["aliases"]; has {
		list, ok := raw.([]any)
		if !ok {
			return CloudFrontPlan{}, fmt.Errorf(
				"implementation.aliases must be a list of domain names, got %T", raw)
		}
		for _, e := range list {
			s, ok := e.(string)
			if !ok {
				return CloudFrontPlan{}, fmt.Errorf(
					"implementation.aliases entries must be domain strings, got %T", e)
			}
			s = strings.ToLower(strings.TrimSpace(s))
			if !cfDomainOK.MatchString(s) {
				return CloudFrontPlan{}, fmt.Errorf("implementation.aliases %q is not a valid FQDN", s)
			}
			p.Aliases = append(p.Aliases, s)
		}
	}
	// ---- certificate operand: the ViewerCertificate. A string ACM ARN or a $ref to
	// a capability.certificate.tls certificateArn output (D226 — wired by the
	// compiler, resolved to the ARN at apply). Unset keeps CloudFrontDefaultCertificate
	// (unchanged — a cert is never forced). A CloudFront viewer cert MUST be an ACM
	// cert in us-east-1; the region is enforced once the ARN is a literal (at apply for
	// a $ref). The ARN is a NAME, never key material — safe to carry (D53). ----
	if raw, has := impl["certificate"]; has {
		switch v := raw.(type) {
		case string:
			p.CertACMArn = strings.TrimSpace(v)
			if !acmCertArnOK.MatchString(p.CertACMArn) {
				return CloudFrontPlan{}, fmt.Errorf(
					"implementation.certificate %q is not an ACM certificate ARN", p.CertACMArn)
			}
			if r := acmARNRegion(p.CertACMArn); r != "us-east-1" {
				return CloudFrontPlan{}, fmt.Errorf(
					"implementation.certificate must be an ACM cert in us-east-1 (CloudFront's viewer-cert "+
						"store), got region %q — a CloudFront viewer certificate is a PUBLIC edge cert, so "+
						"us-east-1 is an AWS infrastructural requirement, not a data-residency choice", r)
			}
		default:
			if isRefShape(raw) {
				p.CertPending = true // resolved to an ACM ARN at apply
			} else {
				return CloudFrontPlan{}, fmt.Errorf(
					"implementation.certificate must be an ACM ARN or a $ref to a certificate.tls output, got %T", raw)
			}
		}
	}

	viewerSet := false
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "origin.domain":
			if originFromOperand {
				return CloudFrontPlan{}, fmt.Errorf(
					"origin is set BOTH by the origin.domain attribute and the implementation.origin_domain operand — set exactly one")
			}
			p.OriginDomain, _ = raw.(string)
			p.OriginDomain = strings.ToLower(strings.TrimSpace(p.OriginDomain))
			if !cfDomainOK.MatchString(p.OriginDomain) {
				return CloudFrontPlan{}, fmt.Errorf("origin.domain %q is not a valid FQDN", p.OriginDomain)
			}
		case "viewer.protocol":
			viewerSet = true
			switch raw {
			case "https-only":
				p.ViewerProtocol = "https-only"
			case "redirect-to-https":
				p.ViewerProtocol = "redirect-to-https"
			case "allow-all":
				p.ViewerProtocol = "allow-all"
			default:
				return CloudFrontPlan{}, fmt.Errorf("viewer.protocol %v has no CloudFront mapping", raw)
			}
		case "service.managed":
			if raw != true {
				return CloudFrontPlan{}, fmt.Errorf("service.managed=false cannot be honored by CloudFront")
			}
		default:
			return CloudFrontPlan{}, fmt.Errorf(
				"attribute %s has no CloudFront mapping — refusing rather than silently dropping it "+
					"(cache behaviors, TTLs, path patterns are opaque implementation config)", path)
		}
	}
	if p.OriginDomain == "" && !p.OriginPending {
		return CloudFrontPlan{}, fmt.Errorf(
			"cdn distribution requires an origin — set the origin.domain attribute (a static host) " +
				"or the implementation.origin_domain operand (a $ref to a producer, e.g. a lambda functionUrlDomain)")
	}
	if !viewerSet {
		return CloudFrontPlan{}, fmt.Errorf("cdn distribution requires viewer.protocol")
	}
	// A custom domain (alias) needs a matching ViewerCertificate — CloudFront rejects
	// Aliases served with the default cert (it only covers *.cloudfront.net). Require
	// the two together in both directions, so neither half is a silent no-op.
	certGiven := p.CertACMArn != "" || p.CertPending
	if len(p.Aliases) > 0 && !certGiven {
		return CloudFrontPlan{}, fmt.Errorf(
			"implementation.aliases requires implementation.certificate — a custom domain served over " +
				"TLS needs an ACM viewer certificate (the default certificate only covers *.cloudfront.net)")
	}
	if certGiven && len(p.Aliases) == 0 {
		return CloudFrontPlan{}, fmt.Errorf(
			"implementation.certificate was given but implementation.aliases is empty — a viewer " +
				"certificate only serves custom domains; refusing an ambiguous shape")
	}
	// The invoke grant needs the OAC to sign the origin request; a grant without
	// signing would leave the origin returning 403 to the edge — refuse.
	if (p.GrantLambdaArn != "" || p.GrantPending) && !p.OACEnabled {
		return CloudFrontPlan{}, fmt.Errorf(
			"implementation.grant_invoke_lambda requires implementation.origin_access: oac — " +
				"without a signed origin request the fronted Function URL (AWS_IAM) would reject the edge")
	}
	// Cache policy default is SAFE PER ORIGIN TYPE. A dynamic Lambda Function URL
	// origin (origin_access: oac, the D316 pattern) MUST NOT cache — CachingOptimized
	// would key dynamic per-user responses by URL and serve one viewer's response to
	// another (stale / cross-user leak, the Acme field finding). A static origin
	// (S3/website) keeps CachingOptimized. The cache_policy operand overrides either.
	switch {
	case cacheOverride != "":
		p.CachePolicyID = cacheOverride
	case p.OACEnabled:
		p.CachePolicyID = cachePolicyDisabled
	default:
		p.CachePolicyID = cachePolicyOptimized
	}
	return p, nil
}

// acmARNRegion extracts the region field from an ACM certificate ARN
// (arn:aws:acm:REGION:account:certificate/...). "" if the ARN is malformed.
func acmARNRegion(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 4 {
		return ""
	}
	return parts[3]
}

// oacXML is the CreateOriginAccessControl request body: always-sign, SigV4, for a
// LAMBDA origin type (a Function URL). SigningBehavior=always makes the edge sign
// EVERY origin request, so a Function URL with AuthType=AWS_IAM accepts it.
func (p CloudFrontPlan) oacXML() string {
	var b strings.Builder
	b.WriteString(`<OriginAccessControlConfig xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">`)
	b.WriteString("<Name>" + xmlEscape(p.OACName) + "</Name>")
	b.WriteString("<Description>groundhold-managed OAC</Description>")
	b.WriteString("<SigningProtocol>sigv4</SigningProtocol>")
	b.WriteString("<SigningBehavior>always</SigningBehavior>")
	b.WriteString("<OriginAccessControlOriginType>lambda</OriginAccessControlOriginType>")
	b.WriteString(`</OriginAccessControlConfig>`)
	return b.String()
}

// createXML is the CreateDistributionWithTags request body. The managed cache policy
// is chosen SAFE PER ORIGIN TYPE (p.CachePolicyID — CachingDisabled for a dynamic
// Function-URL/OAC origin, CachingOptimized for a static one), cache_policy overriding;
// finer cache tuning is opaque impl config. When oacID is non-empty the origin carries
// an OriginAccessControlId so the edge signs the origin request (the OAC was created
// just before this call).
func (p CloudFrontPlan) createXML(capability, environment, oacID string) string {
	cachePolicy := p.CachePolicyID
	if cachePolicy == "" {
		cachePolicy = cachePolicyOptimized // defensive: a plan not built via BuildCloudFront
	}
	var b strings.Builder
	b.WriteString(`<DistributionConfigWithTags xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">`)
	b.WriteString(`<DistributionConfig>`)
	b.WriteString("<CallerReference>" + xmlEscape(p.CallerReference) + "</CallerReference>")
	// Aliases (the alternate domain names / CNAMEs) sit right after CallerReference,
	// their canonical DistributionConfig slot. Omitted entirely when there are none,
	// so the default distribution's body is unchanged.
	if len(p.Aliases) > 0 {
		b.WriteString(`<Aliases><Quantity>` + strconv.Itoa(len(p.Aliases)) + `</Quantity><Items>`)
		for _, a := range p.Aliases {
			b.WriteString("<CNAME>" + xmlEscape(a) + "</CNAME>")
		}
		b.WriteString(`</Items></Aliases>`)
	}
	b.WriteString("<Comment>groundhold-managed distribution</Comment>")
	b.WriteString("<Enabled>true</Enabled>")
	b.WriteString(`<Origins><Quantity>1</Quantity><Items><Origin>`)
	b.WriteString("<Id>origin1</Id>")
	b.WriteString("<DomainName>" + xmlEscape(p.OriginDomain) + "</DomainName>")
	if oacID != "" {
		b.WriteString("<OriginAccessControlId>" + xmlEscape(oacID) + "</OriginAccessControlId>")
	}
	b.WriteString(`<CustomOriginConfig><HTTPPort>80</HTTPPort><HTTPSPort>443</HTTPSPort>` +
		`<OriginProtocolPolicy>https-only</OriginProtocolPolicy></CustomOriginConfig>`)
	b.WriteString(`</Origin></Items></Origins>`)
	b.WriteString(`<DefaultCacheBehavior>`)
	b.WriteString("<TargetOriginId>origin1</TargetOriginId>")
	b.WriteString("<ViewerProtocolPolicy>" + xmlEscape(p.ViewerProtocol) + "</ViewerProtocolPolicy>")
	b.WriteString("<CachePolicyId>" + cachePolicy + "</CachePolicyId>")
	b.WriteString(`</DefaultCacheBehavior>`)
	// ViewerCertificate: an ACM cert in us-east-1 (SNI, TLS 1.2_2021) when a
	// certificate operand was given, else CloudFrontDefaultCertificate (unchanged —
	// the default distribution serves only *.cloudfront.net). A CloudFront viewer
	// cert is a public edge cert; the us-east-1 requirement was enforced at build.
	if p.CertACMArn != "" {
		b.WriteString(`<ViewerCertificate>`)
		b.WriteString("<ACMCertificateArn>" + xmlEscape(p.CertACMArn) + "</ACMCertificateArn>")
		b.WriteString("<SSLSupportMethod>sni-only</SSLSupportMethod>")
		b.WriteString("<MinimumProtocolVersion>TLSv1.2_2021</MinimumProtocolVersion>")
		b.WriteString(`</ViewerCertificate>`)
	}
	b.WriteString(`</DistributionConfig>`)
	b.WriteString(`<Tags><Items>`)
	b.WriteString(`<Tag><Key>groundhold-capability</Key><Value>` + xmlEscape(sanitizeTag(capability)) + `</Value></Tag>`)
	b.WriteString(`<Tag><Key>groundhold-environment</Key><Value>` + xmlEscape(sanitizeTag(environment)) + `</Value></Tag>`)
	b.WriteString(`</Items></Tags>`)
	b.WriteString(`</DistributionConfigWithTags>`)
	return b.String()
}
