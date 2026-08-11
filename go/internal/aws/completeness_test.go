package aws

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

// serviceCases extracts the service tokens dispatched in a `func (d *Driver)
// <method>(` body. Source-parsing is deliberate: the invariant is about the
// dispatch switches themselves, and a source diff is what a reviewer sees. The
// body ends at the first column-0 "}" (a Go function close); every case line in
// these flat service switches names services, so all quoted lowercase tokens on a
// case line are services (comma-separated groups handled).
func serviceCases(t *testing.T, src, method string) map[string]bool {
	t.Helper()
	lines := strings.Split(src, "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "func (d *Driver) "+method+"(") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("method %s not found in source", method)
	}

	caseLine := regexp.MustCompile(`^\s*case .*:\s*$`)
	token := regexp.MustCompile(`"([a-z0-9-]+)"`)
	out := map[string]bool{}
	for i := start + 1; i < len(lines); i++ {
		if lines[i] == "}" {
			break
		}
		if caseLine.MatchString(lines[i]) {
			for _, m := range token.FindAllStringSubmatch(lines[i], -1) {
				out[m[1]] = true
			}
		}
	}
	// D328: a gate that finds nothing PASSES while checking nothing, which is worse

	// than no gate — it reads as a guarantee. A dispatch that parses to an EMPTY set

	// means the source shape changed (a switch rewritten as if-chains, a renamed

	// helper), not that the driver has no services.

	if len(out) == 0 {

		t.Fatalf("%s parsed to ZERO service cases — the dispatch shape changed and "+

			"every completeness gate built on it just went vacuous", method)

	}

	return out
}

// classifyChangeAllowlist is the set of services that can be CREATED but
// deliberately have NO ClassifyChange entry (create-only, in-place update not
// wired). It is the burn-down list behind F15 — NOT a green light. Wiring
// ClassifyChange for one removes it here; adding a new create service without
// ClassifyChange must add it here, with a reason, on purpose.
var classifyChangeAllowlist = map[string]bool{
	"apigateway": true, "backupvault": true, "changefeed": true, "cloudfront": true,
	"cloudwatch": true, "cloudwatchdash": true, "custompolicy": true, "cwlogfilter": true,
	"ecs": true, "efs": true, "elasticache": true,
	"iam": true, "kinesis": true, "kms": true, "msk": true,
	// lambda now wires ClassifyChange (timeout.maximum + network.publicExposure patch in place)
	"opensearch": true, "redshiftserverless": true, "rolepolicy": true, "route53": true,
	"route53health": true, // route53record now wires ClassifyChange (dns.target repoints in place)
	"vpc":           true, "vpngateway": true, "waf": true,
}

// TestClassifyChangeCompleteness pins the invariant behind F15: every service that
// can be CREATED must have a ClassifyChange entry, or reconciling a bound resource
// of that service errors "change-classification is not wired" mid-run — which
// FREEZES every incremental apply after a partial. A create service missing
// ClassifyChange is legal only on the explicit allowlist. Growing the gap (a new
// create service, unwired, un-allowlisted) fails here; wiring an allowlisted
// service without removing it fails too — either is a conscious edit, never a
// silent hole (the pattern of the N1 / provider-verb membership tests).
func TestClassifyChangeCompleteness(t *testing.T) {
	src, err := os.ReadFile("aws_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	// The create switch lives in createService — Create is a thin wrapper that
	// attaches typed outputs (D275) around it.
	create := serviceCases(t, string(src), "createService")
	classify := serviceCases(t, string(src), "ClassifyChange")

	var missing []string
	for svc := range create {
		if !classify[svc] && !classifyChangeAllowlist[svc] {
			missing = append(missing, svc)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("create services with NO ClassifyChange and NOT allowlisted: %v\n"+
			"wire ClassifyChange only if a path is mutable in place (else the D215 default replaces on drift) "+
			"or add them to classifyChangeAllowlist with a reason", missing)
	}

	var stale []string
	for svc := range classifyChangeAllowlist {
		if classify[svc] {
			stale = append(stale, svc) // gained ClassifyChange — must leave the allowlist
		} else if !create[svc] {
			stale = append(stale, svc+" (not a create service)")
		}
	}
	sort.Strings(stale)
	if len(stale) > 0 {
		t.Errorf("classifyChangeAllowlist is stale — these no longer belong: %v", stale)
	}
}

// TestACMChangeClassificationWired is the F15 regression: acm must classify its
// paths (auto.renew is a managed no-op, never the default "not wired" block).
func TestACMChangeClassificationWired(t *testing.T) {
	class, note := classifyACMChange("auto.renew")
	if class != "caveated" {
		t.Fatalf("acm auto.renew must be caveated (managed, non-blocking), got %q (%s)", class, note)
	}
	if class, _ := classifyACMChange("domain"); class != "immutable" {
		t.Fatalf("acm domain change must be immutable (replacement), got %q", class)
	}
	if class, _ := classifyACMChange("cost.monthly"); class != "unsupported" {
		t.Fatalf("acm platform path must be unsupported, got %q", class)
	}
	// updateACM guards its providerId shape before any read (refuse-before-mutate).
	d := NewDriver("eu-central-1")
	if res := d.updateACM("cert", "prod", "not-an-acm-id", []string{"auto.renew"}); res.Status != "failed" {
		t.Fatalf("updateACM must refuse a malformed providerId, got %+v", res)
	}
}

// TestObserveCompleteness (D317) pins the sibling of the ClassifyChange gate: every
// service that can be CREATED must also be OBSERVABLE.
//
// The asymmetry it closes was real — create->ClassifyChange has been gated since
// D210 while create->observe never was, even though observe is the more
// fundamental half: without it a bound capability can never be reconciled against
// reality, D249 marks every declared attribute unverified, and converge reports
// inconclusive forever. The property holds today (measured, both directions
// empty); this keeps a new create service from shipping blind.
//
// There is deliberately NO allowlist. A create with no observe is not a
// burn-down class like an unwired ClassifyChange (where the D215 default still
// replaces on drift, honestly): it is a capability the runtime can build and then
// never check. If one is ever genuinely unobservable, that belongs in the
// vocabulary as an evidence class (D311), not as an exception here.
func TestObserveCompleteness(t *testing.T) {
	raw, err := os.ReadFile("aws_provider.go")
	if err != nil {
		t.Fatal(err)
	}
	create := serviceCases(t, string(raw), "createService")
	observe := serviceCases(t, string(raw), "Observe")

	var blind []string
	for svc := range create {
		if !observe[svc] {
			blind = append(blind, svc)
		}
	}
	sort.Strings(blind)
	if len(blind) > 0 {
		t.Errorf("%s services that can be CREATED but have no observe dispatch: %v\n"+
			"a capability the runtime builds and can never read back is never verified "+
			"against reality — wire observe, or declare the attributes' evidence class "+
			"in the vocabulary (D311)", "aws", blind)
	}

	var phantom []string
	for svc := range observe {
		if !create[svc] {
			phantom = append(phantom, svc)
		}
	}
	sort.Strings(phantom)
	if len(phantom) > 0 {
		t.Errorf("%s services with an observe dispatch but no create: %v — either a "+
			"discover-only service (say so here) or a stale case", "aws", phantom)
	}
}

// Every service that CAN be authored must be able to conclude a lost create.
//
// `resume` exists to get out of `unknown`: a create whose outcome the executor
// never learned is reconciled by re-deriving the resource's deterministic
// identity and asking the provider whether it landed. A service missing from the
// Reconcile dispatch falls to the default — `unknown` with "not wired yet,
// reconcile manually" — which is fail-closed and honest, and also means the whole
// resume machinery does not apply to it.
//
// Azure has carried this gate for a while; AWS and GCP did not, and accumulated
// eleven gaps between them. The absence of the check is the whole explanation:
// the drivers are not worse, nothing was asking. Two of the eleven were added by
// someone who had just finished writing down that the gap existed.
//
// WITNESS services (D177) are exempt, and the exemption is DERIVED from
// `CanAuthor` rather than listed: a witness never creates anything, so there is
// no lost outcome to conclude. A service that stops being a witness is caught
// again the moment it does.
func TestEveryAuthoredServiceCanReconcile(t *testing.T) {
	src, err := os.ReadFile("reconcile_aws.go")
	if err != nil {
		t.Fatalf("read reconcile_aws.go: %v", err)
	}
	dispatch := serviceCases(t, string(src), "Reconcile")
	var missing []string
	for _, svc := range awsCertifyServices {
		if !provider.CanAuthor("aws", svc) {
			continue // a witness has no create to conclude
		}
		if !dispatch[svc] {
			missing = append(missing, svc)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("aws services that can be created but cannot conclude a lost create: %v\n"+
			"Each falls to the reconcile default (`unknown` — reconcile manually), so "+
			"`resume` cannot finish what `apply` started. On a STATEFUL capability that "+
			"is worse than an inconvenience: the operator's natural next step is to "+
			"create another one, which is how data ends up split across two resources.",
			missing)
	}
}
