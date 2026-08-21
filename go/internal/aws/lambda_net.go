// AWS Lambda network shell — the SigV4-signed, REST-JSON half of the AWS
// capability.function.serverless driver. The function NAME is deterministic, so
// the providerId is knowable BEFORE the create response and rides every
// lost/5xx/garbled outcome (D29). Ownership is TAGS (returned inline by
// GetFunction). The create LRO polls the OBSERVABLE state — GetFunction's
// Configuration.State (Active=done, Failed=failed) — never an operation-by-id
// path (a container-image function is Pending after CreateFunction, then Active).
//
// Public exposure is a Function URL. The url_auth operand REFINES it: "none" is
// the anonymous mode — a URL with AuthType NONE AND a resource-based
// lambda:InvokeFunctionUrl grant to principal * (both gates, or the function is
// not truly world-invocable). "iam" is the edge mode — a URL with AuthType
// AWS_IAM and NO anonymous grant; the invoke grant for cloudfront.amazonaws.com
// (scoped by SourceArn to one distribution) is added by the CloudFront driver
// when it fronts this URL with an Origin Access Control (Model 2, the
// distribution grants itself access to its origin). A create that cannot
// complete its gates NEVER reports succeeded — it would lie about the exposure
// the contract exists for.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"groundhold/internal/perr"
	"groundhold/internal/provider"
)

const (
	lambdaFnPath       = "/2015-03-31/functions"    // CreateFunction / GetFunction / DeleteFunction / AddPermission
	lambdaURLPath      = "/2021-10-31/functions"    // CreateFunctionUrlConfig / GetFunctionUrlConfig
	lambdaConcPutPath  = "/2017-10-31/functions"    // PutFunctionConcurrency (the API dates it 2017-10-31)
	lambdaConcGetPath  = "/2019-09-30/functions"    // GetFunctionConcurrency (a later API version)
	lambdaReadAttempts = 4                          // bounded transient-read retry (D260 read-storm gate)
	lambdaPublicStmtID = "groundhold-public-invoke" // deterministic AddPermission statement id

	// lambdaInvokerSidPrefix marks the statements the `invokers` operand owns
	// (D852). Reconciliation removes OUR statements that the operand no longer
	// lists and touches nothing else: an operator's own grant, and the
	// `groundhold-cf-*` edge grants, are not ours to withdraw here.
	lambdaInvokerSidPrefix = "groundhold-invoke-"

	// reserved operand observation paths (F-LC3): the VpcConfig, Environment and
	// container image observe records back and the compiler compares the DECLARED
	// operands against. Not vocab attributes (invariant #4) — implementation
	// config the driver governs, namespaced under provider.OperandPrefix.
	lambdaVpcOperand  = provider.OperandPrefix + "vpcConfig"
	lambdaEnvOperand  = provider.OperandPrefix + "environment"
	lambdaPkgOperand  = provider.OperandPrefix + "package"
	lambdaArchOperand = provider.OperandPrefix + "architecture"
	// D852: WHO may invoke. Observed from the function's own resource policy, so a
	// grant removed by hand comes back and a grant dropped from the candidate goes.
	lambdaInvokersOperand = provider.OperandPrefix + "invokers"
	// D530: the EXECUTION ROLE. It was consumed at create and observed nowhere, so
	// changing it in the candidate produced no drift and no action — a security
	// attribute silently diverging from reality. UpdateFunctionConfiguration has
	// always carried Role, so only the observation was missing.
	lambdaRoleOperand = provider.OperandPrefix + "role"
	// memory_size: memory in MB, which on Lambda is the CPU allocation. Rides
	// UpdateFunctionConfiguration like Timeout, observed from GetFunctionConfiguration,
	// so a change to the declared operand patches online rather than being ignored.
	lambdaMemOperand = provider.OperandPrefix + "memorySize"
	// reserved_concurrency: the per-function concurrency ceiling. Rides a SEPARATE
	// PutFunctionConcurrency call and is read back from GetFunctionConcurrency (its own
	// endpoint, not GetFunctionConfiguration), so a declared change patches in place.
	lambdaConcOperand = provider.OperandPrefix + "reservedConcurrency"
)

// lambdaRoleObservation renders the live execution role for comparison against
// the declared `role_arn` operand (D530). Shared by observe and OperandTargets so
// the two sides render identically — a mismatch in SHAPE would report permanent
// drift on a converged function, which is its own kind of lie.
func lambdaRoleObservation(roleARN string) provider.Observation {
	return provider.Observation{Path: lambdaRoleOperand, Value: roleARN, Derivation: "measured"}
}

// lambdaNameOK bounds a Lambda function name before path interpolation.
var lambdaNameOK = regexp.MustCompile(`^[a-zA-Z0-9-_]{1,64}$`)

// lambdaArnOK bounds a Lambda function ARN (the grant target the cdn driver
// AddPermissions on) before it is trusted from a candidate operand.
var lambdaArnOK = regexp.MustCompile(`^arn:aws:lambda:[a-z0-9-]+:[0-9]{12}:function:[a-zA-Z0-9-_]{1,64}$`)

func (d *Driver) lambdaBase(region string) string {
	if d.LambdaBaseURL != "" {
		return d.LambdaBaseURL
	}
	return "https://lambda." + region + ".amazonaws.com"
}

func lambdaProviderID(region, account, name string) string {
	return "lambda:" + region + ":" + account + ":" + name
}

func splitLambdaProviderID(providerID string) (region, account, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 4 || parts[0] != "lambda" {
		return "", "", "", fmt.Errorf("providerId %q is not lambda:region:account:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !account12.MatchString(parts[2]) {
		return "", "", "", fmt.Errorf("providerId account %q is invalid", parts[2])
	}
	if !lambdaNameOK.MatchString(parts[3]) {
		return "", "", "", fmt.Errorf("providerId function %q is invalid", parts[3])
	}
	return parts[1], parts[2], parts[3], nil
}

// splitLambdaArn parses region + function name out of a Lambda function ARN
// (arn:aws:lambda:<region>:<account>:function:<name>) so a cross-driver caller
// (the cdn driver's invoke grant) can reach the function's own regional endpoint.
func splitLambdaArn(arn string) (region, name string, err error) {
	if !lambdaArnOK.MatchString(arn) {
		return "", "", fmt.Errorf("%q is not a Lambda function ARN", arn)
	}
	parts := strings.Split(arn, ":")
	// arn:aws:lambda:region:account:function:name
	return parts[3], parts[6], nil
}

func (d *Driver) lambdaDo(method, region, path string, body []byte) (int, []byte, error) {
	return d.doSigned(method, d.lambdaBase(region)+path, "lambda", region,
		map[string]string{"Content-Type": "application/json"}, body)
}

// lambdaGet issues a signed Lambda GET and retries a bounded number of times on a
// TRANSIENT failure (transport error / 429 / 5xx) — the read layer's answer to the
// D260 read-storm class; a definitive 2xx/4xx/404 returns at once.
func (d *Driver) lambdaGet(region, path string) (int, []byte, error) {
	var st int
	var body []byte
	var err error
	for attempt := 0; attempt < lambdaReadAttempts; attempt++ {
		st, body, err = d.lambdaDo("GET", region, path, nil)
		if err == nil && st != http.StatusTooManyRequests && st < 500 {
			return st, body, err
		}
		if attempt < lambdaReadAttempts-1 {
			time.Sleep(d.PollInterval)
		}
	}
	return st, body, err
}

func lambdaErr(body []byte) string {
	var e struct {
		Message string `json:"message"`
		Msg     string `json:"Message"`
		Type    string `json:"Type"`
	}
	_ = json.Unmarshal(body, &e)
	switch {
	case e.Message != "":
		return boundMsg(e.Message)
	case e.Msg != "":
		return boundMsg(e.Msg)
	default:
		return "" // D309: never the raw body — this string reaches a persisted receipt
	}
}

// lambdaConfig is the machine-authoritative projection this driver governs.
type lambdaConfig struct {
	State string `json:"State"`
	// Role is the live EXECUTION ROLE ARN. Read for operand drift (D530): the
	// declared role_arn had no observed twin, so a change to it was invisible.
	Role        string `json:"Role"`
	StateReason string `json:"StateReason"`
	Timeout     int    `json:"Timeout"`
	// MemorySize is the live memory-in-MB (== CPU share). Read for operand drift so
	// a change to the declared memory_size on a bound function is drift, not a no-op.
	MemorySize int `json:"MemorySize"`
	// FunctionArn is the live identity GetFunction reports. Claim (takeover) checks
	// it against the ARN built from the providerId so a name that resolves to a
	// DIFFERENT function (a foreign resource in the acting account) is refused
	// rather than tagged as ours.
	FunctionArn string `json:"FunctionArn"`
	// LastUpdateStatus tracks an in-flight UpdateFunctionConfiguration:
	// InProgress -> Successful|Failed. A second config call before Successful
	// is rejected with a 409 ResourceConflictException, so the update path
	// polls this to Successful before concluding (and before any exposure step).
	LastUpdateStatus       string `json:"LastUpdateStatus"`
	LastUpdateStatusReason string `json:"LastUpdateStatusReason"`
	// operand state (F-LC3): the live VpcConfig + Environment observe reads back
	// so a change to these IMPLEMENTATION operands on a bound function is drift,
	// not a silent no-op. VpcConfig/Environment ride Configuration; the container
	// image rides the sibling Code.ImageUri, set by getLambdaFunction manually.
	VpcConfig struct {
		SubnetIds        []string `json:"SubnetIds"`
		SecurityGroupIds []string `json:"SecurityGroupIds"`
	} `json:"VpcConfig"`
	Environment struct {
		Variables map[string]string `json:"Variables"`
	} `json:"Environment"`
	Architectures []string `json:"Architectures"` // D1001: ["arm64"] | ["x86_64"]
	ImageUri      string   `json:"-"`
}

// getLambdaFunction reads GetFunction (Configuration + inline Tags). (config,
// tags, found, err): a 404 is found=false with a NIL error (a real absence); a
// transport/HTTP/parse failure returns a typed read error that NAMES the cause
// (the HTTP status + Lambda's own error code) — never a fabricated absence (D296).
func (d *Driver) getLambdaFunction(region, name string) (cfg lambdaConfig, tags map[string]string, found bool, err error) {
	const op = "GetFunction"
	st, resp, rerr := d.lambdaGet(region, lambdaFnPath+"/"+name)
	if rerr != nil {
		return lambdaConfig{}, nil, false, readTransport(op, rerr)
	}
	if st == http.StatusNotFound {
		return lambdaConfig{}, nil, false, nil
	}
	if st != http.StatusOK {
		return lambdaConfig{}, nil, false, readHTTP(op, st, lambdaErr(resp))
	}
	var out struct {
		Configuration lambdaConfig `json:"Configuration"`
		Code          struct {
			ImageUri string `json:"ImageUri"`
		} `json:"Code"`
		Tags map[string]string `json:"Tags"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return lambdaConfig{}, nil, false, readBody(op, st)
	}
	cfg = out.Configuration
	cfg.ImageUri = out.Code.ImageUri
	return cfg, out.Tags, true, nil
}

func (d *Driver) createLambda(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildLambda(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	// the function name is deterministic, so the providerId is knowable BEFORE the
	// response — a lost/garbled outcome (D29) must carry it so a function that may
	// have landed is never orphaned (handle never lost).
	pid := lambdaProviderID(region, account, plan.Name)

	// ownership pre-read: refuse to touch a foreign function already at our name.
	if _, tags, found, rerr := d.getLambdaFunction(region, plan.Name); rerr == nil && found {
		if !groundholdTagsMatch(tags, capability, environment) {
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("a function with this name exists and is not ours (tags do not "+
					"match) — refusing to adopt it; run `groundhold discover --provider aws --region %s "+
					"%s` then `adopt` to take over a foreign function", region, perr.AtNow)}
		}
		// ours already — ensure exposure + concurrency and conclude (idempotent repair).
		if res := d.ensureLambdaExposure(region, pid, plan); res != nil {
			return *res
		}
		if res := d.ensureLambdaConcurrency(region, pid, plan.Name, plan); res != nil {
			return *res
		}
		return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
	} else if rerr != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "function ownership pre-read failed: " + rerr.Error() + " — reconcile"}
	}

	body, _ := json.Marshal(plan.createBody(capability, environment))
	st, resp, err := d.lambdaDo("POST", region, lambdaFnPath, body)
	switch {
	case err != nil:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateFunction outcome unknown (may have landed): %v", err)}
	case st == http.StatusCreated || st == http.StatusOK:
		// creating — fall through to poll the observable state.
	case st == http.StatusConflict:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "CreateFunction says the name now exists — reconcile ownership"}
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateFunction HTTP %d (server error — may have landed): %s", st, lambdaErr(resp))}
	default:
		if r := provider.MutationResult(st, lambdaErr(resp), nil, "", "create"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("CreateFunction HTTP %d: %s", st, lambdaErr(resp))}
	}

	if res := d.waitLambdaActive(region, pid, plan.Name); res != nil {
		return *res
	}
	if res := d.ensureLambdaExposure(region, pid, plan); res != nil {
		return *res
	}
	// D852: the declared callers, after the function exists and before the create
	// reports success — a create that claims to have realised the contract while
	// the grants it asked for are missing would be the same lie the exposure gates
	// above refuse to tell.
	if len(plan.Invokers) > 0 {
		if res := d.ensureLambdaInvokers(region, pid, plan.Name, plan.Invokers); res != nil {
			return *res
		}
	}
	// the concurrency ceiling, after the function exists — a create that reported success
	// while the declared ceiling was unset would be the same lie the exposure/invoker
	// gates above refuse to tell (the rate limiter's multiplier stays uncapped).
	if res := d.ensureLambdaConcurrency(region, pid, plan.Name, plan); res != nil {
		return *res
	}
	return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
}

// waitLambdaActive polls GetFunction until Configuration.State is Active (a
// container-image function is Pending right after CreateFunction). Failed is a
// failed create WITH the pid (the function object exists); the poll timeout is
// unknown WITH the pid. NEVER polls an operation-by-id path. Returns nil once Active.
func (d *Driver) waitLambdaActive(region, pid, name string) *provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		cfg, _, found, rerr := d.getLambdaFunction(region, name)
		if rerr == nil && found {
			switch cfg.State {
			case "Active":
				return nil
			case "Failed":
				return &provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "function entered Failed during create: " + cfg.StateReason}
			}
			// Pending / "" -> keep polling
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "function still Pending at poll timeout — reconcile via GetFunction"}
		}
		d.progress("function provisioning — waiting for Active")
		time.Sleep(d.PollInterval)
	}
}

// ensureLambdaExposure realises the desired public/private exposure. Public =
// a Function URL whose AuthType is derived from plan.URLAuth: "none" -> NONE +
// a resource-based lambda:InvokeFunctionUrl grant to principal * (the anonymous
// mode, both gates); "iam" -> AWS_IAM + NO anonymous grant (the edge mode — the
// invoke grant is CloudFront's, added by the cdn driver). A create that cannot
// complete its gates never reports succeeded (nil = done; a non-nil result is
// the honest unknown/failed WITH pid). Private needs no wiring (no Function URL).
// Returns nil on success.
func (d *Driver) ensureLambdaExposure(region, pid string, plan LambdaPlan) *provider.CreateResult {
	if !plan.wantsFunctionURL() {
		return nil
	}
	authType := "NONE"
	if plan.URLAuth == "iam" {
		authType = "AWS_IAM"
	}
	// gate 1: the Function URL with the derived AuthType.
	urlBody, _ := json.Marshal(map[string]any{"AuthType": authType})
	st, resp, err := d.lambdaDo("POST", region, lambdaURLPath+"/"+plan.Name+"/url", urlBody)
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateFunctionUrlConfig outcome unknown: %v", err)}
	case st == http.StatusCreated || st == http.StatusOK:
		// created
	case st == http.StatusConflict:
		// a URL config already exists — confirm its AuthType matches what we want,
		// else the existing exposure does not match and cannot be repaired here.
		if existing, ok := d.getLambdaURLAuthType(region, plan.Name); ok && existing != authType {
			return &provider.CreateResult{ProviderID: pid, Status: "failed", Reason: fmt.Sprintf(
				"an existing Function URL uses AuthType %q, not %q — refusing to claim a mismatched exposure", existing, authType)}
		}
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("CreateFunctionUrlConfig HTTP %d (server error): %s", st, lambdaErr(resp))}
	default:
		return &provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("CreateFunctionUrlConfig HTTP %d: %s", st, lambdaErr(resp))}
	}

	// The IAM (edge) mode adds NO anonymous grant — that is the whole point:
	// the org RCP forbids Principal:* invoke, and CloudFront (OAC) supplies a
	// SigV4-signed, SourceArn-scoped grant instead. The URL is the only gate here.
	if plan.URLAuth == "iam" {
		return nil
	}

	// gate 2 (anonymous mode only): the resource-based grant
	// (lambda:InvokeFunctionUrl, principal *).
	permBody, _ := json.Marshal(map[string]any{
		"StatementId":         lambdaPublicStmtID,
		"Action":              "lambda:InvokeFunctionUrl",
		"Principal":           "*",
		"FunctionUrlAuthType": "NONE",
	})
	st, resp, err = d.lambdaDo("POST", region, lambdaPolicyPath(plan.Name), permBody)
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("AddPermission outcome unknown: %v", err)}
	case st == http.StatusCreated || st == http.StatusOK:
		return nil
	case st == http.StatusConflict:
		return nil // the statement already exists — idempotent
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("AddPermission HTTP %d (server error): %s", st, lambdaErr(resp))}
	default:
		return &provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("AddPermission HTTP %d: %s", st, lambdaErr(resp))}
	}
}

// getLambdaURLAuthType reads the Function URL config's AuthType. ok=false when it
// is absent or unreadable (never a default-safe value).
func (d *Driver) getLambdaURLAuthType(region, name string) (authType string, ok bool) {
	st, resp, err := d.lambdaGet(region, lambdaURLPath+"/"+name+"/url")
	if err != nil || st != http.StatusOK {
		return "", false
	}
	var out struct {
		AuthType string `json:"AuthType"`
	}
	if json.Unmarshal(resp, &out) != nil || out.AuthType == "" {
		return "", false
	}
	return out.AuthType, true
}

// lambdaArn renders a function ARN from the pid parts — fully derivable, no read.
func lambdaArn(region, account, name string) string {
	return "arn:aws:lambda:" + region + ":" + account + ":function:" + name
}

// functionURLHost strips the scheme and any trailing slash from a Function URL,
// yielding the bare host a CloudFront origin's DomainName needs.
func functionURLHost(url string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://")
	return strings.TrimRight(h, "/")
}

// getLambdaFunctionURL reads the Function URL (the server-assigned host is NOT in
// the pid). (url, found, err): a 404 is found=false with a NIL error (the
// function has no URL — a private function); a transport/HTTP/parse failure
// returns a typed read error (never a fabricated absence, D296).
func (d *Driver) getLambdaFunctionURL(region, name string) (url string, found bool, err error) {
	const op = "GetFunctionUrlConfig"
	st, resp, rerr := d.lambdaGet(region, lambdaURLPath+"/"+name+"/url")
	if rerr != nil {
		return "", false, readTransport(op, rerr)
	}
	if st == http.StatusNotFound {
		return "", false, nil
	}
	if st != http.StatusOK {
		return "", false, readHTTP(op, st, lambdaErr(resp))
	}
	var out struct {
		FunctionUrl string `json:"FunctionUrl"`
	}
	if json.Unmarshal(resp, &out) != nil || out.FunctionUrl == "" {
		return "", false, readBody(op, st)
	}
	return out.FunctionUrl, true, nil
}

// observeLambda reverse-maps a live function to capability.function.serverless.
// publicExposure is measured from the Function URL config's AuthType (NONE=public);
// an absent URL is private; an unreadable URL surface emits a diagnostic and NOTHING.
func (d *Driver) observeLambda(capability, providerID string) ([]provider.Observation, []string, error) {
	region, _, name, err := splitLambdaProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	cfg, _, found, rerr := d.getLambdaFunction(region, name)
	if rerr != nil {
		// a READ ERROR (transport/HTTP/parse) is unknown, never an absence — the
		// four-valued discipline. It stays a returned error the caller blocks on;
		// only a readable 404 (found=false, nil error) is an authoritative absence.
		return nil, nil, rerr
	}
	if !found {
		// F-LC3 part 2: a BOUND function that GetFunction authoritatively 404s is
		// GONE (e.g. deleted out-of-band). Emit the reserved absence marker so the
		// compiler re-creates it, rather than a bare diagnostic that leaves the
		// binding a no-op forever.
		return []provider.Observation{
			{Path: provider.ResourceAbsentPath, Value: true, Derivation: "measured"},
		}, []string{"function not found — bound resource is gone (will re-create)"}, nil
	}
	obs := []provider.Observation{
		// present: toggle the absence marker back off (F-LC3), so a stale "gone"
		// reading from a prior observe never lingers after a recreate.
		{Path: provider.ResourceAbsentPath, Value: false, Derivation: "measured"},
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "tls.enforced", Value: true, Derivation: "platform-invariant"}, // a Function URL is HTTPS-only
	}
	// operand state (F-LC3): the live VpcConfig, Environment and image, canonicalized
	// exactly as OperandTargets renders the DECLARED operands, so the compiler's
	// operand-drift step compares like for like.
	obs = append(obs,
		provider.Observation{Path: lambdaVpcOperand,
			Value: canonSubnetsSGs(cfg.VpcConfig.SubnetIds, cfg.VpcConfig.SecurityGroupIds), Derivation: "measured"},
		provider.Observation{Path: lambdaEnvOperand,
			Value: canonEnv(cfg.Environment.Variables), Derivation: "measured"},
		provider.Observation{Path: lambdaPkgOperand,
			Value: cfg.ImageUri, Derivation: "measured"},
		provider.Observation{Path: lambdaArchOperand,
			Value: lambdaLiveArch(cfg.Architectures), Derivation: "measured"},
		lambdaRoleObservation(cfg.Role))
	if cfg.Timeout > 0 {
		obs = append(obs, provider.Observation{Path: "timeout.maximum",
			Value: fmt.Sprintf("%ds", cfg.Timeout), Derivation: "measured"})
	}
	if cfg.MemorySize > 0 {
		// operand drift: the live memory, rendered exactly as OperandTargets renders
		// the DECLARED memory_size, so the compiler compares like for like.
		obs = append(obs, provider.Observation{Path: lambdaMemOperand,
			Value: fmt.Sprintf("%d", cfg.MemorySize), Derivation: "measured"})
	}
	var diags []string

	// reserved concurrency rides its OWN endpoint (GetFunctionConcurrency): emit the
	// operand only when a reservation is set. An unreadable read records a diagnostic and
	// NOTHING — never a fabricated "no reservation", which would make a declared ceiling
	// falsely drift (the invokers rule: what we could not read, we do not assert).
	if rc, present, readable, why := d.getLambdaConcurrency(region, name); !readable {
		diags = append(diags, "reserved concurrency unread: "+why)
	} else if present {
		obs = append(obs, provider.Observation{Path: lambdaConcOperand,
			Value: fmt.Sprintf("%d", rc), Derivation: "measured"})
	}

	// D852: the grants the `invokers` operand owns, read back from the function's
	// own resource policy. An unreadable policy records NOTHING rather than an
	// empty set — "we own no grants" and "we could not look" are different answers,
	// and the second one dressed as the first would plan a repair that withdraws
	// grants nobody measured (D847).
	if canon, ok := d.observedLambdaInvokers(region, name); ok {
		obs = append(obs, provider.Observation{Path: lambdaInvokersOperand,
			Value: canon, Derivation: "measured"})
	} else {
		diags = append(diags, "implementation.invokers not observed: the resource policy "+
			"could not be read — the declared callers cannot be compared this run")
	}
	// publicExposure: read the Function URL config. 404 -> no URL -> private.
	st, urlBody, uerr := d.lambdaGet(region, lambdaURLPath+"/"+name+"/url")
	switch {
	case uerr == nil && st == http.StatusNotFound:
		obs = append(obs, provider.Observation{Path: "network.publicExposure", Value: false, Derivation: "measured"})
	case uerr == nil && st == http.StatusOK:
		// D534: the vocabulary defines this as "invokable over public HTTPS by
		// ANYONE (an unauthenticated public endpoint)", and its aws.lambda mapping
		// spells out BOTH gates: "a Function URL with AuthType NONE plus a
		// resource-based lambda:InvokeFunctionUrl grant to principal * (both, or
		// the function stays private)".
		//
		// This used to report true for ANY Function URL. A URL with AuthType
		// AWS_IAM behind CloudFront/OAC — the correct hardening, where only the CDN
		// may sign a request — was observed as publicly exposed. Declaring the
		// truth then produced a diff whose repair DELETES the Function URL, i.e.
		// the CDN's origin. Reading AuthType is not a vocabulary change: the
		// operand stays an operand, and this is the OBSERVATION of a vocab
		// attribute that the mapping always said depended on it.
		pub, measured, why := d.lambdaAnonymouslyInvokable(region, name, urlBody)
		if why != "" {
			diags = append(diags, why)
		}
		// Only a value that was actually established is recorded: absence of evidence
		// stays the signal (D242), exactly as the default branch below already does for
		// an unreadable URL config (D847).
		if measured {
			obs = append(obs, provider.Observation{Path: "network.publicExposure",
				Value: pub, Derivation: "measured"})
		}
	default:
		diags = append(diags, fmt.Sprintf(
			"network.publicExposure not observed: Function URL config read failed (HTTP %d: %v)", st, uerr))
	}

	// D1031/D1032: witness the retention on the function's certified EMITTED log group
	// — the /aws/lambda/<fn> group AWS auto-creates on first invocation, where the
	// function's own logs actually land. A monitoring.logs capability builds a SEPARATE
	// group the function never writes to, so a 365d retention there reads satisfied
	// while the real logs never expire (the field GDPR finding). The emission registry
	// (D1032) is the authority for WHICH companion this compute auto-materialises and
	// WHICH capability governs it; CertifyEmissions proves that companion is named by
	// the lambda `logGroupName` output (D381), so the name below (lambdaLogGroupName —
	// the same derivation) cannot drift from what a bound monitoring.logs would govern
	// (D329). WITNESS ONLY: governing this group is a bound monitoring.logs' job under
	// an adopt grant; here we only READ. Mirror observeCWLogs — a group with no
	// retentionInDays keeps logs forever, an unbounded posture a witness cannot fake as
	// a finite duration — so a never-expires group and a not-yet-created group both
	// leave the attribute UNMEASURED (a hard constraint blocks as unknown, never a
	// false satisfied).
	for _, comp := range d.EmittedCompanions()["lambda"] {
		if comp.GovernedBy != "capability.monitoring.logs" {
			continue
		}
		group := lambdaLogGroupName(name)
		lg, lgFound, lgErr := d.describeCWLogGroup(region, group)
		switch {
		case lgErr != nil:
			diags = append(diags, "defaultLogGroup.retention not observed: DescribeLogGroups on "+
				group+" failed — "+lgErr.Error())
		case lgFound && lg.RetentionInDays > 0:
			obs = append(obs, provider.Observation{Path: "defaultLogGroup.retention",
				Value: fmt.Sprintf("%dh", lg.RetentionInDays*24), Derivation: "measured"})
		case lgFound:
			diags = append(diags, "defaultLogGroup.retention unknown: the certified emission "+group+
				" (governed by "+comp.GovernedBy+") exists but has NO retention policy (never-expires)"+
				" — a witness cannot express unbounded retention as a finite duration; a hard"+
				" constraint blocks as unknown")
		default:
			diags = append(diags, "defaultLogGroup.retention unknown: the certified emission "+group+
				" does not exist yet (created on first invocation)")
		}
	}
	return obs, diags, nil
}

// deleteLambda: ownership pre-read (tags), then DeleteFunction. 404 is idempotent
// success; a foreign function is never deleted.
func (d *Driver) deleteLambda(capability, environment, providerID string) provider.CreateResult {
	region, _, name, err := splitLambdaProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, tags, found, rerr := d.getLambdaFunction(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read failed: " + rerr.Error() + " — reconcile"}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "function tags do not match — refusing to delete a resource that is not ours"}
	}
	st, resp, e := d.lambdaDo("DELETE", region, lambdaFnPath+"/"+name, nil)
	switch {
	case e != nil:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("DeleteFunction outcome unknown: %v", e)}
	case st == http.StatusNotFound:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent
	case st == http.StatusNoContent || st == http.StatusOK || st == http.StatusAccepted:
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
	case st >= 500:
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("DeleteFunction HTTP %d (server error) — reconcile", st)}
	default:
		if r := provider.MutationResult(st, lambdaErr(resp), nil, providerID, "delete"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("DeleteFunction HTTP %d: %s", st, lambdaErr(resp))}
	}
}

// classifyLambdaChange (D46): PURE — can this capability.function.serverless
// transition be honored IN PLACE? timeout.maximum patches online via
// UpdateFunctionConfiguration; network.publicExposure toggles the Function URL
// + resource grant (no replacement). location.region is fixed at creation.
// tls.enforced / service.managed / replicas.minimum are platform properties a
// create already gated — nothing to patch here (they never differ on a bound
// function). VpcConfig + Environment are IMPLEMENTATION operands, not attribute
// paths, so they do not reach ClassifyChange; when any mutable attribute routes
// to an update, updateLambda re-pushes the full derivable config (Role, Timeout,
// VpcConfig, Environment), keeping those operands consistent too.
func classifyLambdaChange(path string) (string, string) {
	switch path {
	case "timeout.maximum":
		return "mutable", "patched online via UpdateFunctionConfiguration"
	case "network.publicExposure":
		return "mutable", "the Function URL + resource grant is added/removed in place (no replacement)"
	case "location.region":
		return "immutable", "a Lambda function's region is fixed at creation — a change is a replacement"
	case lambdaArchOperand:
		// D1001: architecture is set once at CreateFunction — a change is a replacement.
		return "immutable", "a Lambda function's architecture is fixed at creation — a change is a replacement"
	case lambdaRoleOperand:
		// D530: UpdateFunctionConfiguration carries Role, so a role change is a
		// patch. Reading it as immutable would REPLACE a live function to edit
		// a permission.
		return "mutable", "execution role patched online via UpdateFunctionConfiguration"
	case lambdaVpcOperand, lambdaEnvOperand:
		// F-LC3: VpcConfig / Environment drift patches online via the full
		// UpdateFunctionConfiguration (updateConfigBody re-pushes both).
		return "mutable", "operand patched online via UpdateFunctionConfiguration"
	case lambdaMemOperand:
		// memory rides UpdateFunctionConfiguration (updateConfigBody re-pushes it),
		// so a memory_size change patches online — never a replacement.
		return "mutable", "memory size patched online via UpdateFunctionConfiguration"
	case lambdaConcOperand:
		// reserved concurrency rides its own PutFunctionConcurrency call — a change
		// is a secondary patch, never a replacement of the function.
		return "mutable", "reserved concurrency patched in place via PutFunctionConcurrency"
	case lambdaPkgOperand:
		// F-LC3: a container-image swap patches online via UpdateFunctionCode
		// (no replacement — the function identity survives).
		return "mutable", "container image patched online via UpdateFunctionCode"
	case lambdaInvokersOperand:
		// D852: resource-policy statements are added and removed in place; the
		// function identity is untouched. Reading this as immutable would REPLACE a
		// live function to change who may call it.
		return "mutable", "invoke grants added/withdrawn in place via AddPermission/RemovePermission"
	case "tls.enforced", "service.managed", "replicas.minimum":
		return "unsupported", "platform/projection property — nothing to patch in place"
	default:
		return "unsupported", "no Lambda in-place mapping for " + path
	}
}

// observedAbsent reports whether an observation set carries the reserved
// absence marker set true (F-LC3): the resource is authoritatively gone.
func observedAbsent(obs []provider.Observation) bool {
	for _, o := range obs {
		if o.Path == provider.ResourceAbsentPath {
			present, _ := o.Value.(bool)
			return present
		}
	}
	return false
}

// lambdaLiveArch canonicalises the Architectures a GetFunction returns to the single
// value the operand carries. AWS always returns exactly one; an empty read defaults to
// x86_64 (the service default), so observe never fabricates an architecture (D1001).
func lambdaLiveArch(arch []string) string {
	if len(arch) > 0 && arch[0] != "" {
		return arch[0]
	}
	return "x86_64"
}

// OperandTargets (F-LC3, provider.OperandDrifter): the canonical operand values
// this capability's DECLARED implementation should hold, keyed by reserved
// observation path — the desired side the compiler compares against observe's
// recorded operand state. PURE (no network). A build refusal (e.g. a partial
// VpcConfig) surfaces as an error the compiler isolates per capability.
func (d *Driver) OperandTargets(service string, attrs, impl map[string]any) ([]provider.OperandTarget, error) {
	if service == "cloudwatch" {
		return cloudWatchOperandTargets(attrs, impl)
	}
	if service == "eventbridgescheduler" {
		// D1004: the DESIRED schedule expression, so a changed cron/rate drifts (mutable).
		plan, err := BuildEventBridgeScheduler("", "", attrs, impl, 1)
		if err != nil {
			return nil, err
		}
		return []provider.OperandTarget{{Path: ebsScheduleOperand, Desired: plan.Schedule}}, nil
	}
	if service != "lambda" {
		return nil, nil
	}
	// D774, from the field, marked BLOKADA. This derives the DESIRED operand shape so
	// the reconcile can compare it against what was observed — a DRIFT question. It went
	// through BuildLambda, which refuses without `image_uri` because a CREATE needs one.
	// So four ZIP-packaged functions, all bound, all converged, all untouched by the
	// plan, blocked the plan of 43 capabilities — 39 of which have nothing to do with
	// Lambda. A create requirement is not a drift requirement.
	//
	// Without an image the driver cannot state a desired PACKAGE, and says so by
	// omitting that target; it can still state the environment, the role and the VPC
	// config, and those keep drifting-detection alive for the parts it does govern.
	// Partial targets, for the same reason outputs are now partial: the missing piece
	// refuses where it is used, not everywhere.
	probe := impl
	packageKnown := true
	if _, has := impl["image_uri"]; !has {
		packageKnown = false
		probe = make(map[string]any, len(impl)+1)
		for k, v := range impl {
			probe[k] = v
		}
		// A stand-in that satisfies the create-shape check and never leaves this
		// function: the package target it would feed is omitted below.
		probe["image_uri"] = "000000000000.dkr.ecr.us-east-1.amazonaws.com/unknown:unknown"
	}
	plan, err := BuildLambda("000000000000", "", "", attrs, probe, 1)
	if err != nil {
		return nil, err
	}
	vpc, env, pkg := plan.operandCanon()
	// sorted by Path (determinism): implementation.architecture < .environment < .package < .vpcConfig
	targets := []provider.OperandTarget{}
	// D1001: an architecture target ONLY when the operand is declared — an adopted
	// arm64 function whose contract stayed silent must NOT drift-to-x86_64-replace
	// (the D774 lesson: a create default is not a drift requirement).
	if plan.ArchitectureSet {
		targets = append(targets, provider.OperandTarget{Path: lambdaArchOperand, Desired: plan.Architecture})
	}
	// memory_size target ONLY when declared — an adopted function whose contract is
	// silent must not drift toward AWS's 128 MB default (the arch/D774 declared-only rule).
	if plan.MemorySizeSet {
		targets = append(targets, provider.OperandTarget{Path: lambdaMemOperand,
			Desired: fmt.Sprintf("%d", plan.MemorySize)})
	}
	// reserved_concurrency target ONLY when declared — an adopted function's live
	// reservation must not drift to "unset" just because the contract is silent.
	if plan.ReservedConcurrencySet {
		targets = append(targets, provider.OperandTarget{Path: lambdaConcOperand,
			Desired: fmt.Sprintf("%d", plan.ReservedConcurrency)})
	}
	targets = append(targets, provider.OperandTarget{Path: lambdaEnvOperand, Desired: env})
	if packageKnown {
		targets = append(targets, provider.OperandTarget{Path: lambdaPkgOperand, Desired: pkg})
	}
	return append(targets,
		provider.OperandTarget{Path: lambdaInvokersOperand, Desired: CanonLambdaInvokers(plan.Invokers)}, // D852
		provider.OperandTarget{Path: lambdaRoleOperand, Desired: plan.RoleArn},                           // D530
		provider.OperandTarget{Path: lambdaVpcOperand, Desired: vpc},
	), nil
}

// lambdaPatchOutcome folds one Lambda patch call into the four-valued shape:
// nil means "keep going" (2xx accepted); non-nil is terminal. Ambiguous
// (transport / 5xx) or a 409 (a concurrent update in flight) is unknown WITH
// the providerId; any other 4xx/3xx is failed (never a silent success).
func lambdaPatchOutcome(what, providerID string, st int, resp []byte, err error) *provider.CreateResult {
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s outcome unknown (may have landed) — reconcile: %v", what, err)}
	case st >= 500:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s HTTP %d (server error) — reconcile", what, st)}
	case st == http.StatusConflict:
		return &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("%s conflicted (a concurrent update is in progress) — reconcile", what)}
	case st < 200 || st >= 300:
		return &provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("%s failed: HTTP %d: %s", what, st, lambdaErr(resp))}
	default:
		return nil
	}
}

// updateLambda patches a function IN PLACE (D46). Ownership (tags) is re-checked
// before any mutation. timeout.maximum rides the full-config
// UpdateFunctionConfiguration (which also re-pushes Role, VpcConfig and
// Environment, keeping the declared operands consistent); network.publicExposure
// reconciles the Function URL. A config update is async — the driver waits for
// LastUpdateStatus=Successful before the exposure step (a second call in flight
// would 409). Four-valued per D29/D87.
func (d *Driver) updateLambda(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, account, name, err := splitLambdaProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	if err := d.sameAccount(account); err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	_, tags, found, rerr := d.getLambdaFunction(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer — reconcile: " + rerr.Error()}
	}
	if !found {
		return provider.CreateResult{Status: "failed",
			Reason: "function no longer exists — re-observe and re-plan"}
	}
	if !groundholdTagsMatch(tags, capability, environment) {
		return provider.CreateResult{Status: "failed",
			Reason: "function tags do not match — refusing to patch a resource that is not ours"}
	}
	// rebuild the desired config from the resolved attrs+impl (references already
	// resolved by apply); the account rides in the pid, not the create scope.
	plan, berr := BuildLambda(account, environment, capability, attrs, impl, 1)
	if berr != nil {
		return provider.CreateResult{Status: "failed", Reason: berr.Error()}
	}

	wantConfig, wantExposure, wantCode := false, false, false
	wantInvokers := false
	wantConcurrency := false
	for _, path := range changes {
		switch path {
		case "timeout.maximum", lambdaVpcOperand, lambdaEnvOperand, lambdaMemOperand:
			// timeout + VpcConfig + Environment + memory all ride the full-config
			// UpdateFunctionConfiguration (updateConfigBody re-pushes them, F-LC3).
			wantConfig = true
		case "network.publicExposure":
			wantExposure = true
		case lambdaPkgOperand:
			wantCode = true // F-LC3: a container-image swap via UpdateFunctionCode
		case lambdaInvokersOperand:
			wantInvokers = true // D852: the declared callers moved
		case lambdaConcOperand:
			wantConcurrency = true // the concurrency ceiling moved (PutFunctionConcurrency)
		default:
			return provider.CreateResult{Status: "failed",
				Reason: fmt.Sprintf("lambda path %s is not patchable in place", path)}
		}
	}

	if wantConfig {
		body, _ := json.Marshal(plan.updateConfigBody())
		st, resp, uerr := d.lambdaDo("PUT", region, lambdaFnPath+"/"+name+"/configuration", body)
		if r := lambdaPatchOutcome("UpdateFunctionConfiguration", providerID, st, resp, uerr); r != nil {
			return *r
		}
		if r := d.waitLambdaUpdated(region, providerID, name); r != nil {
			return *r
		}
	}
	if wantCode {
		// UpdateFunctionCode is async like the config patch — a second call before
		// LastUpdateStatus=Successful would 409, so wait it out afterwards.
		body, _ := json.Marshal(plan.updateCodeBody())
		st, resp, uerr := d.lambdaDo("PUT", region, lambdaFnPath+"/"+name+"/code", body)
		if r := lambdaPatchOutcome("UpdateFunctionCode", providerID, st, resp, uerr); r != nil {
			return *r
		}
		if r := d.waitLambdaUpdated(region, providerID, name); r != nil {
			return *r
		}
	}
	if wantExposure {
		if plan.wantsFunctionURL() {
			if r := d.ensureLambdaExposure(region, providerID, plan); r != nil {
				return *r
			}
		} else if r := d.removeLambdaExposure(region, providerID, name); r != nil {
			return *r
		}
	}
	// D852: reconcile against the LIVE policy, so an entry dropped from the
	// candidate is withdrawn rather than merely un-added.
	if wantInvokers {
		if r := d.ensureLambdaInvokers(region, providerID, name, plan.Invokers); r != nil {
			return *r
		}
	}
	if wantConcurrency {
		if r := d.ensureLambdaConcurrency(region, providerID, name, plan); r != nil {
			return *r
		}
	}
	return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
}

// waitLambdaUpdated polls GetFunction until Configuration.LastUpdateStatus is
// Successful (the config patch landed). Failed is a failed update WITH the pid;
// the poll timeout is unknown WITH the pid. Returns nil once Successful.
func (d *Driver) waitLambdaUpdated(region, pid, name string) *provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		cfg, _, found, rerr := d.getLambdaFunction(region, name)
		if rerr == nil && found {
			switch cfg.LastUpdateStatus {
			case "Successful", "":
				// "" = a function that reports no in-flight update (already settled).
				return nil
			case "Failed":
				return &provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "UpdateFunctionConfiguration entered Failed: " + cfg.LastUpdateStatusReason}
			}
			// InProgress -> keep polling
		}
		if d.Now().After(deadline) {
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "function still updating at poll timeout — reconcile via GetFunction"}
		}
		d.progress("function updating — waiting for LastUpdateStatus Successful")
		time.Sleep(d.PollInterval)
	}
}

// removeLambdaExposure tears down public exposure (going private): delete the
// Function URL config and remove the resource-based grant. Both are idempotent
// (a 404 is success). Returns nil on success.
func (d *Driver) removeLambdaExposure(region, pid, name string) *provider.CreateResult {
	st, resp, err := d.lambdaDo("DELETE", region, lambdaURLPath+"/"+name+"/url", nil)
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("DeleteFunctionUrlConfig outcome unknown: %v", err)}
	case st == http.StatusNotFound, st == http.StatusNoContent, st == http.StatusOK, st == http.StatusAccepted:
		// gone or removed — idempotent
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("DeleteFunctionUrlConfig HTTP %d (server error): %s", st, lambdaErr(resp))}
	default:
		return &provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("DeleteFunctionUrlConfig HTTP %d: %s", st, lambdaErr(resp))}
	}
	st, resp, err = d.lambdaDo("DELETE", region, lambdaPolicyPath(name)+"/"+lambdaPublicStmtID, nil)
	switch {
	case err != nil:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("RemovePermission outcome unknown: %v", err)}
	case st == http.StatusNotFound, st == http.StatusNoContent, st == http.StatusOK, st == http.StatusAccepted:
		return nil // idempotent
	case st >= 500:
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("RemovePermission HTTP %d (server error): %s", st, lambdaErr(resp))}
	default:
		return &provider.CreateResult{ProviderID: pid, Status: "failed",
			Reason: fmt.Sprintf("RemovePermission HTTP %d: %s", st, lambdaErr(resp))}
	}
}

// discoverLambda enumerates functions in the region (ListFunctions) as
// capability.function.serverless — the SAME reverse map observe uses.
func (d *Driver) discoverLambda(region string) ([]provider.Discovered, []string, error) {
	account, err := d.resolveAccount()
	if err != nil {
		return nil, nil, err
	}
	// D809: FOLLOW the pages. ListFunctions answers 50 at a time and hands back a
	// NextMarker; reading the first page and stopping made an account with 60 functions
	// look like an account with 50. D803 made that visible (the sweep says it stopped
	// early, so the shadow count goes out as a lower bound) — this makes it untrue.
	var lf struct {
		Functions []struct {
			FunctionName string `json:"FunctionName"`
		} `json:"Functions"`
		NextMarker string `json:"NextMarker"`
	}
	var names []string
	marker := ""
	for {
		path := lambdaFnPath + "/"
		if marker != "" {
			path += "?Marker=" + url.QueryEscape(marker)
		}
		st, body, err := d.lambdaGet(region, path)
		if err != nil {
			return nil, nil, err
		}
		if st != http.StatusOK {
			return nil, nil, fmt.Errorf("lambda ListFunctions: HTTP %d: %s", st, lambdaErr(body))
		}
		lf.Functions = nil
		lf.NextMarker = ""
		if json.Unmarshal(body, &lf) != nil {
			return nil, nil, fmt.Errorf("lambda ListFunctions: unparseable response")
		}
		for _, f := range lf.Functions {
			names = append(names, f.FunctionName)
		}
		if lf.NextMarker == "" {
			break
		}
		marker = lf.NextMarker
	}
	var out []provider.Discovered
	var diags []string
	for _, name := range names {
		if !lambdaNameOK.MatchString(name) {
			continue
		}
		pid := lambdaProviderID(region, account, name)
		obs, odiags, oerr := d.observeLambda("", pid)
		if oerr != nil {
			diags = append(diags, name+": observe: "+oerr.Error())
			continue
		}
		if observedAbsent(obs) {
			// listed then 404'd on read — a mid-enumeration race; the absence
			// marker (F-LC3) is meaningful for a BOUND resource, not a discovery.
			continue
		}
		for _, dg := range odiags {
			diags = append(diags, name+": "+dg)
		}
		out = append(out, provider.Discovered{
			ProviderID:   pid,
			ResourceType: "capability.function.serverless",
			Observations: provider.WithoutAbsence(obs),
		})
	}
	return out, diags, nil
}

// lambdaPolicyPath is the ONE spelling of a function's resource-policy route.
//
// D694: the three sites that touch that policy spelled it twice. AddPermission and
// RemovePermission built it on lambdaFnPath (`/2015-03-31`), correctly; the READ that
// decides `network.publicExposure` built it on lambdaURLPath (`/2021-10-31`), which is
// the Function URL API and has no policy route at all. Measured against the live
// endpoint, no credentials needed:
//
//	GET /2015-03-31/functions/x/policy -> {"message":"Missing Authentication Token"}   route exists
//	GET /2021-10-31/functions/x/policy -> "Unable to determine service/operation name"  route does NOT
//
// AWS answered our own bad URL with a 404, the reader took it for "this function has
// no resource policy", and every Function URL with AuthType NONE — the ones that ARE
// anonymously invokable — was observed as `publicExposure: false`. A live function
// answering 200 to an unauthenticated caller, recorded as not exposed, with no
// diagnostic. Reported from the field before any gate here saw it.
//
// One helper rather than three strings: the write path and the read path cannot drift
// apart again.
func lambdaPolicyPath(name string) string {
	return lambdaFnPath + "/" + name + "/policy"
}

// lambdaAnonymouslyInvokable answers the vocabulary's question for a function that
// HAS a Function URL: can anyone call it without credentials? Both gates must be
// open (D534) — AuthType NONE, and a resource policy granting
// lambda:InvokeFunctionUrl to principal *. Either one shut means private.
//
// The returned diagnostic is non-empty when the policy could not be read and the
// answer therefore rests on the AuthType alone; a read failure never invents an
// exposure, in either direction.
// The second return is MEASURED (D847). It used to be inferred from the third: a
// non-empty explanation meant "we did not really establish this". Nothing enforced
// that reading, and the caller emitted the value anyway with Derivation "measured",
// so the prose said NOT measured while the record said the opposite — and only the
// record travels. `audit.evidenceRank` demotes `config-intent` and
// `platform-invariant`; a stamped-measured false is full-strength evidence, so a hard
// `publicExposure == false` came back SATISFIED for a function whose grant nobody
// could read. A separate boolean cannot be forgotten by a branch that returns a value.
func (d *Driver) lambdaAnonymouslyInvokable(region, name string, urlCfg []byte) (pub, measured bool, why string) {
	var cfg struct {
		AuthType string `json:"AuthType"`
	}
	if json.Unmarshal(urlCfg, &cfg) != nil {
		return false, false, "network.publicExposure: the Function URL config did not parse — " +
			"the grant was not established, so nothing is observed for this path"
	}
	if !strings.EqualFold(cfg.AuthType, "NONE") {
		// AWS_IAM: every caller signs. No resource policy can make it anonymous, so
		// this one IS measured — the URL config alone settles it.
		return false, true, ""
	}
	st, body, err := d.lambdaGet(region, lambdaPolicyPath(name))
	switch {
	case err == nil && st == http.StatusNotFound:
		return false, true, "" // no resource policy at all: nobody but IAM principals
	case err != nil || st != http.StatusOK:
		return false, false, fmt.Sprintf(
			"network.publicExposure: AuthType is NONE but the resource policy could not be "+
				"read (HTTP %d: %v) — the world's access turns on that policy, so nothing "+
				"is observed rather than reporting private", st, err)
	}
	var pol struct {
		Policy string `json:"Policy"`
	}
	if json.Unmarshal(body, &pol) != nil {
		return false, false, "network.publicExposure: the resource policy did not parse — " +
			"nothing is observed rather than reporting private"
	}
	return lambdaPolicyGrantsAnonymousInvoke(pol.Policy), true, ""
}

// lambdaPolicyGrantsAnonymousInvoke reports whether the resource policy lets the
// WORLD invoke the Function URL: an Allow of lambda:InvokeFunctionUrl to principal
// "*" (AWS documents both the bare string and {"AWS":"*"}).
func lambdaPolicyGrantsAnonymousInvoke(policy string) bool {
	var doc struct {
		Statement []struct {
			Effect    string `json:"Effect"`
			Principal any    `json:"Principal"`
			Action    any    `json:"Action"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(policy), &doc) != nil {
		return false
	}
	anyStar := func(v any) bool {
		switch t := v.(type) {
		case string:
			return t == "*"
		case map[string]any:
			for _, inner := range t {
				if anyStarLeaf(inner) {
					return true
				}
			}
		}
		return false
	}
	hasInvoke := func(v any) bool {
		switch t := v.(type) {
		case string:
			return t == "lambda:InvokeFunctionUrl"
		case []any:
			for _, a := range t {
				if s, _ := a.(string); s == "lambda:InvokeFunctionUrl" {
					return true
				}
			}
		}
		return false
	}
	for _, st := range doc.Statement {
		if strings.EqualFold(st.Effect, "Allow") && anyStar(st.Principal) && hasInvoke(st.Action) {
			return true
		}
	}
	return false
}

// getLambdaConcurrency reads the function's reserved concurrency from its OWN endpoint
// (GetFunctionConcurrency, not GetFunctionConfiguration). present=false is a readable
// "no reservation set" (the function draws from the account's unreserved pool); a
// transport/HTTP/parse failure is readable=false with a named cause, never a fabricated
// absence (D296) — so a read we could not make is not mistaken for "no reservation".
func (d *Driver) getLambdaConcurrency(region, name string) (value int, present, readable bool, why string) {
	st, resp, rerr := d.lambdaGet(region, lambdaConcGetPath+"/"+name+"/concurrency")
	if rerr != nil {
		return 0, false, false, rerr.Error()
	}
	if st == http.StatusNotFound {
		return 0, false, true, "" // no function / no reservation — a readable absence
	}
	if st != http.StatusOK {
		return 0, false, false, fmt.Sprintf("GetFunctionConcurrency HTTP %d: %s", st, lambdaErr(resp))
	}
	var out struct {
		ReservedConcurrentExecutions *int `json:"ReservedConcurrentExecutions"`
	}
	if json.Unmarshal(resp, &out) != nil {
		return 0, false, false, "GetFunctionConcurrency returned unparseable JSON"
	}
	if out.ReservedConcurrentExecutions == nil {
		return 0, false, true, "" // readable: no reservation is set
	}
	return *out.ReservedConcurrentExecutions, true, true, ""
}

// ensureLambdaConcurrency reconciles the reserved concurrency to the DECLARED value via
// PutFunctionConcurrency (a secondary call, like the Function URL and invoke grants). It
// acts ONLY when the operand is declared — an adopted function's live reservation is left
// alone (the declared-only rule) — and reads the live value first, so a reservation
// already at the ceiling issues no call.
func (d *Driver) ensureLambdaConcurrency(region, pid, name string, plan LambdaPlan) *provider.CreateResult {
	if !plan.ReservedConcurrencySet {
		return nil
	}
	live, present, readable, why := d.getLambdaConcurrency(region, name)
	if !readable {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "reserved concurrency not reconciled: " + why + " — the live value could not be read"}
	}
	if present && live == plan.ReservedConcurrency {
		return nil // already at the declared ceiling
	}
	body, _ := json.Marshal(map[string]any{"ReservedConcurrentExecutions": plan.ReservedConcurrency})
	st, resp, err := d.lambdaDo("PUT", region, lambdaConcPutPath+"/"+name+"/concurrency", body)
	return lambdaPatchOutcome("PutFunctionConcurrency", pid, st, resp, err)
}

func anyStarLeaf(v any) bool {
	switch t := v.(type) {
	case string:
		return t == "*"
	case []any:
		for _, x := range t {
			if s, _ := x.(string); s == "*" {
				return true
			}
		}
	}
	return false
}

// ensureLambdaInvokers reconciles the resource-policy statements the `invokers`
// operand owns (D852): every declared grant present, every grant of OURS that the
// operand no longer lists removed, and nothing else touched.
//
// It READS the policy first, and that read is the whole reason reconciliation can
// be honest: without it the driver could add but never withdraw, so removing an
// entry from the candidate would leave the grant live and the estate would quietly
// keep a caller the contract had dropped.
func (d *Driver) ensureLambdaInvokers(region, pid, name string, want []LambdaInvoker) *provider.CreateResult {
	live, readable, why := d.lambdaOwnedInvokerSids(region, name)
	if !readable {
		return &provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: "invokers not reconciled: " + why + " — the grant set could not be read, " +
				"so this run does not know which statements exist"}
	}

	desired := map[string]bool{}
	for _, e := range want {
		desired[e.StatementID()] = true
		if live[e.StatementID()] {
			continue // already present, byte-identical by construction of the id
		}
		body := map[string]any{
			"StatementId": e.StatementID(),
			"Action":      "lambda:InvokeFunction",
			"Principal":   e.Principal,
		}
		if e.SourceArn != "" {
			body["SourceArn"] = e.SourceArn
		}
		raw, _ := json.Marshal(body)
		st, resp, err := d.lambdaDo("POST", region, lambdaPolicyPath(name), raw)
		switch {
		case err != nil:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("AddPermission (invoker %s) outcome unknown: %v", e.Principal, err)}
		case st == http.StatusCreated || st == http.StatusOK, st == http.StatusConflict:
			// created, or already there under the same id (idempotent)
		case st >= 500:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("AddPermission (invoker %s) HTTP %d (server error) — reconcile",
					e.Principal, st)}
		default:
			return &provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("AddPermission (invoker %s) HTTP %d: %s",
					e.Principal, st, lambdaErr(resp))}
		}
	}

	// Withdraw ours that the operand dropped. Sorted so a failure mid-way is
	// reproducible rather than order-of-map dependent.
	var stale []string
	for sid := range live {
		if !desired[sid] {
			stale = append(stale, sid)
		}
	}
	sort.Strings(stale)
	for _, sid := range stale {
		st, resp, err := d.lambdaDo("DELETE", region, lambdaPolicyPath(name)+"/"+sid, nil)
		switch {
		case err != nil:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("RemovePermission (%s) outcome unknown: %v", sid, err)}
		case st == http.StatusNoContent || st == http.StatusOK, st == http.StatusNotFound:
			// gone, or already gone
		case st >= 500:
			return &provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: fmt.Sprintf("RemovePermission (%s) HTTP %d (server error) — reconcile", sid, st)}
		default:
			return &provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("RemovePermission (%s) HTTP %d: %s", sid, st, lambdaErr(resp))}
		}
	}
	return nil
}

// lambdaOwnedInvokerSids reads the resource policy and returns the statement ids
// this operand owns. readable=false means the policy gave no answer — never an
// empty set, which would read as "we own nothing" and make a reconcile withdraw
// nothing while reporting success (the D847 shape).
func (d *Driver) lambdaOwnedInvokerSids(region, name string) (sids map[string]bool, readable bool, why string) {
	st, body, err := d.lambdaGet(region, lambdaPolicyPath(name))
	switch {
	case err == nil && st == http.StatusNotFound:
		return map[string]bool{}, true, "" // no policy at all: nothing of ours on it
	case err != nil:
		return nil, false, fmt.Sprintf("GetPolicy gave no answer: %v", err)
	case st != http.StatusOK:
		return nil, false, fmt.Sprintf("GetPolicy HTTP %d", st)
	}
	var wrapper struct {
		Policy string `json:"Policy"`
	}
	if json.Unmarshal(body, &wrapper) != nil {
		return nil, false, "GetPolicy response did not parse"
	}
	var doc struct {
		Statement []struct {
			Sid string `json:"Sid"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(wrapper.Policy), &doc) != nil {
		return nil, false, "the resource policy did not parse"
	}
	out := map[string]bool{}
	for _, s := range doc.Statement {
		if strings.HasPrefix(s.Sid, lambdaInvokerSidPrefix) {
			out[s.Sid] = true
		}
	}
	return out, true, ""
}

// observedLambdaInvokers renders the grants OUR statements express, for operand
// drift. It reads the same policy the reconcile does, so the declared and observed
// sides are the same shape by construction.
func (d *Driver) observedLambdaInvokers(region, name string) (canon string, readable bool) {
	st, body, err := d.lambdaGet(region, lambdaPolicyPath(name))
	switch {
	case err == nil && st == http.StatusNotFound:
		return "", true
	case err != nil || st != http.StatusOK:
		return "", false
	}
	var wrapper struct {
		Policy string `json:"Policy"`
	}
	if json.Unmarshal(body, &wrapper) != nil {
		return "", false
	}
	var doc struct {
		Statement []struct {
			Sid       string `json:"Sid"`
			Principal any    `json:"Principal"`
			Condition struct {
				ArnLike struct {
					SourceArn string `json:"AWS:SourceArn"`
				} `json:"ArnLike"`
			} `json:"Condition"`
		} `json:"Statement"`
	}
	if json.Unmarshal([]byte(wrapper.Policy), &doc) != nil {
		return "", false
	}
	var got []LambdaInvoker
	for _, s := range doc.Statement {
		if !strings.HasPrefix(s.Sid, lambdaInvokerSidPrefix) {
			continue
		}
		got = append(got, LambdaInvoker{
			Principal: lambdaPrincipalString(s.Principal),
			SourceArn: s.Condition.ArnLike.SourceArn,
		})
	}
	return CanonLambdaInvokers(got), true
}

// lambdaPrincipalString flattens the two shapes AWS renders a principal in: the
// bare service string, and {"Service": ...} / {"AWS": ...}.
func lambdaPrincipalString(v any) string {
	switch p := v.(type) {
	case string:
		return p
	case map[string]any:
		for _, k := range []string{"Service", "AWS"} {
			switch x := p[k].(type) {
			case string:
				return x
			case []any:
				if len(x) == 1 {
					s, _ := x[0].(string)
					return s
				}
			}
		}
	}
	return ""
}
