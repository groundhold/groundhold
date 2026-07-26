// App Runner network shell: the SigV4-signed, JSON-1.0 half of the second AWS
// workload.container backend. Single-resource create (CreateService), the
// providerId (apprunner:<region>:<serviceName>) attached from the deterministic
// name so a lost/ambiguous outcome is unknown/failed WITH the pid, never
// succeeded (D29 — handle never lost). Ownership is tags (ListTagsForResource);
// delete is DeleteService then poll-to-gone.
//
// CRITICAL LRO discipline (the F29/D273 lesson): the create/delete polls read the
// OBSERVABLE resource state via DescribeService and conclude on Service.Status
// (RUNNING = done; OPERATION_IN_PROGRESS = keep polling; CREATE_FAILED = failed).
// They NEVER construct an operation-by-id path (App Runner exposes ListOperations/
// an OperationId, but a name that never appears there would spin forever). The
// poll is bounded by PollTimeout; a still-in-progress resource at the deadline is
// unknown-with-pid, never a hang and never a fabricated success.
package aws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"groundhold/internal/provider"
	"groundhold/internal/scalars"
)

func (d *Driver) apprunnerBase(region string) string {
	if d.AppRunnerBaseURL != "" {
		return d.AppRunnerBaseURL
	}
	return "https://apprunner." + region + ".amazonaws.com"
}

func apprunnerProviderID(region, name string) string {
	return "apprunner:" + region + ":" + name
}

func splitAppRunnerProviderID(providerID string) (region, name string, err error) {
	parts := strings.Split(providerID, ":")
	if len(parts) != 3 || parts[0] != "apprunner" {
		return "", "", fmt.Errorf("providerId %q is not apprunner:region:name", providerID)
	}
	if !regionOK.MatchString(parts[1]) {
		return "", "", fmt.Errorf("providerId region %q is invalid", parts[1])
	}
	if !apprunnerNameOK.MatchString(parts[2]) {
		return "", "", fmt.Errorf("providerId name %q is invalid", parts[2])
	}
	return parts[1], parts[2], nil
}

// apprunnerCall signs and sends a JSON-1.0 request (X-Amz-Target = AppRunner.<action>).
func (d *Driver) apprunnerCall(region, action, body string) (int, []byte, error) {
	h := map[string]string{
		"Content-Type": "application/x-amz-json-1.0",
		"X-Amz-Target": apprunnerTarget + "." + action,
	}
	return d.doSigned("POST", d.apprunnerBase(region)+"/", "apprunner", region, h, []byte(body))
}

// apprunnerErr pulls a human string out of an App Runner JSON error body (__type +
// Message, joined so both the code and the message survive).
func apprunnerErr(body []byte) string {
	var e struct {
		Type    string `json:"__type"`
		Message string `json:"message"`
		Msg     string `json:"Message"`
	}
	_ = json.Unmarshal(body, &e)
	msg := e.Message
	if msg == "" {
		msg = e.Msg
	}
	s := strings.TrimSpace(e.Type + " " + msg)
	if s == "" {
		return "" // D309: never the raw body — this string reaches a persisted receipt
	}
	return boundMsg(s)
}

type apprunnerService struct {
	ServiceArn           string `json:"ServiceArn"`
	ServiceName          string `json:"ServiceName"`
	Status               string `json:"Status"`
	NetworkConfiguration struct {
		IngressConfiguration struct {
			IsPubliclyAccessible bool `json:"IsPubliclyAccessible"`
		} `json:"IngressConfiguration"`
	} `json:"NetworkConfiguration"`
	AutoScalingConfigurationSummary struct {
		AutoScalingConfigurationArn string `json:"AutoScalingConfigurationArn"`
	} `json:"AutoScalingConfigurationSummary"`
}

// resolveServiceArn maps our deterministic ServiceName to the live ServiceArn via
// ListServices (the ARN carries a server-assigned id the providerId does not hold,
// but the NAME is unique per account+region). (arn, found, err) — D296: a transport
// error / non-200 / parse failure returns a typed error naming the cause (never a
// fabricated absence); a readable list that lacks the name is found=false with nil
// error (a real "gone/never-created").
func (d *Driver) resolveServiceArn(region, name string) (arn string, found bool, err error) {
	const op = "ListServices"
	st, body, cerr := d.apprunnerCall(region, "ListServices", "{}")
	if cerr != nil {
		return "", false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return "", false, readHTTP(op, st, apprunnerErr(body))
	}
	var out struct {
		ServiceSummaryList []struct {
			ServiceName string `json:"ServiceName"`
			ServiceArn  string `json:"ServiceArn"`
		} `json:"ServiceSummaryList"`
	}
	if json.Unmarshal(body, &out) != nil {
		return "", false, readBody(op, st)
	}
	for _, s := range out.ServiceSummaryList {
		if s.ServiceName == name && s.ServiceArn != "" {
			return s.ServiceArn, true, nil
		}
	}
	return "", false, nil // readable list, name absent — a real "gone/never-created"
}

// describeService reads one service by ARN. (svc, found, err): a ResourceNotFound
// (or a DELETED terminal status) is found=false with nil error (gone); a transport/
// non-200/parse error is a typed read error naming the cause (D296), never a
// fabricated absence.
func (d *Driver) describeAppRunnerService(region, arn string) (apprunnerService, bool, error) {
	const op = "DescribeService"
	st, body, err := d.apprunnerCall(region, "DescribeService", jsonBody(map[string]any{"ServiceArn": arn}))
	if err != nil {
		return apprunnerService{}, false, readTransport(op, err)
	}
	if st != http.StatusOK {
		if strings.Contains(apprunnerErr(body), "ResourceNotFound") {
			return apprunnerService{}, false, nil
		}
		return apprunnerService{}, false, readHTTP(op, st, apprunnerErr(body))
	}
	var out struct {
		Service apprunnerService `json:"Service"`
	}
	if json.Unmarshal(body, &out) != nil {
		return apprunnerService{}, false, readBody(op, st)
	}
	// DELETED is a terminal "gone" the describe still reports before the record ages out.
	if out.Service.Status == "DELETED" {
		return out.Service, false, nil
	}
	return out.Service, true, nil
}

// appRunnerTagsMatch reads a service's tags to gate ownership. (ours, err): a
// transport/non-200/parse failure is a typed read error naming the cause (D296),
// never a fabricated "not ours".
func (d *Driver) appRunnerTagsMatch(region, arn, capability, environment string) (ours bool, err error) {
	const op = "ListTagsForResource"
	st, body, cerr := d.apprunnerCall(region, "ListTagsForResource", jsonBody(map[string]any{"ResourceArn": arn}))
	if cerr != nil {
		return false, readTransport(op, cerr)
	}
	if st != http.StatusOK {
		return false, readHTTP(op, st, apprunnerErr(body))
	}
	var out struct {
		Tags []struct {
			Key   string `json:"Key"`
			Value string `json:"Value"`
		} `json:"Tags"`
	}
	if json.Unmarshal(body, &out) != nil {
		return false, readBody(op, st)
	}
	m := map[string]string{}
	for _, t := range out.Tags {
		m[t.Key] = t.Value
	}
	return groundholdTagsMatch(m, capability, environment), nil
}

// createAppRunner: build -> CreateService -> poll DescribeService to RUNNING.
func (d *Driver) createAppRunner(region, account, environment, capability string,
	attrs, impl map[string]any, generation int) provider.CreateResult {
	plan, err := BuildAppRunnerRequests(account, environment, capability, attrs, impl, generation)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	pid := apprunnerProviderID(region, plan.Name)

	st, body, err := d.apprunnerCall(region, "CreateService", plan.CreateServiceBody)
	if err != nil {
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create service outcome unknown: %v", err)}
	}
	var arn string
	switch {
	case st >= 500:
		return provider.CreateResult{ProviderID: pid, Status: "unknown",
			Reason: fmt.Sprintf("create service HTTP %d (server error) — reconcile", st)}
	case st >= 400:
		// A ServiceName is unique per account+region, so a 4xx MAY be "already exists".
		// Resolve by name: if a service with our name exists AND is ours, adopt it
		// (poll to RUNNING); otherwise this is a real failure (bad image, quota, ...),
		// and the resolve returns not-found so we surface the original error.
		rarn, found, rerr := d.resolveServiceArn(region, plan.Name)
		if rerr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "create failed and the existing-service check gave no answer (" + rerr.Error() + ") — reconcile"}
		}
		if !found {
			if r := provider.MutationResult(st, apprunnerErr(body), nil, pid, "create service"); r != nil {
				return *r
			}
			return provider.CreateResult{ProviderID: pid, Status: "failed",
				Reason: fmt.Sprintf("create service: HTTP %d (%s)", st, apprunnerErr(body))}
		}
		ours, terr := d.appRunnerTagsMatch(region, rarn, capability, environment)
		if terr != nil {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "a service with this name exists but its tags gave no answer (" + terr.Error() + ") — reconcile"}
		}
		if !ours {
			return provider.CreateResult{Status: "failed",
				Reason: "a service with this name exists but is not ours (tags do not match)"}
		}
		arn = rarn // ours — fall through to poll
	default:
		var out struct {
			Service apprunnerService `json:"Service"`
		}
		if json.Unmarshal(body, &out) != nil || out.Service.ServiceArn == "" {
			// a 2xx create MUST carry the service (with its ARN); an empty ARN is a
			// truncated/lost body — the service may have landed (D29). Resolve by name.
			rarn, found, rerr := d.resolveServiceArn(region, plan.Name)
			if rerr == nil && found {
				arn = rarn
			} else {
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "create response carried no service ARN — reconcile"}
			}
		} else {
			arn = out.Service.ServiceArn
		}
	}

	return d.pollAppRunnerRunning(region, pid, arn)
}

// pollAppRunnerRunning polls DescribeService until the OBSERVABLE Status settles
// (D273 — read the resource's own state, never an operation-by-id path). RUNNING is
// succeeded; CREATE_FAILED is failed WITH the pid; the poll timeout is unknown WITH
// the pid (still coming up — reconcile). Bounded by PollTimeout, never a hang.
func (d *Driver) pollAppRunnerRunning(region, pid, arn string) provider.CreateResult {
	deadline := d.Now().Add(d.PollTimeout)
	for {
		svc, found, derr := d.describeAppRunnerService(region, arn)
		if derr == nil && found {
			switch svc.Status {
			case "RUNNING":
				return provider.CreateResult{ProviderID: pid, Status: "succeeded"}
			case "CREATE_FAILED":
				return provider.CreateResult{ProviderID: pid, Status: "failed",
					Reason: "service entered CREATE_FAILED during create"}
			case "DELETE_FAILED", "PAUSED":
				return provider.CreateResult{ProviderID: pid, Status: "unknown",
					Reason: "service entered " + svc.Status + " during create — reconcile"}
			}
			// OPERATION_IN_PROGRESS / RESUME_IN_PROGRESS -> keep polling
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: pid, Status: "unknown",
				Reason: "service still creating at poll timeout — reconcile via DescribeService"}
		}
		d.progress("App Runner service provisioning — waiting for RUNNING")
		time.Sleep(d.PollInterval)
	}
}

// observeAppRunner reverse-maps a live service to capability.workload.container.
func (d *Driver) observeAppRunner(capability, providerID string) ([]provider.Observation, []string, error) {
	region, name, err := splitAppRunnerProviderID(providerID)
	if err != nil {
		return nil, nil, err
	}
	arn, found, rerr := d.resolveServiceArn(region, name)
	if rerr != nil {
		return nil, nil, fmt.Errorf("apprunner %w", rerr)
	}
	if !found {
		return nil, []string{"service not found — nothing to observe"}, nil
	}
	svc, sfound, serr := d.describeAppRunnerService(region, arn)
	if serr != nil {
		return nil, nil, fmt.Errorf("apprunner %w", serr)
	}
	if !sfound {
		return nil, []string{"service not found — nothing to observe"}, nil
	}
	obs := []provider.Observation{
		{Path: "location.region", Value: region, Derivation: "measured"},
		{Path: "service.managed", Value: true, Derivation: "measured"},
		{Path: "availability.class", Value: "regional", Derivation: "config-intent"},
		// App Runner's managed endpoint is HTTPS-only by construction; config-intent
		// (a structural guarantee, like Cloud Run's regional), not a measured field.
		{Path: "tls.enforced", Value: true, Derivation: "config-intent"},
		{Path: "network.publicExposure",
			Value:      svc.NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible,
			Derivation: "measured"},
	}
	var diags []string
	// replicas.minimum lives on the referenced AutoScalingConfiguration's MinSize,
	// not on the service — trace it (DescribeAutoScalingConfiguration). An unreadable
	// trace is a diagnostic, never a fabricated minimum.
	if asArn := svc.AutoScalingConfigurationSummary.AutoScalingConfigurationArn; asArn != "" {
		if minSize, merr := d.appRunnerMinSize(region, asArn); merr == nil {
			obs = append(obs, provider.Observation{Path: "replicas.minimum",
				Value: float64(minSize), Derivation: "measured"})
		} else {
			diags = append(diags, "replicas.minimum not observed: "+merr.Error()+" — probe/reconcile")
		}
	}
	return obs, diags, nil
}

// appRunnerMinSize reads an AutoScalingConfiguration's MinSize. (min, err): a
// transport/non-200/parse failure (or an absent MinSize) is a typed read error
// naming the cause (D296) — never a fabricated minimum.
func (d *Driver) appRunnerMinSize(region, asArn string) (int, error) {
	const op = "DescribeAutoScalingConfiguration"
	st, body, err := d.apprunnerCall(region, "DescribeAutoScalingConfiguration",
		jsonBody(map[string]any{"AutoScalingConfigurationArn": asArn}))
	if err != nil {
		return 0, readTransport(op, err)
	}
	if st != http.StatusOK {
		return 0, readHTTP(op, st, apprunnerErr(body))
	}
	var out struct {
		AutoScalingConfiguration struct {
			MinSize *int `json:"MinSize"`
		} `json:"AutoScalingConfiguration"`
	}
	if json.Unmarshal(body, &out) != nil || out.AutoScalingConfiguration.MinSize == nil {
		return 0, readBody(op, st)
	}
	return *out.AutoScalingConfiguration.MinSize, nil
}

// updateAppRunner patches a bound service in place (D46). Only replicas.minimum is
// mutable (swap the AutoScalingConfigurationArn via UpdateService); ClassifyChange
// gates the rest, so a reviewed plan never reaches here with an immutable path.
// Ownership is re-checked (tags) before mutating; four-valued throughout.
func (d *Driver) updateAppRunner(capability, environment, providerID string,
	attrs, impl map[string]any, changes []string) provider.CreateResult {
	region, name, err := splitAppRunnerProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn, found, rerr := d.resolveServiceArn(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update read gave no answer (" + rerr.Error() + ") — reconcile"}
	}
	if !found {
		return provider.CreateResult{Status: "failed", Reason: "service no longer exists — cannot update"}
	}
	ours, terr := d.appRunnerTagsMatch(region, arn, capability, environment)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-update ownership read gave no answer (" + terr.Error() + ") — reconcile"}
	}
	if !ours {
		return provider.CreateResult{Status: "failed",
			Reason: "service tags do not match — refusing to patch a resource that is not ours"}
	}

	body := map[string]any{"ServiceArn": arn}
	for _, path := range changes {
		switch path {
		case "replicas.minimum":
			n, perr := scalars.Parse(attrs["replicas.minimum"])
			if perr != nil || n.Kind != scalars.Number {
				return provider.CreateResult{Status: "failed", Reason: "replicas.minimum is not a number"}
			}
			nf := n.Value.(float64)
			if nf != float64(int64(nf)) {
				return provider.CreateResult{Status: "failed", Reason: fmt.Sprintf("replicas.minimum must be a whole number, got %v", nf)}
			}
			if nf == 0 {
				return provider.CreateResult{Status: "failed",
					Reason: "App Runner has no scale-to-zero (minimum is 1 instance); use " +
						"capability.function.serverless for pay-per-request $0-idle"}
			}
			asArn, aerr := appRunnerAutoScalingArn(int(nf), impl)
			if aerr != nil {
				return provider.CreateResult{Status: "failed", Reason: aerr.Error()}
			}
			if asArn == "" {
				return provider.CreateResult{Status: "failed",
					Reason: "replicas.minimum=1 maps to App Runner's default autoscaling; a downward " +
						"change to the default is a replacement, not an in-place UpdateService patch"}
			}
			body["AutoScalingConfigurationArn"] = asArn
		default:
			return provider.CreateResult{Status: "failed",
				Reason: "no in-place App Runner mapping for " + path}
		}
	}

	st, resp, err := d.apprunnerCall(region, "UpdateService", jsonBody(body))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("update outcome unknown (may have landed): %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("update HTTP %d (server error — may have landed) — reconcile", st)}
	}
	if st >= 400 {
		if r := provider.MutationResult(st, apprunnerErr(resp), nil, providerID, "update service"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("update service: HTTP %d (%s)", st, apprunnerErr(resp))}
	}
	// UpdateService is an LRO — poll the service back to RUNNING (never an op-by-id path).
	return d.pollAppRunnerRunning(region, providerID, arn)
}

// deleteAppRunner: resolve the ARN, ownership pre-check, DeleteService, then poll
// until the service is READABLY gone. 404/absent is idempotent success.
func (d *Driver) deleteAppRunner(capability, environment, providerID string) provider.CreateResult {
	region, name, err := splitAppRunnerProviderID(providerID)
	if err != nil {
		return provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	arn, found, rerr := d.resolveServiceArn(region, name)
	if rerr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete read gave no answer (" + rerr.Error() + ") — reconcile"}
	}
	if !found {
		return provider.CreateResult{ProviderID: providerID, Status: "succeeded"} // idempotent — already gone
	}
	ours, terr := d.appRunnerTagsMatch(region, arn, capability, environment)
	if terr != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-delete ownership read gave no answer (" + terr.Error() + ") — reconcile"}
	}
	if !ours {
		return provider.CreateResult{Status: "failed",
			Reason: "service tags do not match — refusing to delete a resource that is not ours"}
	}
	st, body, err := d.apprunnerCall(region, "DeleteService", jsonBody(map[string]any{"ServiceArn": arn}))
	if err != nil {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete service outcome unknown: %v", err)}
	}
	if st >= 500 {
		return provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: fmt.Sprintf("delete service HTTP %d (server error) — reconcile", st)}
	}
	if st >= 400 && !strings.Contains(apprunnerErr(body), "ResourceNotFound") {
		if r := provider.MutationResult(st, apprunnerErr(body), nil, providerID, "delete service"); r != nil {
			return *r
		}
		return provider.CreateResult{Status: "failed",
			Reason: fmt.Sprintf("delete service: HTTP %d (%s)", st, apprunnerErr(body))}
	}
	// DeleteService is async — poll DescribeService until the service is READABLY gone
	// (ResourceNotFound / DELETED). A DELETE_FAILED, or the poll timeout, is unknown
	// WITH the pid (never a claimed success), never an operation-by-id poll.
	deadline := d.Now().Add(d.PollTimeout)
	for {
		svc, stillThere, derr := d.describeAppRunnerService(region, arn)
		if derr == nil && !stillThere {
			return provider.CreateResult{ProviderID: providerID, Status: "succeeded"}
		}
		if derr == nil && stillThere && svc.Status == "DELETE_FAILED" {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "service entered DELETE_FAILED — reconcile"}
		}
		if d.Now().After(deadline) {
			return provider.CreateResult{ProviderID: providerID, Status: "unknown",
				Reason: "service still deleting at poll timeout — reconcile via DescribeService"}
		}
		time.Sleep(d.PollInterval)
	}
}

// discoverAppRunner enumerates App Runner services in the region as
// capability.workload.container — so `discover --provider aws` surfaces a
// console/TF-stood service for adoption. ListServices -> per-service reverse map.
func (d *Driver) discoverAppRunner(region string) ([]provider.Discovered, []string, error) {
	st, body, err := d.apprunnerCall(region, "ListServices", "{}")
	if err != nil {
		return nil, nil, fmt.Errorf("apprunner ListServices: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("apprunner ListServices: HTTP %d: %s", st, apprunnerErr(body))
	}
	var out struct {
		ServiceSummaryList []struct {
			ServiceName string `json:"ServiceName"`
		} `json:"ServiceSummaryList"`
	}
	if json.Unmarshal(body, &out) != nil {
		return nil, nil, fmt.Errorf("apprunner ListServices: HTTP %d but the response did not parse", st)
	}
	var found []provider.Discovered
	var diags []string
	for _, s := range out.ServiceSummaryList {
		if !apprunnerNameOK.MatchString(s.ServiceName) {
			diags = append(diags, s.ServiceName+": name not representable as apprunner:region:name — needs adoption by explicit id")
			continue
		}
		pid := apprunnerProviderID(region, s.ServiceName)
		obs, od, oerr := d.observeAppRunner("", pid)
		if oerr != nil {
			diags = append(diags, s.ServiceName+": "+oerr.Error())
			continue
		}
		diags = append(diags, od...)
		found = append(found, provider.Discovered{
			ProviderID: pid, ResourceType: "capability.workload.container", Observations: obs})
	}
	return found, diags, nil
}

// claimAppRunner resolves the service ARN (the providerId holds only the name; the
// ARN carries a server-assigned id) and stamps the ownership tags via the generic
// Resource Groups Tagging API — the describe-to-resolve-ARN path (like ecs).
func (d *Driver) claimAppRunnerARN(providerID string) (region, arn string, early *provider.CreateResult) {
	region, name, err := splitAppRunnerProviderID(providerID)
	if err != nil {
		return "", "", &provider.CreateResult{Status: "failed", Reason: err.Error()}
	}
	rarn, found, rerr := d.resolveServiceArn(region, name)
	if rerr != nil {
		return "", "", &provider.CreateResult{ProviderID: providerID, Status: "unknown",
			Reason: "pre-claim apprunner service read gave no answer (" + rerr.Error() + ") — reconcile"}
	}
	if !found {
		return "", "", &provider.CreateResult{Status: "failed",
			Reason: "apprunner service no longer exists — cannot claim"}
	}
	return region, rarn, nil
}
