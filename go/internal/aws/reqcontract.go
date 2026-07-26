// Wire-level provider-request contract (D209): the deterministic, offline gate
// that catches a driver omitting a field the AWS API REQUIRES — at the wire
// chokepoint (doSignedH), before signing, on mutating operations. F10 shipped
// because the test fakes accept any request body, so a driver's own Validate was
// the only guard and it forgot a field; this is defense-in-depth BEHIND every
// driver's Validate, and — because the check runs in the real request path — it
// fires in production (refuse-before-mutate, no partial state) AND in every golden
// test that drives a create (they exercise doSignedH against the fake).
//
// Two tiers, the lesson of F10 (Fable/Codex consult): `required` is the FLOOR
// (unconditionally required — what a generated Smithy table gives). `requiredUnless`
// is the hand-authored OVERLAY for CONDITIONAL requirements a vendor model cannot
// express: AWS Smithy marks MasterUsername "Required: No", yet CreateDBCluster is
// rejected without it unless you restore a snapshot / join a global cluster / let
// AWS manage the password. Each overlay rule cites the evidence that proved it.
package aws

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// awsOpContract is one mutating AWS operation's required-field contract.
type awsOpContract struct {
	required       []string            // unconditionally required (the generated floor)
	requiredUnless map[string][]string // field required UNLESS any listed alternative is present (the overlay)
}

// awsWireContracts covers the AWS Query-protocol mutating operations the drivers
// issue today (the RDS/Aurora family first — where F10 lived). Reads and unmodeled
// operations have no entry and are never checked. Extend as drivers grow; a later
// generated floor (from vendored Smithy) replaces the hand `required` lists,
// leaving `requiredUnless` as the permanent, evidence-cited overlay.
var awsWireContracts = map[string]awsOpContract{
	// Evidence: real CreateDBCluster 400 "The parameter MasterUsername must be
	// provided and must not be blank" (Acme AWS run, 2026-07); AWS RDS API
	// reference CreateDBCluster (MasterUsername "Required: No" — conditional).
	"CreateDBCluster": {
		required: []string{"DBClusterIdentifier", "Engine"},
		requiredUnless: map[string][]string{
			"MasterUsername":     {"SnapshotIdentifier", "SourceDBClusterIdentifier", "GlobalClusterIdentifier"},
			"MasterUserPassword": {"ManageMasterUserPassword", "SnapshotIdentifier", "SourceDBClusterIdentifier", "GlobalClusterIdentifier"},
		},
	},
	"CreateDBInstance": {
		required: []string{"DBInstanceIdentifier", "Engine", "DBInstanceClass"},
		requiredUnless: map[string][]string{
			// a cluster member (DBClusterIdentifier) inherits the cluster's
			// credentials, so master creds are waived for Aurora member instances.
			"MasterUsername":     {"DBClusterIdentifier", "DBSnapshotIdentifier", "SourceDBInstanceIdentifier"},
			"MasterUserPassword": {"DBClusterIdentifier", "ManageMasterUserPassword", "DBSnapshotIdentifier", "SourceDBInstanceIdentifier"},
		},
	},
}

// awsJSONContracts covers AWS JSON-RPC create operations (X-Amz-Target header +
// JSON body — ECS, DynamoDB, …). The op is the segment after the last "." in the
// target. Fields are the TOP-LEVEL JSON keys (required create fields are top-level).
var awsJSONContracts = map[string]awsOpContract{
	// ECS (AmazonEC2ContainerServiceV20141113)
	"CreateService":          {required: []string{"serviceName"}},
	"RegisterTaskDefinition": {required: []string{"family", "containerDefinitions"}},
	// App Runner (AppRunner) — keyed by the FULL target to avoid the bare
	// "CreateService" collision with ECS (which uses lowercase serviceName). A
	// service needs a name and a source (the image/code to run).
	"AppRunner.CreateService": {required: []string{"ServiceName", "SourceConfiguration"}},
	// OpenSearch Serverless (OpenSearchServerless): a collection needs a name and a
	// type; a security policy needs a name, a type, and the policy document. Keyed by
	// the FULL target (aoss uses lowerCamelCase fields distinct from other services).
	"OpenSearchServerless.CreateCollection":     {required: []string{"name", "type"}},
	"OpenSearchServerless.CreateSecurityPolicy": {required: []string{"name", "type", "policy"}},
	// DynamoDB (DynamoDB_20120810): a table needs a name, a key schema, the
	// attribute definitions those keys reference, and a billing choice.
	"CreateTable": {
		required: []string{"TableName", "KeySchema", "AttributeDefinitions"},
		requiredUnless: map[string][]string{
			"BillingMode":           {"ProvisionedThroughput"},
			"ProvisionedThroughput": {"BillingMode"},
		},
	},
}

// enforceAWSWireContract checks a serialized AWS request against its operation
// contract at the wire chokepoint. It covers the AWS Query protocol (form body +
// Action) and JSON-RPC (X-Amz-Target header + JSON body). It is a NO-OP for
// operations with no contract entry (every read, unmodeled writes) and for other
// protocols (REST). It returns a refusal for a mutating request that omits a
// required field, so a driver bug refuses BEFORE signing — never mid-flight after
// a sibling resource already landed (F10's failure mode).
func enforceAWSWireContract(headers map[string]string, body []byte) error {
	if len(body) == 0 {
		return nil
	}
	// JSON-RPC: the operation is in the X-Amz-Target header, fields in the JSON body.
	if target := headers["X-Amz-Target"]; target != "" {
		op := target
		if i := strings.LastIndex(target, "."); i >= 0 {
			op = target[i+1:]
		}
		// Prefer a FULL-target contract (e.g. "AppRunner.CreateService") so an
		// operation name shared across services (CreateService is both ECS and App
		// Runner, with different field casing) resolves to the right contract; fall
		// back to the bare action name for the existing single-owner entries.
		c, ok := awsJSONContracts[target]
		if !ok {
			c, ok = awsJSONContracts[op]
		}
		if !ok {
			return nil
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(body, &fields) != nil {
			return nil // not a JSON object — out of scope
		}
		has := func(f string) bool {
			v, ok := fields[f]
			return ok && len(v) > 0 && string(v) != "null" && string(v) != `""` &&
				string(v) != "[]" && string(v) != "{}"
		}
		return contractMissing(op, c, has)
	}
	// Query protocol: the operation is the Action form field.
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return nil
	}
	action := form.Get("Action")
	if action == "" {
		return nil
	}
	c, ok := awsWireContracts[action]
	if !ok {
		return nil
	}
	return contractMissing(action, c, func(f string) bool { return form.Get(f) != "" })
}

// contractMissing applies an operation contract given a field-presence predicate
// (form field for Query, JSON key for JSON-RPC) and returns a wire refusal naming
// every missing required field, or nil.
func contractMissing(op string, c awsOpContract, has func(string) bool) error {
	var missing []string
	for _, f := range c.required {
		if !has(f) {
			missing = append(missing, f)
		}
	}
	for f, unless := range c.requiredUnless {
		if has(f) {
			continue
		}
		waived := false
		for _, alt := range unless {
			if has(alt) {
				waived = true
				break
			}
		}
		if !waived {
			missing = append(missing, f+" (or one of: "+strings.Join(unless, ", ")+")")
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("aws %s request omits required field(s): %s — refusing at the "+
		"wire before signing (a mutating request must not reach AWS incomplete, which "+
		"would fail mid-flight after sibling resources already landed)",
		op, strings.Join(missing, "; "))
}
