// Typed create outputs (D226/D275): the AWS half of intra-plan output
// references (F13). Each entry declares what a service's succeeded create
// receipts, so a same-plan consumer can wire an operand as
// {$ref: {capability, output}} instead of a hand-pasted literal.
//
// Every output is DERIVED from the create's provider id — the same identity
// resume reconciles by, present on every succeeded path including
// create-adoption (D253) — never from a value the driver merely intended.
// The one exception is vpc, whose subnet ids are not in the pid: they come
// from one read of the standing network (the honest source either way — the
// created OR adopted VPC's real subnets). An underivable output demotes the
// create to unknown (reconcile), mirroring the executor's own receipt gate.
package aws

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"groundhold/internal/provider"
)

// awsOutputs is the typed OutputsFor table (D226): declare ONLY what every
// succeeded create path of the service can truthfully derive.
var awsOutputs = map[string][]provider.OutputSpec{
	"vpc": {
		{Name: "privateSubnetIds", Kind: "list", Sample: []any{"subnet-0aaa1111", "subnet-0bbb2222"}},
		{Name: "publicSubnetIds", Kind: "list", Sample: []any{"subnet-0ccc3333", "subnet-0ddd4444"}},
		{Name: "region", Kind: "string", Sample: "eu-central-1"},
		{Name: "vpcId", Kind: "string", Sample: "vpc-0aaa1111"},
	},
	"kms": {
		{Name: "keyArn", Kind: "string", Sample: "arn:aws:kms:eu-central-1:000000000000:key/1234abcd-12ab-34cd-56ef-1234567890ab"},
		{Name: "keyId", Kind: "string", Sample: "1234abcd-12ab-34cd-56ef-1234567890ab"},
	},
	"s3": {
		{Name: "bucketArn", Kind: "string", Sample: "arn:aws:s3:::groundhold-preflight"},
		{Name: "bucketName", Kind: "string", Sample: "groundhold-preflight"},
	},
	"sns": {{Name: "topicArn", Kind: "string", Sample: "arn:aws:sns:eu-central-1:000000000000:groundhold-preflight"}},
	// elasticache-serverless: the client endpoint host:port a consumer app wires
	// as {$ref: {capability: <cache>, output: endpoint}}. The address is
	// server-assigned (not in the pid), so it comes from one read of the standing
	// cache — the honest source for a created OR adopted cache, exactly as vpc's subnets.
	"elasticache-serverless": {
		{Name: "endpoint", Kind: "string", Sample: "groundhold-sessions-abc123.serverless.euc1.cache.amazonaws.com:6379"},
	},
	// aurora (capability.database.relational): the cluster's connection endpoints.
	// writerEndpoint is the read/write host, readerEndpoint the read-only host, and
	// port the listener port — a consumer app wires a DATABASE_URL host/port as
	// {$ref:{capability:<db>, output: writerEndpoint}} + {output: port} instead of a
	// hand-pasted literal (the PASSWORD is NOT an output — it stays off-ledger). The
	// endpoints are server-assigned (not in the pid), so they come from one read of
	// the standing cluster — the honest source for a created OR adopted cluster,
	// exactly as vpc's subnets and elasticache's endpoint.
	"aurora": {
		{Name: "writerEndpoint", Kind: "string", Sample: "pv-db-prod-1a2b3c4d.cluster-abc123.eu-central-1.rds.amazonaws.com"},
		{Name: "readerEndpoint", Kind: "string", Sample: "pv-db-prod-1a2b3c4d.cluster-ro-abc123.eu-central-1.rds.amazonaws.com"},
		{Name: "port", Kind: "string", Sample: "5432"},
	},
	"acm": {{Name: "certificateArn", Kind: "string", Sample: "arn:aws:acm:eu-central-1:000000000000:certificate/1cf48e24-aaaa-bbbb-cccc-000000000000"}},
	// lambda (capability.function.serverless): functionArn/functionName are fully
	// in the lambda:region:account:name pid (no read). functionUrl/functionUrlDomain
	// require ONE GetFunctionUrlConfig read — the url-id is SERVER-ASSIGNED, not in
	// the pid, exactly as aurora's endpoints — and are present ONLY when the function
	// has a URL (network.publicExposure: true). functionUrlDomain is the host (no
	// scheme/path) a cdn.distribution wires as its origin ({$ref: {capability: <fn>,
	// output: functionUrlDomain}}); functionArn is the AddPermission target the
	// fronting distribution grants itself invoke on.
	"lambda": {
		{Name: "functionArn", Kind: "string", Sample: "arn:aws:lambda:eu-central-1:000000000000:function:pv-api-prod-1a2b3c4d"},
		{Name: "functionName", Kind: "string", Sample: "pv-api-prod-1a2b3c4d"},
		{Name: "functionUrl", Kind: "string", Sample: "https://abc123.lambda-url.eu-central-1.on.aws/"},
		{Name: "functionUrlDomain", Kind: "string", Sample: "abc123.lambda-url.eu-central-1.on.aws"},
	},
	// cloudfront (capability.cdn.distribution): distributionArn is derivable from
	// the cf:account:distId pid (no read). domainName (the public dXXXX.cloudfront.net
	// edge host) is SERVER-ASSIGNED and unrelated to the id, so it comes from ONE
	// GetDistribution read — the honest source for a created OR adopted distribution,
	// exactly as aurora's endpoints. A route53record can wire the edge host by $ref.
	"cloudfront": {
		{Name: "distributionArn", Kind: "string", Sample: "arn:aws:cloudfront::000000000000:distribution/E1234567890ABC"},
		{Name: "domainName", Kind: "string", Sample: "d111111abcdef8.cloudfront.net"},
	},
	"eks": {
		{Name: "clusterName", Kind: "string", Sample: "groundhold-preflight"},
		{Name: "region", Kind: "string", Sample: "eu-central-1"},
	},
	"iam": {
		{Name: "roleArn", Kind: "string", Sample: "arn:aws:iam::000000000000:role/groundhold-preflight"},
		{Name: "roleName", Kind: "string", Sample: "groundhold-preflight"},
	},
	// ecr (capability.registry.image, F-registry): repositoryUri is the pushable
	// image base a workload.container/function.serverless consumer wires as
	// image: {$ref: {capability: <ecr>, output: repositoryUri}}. Both fields are
	// fully in the ecr:region:account:name pid — no read, no STS.
	"ecr": {
		{Name: "repositoryArn", Kind: "string", Sample: "arn:aws:ecr:eu-central-1:000000000000:repository/pv-app-prod-1a2b3c4d"},
		{Name: "repositoryUri", Kind: "string", Sample: "000000000000.dkr.ecr.eu-central-1.amazonaws.com/pv-app-prod-1a2b3c4d"},
	},
	// backupvault (capability.backup.vault): vaultName is the operand a
	// backup.plan consumer wires as targetVaultName: {$ref: {capability: <vault>,
	// output: vaultName}}. AWS Backup refuses CreateBackupPlan with a 400 unless
	// the vault already exists, so the reference forces create + dependsOn instead
	// of a hand-pasted literal. Both fields are fully in the
	// bkv:region:account:name pid — no read.
	"backupvault": {
		{Name: "vaultArn", Kind: "string", Sample: "arn:aws:backup:eu-central-1:000000000000:backup-vault:pv-preflight"},
		{Name: "vaultName", Kind: "string", Sample: "pv-preflight"},
	},
}

// OutputsFor implements provider.OutputProducer (D226). Pure and table-driven,
// parallel to PermissionsFor: the compiler gates $ref names/kinds against this
// table, the executor filters the create result through it.
func (d *Driver) OutputsFor(service string) []provider.OutputSpec {
	return awsOutputs[service]
}

// attachOutputs fills cr.Outputs for a succeeded create of a declaring
// service. On a derivation failure the create demotes to unknown with the
// cause named — a succeeded create whose declared outputs cannot be attested
// must not feed consumers a guess, and resume reconciles it by the pid.
func (d *Driver) attachOutputs(service string, cr *provider.CreateResult) {
	if cr.Status != "succeeded" || len(awsOutputs[service]) == 0 {
		return
	}
	outs, err := d.deriveOutputs(service, cr.ProviderID)
	if err != nil {
		cr.Status = "unknown"
		cr.Reason = fmt.Sprintf("%s create succeeded but its declared outputs "+
			"are underivable — reconcile: %v", service, err)
		return
	}
	cr.Outputs = outs
}

func (d *Driver) deriveOutputs(service, pid string) (map[string]any, error) {
	switch service {
	case "s3":
		_, bucket, err := splitS3ProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"bucketName": bucket,
			"bucketArn":  "arn:aws:s3:::" + bucket,
		}, nil
	case "sns":
		region, account, name, err := splitSNSProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"topicArn": "arn:aws:sns:" + region + ":" + account + ":" + name,
		}, nil
	case "kms":
		region, keyID, err := splitAWSKMSProviderID(pid)
		if err != nil {
			return nil, err
		}
		account, err := d.resolveAccount()
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"keyId":  keyID,
			"keyArn": "arn:aws:kms:" + region + ":" + account + ":key/" + keyID,
		}, nil
	case "acm":
		region, account, certID, err := splitACMProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"certificateArn": "arn:aws:acm:" + region + ":" + account +
				":certificate/" + certID,
		}, nil
	case "eks":
		region, name, err := splitEKSProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{"clusterName": name, "region": region}, nil
	case "iam":
		account, roleName, err := splitIAMRoleProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"roleName": roleName,
			"roleArn":  "arn:aws:iam::" + account + ":role/" + roleName,
		}, nil
	case "ecr":
		region, account, name, err := splitECRProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"repositoryUri": account + ".dkr.ecr." + region + ".amazonaws.com/" + name,
			"repositoryArn": ecrArn(region, account, name),
		}, nil
	case "elasticache-serverless":
		region, _, name, err := splitECacheServerlessProviderID(pid)
		if err != nil {
			return nil, err
		}
		endpoint, err := d.serverlessCacheEndpoint(region, name)
		if err != nil {
			return nil, err
		}
		return map[string]any{"endpoint": endpoint}, nil
	case "aurora":
		region, id, err := splitAuroraProviderID(pid)
		if err != nil {
			return nil, err
		}
		cl, found, rerr := d.describeCluster(region, id)
		if rerr != nil {
			return nil, rerr
		}
		if !found {
			return nil, fmt.Errorf("aurora cluster %s not found", id)
		}
		if cl.Endpoint == "" || cl.ReaderEndpoint == "" || cl.Port == 0 {
			return nil, fmt.Errorf("aurora cluster %s reported no endpoints yet", id)
		}
		return map[string]any{
			"writerEndpoint": cl.Endpoint,
			"readerEndpoint": cl.ReaderEndpoint,
			"port":           strconv.Itoa(cl.Port),
		}, nil
	case "backupvault":
		region, account, name, err := splitBkvProviderID(pid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"vaultName": name,
			"vaultArn":  bkvArn(region, account, name),
		}, nil
	case "lambda":
		region, account, name, err := splitLambdaProviderID(pid)
		if err != nil {
			return nil, err
		}
		out := map[string]any{
			"functionArn":  lambdaArn(region, account, name),
			"functionName": name,
		}
		// The Function URL is present only for a public function; its host is
		// server-assigned (one read). A definitive 404 (a private function) omits
		// the URL outputs rather than failing — attachOutputs must not demote a
		// perfectly good private lambda. A read FAILURE (transport/5xx) IS an error
		// (reconcile), never a fabricated absence.
		if url, found, rerr := d.getLambdaFunctionURL(region, name); rerr != nil {
			return nil, rerr
		} else if found {
			out["functionUrl"] = url
			out["functionUrlDomain"] = functionURLHost(url)
		}
		return out, nil
	case "cloudfront":
		account, distID, err := splitCFProviderID(pid)
		if err != nil {
			return nil, err
		}
		doc, _, found, rerr := d.getCF(distID)
		if rerr != nil {
			return nil, rerr
		}
		if !found {
			return nil, fmt.Errorf("cloudfront distribution %s not found", distID)
		}
		if doc.DomainName == "" {
			return nil, fmt.Errorf("cloudfront distribution %s reported no domainName yet", distID)
		}
		return map[string]any{
			"distributionArn": cfArn(account, distID),
			"domainName":      doc.DomainName,
		}, nil
	case "vpc":
		region, vpcID, err := splitAWSVpcProviderID(pid)
		if err != nil {
			return nil, err
		}
		priv, pub, err := d.classifyVpcSubnets(region, vpcID)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"vpcId":            vpcID,
			"region":           region,
			"privateSubnetIds": priv,
			"publicSubnetIds":  pub,
		}, nil
	}
	return nil, fmt.Errorf("service %q declares outputs but has no derivation", service)
}

// classifyVpcSubnets reads the VPC's subnets and classifies each by its
// EFFECTIVE route table: a subnet whose table routes 0.0.0.0/0 to an internet
// gateway is public; everything else — NAT route, no default route — is
// private. A subnet with no explicit association uses the VPC's main table.
// Lists are sorted for a deterministic receipt.
func (d *Driver) classifyVpcSubnets(region, vpcID string) (priv, pub []any, err error) {
	st, resp, err := d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeSubnets", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID}))
	if err != nil {
		return nil, nil, fmt.Errorf("DescribeSubnets: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("DescribeSubnets: HTTP %d", st)
	}
	var subs struct {
		IDs []string `xml:"subnetSet>item>subnetId"`
	}
	if xml.Unmarshal(resp, &subs) != nil {
		return nil, nil, fmt.Errorf("DescribeSubnets: unparseable response")
	}

	st, resp, err = d.ec2PostBase(region, encodeForm(map[string]string{
		"Action": "DescribeRouteTables", "Version": ec2Version,
		"Filter.1.Name": "vpc-id", "Filter.1.Value.1": vpcID}))
	if err != nil {
		return nil, nil, fmt.Errorf("DescribeRouteTables: %v", err)
	}
	if st != http.StatusOK {
		return nil, nil, fmt.Errorf("DescribeRouteTables: HTTP %d", st)
	}
	var rts struct {
		Tables []struct {
			ID     string `xml:"routeTableId"`
			Routes []struct {
				Dest string `xml:"destinationCidrBlock"`
				Gw   string `xml:"gatewayId"`
			} `xml:"routeSet>item"`
			Assocs []struct {
				SubnetID string `xml:"subnetId"`
				Main     bool   `xml:"main"`
			} `xml:"associationSet>item"`
		} `xml:"routeTableSet>item"`
	}
	if xml.Unmarshal(resp, &rts) != nil {
		return nil, nil, fmt.Errorf("DescribeRouteTables: unparseable response")
	}

	tablePublic := map[string]bool{}
	subnetTable := map[string]string{}
	mainTable := ""
	for _, t := range rts.Tables {
		for _, r := range t.Routes {
			if r.Dest == "0.0.0.0/0" && len(r.Gw) > 4 && r.Gw[:4] == "igw-" {
				tablePublic[t.ID] = true
			}
		}
		for _, a := range t.Assocs {
			if a.Main {
				mainTable = t.ID
			}
			if a.SubnetID != "" {
				subnetTable[a.SubnetID] = t.ID
			}
		}
	}
	privS, pubS := []string{}, []string{}
	for _, id := range subs.IDs {
		table, ok := subnetTable[id]
		if !ok {
			table = mainTable
		}
		if tablePublic[table] {
			pubS = append(pubS, id)
		} else {
			privS = append(privS, id)
		}
	}
	sort.Strings(privS)
	sort.Strings(pubS)
	for _, s := range privS {
		priv = append(priv, s)
	}
	pub = []any{}
	for _, s := range pubS {
		pub = append(pub, s)
	}
	if priv == nil {
		priv = []any{}
	}
	return priv, pub, nil
}

// ReadOutputs implements provider.OutputReader (D283): re-read the declared
// outputs of a BOUND resource by its provider id — the same derivation the
// create path attaches, so observe records exactly what a receipt would carry.
func (d *Driver) ReadOutputs(service, providerID string) (map[string]any, error) {
	if len(awsOutputs[service]) == 0 {
		return nil, nil
	}
	return d.deriveOutputs(service, providerID)
}
