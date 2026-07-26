// MSK request building (D115): the semantic core of the AWS capability.messaging.kafka
// driver — the SAME vocabulary GCP Managed Kafka and Azure Event Hubs Kafka fulfil.
// AWS MSK is a managed multi-AZ Apache Kafka cluster. Broker count, instance type,
// storage volume and client-auth are implementation sizing; residency, Kafka
// protocol, availability and encryption are the capability. An MSK cluster is ALWAYS
// multi-AZ, so availability.class=zonal is an honest refusal here. encryption.inTransit
// is true-only (TLS is enforced).
package aws

import (
	"fmt"
	"regexp"
	"strings"
)

// mskNameOK bounds an MSK cluster name (1-64: letters, digits, hyphen).
var mskNameOK = regexp.MustCompile(`^[a-zA-Z0-9-]{1,64}$`)

// MSKClusterName is the deterministic cluster name (the idempotency/recovery handle).
func MSKClusterName(environment, capability string, generation int) string {
	slug := capability
	if environment != "" {
		slug += "-" + environment
	}
	slug = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, slug)
	slug = strings.Trim(slug, "-")
	return "pv-" + slug + "-" + letterHash(environment+"|"+capability+genSuffix(generation), 8)
}

// kafkaVersionFor maps engine.protocol (kafka/N) to an MSK KafkaVersion. A non-kafka
// protocol is refused.
func kafkaVersionFor(protocol string) (string, error) {
	engine, ver, ok := strings.Cut(protocol, "/")
	if !ok || strings.ToLower(engine) != "kafka" {
		return "", fmt.Errorf("engine.protocol %q is not a kafka/N protocol", protocol)
	}
	switch strings.SplitN(ver, ".", 2)[0] {
	case "3":
		return "3.5.1", nil
	case "2":
		return "2.8.1", nil
	default:
		return "", fmt.Errorf("kafka version %q has no MSK mapping (2 or 3)", ver)
	}
}

// MSKPlan is the attribute-derived shape a create assembles.
type MSKPlan struct {
	Cluster        string
	KafkaVersion   string
	Brokers        int
	Subnets        []string
	SecurityGroups []string
	InTransitTLS   bool
	CMEK           bool
	KmsKeyId       string
}

// BuildMSK maps capability.messaging.kafka attributes + impl to a plan. Every error
// is a preflight refusal, never a silent drop.
func BuildMSK(environment, capability string,
	attrs, impl map[string]any, generation int) (MSKPlan, error) {
	p := MSKPlan{Cluster: MSKClusterName(environment, capability, generation)}
	for _, path := range sortedKeys(attrs) {
		raw := attrs[path]
		switch path {
		case "location.region":
			// region is the driver scope (createScope); nothing in the body.
		case "engine.protocol":
			proto, _ := raw.(string)
			v, err := kafkaVersionFor(proto)
			if err != nil {
				return MSKPlan{}, err
			}
			p.KafkaVersion = v
		case "availability.class":
			switch raw {
			case "regional":
				// an MSK cluster is always multi-AZ — the native mode
			case "zonal":
				return MSKPlan{}, fmt.Errorf(
					"availability.class=zonal cannot be honored by MSK — a cluster is always " +
						"multi-AZ; refusing rather than misrepresenting it as zonal")
			default:
				return MSKPlan{}, fmt.Errorf("availability.class %v has no MSK mapping", raw)
			}
		case "encryption.inTransit":
			p.InTransitTLS, _ = raw.(bool)
			if raw != true {
				return MSKPlan{}, fmt.Errorf(
					"encryption.inTransit=false cannot be honored — MSK enforces client-broker TLS")
			}
		case "encryption.customerManagedKeys":
			if raw == true {
				p.CMEK = true
				p.KmsKeyId, _ = impl["kms_key_id"].(string)
				if p.KmsKeyId == "" {
					return MSKPlan{}, fmt.Errorf(
						"encryption.customerManagedKeys requires implementation.kms_key_id")
				}
			}
		case "service.managed":
			if raw != true {
				return MSKPlan{}, fmt.Errorf("service.managed=false cannot be honored by MSK")
			}
		default:
			return MSKPlan{}, fmt.Errorf(
				"attribute %s has no MSK mapping — refusing rather than silently dropping it "+
					"(broker count, instance type, storage are implementation sizing)", path)
		}
	}
	if p.KafkaVersion == "" {
		return MSKPlan{}, fmt.Errorf("kafka cluster requires engine.protocol (e.g. kafka/3)")
	}
	// a Kafka cluster lives in a VPC — subnets/security groups are topology (impl).
	p.Subnets = implStrings(impl, "subnet_ids")
	p.SecurityGroups = implStrings(impl, "security_group_ids")
	if len(p.Subnets) < 2 || len(p.SecurityGroups) == 0 {
		return MSKPlan{}, fmt.Errorf(
			"an MSK cluster requires implementation.subnet_ids (>= 2, one per AZ) AND " +
				"implementation.security_group_ids (VPC placement is topology)")
	}
	p.Brokers = len(p.Subnets) // one broker per AZ (a multiple of the subnet count)
	if !mskNameOK.MatchString(p.Cluster) {
		return MSKPlan{}, fmt.Errorf("derived cluster name %q is invalid", p.Cluster)
	}
	return p, nil
}

// implStrings is the shared list extractor, defined once in opensearch.go (D113)
// and reused here (D115 dedup on rebase).

// createBody is the CreateClusterV2 (provisioned) request body. Ownership is tags.
func (p MSKPlan) createBody(capability, environment string) map[string]any {
	subnets := make([]any, len(p.Subnets))
	for i, s := range p.Subnets {
		subnets[i] = s
	}
	sgs := make([]any, len(p.SecurityGroups))
	for i, s := range p.SecurityGroups {
		sgs[i] = s
	}
	encAtRest := map[string]any{}
	if p.CMEK {
		encAtRest["DataVolumeKMSKeyId"] = p.KmsKeyId
	}
	return map[string]any{
		"ClusterName": p.Cluster,
		"Provisioned": map[string]any{
			"KafkaVersion":        p.KafkaVersion,
			"NumberOfBrokerNodes": p.Brokers,
			"BrokerNodeGroupInfo": map[string]any{
				"InstanceType":   "kafka.m5.large",
				"ClientSubnets":  subnets,
				"SecurityGroups": sgs,
				"StorageInfo":    map[string]any{"EbsStorageInfo": map[string]any{"VolumeSize": 100}},
			},
			"EncryptionInfo": map[string]any{
				"EncryptionInTransit": map[string]any{"ClientBroker": "TLS", "InCluster": true},
				"EncryptionAtRest":    encAtRest,
			},
			"EnhancedMonitoring": "DEFAULT",
		},
		"Tags": map[string]any{
			"groundhold-capability":  sanitizeTag(capability),
			"groundhold-environment": sanitizeTag(environment),
		},
	}
}
