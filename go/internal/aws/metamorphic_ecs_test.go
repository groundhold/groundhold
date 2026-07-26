package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87) for ECS/Fargate — the metamorphic write/read round-trip. A
// STATEFUL fake records what CreateService WRITES (assignPublicIp, desiredCount)
// and reflects it on DescribeServices; the test asserts observeECS reverse-maps
// the SAME semantic attributes create was given. A driver that inverts the
// ENABLED test for public exposure, or reads desiredCount from the wrong
// element, fails here without any fault injected.
//
// Round-trippers exercised through the wire: network.publicExposure
// (assignPublicIp) and replicas.minimum (desiredCount). location.region is
// asserted but is providerId-derived (observeECS reads it from the pid, not the
// wire), so it is held constant, not a wire round-tripper.
func metamorphicECSServer(t *testing.T) *httptest.Server {
	t.Helper()
	var (
		created        bool
		assignPublicIP string
		desiredCount   int
	)
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			action := target[strings.LastIndex(target, ".")+1:]
			switch action {
			// ---- create writes ----
			case "CreateCluster":
				_, _ = w.Write([]byte(`{"cluster":{"status":"ACTIVE"}}`))
			case "RegisterTaskDefinition":
				_, _ = w.Write([]byte(`{"taskDefinition":{"taskDefinitionArn":` +
					`"arn:aws:ecs:eu-central-1:000000000000:task-definition/app:1"}}`))
			case "CreateService":
				raw, _ := io.ReadAll(r.Body)
				var body struct {
					DesiredCount         int `json:"desiredCount"`
					NetworkConfiguration struct {
						AwsvpcConfiguration struct {
							AssignPublicIP string `json:"assignPublicIp"`
						} `json:"awsvpcConfiguration"`
					} `json:"networkConfiguration"`
				}
				_ = json.Unmarshal(raw, &body)
				created = true
				desiredCount = body.DesiredCount
				assignPublicIP = body.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIP
				_, _ = w.Write([]byte(`{"service":{"status":"ACTIVE"}}`))
			// ---- observe reads reflect the recorded state ----
			case "DescribeServices":
				if !created {
					_, _ = w.Write([]byte(`{"services":[]}`))
					return
				}
				resp := map[string]any{"services": []any{map[string]any{
					"status":       "ACTIVE",
					"runningCount": desiredCount,
					"desiredCount": desiredCount,
					"launchType":   "FARGATE",
					"networkConfiguration": map[string]any{
						"awsvpcConfiguration": map[string]any{"assignPublicIp": assignPublicIP},
					},
					"deployments": []any{map[string]any{"rolloutState": "COMPLETED"}},
					"tags": []any{
						map[string]any{"key": "groundhold-capability", "value": "app"},
						map[string]any{"key": "groundhold-environment", "value": "prod"},
					},
				}}}
				_ = json.NewEncoder(w).Encode(resp)
			default:
				w.WriteHeader(400)
			}
		}))
}

func TestMetamorphicECSRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		public   bool
		replicas int
	}{
		{"public-2", true, 2},
		{"private-1", false, 1},
		{"public-3", true, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicECSServer(t)
			defer srv.Close()
			d := ecsTestDriver(t, srv)

			attrs := ecsAttrs()
			attrs["network.publicExposure"] = c.public
			attrs["replicas.minimum"] = float64(c.replicas)
			res := d.createECS("eu-central-1", "000000000000", "prod", "app", attrs, ecsImpl(), 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, _, err := d.observeECS("app", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			// the metamorphic invariant: Observe reverse-maps what Create wrote.
			if got["network.publicExposure"] != c.public {
				t.Errorf("public-exposure round-trip broke: wrote %v, observed %v", c.public, got["network.publicExposure"])
			}
			if got["replicas.minimum"] != float64(c.replicas) {
				t.Errorf("replicas.minimum round-trip broke: wrote %v, observed %v", c.replicas, got["replicas.minimum"])
			}
			// location.region is providerId-derived (observeECS reads it from the
			// pid, not the wire) — held constant, not a wire round-tripper.
			if got["location.region"] != "eu-central-1" {
				t.Errorf("region round-trip broke: observed %v", got["location.region"])
			}
		})
	}
}
