package gcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Weapon 2 (D87) for GCP VPC (Compute private networking) — the metamorphic
// write/read round-trip. A STATEFUL compute fake records what the multi-resource
// create WRITES (the subnet's logConfig.enable and whether a default-deny egress
// firewall was inserted) and reflects it on the observe reads (networks.get ->
// subnetworks.get -> firewalls.list). The test asserts observeVPC reverse-maps
// the SAME semantic attributes create was given. A driver that reads logConfig
// from the wrong element, or inverts the deny-egress detection, fails here.
//
// Round-trippers exercised through the wire: flowLogs.enabled (subnet logConfig)
// and egress.restricted (deny-egress firewall presence). ingress.public is
// private-by-construction (create refuses ingress.public=true and never inserts
// an allow-all-ingress rule) so it is asserted constant-false, NOT a round-
// tripper. location.region is providerId-derived (read from the pid, not the
// wire), also held constant.
func metamorphicVPCServerGCP(t *testing.T) *httptest.Server {
	t.Helper()
	var (
		netDesc          string
		subnetName       string
		subnetDesc       string
		subnetLogEnabled bool
		region           string
		egressFw         map[string]any // nil unless a deny-egress firewall was created
	)
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case strings.Contains(p, "/operations/"):
				_, _ = w.Write([]byte(`{"status":"DONE"}`))
			// ---- create writes ----
			case r.Method == "POST" && strings.HasSuffix(p, "/networks"):
				var b map[string]any
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &b)
				netDesc, _ = b["description"].(string)
				_, _ = w.Write([]byte(`{"name":"op-net"}`))
			case r.Method == "POST" && strings.HasSuffix(p, "/subnetworks"):
				var b map[string]any
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &b)
				subnetName, _ = b["name"].(string)
				subnetDesc, _ = b["description"].(string)
				region, _ = b["region"].(string)
				if lc, ok := b["logConfig"].(map[string]any); ok {
					subnetLogEnabled, _ = lc["enable"].(bool)
				}
				_, _ = w.Write([]byte(`{"name":"op-sub"}`))
			case r.Method == "POST" && strings.HasSuffix(p, "/firewalls"):
				var b map[string]any
				raw, _ := io.ReadAll(r.Body)
				_ = json.Unmarshal(raw, &b)
				egressFw = b
				_, _ = w.Write([]byte(`{"name":"op-fw"}`))
			// ---- observe reads reflect the recorded state ----
			case strings.Contains(p, "/firewalls") && r.Method == "GET":
				items := []any{}
				if egressFw != nil {
					items = append(items, egressFw)
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
			case strings.Contains(p, "/subnetworks/") && r.Method == "GET":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"description": subnetDesc,
					"logConfig":   map[string]any{"enable": subnetLogEnabled},
				})
			case strings.Contains(p, "/networks/") && r.Method == "GET":
				selfLink := fmt.Sprintf(
					"https://x/projects/acme-prod/regions/%s/subnetworks/%s", region, subnetName)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"description":           netDesc,
					"autoCreateSubnetworks": false,
					"subnetworks":           []any{selfLink},
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
}

func TestMetamorphicVPCRoundTripGCP(t *testing.T) {
	cases := []struct {
		name     string
		flowLogs bool
		egress   bool
	}{
		{"nologs-openegress", false, false},
		{"logs-restrictedegress", true, true},
		{"logs-openegress", true, false},
		{"nologs-restrictedegress", false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := metamorphicVPCServerGCP(t)
			defer srv.Close()
			d := vpcDriver(t, srv)
			d.PollInterval = 0

			attrs := map[string]any{
				"location.region":   "europe-central2",
				"ingress.public":    false,
				"egress.restricted": c.egress,
				"flowLogs.enabled":  c.flowLogs,
				"service.managed":   true,
			}
			res := d.createVPC("app-net", "prod", attrs, nil, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create failed: %+v", res)
			}
			obs, diags, err := d.observeVPC("app-net", res.ProviderID)
			if err != nil {
				t.Fatalf("observe: %v", err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			// the metamorphic invariant: Observe reverse-maps what Create wrote.
			if got["flowLogs.enabled"] != c.flowLogs {
				t.Errorf("flowLogs.enabled round-trip broke: wrote %v, observed %v (diags %v)", c.flowLogs, got["flowLogs.enabled"], diags)
			}
			if got["egress.restricted"] != c.egress {
				t.Errorf("egress.restricted round-trip broke: wrote %v, observed %v (diags %v)", c.egress, got["egress.restricted"], diags)
			}
			// ingress.public is private-by-construction (no allow-all-ingress rule
			// is ever inserted); assert it never flips public, not a round-tripper.
			if got["ingress.public"] != false {
				t.Errorf("private VPC must observe ingress.public=false, got %v", got["ingress.public"])
			}
			// location.region is providerId-derived (read from the pid, not the
			// wire) — held constant, not a wire round-tripper.
			if got["location.region"] != "europe-central2" {
				t.Errorf("region round-trip broke: observed %v", got["location.region"])
			}
		})
	}
}
