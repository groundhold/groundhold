package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func uamiAttrs() map[string]any {
	return map[string]any{
		"display.name":    "batch runner",
		"key.exportable":  false,
		"service.managed": true,
	}
}

func uamiImpl() map[string]any {
	return map[string]any{"resource_group": "rg1", "location": "eastus"}
}

func TestBuildManagedIdentityHonors(t *testing.T) {
	p, err := BuildManagedIdentity("prod", "runner", uamiAttrs(), uamiImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !azNameOK.MatchString(p.Name) || !strings.HasPrefix(p.Name, "id-runner-prod-") {
		t.Fatalf("identity name = %q", p.Name)
	}
	if p.Location != "eastus" || p.DisplayName != "batch runner" {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildManagedIdentityRefusals(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]any
		impl  map[string]any
	}{
		"exportable-key-refused": {map[string]any{"key.exportable": true}, uamiImpl()},
		"unmanaged":              {map[string]any{"service.managed": false}, uamiImpl()},
		"unknown-attr":           {map[string]any{"identity.tier": "x"}, uamiImpl()},
		"no-location":            {nil, map[string]any{"resource_group": "rg1"}},
	}
	for name, c := range cases {
		a := uamiAttrs()
		for k, v := range c.attrs {
			a[k] = v
		}
		if _, err := BuildManagedIdentity("prod", "runner", a, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func uamiServer(t *testing.T, capLabel, display string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case "PUT":
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"location":"eastus","properties":{"clientId":"c","principalId":"p"}}`))
			case "GET":
				_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"` + capLabel +
					`","groundhold-environment":"prod","groundhold-display":"` + display +
					`"},"properties":{"clientId":"c","principalId":"p"}}`))
			case "DELETE":
				w.WriteHeader(200)
			default:
				w.WriteHeader(404)
			}
		}))
}

func uamiDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	d := NewDriver(testSub)
	d.BaseURL = srv.URL
	d.token = "test-token"
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteManagedIdentity(t *testing.T) {
	srv := uamiServer(t, "runner", "batch runner")
	defer srv.Close()
	d := uamiDriver(t, srv)
	res := d.Create("managedidentity", "runner", "prod", uamiAttrs(), uamiImpl(), "k", 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "uami:"+testSub+":rg1:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeManagedIdentity("runner", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["display.name"] != "batch runner" || got["key.exportable"] != false || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.Delete("managedidentity", "runner", "prod", res.ProviderID, "k"); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteManagedIdentityForeignRefused(t *testing.T) {
	srv := uamiServer(t, "someone-else", "batch runner")
	defer srv.Close()
	d := uamiDriver(t, srv)
	pid := uamiProviderID(testSub, "rg1", azResourceName("id", "prod", "runner", 1))
	res := d.Delete("managedidentity", "runner", "prod", pid, "k")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign identity must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87): the metamorphic write/read round-trip. A STATEFUL fake records the
// display name the create writes (into the groundhold-display tag) and reflects it.
func TestMetamorphicManagedIdentityRoundTrip(t *testing.T) {
	for _, name := range []string{"batch runner", "sync worker"} {
		t.Run(name, func(t *testing.T) {
			var display string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch r.Method {
					case "PUT":
						b, _ := io.ReadAll(r.Body)
						var body struct {
							Tags map[string]string `json:"tags"`
						}
						_ = json.Unmarshal(b, &body)
						display = body.Tags["groundhold-display"]
						w.WriteHeader(200)
						_, _ = w.Write([]byte(`{"properties":{"clientId":"c"}}`))
					case "GET":
						// a real ARM GET always carries the server-assigned GUIDs —
						// the D284 outputs read depends on them
						_, _ = w.Write([]byte(`{"location":"eastus","tags":{"groundhold-capability":"runner",` +
							`"groundhold-environment":"prod","groundhold-display":"` + display + `"},` +
							`"properties":{"clientId":"cccccccc-0000-0000-0000-000000000001",` +
							`"principalId":"pppppppp-0000-0000-0000-000000000002"}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := uamiDriver(t, srv)
			a := uamiAttrs()
			a["display.name"] = name
			res := d.Create("managedidentity", "runner", "prod", a, uamiImpl(), "k", 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeManagedIdentity("runner", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["display.name"] != name {
				t.Errorf("display name round-trip: want %q got %v", name, got["display.name"])
			}
		})
	}
}
