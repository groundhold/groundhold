package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func kmsAttrs() map[string]any {
	return map[string]any{
		"location.region":  "europe-west1",
		"rotation.period":  "30d",
		"protection.level": "hsm",
		"service.managed":  true,
	}
}

func TestBuildKMSHonors(t *testing.T) {
	p, err := BuildKMSKey("acme-prod", "prod", "datakey", kmsAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Location != "europe-west1" || p.RotationSeconds != 2592000 || p.ProtectionLevel != "HSM" ||
		p.Ring != "groundhold-prod" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.cryptoKeyBody("datakey", "prod", "2026-08-01T00:00:00Z")
	if body["purpose"] != "ENCRYPT_DECRYPT" || body["rotationPeriod"] != "2592000s" ||
		body["nextRotationTime"] != "2026-08-01T00:00:00Z" {
		t.Fatalf("body = %+v", body)
	}
	vt := body["versionTemplate"].(map[string]any)
	if vt["protectionLevel"] != "HSM" {
		t.Fatalf("versionTemplate = %+v", vt)
	}
}

func TestBuildKMSRefusals(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"location.region": "europe-west1", "protection.level": "software", "service.managed": true}
	}
	cases := map[string]map[string]any{
		"rotation-too-short": {"rotation.period": "1h"}, // below 1 day
		"bad-protection":     {"protection.level": "quantum"},
		"unmanaged":          {"service.managed": false},
		"unknown-attr":       {"key.material": "AAAA"}, // material is never declared
	}
	for name, extra := range cases {
		a := base()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildKMSKey("acme-prod", "prod", "datakey", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	// missing region
	if _, err := BuildKMSKey("acme-prod", "prod", "datakey",
		map[string]any{"protection.level": "software", "service.managed": true}, nil, 1); err == nil {
		t.Error("missing location.region must refuse")
	}
	// a key with NO rotation is fine (manual rotation)
	if _, err := BuildKMSKey("acme-prod", "prod", "datakey",
		map[string]any{"location.region": "europe-west1", "protection.level": "software", "service.managed": true}, nil, 1); err != nil {
		t.Errorf("a key without rotation should build: %v", err)
	}
}

func kmsServer(t *testing.T, tagCap, protection, rotationPeriod string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "keyRingId="):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/keyRings/groundhold-prod"}`))
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "cryptoKeyId="):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-west1/keyRings/groundhold-prod/cryptoKeys/x"}`))
			case r.Method == "POST" && strings.HasSuffix(r.URL.Path, ":destroy"):
				_, _ = w.Write([]byte(`{"state":"DESTROY_SCHEDULED"}`))
			case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/cryptoKeyVersions"):
				_, _ = w.Write([]byte(`{"cryptoKeyVersions":[{"name":"projects/acme-prod/locations/europe-west1/keyRings/groundhold-prod/cryptoKeys/x/cryptoKeyVersions/1","state":"ENABLED"}]}`))
			case r.Method == "GET":
				doc := `{"name":"projects/acme-prod/locations/europe-west1/keyRings/groundhold-prod/cryptoKeys/x",` +
					`"labels":{"groundhold-capability":"` + tagCap + `","groundhold-environment":"prod"},` +
					`"versionTemplate":{"protectionLevel":"` + protection + `"}`
				if rotationPeriod != "" {
					doc += `,"rotationPeriod":"` + rotationPeriod + `"`
				}
				doc += `}`
				_, _ = w.Write([]byte(doc))
			default:
				w.WriteHeader(404)
			}
		}))
}

func kmsDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.KMSBaseURL = srv.URL
	d.Now = time.Now
	return d
}

func TestCreateObserveDeleteKMS(t *testing.T) {
	srv := kmsServer(t, "datakey", "HSM", "2592000s")
	defer srv.Close()
	d := kmsDriver(t, srv)
	res := d.createKMS("prod", "datakey", kmsAttrs(), nil, 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "gkms:acme-prod:europe-west1:groundhold-prod:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeKMS("datakey", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-west1" || got["protection.level"] != "hsm" ||
		got["rotation.period"] != "2592000s" {
		t.Fatalf("observe: %+v", got)
	}
	// delete destroys the material but is honest that the shell is permanent.
	del := d.deleteKMS("datakey", "prod", res.ProviderID)
	if del.Status != "succeeded" || !strings.Contains(del.Reason, "PERMANENT") {
		t.Fatalf("delete must succeed + note permanence: %+v", del)
	}
}

func TestDeleteKMSForeignRefused(t *testing.T) {
	srv := kmsServer(t, "someone-else", "SOFTWARE", "")
	defer srv.Close()
	d := kmsDriver(t, srv)
	res := d.deleteKMS("datakey", "prod", "gkms:acme-prod:europe-west1:groundhold-prod:x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign key must refuse delete, got %+v", res)
	}
}
