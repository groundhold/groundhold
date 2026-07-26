package gcp

import (
	"strings"
	"testing"
)

func gcsAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-central2",
		"durability.class":       "regional",
		"versioning.enabled":     true,
		"network.publicExposure": false,
		"encryption.atRest":      true,
		"service.managed":        true,
	}
}

func TestBuildGCSCreateGolden(t *testing.T) {
	req, err := BuildGCSCreateRequest("acme-prod", "prod", "assets", gcsAttrs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || !strings.Contains(req.URL, "/b?project=acme-prod") {
		t.Fatalf("method/url = %s %s", req.Method, req.URL)
	}
	if req.Body["location"] != "europe-central2" {
		t.Fatalf("location=%v", req.Body["location"])
	}
	iam := req.Body["iamConfiguration"].(map[string]any)
	if iam["publicAccessPrevention"] != "enforced" {
		t.Fatalf("private bucket must ENFORCE public-access-prevention, got %v",
			iam["publicAccessPrevention"])
	}
	if ubla := iam["uniformBucketLevelAccess"].(map[string]any); ubla["enabled"] != true {
		t.Fatal("uniform bucket-level access must be the secure baseline")
	}
	ver := req.Body["versioning"].(map[string]any)
	if ver["enabled"] != true {
		t.Fatalf("versioning=%v", ver)
	}
	labels := req.Body["labels"].(map[string]any)
	if labels["groundhold-capability"] != "assets" {
		t.Fatalf("labels=%v", labels)
	}
	name, _ := req.Body["name"].(string)
	if !strings.HasPrefix(name, "assets-prod-") {
		t.Fatalf("bucket name=%q", name)
	}
}

func TestGCSPublicRelaxesPrevention(t *testing.T) {
	a := gcsAttrs()
	a["network.publicExposure"] = true
	req, err := BuildGCSCreateRequest("p", "prod", "assets", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	iam := req.Body["iamConfiguration"].(map[string]any)
	if iam["publicAccessPrevention"] != "inherited" {
		t.Fatalf("public bucket must not ENFORCE prevention, got %v",
			iam["publicAccessPrevention"])
	}
}

func TestGCSReplicationDualRegionTurbo(t *testing.T) {
	// replication.enabled honored as a configurable dual-region bucket + turbo
	// replication (rpo=ASYNC_TURBO), NOT S3-style CRR to an arbitrary region.
	a := gcsAttrs()
	a["location.region"] = "europe-west1"
	a["replication.enabled"] = true
	a["replication.destinationRegion"] = "europe-north1"
	req, err := BuildGCSCreateRequest("acme-prod", "prod", "assets", a, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	if req.Body["location"] != "EU" {
		t.Fatalf("dual-region location must be the continent code EU, got %v", req.Body["location"])
	}
	cpc, ok := req.Body["customPlacementConfig"].(map[string]any)
	if !ok {
		t.Fatalf("expected customPlacementConfig, body=%v", req.Body)
	}
	dl := cpc["dataLocations"].([]any)
	if len(dl) != 2 || dl[0] != "EUROPE-WEST1" || dl[1] != "EUROPE-NORTH1" {
		t.Fatalf("dataLocations=%v, want [EUROPE-WEST1 EUROPE-NORTH1]", dl)
	}
	if req.Body["rpo"] != "ASYNC_TURBO" {
		t.Fatalf("turbo replication must set rpo=ASYNC_TURBO, got %v", req.Body["rpo"])
	}
}

func TestGCSReplicationRefusals(t *testing.T) {
	cases := map[string]func(a map[string]any){
		"enabled without destination": func(a map[string]any) {
			a["replication.enabled"] = true
		},
		"destination without enabled": func(a map[string]any) {
			a["replication.destinationRegion"] = "europe-north1"
		},
		"same region pair": func(a map[string]any) {
			a["location.region"] = "europe-west1"
			a["replication.enabled"] = true
			a["replication.destinationRegion"] = "europe-west1"
		},
		"cross-continent pair": func(a map[string]any) {
			a["location.region"] = "europe-west1"
			a["replication.enabled"] = true
			a["replication.destinationRegion"] = "us-east1"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := gcsAttrs()
			mutate(a)
			if _, err := BuildGCSCreateRequest("p", "prod", "assets", a, nil, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}

func TestGCSRefusals(t *testing.T) {
	cases := map[string]func(a map[string]any){
		"single-zone":   func(a map[string]any) { a["durability.class"] = "single-zone" },
		"no encryption": func(a map[string]any) { a["encryption.atRest"] = false },
		"unmanaged":     func(a map[string]any) { a["service.managed"] = false },
		"no location":   func(a map[string]any) { delete(a, "location.region") },
		"unknown attr":  func(a map[string]any) { a["engine.protocol"] = "postgresql/16" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := gcsAttrs()
			mutate(a)
			if _, err := BuildGCSCreateRequest("p", "prod", "assets", a, nil, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}
