package gcp

import (
	"regexp"
	"strings"
	"testing"
)

func cfAttrs() map[string]any {
	return map[string]any{
		"location.region":        "europe-central2",
		"availability.class":     "regional",
		"network.publicExposure": true,
		"replicas.minimum":       float64(1),
		"autoscaling.enabled":    true,
		"tls.enforced":           true,
		"service.managed":        true,
	}
}

func cfImpl() map[string]any {
	return map[string]any{
		"runtime":     "nodejs20",
		"entry_point": "handler",
		"source":      map[string]any{"bucket": "my-src", "object": "fn.zip"},
	}
}

// Cloud Functions Gen2 ids are letters+hyphens only (no digits) — the name must
// match even though the deterministic hash would be hex elsewhere.
func TestFunctionNameLettersOnly(t *testing.T) {
	name := FunctionName("proj-1", "prod9", "app2-svc", 1)
	if !regexp.MustCompile(`^[a-z][a-z-]{2,62}$`).MatchString(name) {
		t.Fatalf("function name must be [a-z-] only, 4-63 chars, got %q", name)
	}
	// deterministic
	if name != FunctionName("proj-1", "prod9", "app2-svc", 1) {
		t.Fatal("function name must be deterministic")
	}
}

func TestBuildCloudFunctionGolden(t *testing.T) {
	req, err := BuildCloudFunctionCreateRequest("acme-prod", "prod", "api", cfAttrs(), cfImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if req.Method != "POST" || !strings.Contains(req.URL, "/functions?functionId=") {
		t.Fatalf("method/url = %s %s", req.Method, req.URL)
	}
	if req.Body["environment"] != "GEN_2" {
		t.Fatalf("must be GEN_2, got %v", req.Body["environment"])
	}
	sc := req.Body["serviceConfig"].(map[string]any)
	if sc["ingressSettings"] != "ALLOW_ALL" {
		t.Fatalf("public exposure must be ALLOW_ALL, got %v", sc["ingressSettings"])
	}
	if sc["minInstanceCount"] != 1 {
		t.Fatalf("minInstanceCount = %v", sc["minInstanceCount"])
	}
	bc := req.Body["buildConfig"].(map[string]any)
	if bc["runtime"] != "nodejs20" || bc["entryPoint"] != "handler" {
		t.Fatalf("buildConfig = %v", bc)
	}
	src := bc["source"].(map[string]any)["storageSource"].(map[string]any)
	if src["bucket"] != "my-src" || src["object"] != "fn.zip" {
		t.Fatalf("source = %v", src)
	}
	lbl := req.Body["labels"].(map[string]any)
	if lbl["groundhold-capability"] != "api" {
		t.Fatalf("labels = %v", lbl)
	}
}

func TestCloudFunctionPrivateIngress(t *testing.T) {
	a := cfAttrs()
	a["network.publicExposure"] = false
	req, err := BuildCloudFunctionCreateRequest("p", "prod", "api", a, cfImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	sc := req.Body["serviceConfig"].(map[string]any)
	if sc["ingressSettings"] != "ALLOW_INTERNAL_ONLY" {
		t.Fatalf("private must be ALLOW_INTERNAL_ONLY, got %v", sc["ingressSettings"])
	}
}

func TestCloudFunctionRefusals(t *testing.T) {
	cases := map[string]struct {
		mutAttr func(map[string]any)
		mutImpl func(map[string]any)
	}{
		"event trigger":     {nil, func(i map[string]any) { i["event_trigger"] = map[string]any{"eventType": "x"} }},
		"signed provenance": {func(a map[string]any) { a["image.signedProvenance"] = true }, nil},
		"no runtime":        {nil, func(i map[string]any) { delete(i, "runtime") }},
		"no entry point":    {nil, func(i map[string]any) { delete(i, "entry_point") }},
		"no source":         {nil, func(i map[string]any) { delete(i, "source") }},
		"not regional":      {func(a map[string]any) { a["availability.class"] = "zonal" }, nil},
		"no tls":            {func(a map[string]any) { a["tls.enforced"] = false }, nil},
		"no region":         {func(a map[string]any) { delete(a, "location.region") }, nil},
		"unknown attr":      {func(a map[string]any) { a["engine.protocol"] = "x" }, nil},
		"fractional min":    {func(a map[string]any) { a["replicas.minimum"] = 1.5 }, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a, i := cfAttrs(), cfImpl()
			if c.mutAttr != nil {
				c.mutAttr(a)
			}
			if c.mutImpl != nil {
				c.mutImpl(i)
			}
			if _, err := BuildCloudFunctionCreateRequest("p", "prod", "api", a, i, 1); err == nil {
				t.Fatalf("expected refusal for %q", name)
			}
		})
	}
}
