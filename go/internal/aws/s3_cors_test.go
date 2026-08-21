package aws

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"groundhold/internal/provider"
)

func corsAttrs(origins ...any) map[string]any {
	return map[string]any{"location.region": "eu-central-1", "cors.allowedOrigins": origins}
}

func corsRule(origins, methods []any) map[string]any {
	return map[string]any{"allowedOrigins": origins, "allowedMethods": methods}
}

// TestBuildS3CorsProjectionGate pins the design's core honesty guarantee: the
// cors.allowedOrigins ATTRIBUTE must be the exact origin-union of the implementation.cors
// OPERAND, or the build refuses — so a hard constraint can never pass over a rule set that
// allows different origins than the contract asserts (the write-only-operand smuggling channel).
func TestBuildS3CorsProjectionGate(t *testing.T) {
	// attribute matches the operand's origin union -> PUT /?cors with the rules
	p, err := BuildS3Requests("pv", "prod", "media",
		corsAttrs("https://app.example.com"),
		map[string]any{"cors": []any{corsRule([]any{"https://app.example.com"}, []any{"PUT", "GET"})}}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Cors == nil || p.Cors.Method != "PUT" || p.Cors.Path != "/?cors" {
		t.Fatalf("a declared cors must build a PUT /?cors, got %+v", p.Cors)
	}
	if !strings.Contains(p.Cors.Body, "https://app.example.com") || !strings.Contains(p.Cors.Body, "<AllowedMethod>PUT") {
		t.Fatalf("the cors body must carry the rule, got %q", p.Cors.Body)
	}

	// attribute claims an origin the operand's rules do NOT allow -> refuse
	_, err = BuildS3Requests("pv", "prod", "media",
		corsAttrs("https://app.example.com"),
		map[string]any{"cors": []any{corsRule([]any{"https://OTHER.example.com"}, []any{"GET"})}}, 1)
	if err == nil {
		t.Fatal("the projection gate must refuse when the attribute origin set != the operand's union")
	}

	// declared origins but NO operand -> refuse (never synthesise a default rule)
	_, err = BuildS3Requests("pv", "prod", "media", corsAttrs("https://app.example.com"), map[string]any{}, 1)
	if err == nil {
		t.Fatal("declared cors.allowedOrigins with no implementation.cors must refuse")
	}

	// declared EMPTY -> DeleteBucketCors (explicit "no cross-origin", enforced)
	pe, err := BuildS3Requests("pv", "prod", "media", corsAttrs(), map[string]any{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if pe.Cors == nil || pe.Cors.Method != "DELETE" {
		t.Fatalf("cors.allowedOrigins: [] must build a DeleteBucketCors, got %+v", pe.Cors)
	}

	// UNDECLARED -> hands off (nil), the surface is unmanaged (brownfield not stomped)
	pu, _ := BuildS3Requests("pv", "prod", "media", map[string]any{"location.region": "eu-central-1"}, map[string]any{}, 1)
	if pu.Cors != nil {
		t.Fatal("an undeclared cors surface must be left unmanaged (nil), never DELETE'd")
	}
}

// TestObserveS3Cors pins the observe side: the origin UNION across rules (sorted-unique),
// and — the design's key point — a NoSuchCORSConfiguration is a MEASURED empty set, never
// unknown, so a blind bucket reads [] and a hard `equals` constraint blocks it.
func TestObserveS3Cors(t *testing.T) {
	// present: two rules, overlapping origins -> deduped, sorted union
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		switch r.URL.RawQuery {
		case "cors":
			_, _ = w.Write([]byte(`<CORSConfiguration>` +
				`<CORSRule><AllowedOrigin>https://b.example.com</AllowedOrigin>` +
				`<AllowedOrigin>https://a.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule>` +
				`<CORSRule><AllowedOrigin>https://a.example.com</AllowedOrigin><AllowedMethod>PUT</AllowedMethod></CORSRule>` +
				`</CORSConfiguration>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	d := s3TestDriver(t, srv)
	obs, _, err := d.observeS3("media", "s3:eu-central-1:pv-media")
	if err != nil {
		t.Fatal(err)
	}
	got := valueOf(obs, "cors.allowedOrigins")
	want := []any{"https://a.example.com", "https://b.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("cors union must be sorted-unique %v, got %v", want, got)
	}

	// absent: NoSuchCORSConfiguration -> MEASURED empty set (not unknown, not a diag)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.RawQuery == "cors" {
			w.WriteHeader(404)
			_, _ = w.Write([]byte("<Error><Code>NoSuchCORSConfiguration</Code></Error>"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv2.Close()
	d2 := s3TestDriver(t, srv2)
	obs2, _, err := d2.observeS3("media", "s3:eu-central-1:pv-media")
	if err != nil {
		t.Fatal(err)
	}
	got2 := valueOf(obs2, "cors.allowedOrigins")
	if got2 == nil || !reflect.DeepEqual(got2, []any{}) {
		t.Fatalf("a bucket with no CORS must observe a MEASURED empty set [], got %v", got2)
	}
	// classify is an in-place patch
	if class, _ := classifyS3Change("cors.allowedOrigins", []any{"https://app.example.com"}, nil); class != "mutable" {
		t.Fatalf("a cors change must be an in-place patch, got %q", class)
	}
}

func valueOf(obs []provider.Observation, path string) any {
	for _, o := range obs {
		if o.Path == path {
			return o.Value
		}
	}
	return nil
}

// TestCreateS3CorsHappyPath exercises the create fold: a declared cors issues a
// PutBucketCors after the bucket exists (and captures/verifies the PUT /?cors route).
func TestCreateS3CorsHappyPath(t *testing.T) {
	srv := s3Server(t, 200, "")
	defer srv.Close()
	d := s3TestDriver(t, srv)
	a := s3Attrs()
	a["cors.allowedOrigins"] = []any{"https://app.example.com"}
	res := d.createS3("000000000000", "prod", "assets", a, map[string]any{
		"cors": []any{map[string]any{
			"allowedOrigins": []any{"https://app.example.com"},
			"allowedMethods": []any{"PUT", "GET"}}},
	}, 1)
	if res.Status != "succeeded" {
		t.Fatalf("create with CORS must succeed, got %+v", res)
	}
}
