package fixture

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShapeOfErasesValuesKeepsStructure(t *testing.T) {
	a := `{"name":"bucket-a","versioning":{"enabled":true},"loc":"EU"}`
	b := `{"name":"bucket-ZZZ","versioning":{"enabled":false},"loc":"US"}`
	_, ha, _ := ShapeOf(json.RawMessage(a))
	_, hb, _ := ShapeOf(json.RawMessage(b))
	if ha != hb {
		t.Fatal("same structure, different values -> same shape hash (values must be erased)")
	}
	// a renamed field moves the hash (structural drift)
	c := `{"name":"x","versioningRENAMED":{"enabled":true},"loc":"EU"}`
	_, hc, _ := ShapeOf(json.RawMessage(c))
	if hc == ha {
		t.Fatal("a renamed field must change the shape hash")
	}
	// a new field moves the hash; a type change moves the hash
	d := `{"name":"x","versioning":{"enabled":"yes"},"loc":"EU"}` // enabled bool->string
	_, hd, _ := ShapeOf(json.RawMessage(d))
	if hd == ha {
		t.Fatal("a field type change must change the shape hash")
	}
}

func TestLoadRejectsCorruptShapeHash(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.json")
	os.WriteFile(p, []byte(`{"schema":"groundhold/fixture/v1","provider":"gcp","service":"gcs",
		"operation":"buckets.get","variant":"ok","provenance":"handwritten-pending-canary",
		"request":{"method":"GET","path":"/b/x"},
		"response":{"status":200,"raw":{"name":"x"}},
		"shapeHash":"sha256:deadbeef",
		"expected":{"observations":[{"path":"service.managed","value":true}]}}`), 0o600)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "shapeHash") {
		t.Fatalf("a committed shapeHash disagreeing with the bytes must fail Load, got %v", err)
	}
}

func TestLoadRequiresExpectedAndProvenance(t *testing.T) {
	dir := t.TempDir()
	// missing expected block
	p := filepath.Join(dir, "noexp.json")
	os.WriteFile(p, []byte(`{"schema":"groundhold/fixture/v1","provider":"gcp","service":"gcs",
		"operation":"x","variant":"ok","provenance":"handwritten-pending-canary",
		"request":{"method":"GET","path":"/b/x"},"response":{"status":200,"raw":{"a":1}}}`), 0o600)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "expected block") {
		t.Fatalf("missing expected block must fail Load, got %v", err)
	}
	// live without capturedBy
	p2 := filepath.Join(dir, "fakelive.json")
	os.WriteFile(p2, []byte(`{"schema":"groundhold/fixture/v1","provider":"gcp","service":"gcs",
		"operation":"x","variant":"ok","provenance":"live",
		"request":{"method":"GET","path":"/b/x"},"response":{"status":200,"raw":{"a":1}},
		"expected":{"observations":[{"path":"p","value":1}]}}`), 0o600)
	if _, err := Load(p2); err == nil || !strings.Contains(err.Error(), "capturedBy") {
		t.Fatalf("provenance:live without capturedBy must fail Load, got %v", err)
	}
}

// TestFixtureProvenance is the honesty gate IN CODE: every committed fixture
// loads (schema/provenance/expected/shapeHash all valid), a `live` fixture must
// carry a canary capturedBy, and pending fixtures must carry a note explaining
// why they are not yet live. A new fixture cannot land dishonestly.
func TestFixtureProvenance(t *testing.T) {
	root := "data"
	var n int
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		n++
		f, lerr := Load(path)
		if lerr != nil {
			t.Errorf("%s: %v", path, lerr)
			return nil
		}
		if f.Provenance == ProvenanceLive && f.CapturedBy == "" {
			t.Errorf("%s: live fixture without capturedBy", path)
		}
		if f.Provenance == ProvenancePendingCanary && f.Note == "" {
			t.Errorf("%s: a pending fixture must carry a note (why not yet live)", path)
		}
		return nil
	})
	if n == 0 {
		t.Fatal("no fixtures found under data/ — the harness has nothing to guard")
	}
}

func TestMatchesIsStrict(t *testing.T) {
	f, err := Load(filepath.Join("data", "gcp", "gcs", "buckets-get.ok.json"))
	if err != nil {
		t.Fatal(err)
	}
	ok := reqFor("GET", "/b/gh-fixture-bucket")
	if !matches(f, ok) {
		t.Fatal("the recorded method+path must match")
	}
	for _, bad := range []*http.Request{
		reqFor("POST", "/b/gh-fixture-bucket"), // wrong verb
		reqFor("GET", "/b/other-bucket"),       // wrong path
	} {
		if matches(f, bad) {
			t.Fatalf("an unrecorded request (%s %s) must NOT match — replay is fail-closed",
				bad.Method, bad.URL.Path)
		}
	}
}

func reqFor(method, path string) *http.Request {
	return httptest.NewRequest(method, path, nil)
}
