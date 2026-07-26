package fixture

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"groundhold/internal/provider"
)

// Serve returns an httptest.Server that answers ONLY the requests the fixtures
// recorded (method + path, and every recorded query key), serving the verbatim
// response bytes and status. Any other request — wrong verb, wrong path, an
// extra unexpected call — fails the test. This is the fail-closed rule that
// stops replay from degrading into another permissive fake: the driver must make
// exactly the call the fixture captured, or the test breaks.
func Serve(t *testing.T, fx ...*Fixture) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, f := range fx {
			if !matches(f, r) {
				continue
			}
			for k, v := range f.Response.Headers {
				w.Header().Set(k, v)
			}
			status := f.Response.Status
			if status == 0 {
				status = http.StatusOK
			}
			w.WriteHeader(status)
			_, _ = w.Write(f.Response.Raw)
			return
		}
		t.Errorf("unfixtured request: %s %s?%s — replay serves only recorded calls",
			r.Method, r.URL.Path, r.URL.RawQuery)
		http.Error(w, "unfixtured request", http.StatusNotImplemented)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func matches(f *Fixture, r *http.Request) bool {
	if f.Request.Method != "" && f.Request.Method != r.Method {
		return false
	}
	if f.Request.Path != r.URL.Path {
		return false
	}
	q := r.URL.Query()
	for k, want := range f.Request.Query {
		if q.Get(k) != want {
			return false
		}
	}
	return true
}

// AssertExpected deep-compares a driver's parse against the fixture's Expected
// block. It asserts the SEMANTIC — the exact observations (path/value/derivation)
// the driver must extract — not merely that parsing did not error. When the
// fixture expects a refusal (ErrContains), it asserts the error instead.
func AssertExpected(t *testing.T, f *Fixture, obs []provider.Observation, err error) {
	t.Helper()
	if f.Expected.ErrContains != "" {
		if err == nil {
			t.Fatalf("%s: expected an error containing %q, got none", f.Operation, f.Expected.ErrContains)
		}
		if !contains(err.Error(), f.Expected.ErrContains) {
			t.Fatalf("%s: error %q does not contain %q", f.Operation, err.Error(), f.Expected.ErrContains)
		}
		return
	}
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", f.Operation, err)
	}
	got := map[string]provider.Observation{}
	for _, o := range obs {
		got[o.Path] = o
	}
	for _, want := range f.Expected.Observations {
		g, ok := got[want.Path]
		if !ok {
			t.Errorf("%s: missing expected observation %q", f.Operation, want.Path)
			continue
		}
		if !valueEqual(g.Value, want.Value) {
			t.Errorf("%s: %s value = %v (%T), want %v (%T)",
				f.Operation, want.Path, g.Value, g.Value, want.Value, want.Value)
		}
		if want.Derivation != "" && g.Derivation != want.Derivation {
			t.Errorf("%s: %s derivation = %q, want %q",
				f.Operation, want.Path, g.Derivation, want.Derivation)
		}
	}
}

// valueEqual compares an observation value against a JSON-decoded expected value
// (JSON numbers decode to float64; the driver may emit int/bool/string). It
// normalizes numerics and falls back to string form for the rest.
func valueEqual(got, want any) bool {
	if reflect.DeepEqual(got, want) {
		return true
	}
	gf, gok := toFloat(got)
	wf, wok := toFloat(want)
	if gok && wok {
		return gf == wf
	}
	return fmt.Sprintf("%v", got) == fmt.Sprintf("%v", want)
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	}
	return 0, false
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
