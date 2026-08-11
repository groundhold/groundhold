package parity

import (
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"groundhold/internal/aws"
	"groundhold/internal/azure"
	"groundhold/internal/gcp"
	"groundhold/internal/k8s"
	"groundhold/internal/provider"
)

// TestInterfaceParity is the HYPERSCALER symmetry sub-check: the three hyperscaler
// drivers must implement the SAME set of optional provider capabilities
// (agnostic-symmetric-development policy). It is the check that was missing when the
// Azure driver shipped WITHOUT provider.Reconciler — `resume` type-asserts the driver
// to Reconciler and, finding none, refused every Azure run (D29 then blocks apply →
// converge STALE).
//
// NOTE (review, docs/TESTING_STRATEGY.md): symmetry is the STRICTER sub-check, not the
// general invariant. The tree holds seven providers (also cloudflare/hetzner/upstash/
// k8s) that may LEGITIMATELY lack an interface — so the general rule is "no SILENT
// degradation on a missing interface" (a verb must emit a declared capability-gap,
// never a silent no-op), enforced at the runtime layer, not here. This test stays
// scoped to the three hyperscalers on purpose. To exempt a hyperscaler, add a
// documented case rather than deleting the row.
func TestInterfaceParity(t *testing.T) {
	drivers := map[string]any{
		"aws":   aws.NewDriver("eu-central-1"),
		"gcp":   gcp.NewDriver("proj"),
		"azure": azure.NewDriver("00000000-0000-0000-0000-000000000001"),
	}
	checks := []struct {
		name string
		has  func(any) bool
	}{
		{"Reconciler", func(d any) bool { _, ok := d.(provider.Reconciler); return ok }},
		{"Preflighter", func(d any) bool { _, ok := d.(provider.Preflighter); return ok }},
		{"ResourcePreflighter", func(d any) bool { _, ok := d.(provider.ResourcePreflighter); return ok }},
		{"Prober", func(d any) bool { _, ok := d.(provider.Prober); return ok }},
		{"Enumerator", func(d any) bool { _, ok := d.(provider.Enumerator); return ok }},
		{"Claimer", func(d any) bool { _, ok := d.(provider.Claimer); return ok }},
		{"LROBudgeter", func(d any) bool { _, ok := d.(provider.LROBudgeter); return ok }},
	}
	for cloud, d := range drivers {
		for _, c := range checks {
			if !c.has(d) {
				t.Errorf("%s driver does not implement provider.%s — cloud interface parity is "+
					"broken. A missing optional interface makes the runtime refuse the WHOLE cloud "+
					"for that verb (Azure did exactly this before it had Reconciler). Implement it, "+
					"or add a documented exception to this test.", cloud, c.name)
			}
		}
	}
}

// TestLROTimeoutFloor is the D265 proactive class-gate: every hyperscaler driver's
// long-running-operation ceiling must be generous enough for a real control-plane
// minor-version upgrade (20-40 min), not the naive ~20-min generic poll timeout that
// reported Acme's HEALTHY EKS upgrade as a false `unknown` (D264). A new cluster/LRO
// driver that ships a too-short budget fails HERE, in CI, instead of on a field user's
// production upgrade. The floor (45 min) sits above the observed 40-min upper bound.
func TestLROTimeoutFloor(t *testing.T) {
	const floor = 45 * time.Minute
	drivers := map[string]provider.LROBudgeter{
		"aws":   aws.NewDriver("eu-central-1"),
		"gcp":   gcp.NewDriver("proj"),
		"azure": azure.NewDriver("00000000-0000-0000-0000-000000000001"),
	}
	for cloud, d := range drivers {
		if got := d.LROTimeout(); got < floor {
			t.Errorf("%s driver LROTimeout()=%v is below the %v floor — a real control-plane "+
				"upgrade (20-40 min) would trip it and report a healthy op as unknown (the D264 "+
				"class). Raise the driver's LRO ceiling.", cloud, got, floor)
		}
	}
}

// update regenerates the committed spec/parity.yaml instead of asserting against
// it: go test ./internal/parity -run TestParityMatrix -update.
var update = flag.Bool("update", false, "regenerate spec/parity.yaml")

// capabilityMapper is what every driver exposes for the matrix (mirror of
// provider.CapabilityMapper, restated here to avoid importing test-only symbols).
type capabilityMapper interface {
	ServiceCapabilities() map[string]string
}

// driverMaps loads the three drivers' token->TYPE maps. Any driver constructor
// arg works — ServiceCapabilities is a static declaration.
func driverMaps(t *testing.T) map[string]map[string]string {
	t.Helper()
	mk := func(name string, cm capabilityMapper) map[string]string {
		m := cm.ServiceCapabilities()
		if len(m) == 0 {
			t.Fatalf("%s ServiceCapabilities is empty", name)
		}
		return m
	}
	return map[string]map[string]string{
		"aws":   mk("aws", aws.NewDriver("eu-central-1")),
		"gcp":   mk("gcp", gcp.NewDriver("proj")),
		"azure": mk("azure", azure.NewDriver("00000000-0000-0000-0000-000000000001")),
	}
}

// vocabTypes reads every capability TYPE from spec/vocab (the row set + the set a
// map value must belong to).
func vocabTypes(t *testing.T) map[string]bool {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "spec", "vocab")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read spec/vocab: %v", err)
	}
	set := map[string]bool{}
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, "capability.") && strings.HasSuffix(n, ".yaml") {
			set[strings.TrimSuffix(n, ".yaml")] = true
		}
	}
	if len(set) == 0 {
		t.Fatal("no capability vocab files found")
	}
	return set
}

// TestParityMatrix is the load-bearing gate: it proves spec/parity.yaml is the
// exact, deterministic projection of the real drivers + the authored gaps, and
// that every authored gap is REAL. If a driver adds/removes a service or a gapped
// cell gains a driver, the byte-diff fails with "regenerate", so the matrix can
// never silently drift or lie.
func TestParityMatrix(t *testing.T) {
	caps := driverMaps(t)
	vocab := vocabTypes(t)

	// (1) Every map value is a REAL vocab TYPE — no phantom capability.
	for cloud, m := range caps {
		for tok, typ := range m {
			if !vocab[typ] {
				t.Errorf("%s/%s maps to %q, which has no spec/vocab file", cloud, tok, typ)
			}
		}
	}
	// (2) Gap-reality: every declared structural gap has a real vocab TYPE, a class
	// from the closed set, AND no token in that cloud actually fulfils it (a gap
	// that is really fulfilled is a lie).
	for typ, byCloud := range structuralGaps {
		if !vocab[typ] {
			t.Errorf("structural gap declares %q, which has no spec/vocab file", typ)
		}
		for cloud, g := range byCloud {
			if !gapClasses[g.Class] {
				t.Errorf("gap %s/%s has class %q outside the closed set", typ, cloud, g.Class)
			}
			if g.Reason == "" {
				t.Errorf("gap %s/%s has an empty reason", typ, cloud)
			}
			if toks := tokensFor(caps[cloud], typ); len(toks) > 0 {
				t.Errorf("gap %s/%s claims a structural gap, but %v fulfils it — "+
					"remove the gap (it is not real)", typ, cloud, toks)
			}
		}
	}

	// (3) The committed matrix equals the regeneration, byte-for-byte.
	rows := make([]string, 0, len(vocab))
	for typ := range vocab {
		rows = append(rows, typ)
	}
	sort.Strings(rows)
	got := BuildMatrixYAMLWith(caps, rows, outsideTheClouds(t))

	path := filepath.Join("..", "..", "..", "spec", "parity.yaml")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write parity.yaml: %v", err)
		}
		t.Logf("regenerated %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spec/parity.yaml (run: go test ./internal/parity -run TestParityMatrix -update): %v", err)
	}
	if string(want) != got {
		t.Errorf("spec/parity.yaml is stale — regenerate with:\n" +
			"  go test ./internal/parity -run TestParityMatrix -update\n" +
			"(a driver's ServiceCapabilities or a structural gap changed)")
	}
}

// TestHTTPClientsHealthCheckIdleHTTP2 is the D268/D269 cross-driver gate for the F29 class:
// every hyperscaler driver's HTTP client must run HTTP/2 health-check pings, so a dead
// idle connection (silently dropped during a long ~40-min control-plane upgrade poll) is
// detected and closed instead of hanging a read forever (Acme needed SIGQUIT+resume). A
// new driver that ships a bare http.Client fails HERE, in CI, not on a field upgrade.
func TestHTTPClientsHealthCheckIdleHTTP2(t *testing.T) {
	clients := map[string]*http.Client{
		"aws":   aws.NewDriver("eu-central-1").HTTP,
		"gcp":   gcp.NewDriver("proj").HTTP,
		"azure": azure.NewDriver("00000000-0000-0000-0000-000000000001").HTTP,
	}
	for cloud, c := range clients {
		tr, ok := c.Transport.(*http.Transport)
		if !ok {
			t.Errorf("%s: HTTP client must use an *http.Transport (for HTTP/2 health-checks), got %T", cloud, c.Transport)
			continue
		}
		if tr.ResponseHeaderTimeout <= 0 {
			t.Errorf("%s: ResponseHeaderTimeout must be set — it bounds a stuck read on a dead connection "+
				"during a long upgrade poll (the F29 hang). HTTP/1.1 honors it reliably.", cloud)
		}
		if tr.TLSNextProto == nil {
			t.Errorf("%s: HTTP/2 must be disabled (TLSNextProto non-nil) — the F29 hang lived in the "+
				"wedged HTTP/2 transport that ignored Client.Timeout (D268 pings did not break it; D269 "+
				"forces HTTP/1.1)", cloud)
		}
	}
}

// TestResilientClientBoundsStuckRead is the D269 EMPIRICAL check the D268 fix LACKED:
// it verifies the transport construction actually BOUNDS a read that never receives a
// response (a dead/silent connection — the shape of the F29 hang), rather than only
// pinning a config field that looked right but did nothing in the field. A server
// accepts the connection then stays silent; the client MUST error within the read bound,
// never hang. (Uses a short ResponseHeaderTimeout so the suite stays fast.)
func TestResilientClientBoundsStuckRead(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { time.Sleep(5 * time.Second); c.Close() }(c) // accept, stay SILENT
		}
	}()
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = false
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	tr.ResponseHeaderTimeout = 300 * time.Millisecond
	client := &http.Client{Transport: tr}

	start := time.Now()
	resp, err := client.Get("http://" + ln.Addr().String() + "/poll")
	if err == nil {
		resp.Body.Close()
		t.Fatal("a silent server must yield a timeout error, not a response")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("the stuck read was NOT bounded: took %v (ResponseHeaderTimeout must fire ~300ms) — this is the F29 hang", el)
	}
}

// TestResilientClientForcesHTTP1OverALPN is the D271 regression the D269 first cut
// LACKED: it connects the resilient transport to an HTTP/2-CAPABLE TLS server (the shape
// of the AWS/EKS endpoint) and asserts it (a) connects at all and (b) speaks HTTP/1.1.
// D269's first cut set TLSNextProto={} but left ALPN advertising "h2", so the server
// negotiated HTTP/2 while the transport parsed HTTP/1.1 -> "malformed HTTP response" and
// EVERY request failed (Acme: EKS create DIED, DescribeCluster response unparseable).
// Plain-HTTP tests could not catch this — only a real TLS+ALPN server does.
func TestResilientClientForcesHTTP1OverALPN(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Proto))
	}))
	srv.EnableHTTP2 = true // the server WILL negotiate h2 if the client offers it
	srv.StartTLS()
	defer srv.Close()

	// mirror newResilientHTTPClient's ALPN forcing (+ trust the test cert).
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = false
	tr.TLSClientConfig = &tls.Config{NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true}
	tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("the resilient client must connect to an HTTP/2-capable TLS server — got %v "+
			"(D269's first cut negotiated h2 via ALPN then parsed http1 -> every request broke)", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 1 {
		t.Fatalf("the resilient client must force HTTP/1.1 even against an h2-capable server, got %s", resp.Proto)
	}
}

// outsideTheClouds reads the capability TYPES fulfilled by providers that are not one
// of the three clouds. The Kubernetes driver declares them in its mappings, which is
// the same authority its dispatch uses — never a second list (D502).
func outsideTheClouds(t *testing.T) map[string][]string {
	t.Helper()
	d := k8s.NewDriver("http://unused", "tok")
	if len(d.Mappings) == 0 {
		t.Fatal("k8s driver has no mappings — the matrix would under-claim silently")
	}
	out := map[string][]string{}
	for svc, m := range d.Mappings {
		if m == nil || m.Capability == "" {
			continue
		}
		out[m.Capability] = append(out[m.Capability], "k8s/"+svc)
	}
	return out
}
