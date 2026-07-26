package gcp

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"groundhold/internal/provider"
)

var attrs = map[string]any{
	"engine.protocol":        "postgresql/16.4",
	"location.region":        "europe-west1",
	"network.publicExposure": false,
	"encryption.atRest":      true,
	"recovery.rpo":           "5m",
	"availability.class":     "regional",
}
var impl = map[string]any{
	"tier":      "db-custom-2-8192",
	"disk_type": "PD_SSD",
	"flags":     map[string]any{"max_connections": 500, "log_checkpoints": true},
	"network":   map[string]any{"privateNetwork": "projects/p/global/networks/vpc"},
}

// The golden: byte-exact request body for fixed inputs. The mapping
// table cannot drift silently.
func TestBuildCreateRequestGolden(t *testing.T) {
	req, err := BuildCreateRequest("acme-prod", "production", "orders-db",
		attrs, impl, 1)
	if err != nil {
		t.Fatal(err)
	}
	name, _ := req.Body["name"].(string)
	req.Body["name"] = "NAME" // pinned separately below
	got, _ := json.Marshal(req.Body)
	// deletionProtectionEnabled defaults ON (D47) — databases are stateful
	want := `{"databaseVersion":"POSTGRES_16","name":"NAME","region":"europe-west1","settings":{"availabilityType":"REGIONAL","backupConfiguration":{"enabled":true,"pointInTimeRecoveryEnabled":true},"dataDiskType":"PD_SSD","databaseFlags":[{"name":"log_checkpoints","value":"on"},{"name":"max_connections","value":"500"}],"deletionProtectionEnabled":true,"ipConfiguration":{"authorizedNetworks":[],"ipv4Enabled":false,"privateNetwork":"projects/p/global/networks/vpc"},"tier":"db-custom-2-8192","userLabels":{"groundhold-capability":"orders-db","groundhold-environment":"production"}}}`
	if string(got) != want {
		t.Errorf("golden mismatch:\n got: %s\nwant: %s", got, want)
	}
	// deterministic name: slug + stable hash, pinned
	again := InstanceName("acme-prod", "production", "orders-db", 1)
	if name != again {
		t.Errorf("name not deterministic: %s vs %s", name, again)
	}
	if req.URL != "https://sqladmin.googleapis.com/v1/projects/acme-prod/instances" {
		t.Errorf("url: %s", req.URL)
	}
}

func TestRefusals(t *testing.T) {
	cases := []struct {
		name  string
		attrs map[string]any
		impl  map[string]any
	}{
		{"private-without-network",
			map[string]any{"engine.protocol": "postgresql/16",
				"location.region":        "europe-west1",
				"network.publicExposure": false},
			map[string]any{"tier": "t"}},
		{"multi-regional",
			map[string]any{"engine.protocol": "postgresql/16",
				"location.region": "x", "availability.class": "multi-regional"},
			map[string]any{"tier": "t"}},
		{"unmapped-attribute",
			map[string]any{"engine.protocol": "postgresql/16",
				"location.region": "x", "custom.thing": 1},
			map[string]any{"tier": "t"}},
		{"unencrypted",
			map[string]any{"engine.protocol": "postgresql/16",
				"location.region": "x", "encryption.atRest": false},
			map[string]any{"tier": "t"}},
		{"missing-tier",
			map[string]any{"engine.protocol": "postgresql/16",
				"location.region": "x"},
			map[string]any{}},
		{"rpo-beyond-pitr",
			map[string]any{"engine.protocol": "postgresql/16",
				"location.region": "x", "recovery.rpo": "30d"},
			map[string]any{"tier": "t"}},
		// deletion_protection must FAIL CLOSED on a non-bool — a quoted
		// "false" or a typo must never silently disable protection.
		{"deletion-protection-string",
			map[string]any{"engine.protocol": "postgresql/16",
				"location.region": "x"},
			map[string]any{"tier": "t", "deletion_protection": "false"}},
		{"deletion-protection-number",
			map[string]any{"engine.protocol": "postgresql/16",
				"location.region": "x"},
			map[string]any{"tier": "t", "deletion_protection": 0}},
	}
	for _, c := range cases {
		if _, err := BuildCreateRequest("p", "e", "cap", c.attrs, c.impl, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", c.name)
		}
	}
}

// A real bool false is the ONLY way to opt out of deletion protection;
// it must be honored (fail-closed applies to typos, not to a reviewed
// decision).
func TestDeletionProtectionBoolOptOut(t *testing.T) {
	req, err := BuildCreateRequest("p", "e", "cap",
		map[string]any{"engine.protocol": "postgresql/16",
			"location.region": "x"},
		map[string]any{"tier": "t", "deletion_protection": false}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := req.Body["settings"].(map[string]any)
	if s["deletionProtectionEnabled"] != false {
		t.Errorf("bool false opt-out not honored: %v",
			s["deletionProtectionEnabled"])
	}
}

func TestEditionPinnedAndValidated(t *testing.T) {
	base := map[string]any{"engine.protocol": "postgresql/16", "location.region": "x"}
	// valid edition rides into settings verbatim
	req, err := BuildCreateRequest("p", "e", "cap", base,
		map[string]any{"tier": "t", "edition": "ENTERPRISE"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := req.Body["settings"].(map[string]any)
	if s["edition"] != "ENTERPRISE" {
		t.Fatalf("edition not pinned into settings: %v", s["edition"])
	}
	// an unknown edition is refused, not passed to GCP to reinterpret
	if _, err := BuildCreateRequest("p", "e", "cap", base,
		map[string]any{"tier": "t", "edition": "PLATINUM"}, 1); err == nil {
		t.Fatal("expected refusal for an unknown edition")
	}
	// absent edition leaves settings without the key (GCP default applies)
	req, _ = BuildCreateRequest("p", "e", "cap", base, map[string]any{"tier": "t"}, 1)
	s, _ = req.Body["settings"].(map[string]any)
	if _, has := s["edition"]; has {
		t.Fatal("edition must be absent from settings when not declared")
	}
}

// ---- network shell ----------------------------------------------------------

func testDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	clock := time.Unix(0, 0)
	d := NewDriver("acme-prod")
	d.BaseURL = srv.URL
	d.HTTP = srv.Client()
	d.PollInterval = 0
	d.PollTimeout = 100 * time.Millisecond
	d.Now = func() time.Time {
		clock = clock.Add(30 * time.Millisecond)
		return clock
	}
	d.auth.http = srv.Client()
	return d
}

func TestCreateHappyPath(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST":
				fmt.Fprint(w, `{"name":"op-123"}`)
			case r.URL.Path == "/projects/acme-prod/operations/op-123":
				if polls.Add(1) < 2 {
					fmt.Fprint(w, `{"status":"RUNNING"}`)
				} else {
					fmt.Fprint(w, `{"status":"DONE"}`)
				}
			default:
				http.NotFound(w, r)
			}
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "succeeded" || cr.OperationID != "op-123" {
		t.Errorf("got %+v", cr)
	}
}

func TestDoneWithErrorIsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				fmt.Fprint(w, `{"name":"op-err"}`)
				return
			}
			fmt.Fprint(w, `{"status":"DONE","error":{"errors":[{"code":"QUOTA_EXCEEDED"}]}}`)
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "failed" {
		t.Errorf("DONE with error must be failure, got %+v", cr)
	}
}

func TestPollTimeoutIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				fmt.Fprint(w, `{"name":"op-slow"}`)
				return
			}
			fmt.Fprint(w, `{"status":"RUNNING"}`)
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "unknown" || cr.OperationID != "op-slow" {
		t.Errorf("timeout must be unknown with the real op id, got %+v", cr)
	}
}

// DONE carrying an error object with an EMPTY errors array must still be a
// failure — not fall through to success (fail-open, adversarial review).
func TestDoneWithEmptyErrorObjectIsFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				fmt.Fprint(w, `{"name":"op-err"}`)
				return
			}
			fmt.Fprint(w, `{"status":"DONE","error":{"errors":[]}}`)
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "failed" {
		t.Errorf("DONE with a non-nil error object must be failure, got %+v", cr)
	}
}

// A 5xx on a mutating insert does NOT prove the mutation did not land — it is
// unknown (D29), routed into reconcile, never a terminal failed.
func TestInsert5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "unknown" {
		t.Errorf("a 5xx on insert must be unknown, got %+v", cr)
	}
}

// A 2xx insert with no operation name is a truncated body -> unknown, never a
// 20-minute poll of the operations LIST endpoint.
func TestInsertEmptyOpIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{}`)
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "unknown" {
		t.Errorf("an insert with no operation must be unknown, got %+v", cr)
	}
}

// A non-bool deletionProtectionEnabled must REFUSE, not collapse to false in the
// dangerous direction (adversarial review).
func TestDeleteNonBoolProtectionRefused(t *testing.T) {
	inst := `{"settings":{"userLabels":{"groundhold-capability":"orders-db",` +
		`"groundhold-environment":"production"},"deletionProtectionEnabled":"true"}}`
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, inst) // GET returns the instance; DELETE never reached
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Delete("cloudsql", "orders-db", "production",
		"acme-prod:europe-west1:orders-db-x", "k1")
	if cr.Status != "failed" || !strings.Contains(cr.Reason, "not a boolean") {
		t.Errorf("non-bool protection must refuse, got %+v", cr)
	}
}

func Test409ContinuationOnlyWithMatchingLabels(t *testing.T) {
	labels := `{"settings":{"userLabels":{"groundhold-capability":"orders-db","groundhold-environment":"production"}}}`
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "POST" {
				w.WriteHeader(http.StatusConflict)
				return
			}
			fmt.Fprint(w, labels)
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "succeeded" {
		t.Errorf("matching labels must continue idempotently, got %+v", cr)
	}

	labels = `{"settings":{"userLabels":{"team":"someone-else"}}}`
	cr = testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "failed" {
		t.Errorf("foreign instance must fail, got %+v", cr)
	}
}

func TestLostResponseIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			panic("connection dropped") // httptest turns this into a broken response
		}))
	defer srv.Close()
	cr := testDriver(t, srv).Create("cloudsql", "orders-db", "production", attrs, impl, "k1", 1)
	if cr.Status != "unknown" {
		t.Errorf("lost response after a mutating request must be unknown, got %+v", cr)
	}
}

// Discovery (D52): instances.list runs each item through the same pure
// MapInstance as Observe; region filters; providerId is canonical.
func TestListDiscoversExistingInstances(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/projects/acme-prod/instances":
				w.Write([]byte(`{"items":[
				  {"name":"legacy-db","region":"europe-central2",
				   "databaseVersion":"MYSQL_8_0",
				   "ipAddresses":[{"type":"PRIVATE","ipAddress":"10.1.2.3"}],
				   "settings":{"ipConfiguration":{"ipv4Enabled":false}}},
				  {"name":"other-region-db","region":"us-east1",
				   "databaseVersion":"POSTGRES_16"}
				]}`))
			case r.URL.Path == "/b": // GCS buckets.list
				w.Write([]byte(`{"items":[
				  {"name":"assets-bucket","location":"europe-central2"},
				  {"name":"far-bucket","location":"us-east1"}
				]}`))
			case strings.HasPrefix(r.URL.Path, "/b/"): // observeGCS buckets.get
				name := strings.TrimPrefix(r.URL.Path, "/b/")
				w.Write([]byte(`{"name":"` + name + `","location":"europe-central2"}`))
			case r.URL.Path == "/projects/acme-prod/topics": // Pub/Sub topics.list
				w.Write([]byte(`{"topics":[{"name":"projects/acme-prod/topics/alerts"}]}`))
			case strings.HasPrefix(r.URL.Path, "/projects/acme-prod/topics/"): // topics.get
				w.Write([]byte(`{"name":"` + strings.TrimPrefix(r.URL.Path, "/") + `"}`))
			case r.URL.Path == "/projects/acme-prod/subscriptions": // subscriptions.list
				w.Write([]byte(`{"subscriptions":[{"name":"projects/acme-prod/subscriptions/worker"}]}`))
			case strings.HasPrefix(r.URL.Path, "/projects/acme-prod/subscriptions/"): // subscriptions.get
				w.Write([]byte(`{"name":"` + strings.TrimPrefix(r.URL.Path, "/") + `","topic":"projects/acme-prod/topics/alerts"}`))
			case r.URL.Path == "/projects/acme-prod/locations/-/instances": // Memorystore instances.list
				w.Write([]byte(`{"instances":[{"name":"projects/acme-prod/locations/europe-central2/instances/cache"}]}`))
			case strings.Contains(r.URL.Path, "/locations/") && strings.Contains(r.URL.Path, "/instances/"): // instances.get
				w.Write([]byte(`{"name":"projects/acme-prod/locations/europe-central2/instances/cache","state":"READY"}`))
			case r.URL.Path == "/projects/acme-prod/databases": // Firestore databases.list
				w.Write([]byte(`{"databases":[{"name":"projects/acme-prod/databases/orders","locationId":"europe-central2"}]}`))
			case strings.HasPrefix(r.URL.Path, "/projects/acme-prod/databases/"): // databases.get
				w.Write([]byte(`{"name":"projects/acme-prod/databases/orders","locationId":"europe-central2","type":"FIRESTORE_NATIVE"}`))
			default:
				t.Errorf("unexpected call: %s %s", r.Method, r.URL.Path)
			}
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	d.GcsBaseURL = srv.URL
	d.PubSubBaseURL = srv.URL
	d.MemorystoreBaseURL = srv.URL
	d.FirestoreBaseURL = srv.URL

	got, _, err := d.List("europe-central2")
	if err != nil {
		t.Fatal(err)
	}
	byType := map[string][]provider.Discovered{}
	for _, g := range got {
		byType[g.ResourceType] = append(byType[g.ResourceType], g)
	}
	rel := byType["capability.database.relational"]
	if len(rel) != 1 || rel[0].ProviderID != "acme-prod:europe-central2:legacy-db" {
		t.Fatalf("relational: %+v", rel)
	}
	byPath := map[string]any{}
	for _, o := range rel[0].Observations {
		byPath[o.Path] = o.Value
	}
	if byPath["engine.protocol"] != "mysql/8.0" || byPath["network.publicExposure"] != false {
		t.Errorf("cloudsql observations: %v", byPath)
	}
	wantID := map[string]string{
		"capability.storage.object":  "gcs:acme-prod:assets-bucket",
		"capability.messaging.topic": "pubsub:acme-prod:alerts",
		"capability.messaging.queue": "pubsub:acme-prod:worker",
		"capability.cache.keyvalue":  "gredis:acme-prod:europe-central2:cache",
		"capability.database.nosql":  "firestore:acme-prod:orders",
	}
	for typ, id := range wantID {
		got := byType[typ]
		if len(got) != 1 || got[0].ProviderID != id {
			t.Fatalf("%s: %+v (want %q)", typ, got, id)
		}
	}

	all, _, err := d.List("")
	if err != nil {
		t.Fatal(err)
	}
	// 2 sql + 2 gcs + 1 topic + 1 subscription + 1 redis + 1 firestore
	// (topics/subs global; redis+firestore europe-central2 match empty too)
	if len(all) != 8 {
		t.Fatalf("empty region must match everything, got %d", len(all))
	}
}

// Reconcile (D57) is read-only and never guesses: create+404 stays
// unknown; delete+404 succeeds only via the pinned target; ownership
// labels decide a live instance.
func TestReconcileVerdicts(t *testing.T) {
	instances := map[string]string{
		"ours": `{"region":"europe-central2","settings":{"userLabels":
		  {"groundhold-capability":"db","groundhold-environment":"production"}}}`,
		"foreign": `{"region":"europe-central2","settings":{"userLabels":{}}}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			parts := strings.Split(r.URL.Path, "/")
			name := parts[len(parts)-1]
			if body, ok := instances[name]; ok {
				w.Write([]byte(body))
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
	defer srv.Close()
	d := testDriver(t, srv)

	del := d.Reconcile("db", "production", map[string]any{
		"target": "gcp.cloudsql/db", "operation": "delete",
		"targetProviderId": "acme-prod:europe-central2:gone-db"})
	if del.Status != "succeeded" ||
		del.ProviderID != "acme-prod:europe-central2:gone-db" {
		t.Errorf("delete+404: %+v", del)
	}
	delLive := d.Reconcile("db", "production", map[string]any{
		"target": "gcp.cloudsql/db", "operation": "delete",
		"targetProviderId": "acme-prod:europe-central2:ours"})
	if delLive.Status != "failed" {
		t.Errorf("delete of a live instance must conclude failed: %+v", delLive)
	}
	// create by name: not found stays unknown (never guessed)
	cr404 := d.Reconcile("db", "production", map[string]any{
		"target": "gcp.cloudsql/db", "operation": "create", "generation": 1})
	if cr404.Status != "unknown" {
		t.Errorf("create+404 must stay unknown: %+v", cr404)
	}
	// a live foreign instance under our deterministic name: failed
	instances[InstanceName("acme-prod", "production", "db", 1)] =
		instances["foreign"]
	crForeign := d.Reconcile("db", "production", map[string]any{
		"target": "gcp.cloudsql/db", "operation": "create", "generation": 1})
	if crForeign.Status != "failed" {
		t.Errorf("foreign labels must conclude failed: %+v", crForeign)
	}
	// same name, our labels: succeeded with canonical providerId
	instances[InstanceName("acme-prod", "production", "db", 1)] =
		instances["ours"]
	crOurs := d.Reconcile("db", "production", map[string]any{
		"target": "gcp.cloudsql/db", "operation": "create", "generation": 1})
	want := "acme-prod:europe-central2:" +
		InstanceName("acme-prod", "production", "db", 1)
	if crOurs.Status != "succeeded" || crOurs.ProviderID != want {
		t.Errorf("ours must succeed with canonical id: %+v", crOurs)
	}
}

// D72: a lost UPDATE concludes by MEASURING the pinned desired values
// against the live reverse mapping. All-equal -> succeeded; any
// mismatch or unobservable path stays unknown (patch may be in flight),
// never guessed. Also pins the cross-project safety: measurement uses
// the ownership-validated project, not the receipt's project component.
func TestReconcileUpdateByValues(t *testing.T) {
	label := `"userLabels":{"groundhold-capability":"db","groundhold-environment":"production"}`
	regional := `{"region":"europe-central2","settings":{"availabilityType":"REGIONAL",` + label + `}}`
	zonal := `{"region":"europe-central2","settings":{"availabilityType":"ZONAL",` + label + `}}`
	body := regional
	seenProjects := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/projects/victim-project/") {
				seenProjects["victim-project"] = true
			}
			if !strings.Contains(r.URL.Path, "/projects/acme-prod/") {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			seenProjects["acme-prod"] = true
			w.Write([]byte(body))
		}))
	defer srv.Close()
	d := testDriver(t, srv)

	receipt := func(pid string) map[string]any {
		return map[string]any{"operation": "update",
			"target":           "gcp.cloudsql/db", // D76: reconciler dispatches on it
			"targetProviderId": pid,
			"changes": []any{map[string]any{
				"path": "availability.class", "to": "regional"}}}
	}
	// desired value matches the live instance -> succeeded
	body = regional
	ok := d.Reconcile("db", "production",
		receipt("acme-prod:europe-central2:db-x"))
	if ok.Status != "succeeded" {
		t.Errorf("matching update must conclude succeeded: %+v", ok)
	}
	// live instance not yet at the desired value -> unknown (in flight)
	body = zonal
	pending := d.Reconcile("db", "production",
		receipt("acme-prod:europe-central2:db-x"))
	if pending.Status != "unknown" {
		t.Errorf("mismatched update must stay unknown: %+v", pending)
	}
	// a forged receipt naming a DIFFERENT project must NOT redirect any
	// request to that project — the driver forces its own project for
	// both ownership and measurement, neutralizing the forgery.
	body = regional
	seenProjects = map[string]bool{}
	d.Reconcile("db", "production",
		receipt("victim-project:europe-central2:db-x"))
	if seenProjects["victim-project"] {
		t.Error("forged receipt redirected a request to victim-project — " +
			"cross-project confusion")
	}
	if !seenProjects["acme-prod"] {
		t.Error("measurement did not use the driver's own project")
	}
}

// D65: the GCP Prober. Exposure by ACTUAL handshake; RTO by a timed
// restore into a deterministic scratch, cleaned up loudly.
func TestProbeExposureVerdicts(t *testing.T) {
	instances := map[string]string{
		"public-db": `{"databaseVersion":"MYSQL_8_0",
		  "ipAddresses":[{"type":"PRIMARY","ipAddress":"203.0.113.7"}],
		  "settings":{"tier":"db-f1-micro"}}`,
		"private-db": `{"databaseVersion":"MYSQL_8_0",
		  "ipAddresses":[{"type":"PRIVATE","ipAddress":"10.0.0.7"}],
		  "settings":{"tier":"db-f1-micro"}}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			parts := strings.Split(r.URL.Path, "/")
			if body, ok := instances[parts[len(parts)-1]]; ok {
				w.Write([]byte(body))
				return
			}
			http.NotFound(w, r)
		}))
	defer srv.Close()

	d := testDriver(t, srv)
	d.Dial = func(network, addr string,
		timeout time.Duration) (net.Conn, error) {
		if addr == "203.0.113.7:3306" {
			c, s := net.Pipe()
			go s.Close()
			return c, nil
		}
		return nil, fmt.Errorf("refused")
	}

	pub, err := d.Probe("cloudsql", "db", "acme-prod:europe-central2:public-db", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub.Measurements) != 1 || pub.Measurements[0].Value != true {
		t.Errorf("handshake success must measure exposure true: %+v", pub)
	}

	priv, err := d.Probe("cloudsql", "db", "acme-prod:europe-central2:private-db", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv.Measurements) != 1 || priv.Measurements[0].Value != false {
		t.Errorf("no public address must measure false: %+v", priv)
	}

	// allocated address, dead handshake: CANNOT conclude — a failure
	d.Dial = func(network, addr string,
		timeout time.Duration) (net.Conn, error) {
		return nil, fmt.Errorf("timeout")
	}
	filt, err := d.Probe("cloudsql", "db", "acme-prod:europe-central2:public-db", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(filt.Measurements) != 0 || len(filt.Failures) != 1 {
		t.Errorf("filtered handshake must be a failure, not a value: %+v",
			filt)
	}
}

func TestProbeRTORestoreTest(t *testing.T) {
	var deleted atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/projects/acme-prod/instances/source-db/backupRuns",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"items":[{"id":"bk-42","status":"SUCCESSFUL"}]}`)
		})
	mux.HandleFunc("/projects/acme-prod/instances/source-db",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"databaseVersion":"POSTGRES_16",
			  "ipAddresses":[],"settings":{"tier":"db-custom-2-8192",
			  "userLabels":{"groundhold-capability":"db"}}}`)
		})
	mux.HandleFunc("/projects/acme-prod/instances",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"name":"op-create"}`)
		})
	mux.HandleFunc("/projects/acme-prod/operations/op-create",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"status":"DONE"}`)
		})
	mux.HandleFunc("/projects/acme-prod/operations/op-restore",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"status":"DONE"}`)
		})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/restoreBackup"):
			fmt.Fprint(w, `{"name":"op-restore"}`)
		case r.Method == "DELETE":
			deleted.Store(true)
			fmt.Fprint(w, `{"name":"op-del"}`)
		default:
			http.NotFound(w, r)
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	d := testDriver(t, srv) // injected clock: +30ms per Now() call
	out, err := d.Probe("cloudsql", "db", "acme-prod:europe-central2:source-db", true)
	if err != nil {
		t.Fatal(err)
	}
	var rto *string
	for _, m := range out.Measurements {
		if m.Path == "recovery.rto" {
			v, _ := m.Value.(string)
			rto = &v
			if !m.Intrusive {
				t.Error("restore-test must be marked intrusive")
			}
		}
	}
	if rto == nil {
		t.Fatalf("no rto measurement: %+v", out)
	}
	if *rto != "1m" { // sub-minute elapsed rounds UP, never down
		t.Errorf("rto: %s (want 1m)", *rto)
	}
	if !deleted.Load() {
		t.Error("scratch instance was not deleted")
	}
	for _, f := range out.Failures {
		t.Errorf("unexpected failure: %+v", f)
	}
}

func TestProbeRTONoBackupIsFailureNotValue(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/projects/acme-prod/instances/source-db/backupRuns",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"items":[]}`)
		})
	mux.HandleFunc("/projects/acme-prod/instances/source-db",
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"databaseVersion":"POSTGRES_16",
			  "ipAddresses":[],"settings":{"tier":"t",
			  "userLabels":{"groundhold-capability":"db"}}}`)
		})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	out, err := testDriver(t, srv).Probe("cloudsql", "db",
		"acme-prod:europe-central2:source-db", true)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range out.Measurements {
		if m.Path == "recovery.rto" {
			t.Fatalf("rto fabricated without a restore: %+v", m)
		}
	}
	found := false
	for _, f := range out.Failures {
		if f.Path == "recovery.rto" &&
			strings.Contains(f.Reason, "no successful backup") {
			found = true
		}
	}
	if !found {
		t.Errorf("missing no-backup failure: %+v", out.Failures)
	}
}
