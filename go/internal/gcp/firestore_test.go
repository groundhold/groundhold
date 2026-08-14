package gcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func firestoreAttrs() map[string]any {
	return map[string]any{
		"location.region":                "europe-west1",
		"availability.class":             "regional",
		"encryption.customerManagedKeys": true,
		"backup.pointInTimeRecovery":     true,
		"deletion.protection":            false,
		"service.managed":                true,
	}
}

func firestoreImpl() map[string]any {
	return map[string]any{"kms_key_name": "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k"}
}

func TestBuildFirestoreHonors(t *testing.T) {
	a := firestoreAttrs()
	a["deletion.protection"] = true
	p, err := BuildFirestoreCreate("acme-prod", "prod", "sessions", a, firestoreImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.Location != "europe-west1" || !p.PITR || !p.DeletionProtection || p.KmsKey == "" {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody()
	if body["pointInTimeRecoveryEnablement"] != "POINT_IN_TIME_RECOVERY_ENABLED" ||
		body["deleteProtectionState"] != "DELETE_PROTECTION_ENABLED" || body["cmekConfig"] == nil {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildFirestoreRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"multi-regional": {"availability.class": "multi-regional"},
		"bad-avail":      {"availability.class": "planetary"},
		"unmanaged":      {"service.managed": false},
		"unknown-attr":   {"nosql.tier": "x"},
	}
	for name, extra := range cases {
		a := firestoreAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildFirestoreCreate("acme-prod", "prod", "sessions", a, firestoreImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := firestoreAttrs()
	delete(a, "location.region")
	if _, err := BuildFirestoreCreate("acme-prod", "prod", "sessions", a, firestoreImpl(), 1); err == nil {
		t.Error("missing location.region must refuse")
	}
}

func firestoreServer(t *testing.T, loc string, pitr, delProt bool, kms string) *httptest.Server {
	t.Helper()
	pitrState := "POINT_IN_TIME_RECOVERY_DISABLED"
	if pitr {
		pitrState = "POINT_IN_TIME_RECOVERY_ENABLED"
	}
	delState := "DELETE_PROTECTION_DISABLED"
	if delProt {
		delState = "DELETE_PROTECTION_ENABLED"
	}
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "databaseId="):
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/operations/op1"}`))
			case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
				_, _ = w.Write([]byte(`{"done":true}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/operations/opdel"}`))
			case r.Method == "GET":
				cmek := ""
				if kms != "" {
					cmek = `,"cmekConfig":{"kmsKeyName":"` + kms + `"}`
				}
				_, _ = w.Write([]byte(`{"name":"projects/acme-prod/databases/x","locationId":"` + loc +
					`","type":"FIRESTORE_NATIVE","pointInTimeRecoveryEnablement":"` + pitrState +
					`","deleteProtectionState":"` + delState + `"` + cmek + `}`))
			default:
				w.WriteHeader(404)
			}
		}))
}

func firestoreDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("GROUNDHOLD_GCP_ACCESS_TOKEN", "test-token")
	d := NewDriver("acme-prod")
	d.FirestoreBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteFirestore(t *testing.T) {
	srv := firestoreServer(t, "europe-west1", true, false, "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k")
	defer srv.Close()
	d := firestoreDriver(t, srv)
	res := d.createFirestore("prod", "sessions", firestoreAttrs(), firestoreImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "firestore:acme-prod:") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeFirestore("sessions", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "europe-west1" || got["backup.pointInTimeRecovery"] != true ||
		got["deletion.protection"] != false || got["encryption.customerManagedKeys"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteFirestore("sessions", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteFirestoreProtectedRefused(t *testing.T) {
	srv := firestoreServer(t, "europe-west1", false, true, "") // delete protection ON
	defer srv.Close()
	d := firestoreDriver(t, srv)
	pid := firestoreProviderID("acme-prod", FirestoreDatabaseID("acme-prod", "prod", "sessions", 1))
	res := d.deleteFirestore("sessions", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "delete protection") {
		t.Fatalf("protected database must refuse delete, got %+v", res)
	}
}

func TestDeleteFirestoreForeignRefused(t *testing.T) {
	srv := firestoreServer(t, "europe-west1", false, false, "")
	defer srv.Close()
	d := firestoreDriver(t, srv)
	// a databaseId our naming scheme could never have produced for (sessions, prod).
	res := d.deleteFirestore("sessions", "prod", "firestore:acme-prod:foreign-db-00000000")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign database must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.database.nosql on GCP Firestore. A STATEFUL fake records the PITR,
// delete-protection and CMEK the create writes and reflects them on the read.
func TestMetamorphicFirestoreRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		pitr    bool
		delProt bool
		cmek    bool
	}{
		{"bare", false, false, false},
		{"full", true, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var pitr, delProt, kms string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && strings.Contains(r.URL.RawQuery, "databaseId="):
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							PointInTimeRecoveryEnablement string `json:"pointInTimeRecoveryEnablement"`
							DeleteProtectionState         string `json:"deleteProtectionState"`
							CmekConfig                    *struct {
								KmsKeyName string `json:"kmsKeyName"`
							} `json:"cmekConfig"`
						}
						_ = json.Unmarshal(body, &doc)
						pitr, delProt = doc.PointInTimeRecoveryEnablement, doc.DeleteProtectionState
						if doc.CmekConfig != nil {
							kms = doc.CmekConfig.KmsKeyName
						}
						_, _ = w.Write([]byte(`{"name":"projects/acme-prod/operations/op1"}`))
					case r.Method == "GET" && strings.Contains(r.URL.Path, "/operations/"):
						_, _ = w.Write([]byte(`{"done":true}`))
					case r.Method == "GET":
						cmek := ""
						if kms != "" {
							cmek = `,"cmekConfig":{"kmsKeyName":"` + kms + `"}`
						}
						_, _ = w.Write([]byte(`{"locationId":"europe-west1","pointInTimeRecoveryEnablement":"` + pitr +
							`","deleteProtectionState":"` + delProt + `"` + cmek + `}`))
					default:
						w.WriteHeader(404)
					}
				}))
			defer srv.Close()
			d := firestoreDriver(t, srv)
			a := firestoreAttrs()
			a["backup.pointInTimeRecovery"] = c.pitr
			a["deletion.protection"] = c.delProt
			impl := map[string]any{}
			if c.cmek {
				a["encryption.customerManagedKeys"] = true
				impl["kms_key_name"] = "projects/acme-prod/locations/europe-west1/keyRings/r/cryptoKeys/k"
			} else {
				a["encryption.customerManagedKeys"] = false
			}
			res := d.createFirestore("prod", "sessions", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeFirestore("sessions", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["backup.pointInTimeRecovery"] != c.pitr {
				t.Errorf("pitr round-trip: want %v got %v", c.pitr, got["backup.pointInTimeRecovery"])
			}
			if got["deletion.protection"] != c.delProt {
				t.Errorf("delProt round-trip: want %v got %v", c.delProt, got["deletion.protection"])
			}
			// D1003: no key is a measured false, not an absence.
			if got["encryption.customerManagedKeys"] != c.cmek {
				t.Errorf("cmek round-trip: want %v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}

// D799. A Firestore database can live in a MULTI-REGION (nam5, eur3), and the driver
// reported that identifier as location.region while calling "regional" an invariant of
// the platform. Both wrong, and together they let a residency constraint compare against
// a name that stands for several regions at once.
func TestFirestoreMultiRegionIsNotCalledRegional(t *testing.T) {
	for _, loc := range []string{"nam5", "eur3"} {
		if got := firestoreAvailability(loc); got != "multi-regional" {
			t.Errorf("location %q reported as %q", loc, got)
		}
	}
	for _, loc := range []string{"europe-west1", "us-central1", "asia-northeast3"} {
		if got := firestoreAvailability(loc); got != "regional" {
			t.Errorf("region %q reported as %q", loc, got)
		}
	}
}

// D1043: the shared multi-region residency guard. A single region does not diagnose;
// a multi-region (US, EU, ASIA, nam5, eur3) does — else a residency constraint compares
// against a name standing for several regions and can pass over data resident elsewhere.
func TestResidencyMultiRegionDiag(t *testing.T) {
	for _, r := range []string{"europe-west1", "us-central1", "asia-southeast1", ""} {
		if d := residencyMultiRegionDiag(r, "x"); d != "" {
			t.Errorf("%q is a single region (or empty) and must NOT diagnose, got: %q", r, d)
		}
	}
	for _, m := range []string{"US", "EU", "ASIA", "nam5", "eur3"} {
		if residencyMultiRegionDiag(m, "bucket") == "" {
			t.Errorf("%q is a MULTI-REGION and must diagnose", m)
		}
	}
}
