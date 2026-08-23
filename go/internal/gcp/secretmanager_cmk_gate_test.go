package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D1238. Two defects met in one branch.
//
// The customer-key question rode on the RESIDENCY branch: only a single-replica
// user-managed secret got `encryption.customerManagedKeys`, and the else-branch
// diagnosed the missing REGION while saying nothing about the missing key. So an
// automatic or multi-replica secret withheld a security attribute with a reason that
// was about something else — the D1226 shape, where a withholding is explained by a
// cause that does not cover it.
//
// And the reason it was withheld was not true. The driver's comment said the automatic
// shape "does NOT read CMK", and the doc struct modelled `automatic` as an EMPTY
// object. The API defines `Automatic.customerManagedEncryption`, exactly like a
// per-replica one. A secret with automatic replication AND a customer key therefore
// reported nothing, on an encryption attribute.
//
// `true` now means EVERY copy is customer-keyed — the weakest-across-the-set rule this
// codebase applies to encryption elsewhere. A half-keyed secret is not a
// customer-managed secret, and the diagnostic says which fraction is.

func secretCMKObserve(t *testing.T, replication string) (map[string]any, []string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			_, _ = w.Write([]byte(`{"bindings":[]}`))
		default:
			_, _ = w.Write([]byte(`{"name":"projects/acme-prod/secrets/gh","replication":` +
				replication + `}`))
		}
	}))
	defer srv.Close()
	d := secretDriver(t, srv)
	obs, diags, err := d.observeSecret("dbcreds", gsecretProviderID("acme-prod", "gh"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	return got, diags
}

const cmkPath = "encryption.customerManagedKeys"

// The defect itself: automatic replication WITH a customer key reported nothing.
func TestAutomaticReplicationWithACustomerKeyIsMeasuredTrue(t *testing.T) {
	got, diags := secretCMKObserve(t,
		`{"automatic":{"customerManagedEncryption":{"kmsKeyName":"projects/p/locations/l/keyRings/r/cryptoKeys/k"}}}`)
	if got[cmkPath] != true {
		t.Fatalf("the API carries automatic.customerManagedEncryption — a keyed secret must "+
			"measure true, got %v (diags %v)", got[cmkPath], diags)
	}
}

// ...and automatic replication WITHOUT one is a measured FALSE, not an absence: a
// readable no is an answer, and withholding would let a hard constraint pass vacuously.
func TestAutomaticReplicationWithoutAKeyIsMeasuredFalse(t *testing.T) {
	got, _ := secretCMKObserve(t, `{"automatic":{}}`)
	v, present := got[cmkPath]
	if !present {
		t.Fatalf("automatic replication is readable, so no key is a measured false")
	}
	if v != false {
		t.Fatalf("%s = %v, want false", cmkPath, v)
	}
}

// Multi-replica, every copy keyed: true. This shape used to withhold entirely.
func TestEveryReplicaKeyedIsMeasuredTrue(t *testing.T) {
	got, _ := secretCMKObserve(t, `{"userManaged":{"replicas":[`+
		`{"location":"europe-west1","customerManagedEncryption":{"kmsKeyName":"k1"}},`+
		`{"location":"europe-west4","customerManagedEncryption":{"kmsKeyName":"k2"}}]}}`)
	if got[cmkPath] != true {
		t.Fatalf("every replica keyed means the secret is customer-managed, got %v", got[cmkPath])
	}
}

// Mixed: false, and the diagnostic says which fraction — otherwise "false" hides that
// some copies ARE keyed and the reader cannot tell a half-migration from a fresh one.
func TestPartlyKeyedRepliasAreFalseAndSayWhichFraction(t *testing.T) {
	got, diags := secretCMKObserve(t, `{"userManaged":{"replicas":[`+
		`{"location":"europe-west1","customerManagedEncryption":{"kmsKeyName":"k1"}},`+
		`{"location":"europe-west4"}]}}`)
	if got[cmkPath] != false {
		t.Fatalf("a half-keyed secret is not customer-managed, got %v", got[cmkPath])
	}
	var told bool
	for _, d := range diags {
		if strings.Contains(d, "1 of 2 replicas") {
			told = true
		}
	}
	if !told {
		t.Fatalf("the diagnostic must say which fraction is keyed: %v", diags)
	}
}

// Neither shape present: the read cannot answer, and says so about the KEY rather than
// only about the region — which is the branch-sharing defect this entry started from.
func TestNoReplicationShapeWithholdsTheKeyWithItsOwnReason(t *testing.T) {
	got, diags := secretCMKObserve(t, `{}`)
	if _, present := got[cmkPath]; present {
		t.Fatalf("with no replication shape there is no replica whose key could be read")
	}
	var told bool
	for _, d := range diags {
		if strings.Contains(d, cmkPath+" not observed") {
			told = true
		}
	}
	if !told {
		t.Fatalf("the key must be withheld with a reason ABOUT THE KEY, not only a region "+
			"diagnostic: %v", diags)
	}
}

// The residency answer must not have moved: it is a different question and stays on
// its own branch (single user-managed replica only).
func TestResidencyStillOnlyFromASingleUserManagedReplica(t *testing.T) {
	got, _ := secretCMKObserve(t, `{"userManaged":{"replicas":[`+
		`{"location":"europe-west1","customerManagedEncryption":{"kmsKeyName":"k1"}}]}}`)
	if got["location.region"] != "europe-west1" {
		t.Fatalf("location.region = %v, want europe-west1", got["location.region"])
	}
	got, _ = secretCMKObserve(t, `{"automatic":{}}`)
	if v, present := got["location.region"]; present {
		t.Fatalf("automatic replication carries no single-region guarantee, got %v", v)
	}
}
