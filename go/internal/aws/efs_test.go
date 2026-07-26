package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func efsAttrs() map[string]any {
	return map[string]any{
		"location.region":    "eu-central-1",
		"protocol":           "nfs/4.1",
		"availability.class": "regional",
		"encryption.atRest":  true,
		"service.managed":    true,
	}
}

func efsImpl() map[string]any { return map[string]any{} }

func TestBuildEFSHonors(t *testing.T) {
	a := efsAttrs()
	a["encryption.customerManagedKeys"] = true
	p, err := BuildEFSCreate("prod", "shared", a,
		map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Encrypted || p.KmsKeyId == "" || p.OneZone || !strings.HasPrefix(p.CreationToken, "groundhold-") {
		t.Fatalf("plan = %+v", p)
	}
	body := p.createBody("shared", "prod")
	if body["KmsKeyId"] == nil || body["CreationToken"] == "" {
		t.Fatalf("body = %+v", body)
	}
}

func TestBuildEFSZonalNeedsAZ(t *testing.T) {
	a := efsAttrs()
	a["availability.class"] = "zonal"
	if _, err := BuildEFSCreate("prod", "shared", a, nil, 1); err == nil {
		t.Fatal("zonal without impl.availability_zone must refuse")
	}
	p, err := BuildEFSCreate("prod", "shared", a, map[string]any{"availability_zone": "eu-central-1a"}, 1)
	if err != nil || !p.OneZone || p.AvailabilityZone != "eu-central-1a" {
		t.Fatalf("zonal plan = %+v err=%v", p, err)
	}
}

func TestBuildEFSRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"smb-refused":  {"protocol": "smb/3"},        // SMB is FSx, not EFS
		"atrest-false": {"encryption.atRest": false}, // always encrypted
		"unmanaged":    {"service.managed": false},
		"bad-avail":    {"availability.class": "planetary"},
		"unknown-attr": {"filesystem.tier": "x"},
	}
	for name, extra := range cases {
		a := efsAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildEFSCreate("prod", "shared", a, nil, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := efsAttrs()
	a["encryption.customerManagedKeys"] = true
	if _, err := BuildEFSCreate("prod", "shared", a, nil, 1); err == nil {
		t.Error("cmek without impl.kms_key_id must refuse")
	}
}

// efsServer is a happy server: create returns a fixed fs id, describe reflects
// an owned available fs, tags report ownership, delete 204.
func efsServer(t *testing.T, capLabel, kms, az string) *httptest.Server {
	t.Helper()
	const fsID = "fs-0123456789abcdef0"
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == "POST" && r.URL.Path == efsPath+"/file-systems":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"FileSystemId":"` + fsID + `","LifeCycleState":"available"}`))
			case r.Method == "GET" && strings.HasPrefix(r.URL.Path, efsPath+"/resource-tags/"):
				_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"` + capLabel +
					`"},{"Key":"groundhold-environment","Value":"prod"}]}`))
			case r.Method == "GET" && r.URL.Path == efsPath+"/file-systems":
				fs := map[string]any{"FileSystemId": fsID, "LifeCycleState": "available", "Encrypted": true}
				if kms != "" {
					fs["KmsKeyId"] = kms
				}
				if az != "" {
					fs["AvailabilityZoneName"] = az
				}
				b, _ := json.Marshal(map[string]any{"FileSystems": []any{fs}})
				_, _ = w.Write(b)
			case r.Method == "DELETE":
				w.WriteHeader(204)
			default:
				w.WriteHeader(404)
			}
		}))
}

func efsDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.EFSBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteEFS(t *testing.T) {
	srv := efsServer(t, "shared", "arn:aws:kms:eu-central-1:000000000000:key/abc", "")
	defer srv.Close()
	d := efsDriver(t, srv)
	res := d.createEFS("eu-central-1", "000000000000", "prod", "shared", efsAttrs(), efsImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "efs:eu-central-1:000000000000:fs-") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeEFS("shared", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" || got["availability.class"] != "regional" ||
		got["encryption.customerManagedKeys"] != true || got["protocol"] != "nfs/4.1" {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteEFS("shared", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteEFSForeignRefused(t *testing.T) {
	srv := efsServer(t, "someone-else", "", "")
	defer srv.Close()
	d := efsDriver(t, srv)
	res := d.deleteEFS("shared", "prod", "efs:eu-central-1:000000000000:fs-0123456789abcdef0")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign fs must refuse delete, got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.storage.filesystem on AWS EFS. A STATEFUL fake records the KmsKeyId
// and AvailabilityZoneName createEFS writes and reflects them on the describe
// read; the test varies (availability, cmek) and asserts observe reverse-maps
// what create was given.
func TestMetamorphicEFSRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		zonal     bool
		cmek      bool
		wantAvail string
	}{
		{"regional-nocmek", false, false, "regional"},
		{"zonal-cmek", true, true, "zonal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const fsID = "fs-0123456789abcdef0"
			var kms, az string
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.Method == "POST" && r.URL.Path == efsPath+"/file-systems":
						body, _ := io.ReadAll(r.Body)
						var doc struct {
							KmsKeyId             string `json:"KmsKeyId"`
							AvailabilityZoneName string `json:"AvailabilityZoneName"`
						}
						_ = json.Unmarshal(body, &doc)
						kms, az = doc.KmsKeyId, doc.AvailabilityZoneName
						w.WriteHeader(201)
						_, _ = w.Write([]byte(`{"FileSystemId":"` + fsID + `","LifeCycleState":"available"}`))
					case r.Method == "GET" && r.URL.Path == efsPath+"/file-systems":
						fs := map[string]any{"FileSystemId": fsID, "LifeCycleState": "available", "Encrypted": true}
						if kms != "" {
							fs["KmsKeyId"] = kms
						}
						if az != "" {
							fs["AvailabilityZoneName"] = az
						}
						b, _ := json.Marshal(map[string]any{"FileSystems": []any{fs}})
						_, _ = w.Write(b)
					default:
						w.WriteHeader(404)
					}
				}))
			defer srv.Close()
			d := efsDriver(t, srv)
			a := efsAttrs()
			impl := map[string]any{}
			if c.zonal {
				a["availability.class"] = "zonal"
				impl["availability_zone"] = "eu-central-1a"
			}
			if c.cmek {
				a["encryption.customerManagedKeys"] = true
				impl["kms_key_id"] = "arn:aws:kms:eu-central-1:000000000000:key/abc"
			}
			res := d.createEFS("eu-central-1", "000000000000", "prod", "shared", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeEFS("shared", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			if got["availability.class"] != c.wantAvail {
				t.Errorf("availability round-trip: want %q got %v", c.wantAvail, got["availability.class"])
			}
			if _, has := got["encryption.customerManagedKeys"]; has != c.cmek {
				t.Errorf("cmek round-trip: want present=%v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}
