package aws

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func readJSON(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func kinesisAttrs() map[string]any {
	return map[string]any{
		"location.region":                "eu-central-1",
		"retention.window":               "168h",
		"availability.class":             "regional",
		"encryption.customerManagedKeys": true,
		"service.managed":                true,
	}
}

func kinesisImpl() map[string]any {
	return map[string]any{"kms_key_id": "arn:aws:kms:eu-central-1:000000000000:key/abc"}
}

func TestBuildKinesisHonors(t *testing.T) {
	p, err := BuildKinesis("prod", "events", kinesisAttrs(), kinesisImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if p.RetentionHours != 168 || !p.CMEK || p.KmsKeyId == "" {
		t.Fatalf("plan = %+v", p)
	}
}

func TestBuildKinesisRefusals(t *testing.T) {
	cases := map[string]map[string]any{
		"zonal-refused": {"availability.class": "zonal"}, // Kinesis is always regional
		"bad-avail":     {"availability.class": "planetary"},
		"short-retain":  {"retention.window": "1h"},     // below the 24h floor
		"long-retain":   {"retention.window": "10000h"}, // above the 8760h ceiling
		"unmanaged":     {"service.managed": false},
		"unknown-attr":  {"stream.tier": "x"},
	}
	for name, extra := range cases {
		a := kinesisAttrs()
		for k, v := range extra {
			a[k] = v
		}
		if _, err := BuildKinesis("prod", "events", a, kinesisImpl(), 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
	a := kinesisAttrs()
	if _, err := BuildKinesis("prod", "events", a, nil, 1); err == nil {
		t.Error("cmek without impl.kms_key_id must refuse")
	}
}

func kinesisTarget2(r *http.Request) string {
	full := r.Header.Get("X-Amz-Target")
	return full[strings.LastIndex(full, ".")+1:]
}

func kinesisServer(t *testing.T, capLabel string, retentionHours int, cmek bool) *httptest.Server {
	t.Helper()
	deleted := false
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch kinesisTarget2(r) {
			case "CreateStream":
				w.WriteHeader(200)
			case "DescribeStreamSummary":
				if deleted {
					// the stream has finished deleting — the delete's poll-to-absence (D979)
					// confirms gone.
					w.WriteHeader(400)
					_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","message":"gone"}`))
					return
				}
				enc := `"NONE"`
				kid := ""
				if cmek {
					enc = `"KMS"`
					kid = `,"KeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc"`
				}
				_, _ = w.Write([]byte(`{"StreamDescriptionSummary":{"StreamStatus":"ACTIVE","StreamARN":"arn:aws:kinesis:eu-central-1:000000000000:stream/s",` +
					`"RetentionPeriodHours":` + itoaK(retentionHours) + `,"EncryptionType":` + enc + kid + `}}`))
			case "ListTagsForStream":
				_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"` + capLabel + `"},{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "AddTagsToStream", "IncreaseStreamRetentionPeriod", "StartStreamEncryption":
				w.WriteHeader(200)
			case "DeleteStream":
				deleted = true
				w.WriteHeader(200)
			default:
				w.WriteHeader(400)
			}
		}))
}

func itoaK(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func kinesisDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.KinesisBaseURL = srv.URL
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteKinesis(t *testing.T) {
	srv := kinesisServer(t, "events", 168, true)
	defer srv.Close()
	d := kinesisDriver(t, srv)
	res := d.createKinesis("eu-central-1", "000000000000", "prod", "events", kinesisAttrs(), kinesisImpl(), 1)
	if res.Status != "succeeded" || !strings.HasPrefix(res.ProviderID, "kinesis:eu-central-1:000000000000:pv-") {
		t.Fatalf("create: %+v", res)
	}
	obs, _, err := d.observeKinesis("events", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["location.region"] != "eu-central-1" || got["retention.window"] != "168h" ||
		got["availability.class"] != "regional" || got["encryption.customerManagedKeys"] != true {
		t.Fatalf("observe: %+v", got)
	}
	if del := d.deleteKinesis("events", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestDeleteKinesisForeignRefused(t *testing.T) {
	srv := kinesisServer(t, "someone-else", 24, false)
	defer srv.Close()
	d := kinesisDriver(t, srv)
	pid := kinesisProviderID("eu-central-1", "000000000000", KinesisStreamName("prod", "events", 1))
	res := d.deleteKinesis("events", "prod", pid)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign stream must refuse delete, got %+v", res)
	}
}

// TestDeleteKinesisAsyncNotGoneIsUnknown pins D979: a stream delete the provider
// ACCEPTS but that stays present (DELETING, not gone) must report unknown — never a
// terminal "succeeded" that tombstones a data-bearing stream still live.
func TestDeleteKinesisAsyncNotGoneIsUnknown(t *testing.T) {
	// a server that owns the stream, accepts DeleteStream, but never lets the stream
	// leave ACTIVE (the async delete stalls).
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch kinesisTarget2(r) {
			case "DescribeStreamSummary": // never gone
				_, _ = w.Write([]byte(`{"StreamDescriptionSummary":{"StreamStatus":"ACTIVE",` +
					`"StreamARN":"arn:aws:kinesis:eu-central-1:000000000000:stream/s","RetentionPeriodHours":24,"EncryptionType":"NONE"}}`))
			case "ListTagsForStream":
				_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"events"},{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "DeleteStream":
				w.WriteHeader(200)
			default:
				w.WriteHeader(400)
			}
		}))
	defer srv.Close()
	d := kinesisDriver(t, srv)
	d.PollTimeout = 5 * time.Millisecond // the stream never leaves ACTIVE → times out fast
	pid := kinesisProviderID("eu-central-1", "000000000000", KinesisStreamName("prod", "events", 1))
	res := d.deleteKinesis("events", "prod", pid)
	if res.Status != "unknown" {
		t.Fatalf("an accepted-but-still-deleting stream must be unknown (keep the handle), got %+v", res)
	}
}

// Weapon 2 (D87), the metamorphic write/read round-trip for
// capability.streaming.pipe on AWS Kinesis. A STATEFUL fake records the retention
// (IncreaseStreamRetentionPeriod) and CMK (StartStreamEncryption) the create
// applies and reflects them on the summary read.
func TestMetamorphicKinesisRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		retention string
		wantHours int
		cmek      bool
	}{
		{"default-nocmek", "24h", 24, false},
		{"long-cmek", "168h", 168, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			retentionHours := 24
			cmek := false
			srv := httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch kinesisTarget2(r) {
					case "CreateStream", "AddTagsToStream":
						w.WriteHeader(200)
					case "IncreaseStreamRetentionPeriod":
						body := readJSON(r)
						if v, ok := body["RetentionPeriodHours"].(float64); ok {
							retentionHours = int(v)
						}
						w.WriteHeader(200)
					case "StartStreamEncryption":
						cmek = true
						w.WriteHeader(200)
					case "DescribeStreamSummary":
						enc := `"NONE"`
						kid := ""
						if cmek {
							enc = `"KMS"`
							kid = `,"KeyId":"arn:aws:kms:x:y:key/z"`
						}
						_, _ = w.Write([]byte(`{"StreamDescriptionSummary":{"StreamStatus":"ACTIVE",` +
							`"RetentionPeriodHours":` + itoaK(retentionHours) + `,"EncryptionType":` + enc + kid + `}}`))
					default:
						w.WriteHeader(200)
					}
				}))
			defer srv.Close()
			d := kinesisDriver(t, srv)
			a := kinesisAttrs()
			a["retention.window"] = c.retention
			impl := map[string]any{}
			if c.cmek {
				impl["kms_key_id"] = "arn:aws:kms:x:y:key/z"
			} else {
				a["encryption.customerManagedKeys"] = false
			}
			res := d.createKinesis("eu-central-1", "000000000000", "prod", "events", a, impl, 1)
			if res.Status != "succeeded" {
				t.Fatalf("create: %+v", res)
			}
			obs, _, err := d.observeKinesis("events", res.ProviderID)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]any{}
			for _, o := range obs {
				got[o.Path] = o.Value
			}
			wantWindow := itoaK(c.wantHours) + "h"
			if got["retention.window"] != wantWindow {
				t.Errorf("retention round-trip: want %q got %v", wantWindow, got["retention.window"])
			}
			if got["encryption.customerManagedKeys"] != c.cmek {
				t.Errorf("cmek round-trip: want %v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}

func kinesisRole(req *http.Request, _ []byte) certifynet.Role {
	switch kinesisTarget2(req) {
	case "DescribeStreamSummary", "ListTagsForStream", "ListStreams":
		return certifynet.RoleRead
	}
	return certifynet.RoleMutateOpaque
}

// TestAdoptsExistingKinesis enrols kinesis in the D391 gate. The stream name is
// deterministic, a second CreateStream is answered ResourceInUseException, and the tags
// decide whether it is ours to bind.
func TestAdoptsExistingKinesis(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	p := &certifynet.ExistingProbe{
		Name:     "aws/kinesis",
		Classify: kinesisRole,
		ExistingServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(
				func(w http.ResponseWriter, r *http.Request) {
					switch kinesisTarget2(r) {
					case "CreateStream":
						w.WriteHeader(400)
						_, _ = w.Write([]byte(`{"__type":"ResourceInUseException","message":"exists"}`))
					case "DescribeStreamSummary":
						_, _ = w.Write([]byte(`{"StreamDescriptionSummary":{"StreamStatus":"ACTIVE",` +
							`"StreamARN":"arn:aws:kinesis:eu-central-1:000000000000:stream/s",` +
							`"RetentionPeriodHours":24,"EncryptionType":"KMS",` +
							`"KeyId":"arn:aws:kms:eu-central-1:000000000000:key/abc"}}`))
					case "ListTagsForStream":
						_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"events"},` +
							`{"Key":"groundhold-environment","Value":"prod"}]}`))
					case "AddTagsToStream", "IncreaseStreamRetentionPeriod", "StartStreamEncryption":
						w.WriteHeader(200)
					default:
						w.WriteHeader(400)
					}
				}))
		},
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			d := NewDriver("eu-central-1")
			d.HTTP = &http.Client{Transport: rt}
			d.KinesisBaseURL = happyURL
			d.Account = "000000000000" // no STS round-trip: the gate must not leave the fake
			d.PollInterval = time.Millisecond
			d.PollTimeout = 2 * time.Second
			return d
		},
		Create: func(pr provider.Provider) provider.CreateResult {
			return pr.Create("kinesis", "events", "prod", kinesisAttrs(), kinesisImpl(), "events", 1)
		},
		AllowedMutations: 4, // the refused create + retention/encryption/tag convergence
	}
	certifynet.CertifyCreateAdoptsExisting(t, p)
}

// D1211: updateKinesis changes retention.window in place — Increase or Decrease chosen against
// the stream's CURRENT window, never a replacement. Ownership re-checked by tags; foreign refused.
func TestUpdateKinesisRetention(t *testing.T) {
	type call struct {
		action string
		hours  int
	}
	newSrv := func(capLabel string, current int, seen *[]call) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch kinesisTarget2(r) {
			case "DescribeStreamSummary":
				_, _ = w.Write([]byte(`{"StreamDescriptionSummary":{"StreamStatus":"ACTIVE",` +
					`"RetentionPeriodHours":` + itoaK(current) + `}}`))
			case "ListTagsForStream":
				_, _ = w.Write([]byte(`{"Tags":[{"Key":"groundhold-capability","Value":"` + capLabel +
					`"},{"Key":"groundhold-environment","Value":"prod"}]}`))
			case "IncreaseStreamRetentionPeriod", "DecreaseStreamRetentionPeriod":
				body, _ := io.ReadAll(r.Body)
				var b struct {
					RetentionPeriodHours int `json:"RetentionPeriodHours"`
				}
				_ = json.Unmarshal(body, &b)
				*seen = append(*seen, call{action: kinesisTarget2(r), hours: b.RetentionPeriodHours})
				w.WriteHeader(200)
			default:
				t.Errorf("unexpected %q", kinesisTarget2(r))
				w.WriteHeader(400)
			}
		}))
	}
	pid := kinesisProviderID("eu-central-1", "000000000000", KinesisStreamName("prod", "events", 1))

	t.Run("increase (24h -> 168h)", func(t *testing.T) {
		var seen []call
		srv := newSrv("events", 24, &seen)
		defer srv.Close()
		d := kinesisDriver(t, srv)
		res := d.updateKinesis("events", "prod", pid,
			map[string]any{"retention.window": "168h"}, []string{"retention.window"})
		if res.Status != "succeeded" {
			t.Fatalf("update: %+v", res)
		}
		if len(seen) != 1 || seen[0].action != "IncreaseStreamRetentionPeriod" || seen[0].hours != 168 {
			t.Fatalf("must Increase to 168, got %+v", seen)
		}
	})

	t.Run("decrease (168h -> 48h)", func(t *testing.T) {
		var seen []call
		srv := newSrv("events", 168, &seen)
		defer srv.Close()
		d := kinesisDriver(t, srv)
		res := d.updateKinesis("events", "prod", pid,
			map[string]any{"retention.window": "48h"}, []string{"retention.window"})
		if res.Status != "succeeded" {
			t.Fatalf("update: %+v", res)
		}
		if len(seen) != 1 || seen[0].action != "DecreaseStreamRetentionPeriod" || seen[0].hours != 48 {
			t.Fatalf("must Decrease to 48, got %+v", seen)
		}
	})

	t.Run("no-op (equal) issues no call", func(t *testing.T) {
		var seen []call
		srv := newSrv("events", 168, &seen)
		defer srv.Close()
		d := kinesisDriver(t, srv)
		res := d.updateKinesis("events", "prod", pid,
			map[string]any{"retention.window": "168h"}, []string{"retention.window"})
		if res.Status != "succeeded" {
			t.Fatalf("update: %+v", res)
		}
		if len(seen) != 0 {
			t.Fatalf("equal retention must issue NO call, got %+v", seen)
		}
	})

	t.Run("foreign stream refused, no call", func(t *testing.T) {
		var seen []call
		srv := newSrv("someone-else", 24, &seen)
		defer srv.Close()
		d := kinesisDriver(t, srv)
		res := d.updateKinesis("events", "prod", pid,
			map[string]any{"retention.window": "168h"}, []string{"retention.window"})
		if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
			t.Fatalf("a foreign stream must be refused, got %+v", res)
		}
		if len(seen) != 0 {
			t.Fatalf("a refused update must issue NO call, got %+v", seen)
		}
	})
}

func TestClassifyKinesisChange(t *testing.T) {
	if got, _ := classifyKinesisChange("retention.window"); got != "mutable" {
		t.Fatalf("retention.window must be mutable (in-place), got %q", got)
	}
	for _, p := range []string{"location.region", "encryption.customerManagedKeys", "availability.class"} {
		if got, _ := classifyKinesisChange(p); got != "immutable" {
			t.Fatalf("%s must be immutable (replacement), got %q", p, got)
		}
	}
}
