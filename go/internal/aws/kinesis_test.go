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
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch kinesisTarget2(r) {
			case "CreateStream":
				w.WriteHeader(200)
			case "DescribeStreamSummary":
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
			case "AddTagsToStream", "IncreaseStreamRetentionPeriod", "StartStreamEncryption", "DeleteStream":
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
			if _, has := got["encryption.customerManagedKeys"]; has != c.cmek {
				t.Errorf("cmek round-trip: want present=%v got %v", c.cmek, got["encryption.customerManagedKeys"])
			}
		})
	}
}
