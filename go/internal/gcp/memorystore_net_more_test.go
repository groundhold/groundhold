package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// This file extends memorystore_test.go, which pins the happy create/observe/
// delete LRO loop and the foreign-instance delete refusal. These tests pin
// the remaining branches: redisProtocolFor's unmatched/legacy versions,
// getRedis's error branches, createMemorystore's transport/5xx/conflict
// ladder, pollRedisOperation's failed/timeout branches, observeMemorystore's
// not-found branch, and deleteMemorystore's transport/5xx branches.

// --- redisProtocolFor -----------------------------------------------------

func TestRedisProtocolFor(t *testing.T) {
	cases := map[string]string{
		"REDIS_7_0": "redis/7",
		"REDIS_7_2": "redis/7",
		"REDIS_6_X": "redis/6",
		"REDIS_5_0": "redis/5",
		"REDIS_4_0": "redis/4",
		"REDIS_99":  "",
		"":          "",
	}
	for in, want := range cases {
		if got := redisProtocolFor(in); got != want {
			t.Errorf("redisProtocolFor(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- getRedis error branches -----------------------------------------

func TestGetRedisErrorBranches(t *testing.T) {
	t.Run("transport", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		d := redisDriver(t, srv)
		srv.Close()
		if _, _, err := d.getRedis("acme-prod", "europe-west1", "x"); err == nil {
			t.Fatal("expected a transport error")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		d := redisDriver(t, srv)
		if _, _, err := d.getRedis("acme-prod", "europe-west1", "x"); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("expected an HTTP 403 error, got %v", err)
		}
	})
	t.Run("unparseable body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()
		d := redisDriver(t, srv)
		if _, _, err := d.getRedis("acme-prod", "europe-west1", "x"); err == nil {
			t.Fatal("expected a body-parse error")
		}
	})
	t.Run("404 is a clean absence", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()
		d := redisDriver(t, srv)
		_, found, err := d.getRedis("acme-prod", "europe-west1", "x")
		if err != nil || found {
			t.Fatalf("a 404 must be found=false, err=nil, got found=%v err=%v", found, err)
		}
	})
}

// --- createMemorystore transport/5xx/conflict branches ---------------------

func TestCreateMemorystoreTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := redisDriver(t, srv)
	srv.Close()
	res := d.createMemorystore("prod", "sessions", redisAttrs(), redisImpl(), 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a lost create must be unknown WITH the deterministic pid, got %+v", res)
	}
}

func TestCreateMemorystore5xxIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.createMemorystore("prod", "sessions", redisAttrs(), redisImpl(), 1)
	if res.Status != "unknown" || res.ProviderID == "" {
		t.Fatalf("a 503 create must be unknown WITH the pid, got %+v", res)
	}
}

func TestCreateMemorystoreTerminalRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"malformed instance"}}`))
		}
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.createMemorystore("prod", "sessions", redisAttrs(), redisImpl(), 1)
	if res.Status != "failed" {
		t.Fatalf("a clean 400 must be a terminal failed, got %+v", res)
	}
}

func TestCreateMemorystoreConflictNotOursRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST":
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET":
			_, _ = w.Write([]byte(`{"name":"x","labels":{"groundhold-capability":"other"}}`))
		}
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.createMemorystore("prod", "sessions", redisAttrs(), redisImpl(), 1)
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("a foreign-labeled conflict must be failed, got %+v", res)
	}
}

func TestCreateMemorystoreConflictReadUnreadable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST":
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.createMemorystore("prod", "sessions", redisAttrs(), redisImpl(), 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "gave no answer") {
		t.Fatalf("an unreadable follow-up must be unknown, got %+v", res)
	}
}

func TestCreateMemorystoreConflictOursIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "POST":
			w.WriteHeader(http.StatusConflict)
		case r.Method == "GET":
			_, _ = w.Write([]byte(`{"name":"x","labels":{"groundhold-capability":"sessions","groundhold-environment":"prod"}}`))
		}
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.createMemorystore("prod", "sessions", redisAttrs(), redisImpl(), 1)
	if res.Status != "succeeded" {
		t.Fatalf("a matching conflict (idempotent) must succeed, got %+v", res)
	}
}

func TestCreateMemorystoreEmptyOperationIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_, _ = w.Write([]byte(`{}`)) // 200 but no op name
		}
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.createMemorystore("prod", "sessions", redisAttrs(), redisImpl(), 1)
	if res.Status != "unknown" || !strings.Contains(res.Reason, "carried no operation") {
		t.Fatalf("an empty operation response must be unknown, got %+v", res)
	}
}

// --- pollRedisOperation failed/timeout branches -------------------------

func TestPollRedisOperationFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"done":true,"error":{"message":"quota exceeded"}}`))
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.pollRedisOperation("projects/acme-prod/locations/europe-west1/operations/op1")
	if res.Status != "failed" || !strings.Contains(res.Reason, "quota exceeded") {
		t.Fatalf("a failed op must map to failed, got %+v", res)
	}
}

func TestPollRedisOperationTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"done":false}`))
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	d.Now = time.Now
	d.PollInterval = time.Millisecond
	d.PollTimeout = 5 * time.Millisecond
	res := d.pollRedisOperation("projects/acme-prod/locations/europe-west1/operations/op1")
	if res.Status != "unknown" || !strings.Contains(res.Reason, "poll timeout") {
		t.Fatalf("a still-running op at timeout must be unknown, got %+v", res)
	}
}

// --- observeMemorystore not-found / error branches --------------------

func TestObserveMemorystoreNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	obs, diags, err := d.observeMemorystore("sessions", "gredis:acme-prod:europe-west1:x")
	// Corrected with D519: this asserted SILENCE for an absent bound resource,
	// which is the defect F-LC3 exists to prevent — the compile sees an empty set,
	// plans nothing, and converge reports a world that no longer contains it.
	if err != nil || !absentMarked(obs) || len(diags) == 0 {
		t.Fatalf("a gone instance must be nothing-to-observe, got obs=%v diags=%v err=%v", obs, diags, err)
	}
}

func TestObserveMemorystoreErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	if _, _, err := d.observeMemorystore("sessions", "gredis:acme-prod:europe-west1:x"); err == nil {
		t.Fatal("an unreadable instance must propagate an error, not nothing-to-observe")
	}
}

func TestObserveMemorystoreBasicTierIsZonal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"x","redisVersion":"REDIS_6_X","tier":"BASIC","transitEncryptionMode":"DISABLED"}`))
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	obs, _, err := d.observeMemorystore("sessions", "gredis:acme-prod:europe-west1:x")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["availability.class"] != "zonal" || got["engine.protocol"] != "redis/6" || got["encryption.inTransit"] != false {
		t.Fatalf("BASIC tier observe: %+v", got)
	}
}

func TestObserveMemorystoreCrossProjectRefused(t *testing.T) {
	d := redisDriver(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	if _, _, err := d.observeMemorystore("sessions", "gredis:other-proj:europe-west1:x"); err == nil || !strings.Contains(err.Error(), "cross-project") {
		t.Fatalf("a cross-project pid must refuse, got %v", err)
	}
}

// --- deleteMemorystore transport/5xx branches -----------------------------

func TestDeleteMemorystoreTransportErrorIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	d := redisDriver(t, srv)
	srv.Close()
	res := d.deleteMemorystore("sessions", "prod", "gredis:acme-prod:europe-west1:x")
	if res.Status != "unknown" {
		t.Fatalf("a lost pre-delete read must be unknown, got %+v", res)
	}
}

func TestDeleteMemorystoreNotFoundIsIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.deleteMemorystore("sessions", "prod", "gredis:acme-prod:europe-west1:x")
	if res.Status != "succeeded" {
		t.Fatalf("a gone instance must be idempotent success, got %+v", res)
	}
}

func TestDeleteMemorystore5xxOnDeleteIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			_, _ = w.Write([]byte(`{"name":"x","labels":{"groundhold-capability":"sessions","groundhold-environment":"prod"}}`))
		case "DELETE":
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.deleteMemorystore("sessions", "prod", "gredis:acme-prod:europe-west1:x")
	if res.Status != "unknown" {
		t.Fatalf("a 503 on delete must be unknown, got %+v", res)
	}
}

func TestDeleteMemorystoreTerminalRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			_, _ = w.Write([]byte(`{"name":"x","labels":{"groundhold-capability":"sessions","groundhold-environment":"prod"}}`))
		case "DELETE":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":{"message":"bad delete"}}`))
		}
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.deleteMemorystore("sessions", "prod", "gredis:acme-prod:europe-west1:x")
	if res.Status != "failed" {
		t.Fatalf("a clean 400 delete must be a terminal failed, got %+v", res)
	}
}

func TestDeleteMemorystoreEmptyOperationIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			_, _ = w.Write([]byte(`{"name":"x","labels":{"groundhold-capability":"sessions","groundhold-environment":"prod"}}`))
		case "DELETE":
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	d := redisDriver(t, srv)
	res := d.deleteMemorystore("sessions", "prod", "gredis:acme-prod:europe-west1:x")
	if res.Status != "unknown" || !strings.Contains(res.Reason, "carried no operation") {
		t.Fatalf("an empty delete-op response must be unknown, got %+v", res)
	}
}

func TestDeleteMemorystoreCrossProjectRefused(t *testing.T) {
	d := redisDriver(t, httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})))
	res := d.deleteMemorystore("sessions", "prod", "gredis:other-proj:europe-west1:x")
	if res.Status != "failed" || !strings.Contains(res.Reason, "cross-project") {
		t.Fatalf("a cross-project pid must refuse the delete, got %+v", res)
	}
}

// --- splitGRedisProviderID additional invalids -----------------------------

func TestSplitGRedisProviderIDInvalids(t *testing.T) {
	cases := []string{
		"gcache:acme-prod:europe-west1:x", // wrong prefix
		"gredis:acme-prod:europe-west1",   // too few parts
		"gredis:BAD PROJECT:europe-west1:x",
		"gredis:acme-prod:BADREGION:x", // no digit suffix
		"gredis:acme-prod:europe-west1:BAD NAME",
	}
	for _, c := range cases {
		if _, _, _, err := splitGRedisProviderID(c); err == nil {
			t.Errorf("accepted malformed gredis id %q", c)
		}
	}
}
