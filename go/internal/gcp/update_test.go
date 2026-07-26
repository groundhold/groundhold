package gcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildUpdateRequestGolden(t *testing.T) {
	current := parse(t, `{"settings": {
	  "settingsVersion": "7",
	  "backupConfiguration": {"enabled": true, "startTime": "03:00",
	    "pointInTimeRecoveryEnabled": false},
	  "tier": "db-custom-2-8192"}}`)
	req, err := BuildUpdateRequest("acme-prod", "orders-db-x",
		[]string{"availability.class", "recovery.rpo"},
		map[string]any{"availability.class": "regional",
			"recovery.rpo": "5m"},
		map[string]any{}, current)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(req.Body)
	// siblings of backupConfiguration (startTime) survive the merge;
	// settingsVersion rides along; ONLY changed paths appear
	want := `{"settings":{"availabilityType":"REGIONAL","backupConfiguration":{"enabled":true,"pointInTimeRecoveryEnabled":true,"startTime":"03:00"},"settingsVersion":"7"}}`
	if string(got) != want {
		t.Errorf("golden mismatch:\n got: %s\nwant: %s", got, want)
	}
	if req.Method != "PATCH" {
		t.Errorf("method: %s", req.Method)
	}
}

func TestBuildUpdateRefusals(t *testing.T) {
	current := parse(t, `{"settings": {"settingsVersion": "7"}}`)
	// unpatchable path
	if _, err := BuildUpdateRequest("p", "n", []string{"location.region"},
		map[string]any{"location.region": "x"}, nil, current); err == nil {
		t.Error("region must not be patchable")
	}
	// blind patch without settingsVersion
	noVersion := parse(t, `{"settings": {}}`)
	if _, err := BuildUpdateRequest("p", "n", []string{"recovery.rpo"},
		map[string]any{"recovery.rpo": "5m"}, nil, noVersion); err == nil {
		t.Error("missing settingsVersion must refuse a blind patch")
	}
}

func TestUpdateRefusesForeignInstance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"settings":{"settingsVersion":"7",
			  "userLabels":{"team":"someone-else"}}}`)
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	cr := d.Update("cloudsql", "orders-db", "production",
		"acme-prod:europe-west1:orders-db-x",
		map[string]any{"availability.class": "regional"}, nil,
		[]string{"availability.class"}, "k1")
	if cr.Status != "failed" {
		t.Errorf("foreign instance must refuse the patch, got %+v", cr)
	}
}

func TestUpdateSettingsVersionConflict(t *testing.T) {
	labels := `{"settings":{"settingsVersion":"7","userLabels":{"groundhold-capability":"orders-db","groundhold-environment":"production"}}}`
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				fmt.Fprint(w, labels)
				return
			}
			w.WriteHeader(http.StatusConflict)
		}))
	defer srv.Close()
	d := testDriver(t, srv)
	cr := d.Update("cloudsql", "orders-db", "production",
		"acme-prod:europe-west1:orders-db-x",
		map[string]any{"availability.class": "regional"}, nil,
		[]string{"availability.class"}, "k1")
	if cr.Status != "failed" {
		t.Errorf("settingsVersion conflict must fail, got %+v", cr)
	}
}
