package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// BATCH 1 reconcile tests: each service gets a succeeded path (a live, ready,
// owned resource reconciles to succeeded with the recomputed providerId) and one
// negative (a readable absence => failed, or an unreadable read => unknown). All
// drive d.Reconcile(capability, environment, receipt) with a create receipt, so
// the switch dispatch is exercised end to end.

func rc1Receipt(service string) map[string]any {
	return map[string]any{
		"target":     "aws." + service + "/x",
		"operation":  "create",
		"generation": 1,
	}
}

// ---- SNS ----

func TestReconcileSNS_LiveOwnedTopic(t *testing.T) {
	srv := snsServer(t)
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.Reconcile("events", "prod", rc1Receipt("sns"))
	want := snsProviderID("eu-central-1", "000000000000", TopicName("000000000000", "prod", "events", 1))
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("reconcile sns = %+v, want succeeded + %s", res, want)
	}
}

func TestReconcileSNS_AbsentTopicFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if queryAction(body) == "ListTagsForResource" {
			w.WriteHeader(http.StatusNotFound) // readable "topic does not exist"
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := snsTestDriver(t, srv)
	res := d.Reconcile("events", "prod", rc1Receipt("sns"))
	if res.Status != "failed" {
		t.Fatalf("absent topic must reconcile failed, got %+v", res)
	}
}

// ---- SQS ----

func TestReconcileSQS_LiveOwnedQueue(t *testing.T) {
	srv := sqsServer(t)
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.Reconcile("orders", "prod", rc1Receipt("sqs"))
	want := sqsProviderID("eu-central-1", "000000000000", QueueName("000000000000", "prod", "orders", 1, false))
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("reconcile sqs = %+v, want succeeded + %s", res, want)
	}
}

func TestReconcileSQS_AbsentQueueFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if queryAction(body) == "ListQueueTags" {
			w.WriteHeader(http.StatusNotFound) // readable "queue does not exist" (both variants)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	d := sqsTestDriver(t, srv)
	res := d.Reconcile("orders", "prod", rc1Receipt("sqs"))
	if res.Status != "failed" {
		t.Fatalf("absent queue must reconcile failed, got %+v", res)
	}
}

// ---- ECR ----

func TestReconcileECR_LiveOwnedRepo(t *testing.T) {
	srv := ecrServer(t, "images")
	defer srv.Close()
	d := ecrDriver(t, srv)
	res := d.Reconcile("images", "prod", rc1Receipt("ecr"))
	want := ecrProviderID("eu-central-1", "000000000000", ecrRepoName("prod", "images", 1))
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("reconcile ecr = %+v, want succeeded + %s", res, want)
	}
}

func TestReconcileECR_AbsentRepoFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"RepositoryNotFoundException"}`))
	}))
	defer srv.Close()
	d := ecrDriver(t, srv)
	res := d.Reconcile("images", "prod", rc1Receipt("ecr"))
	if res.Status != "failed" {
		t.Fatalf("absent repository must reconcile failed, got %+v", res)
	}
}

// ---- DynamoDB ----

func TestReconcileDynamoDB_ActiveOwnedTable(t *testing.T) {
	srv := dynamoServer(t, "sessions", false, false, false)
	defer srv.Close()
	d := dynamoDriver(t, srv)
	res := d.Reconcile("sessions", "prod", rc1Receipt("dynamodb"))
	want := dynamoProviderID("eu-central-1", "000000000000", DynamoTableName("prod", "sessions", 1))
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("reconcile dynamodb = %+v, want succeeded + %s", res, want)
	}
}

func TestReconcileDynamoDB_AbsentTableFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException"}`))
	}))
	defer srv.Close()
	d := dynamoDriver(t, srv)
	res := d.Reconcile("sessions", "prod", rc1Receipt("dynamodb"))
	if res.Status != "failed" {
		t.Fatalf("absent table must reconcile failed, got %+v", res)
	}
}

// ---- Kinesis ----

func TestReconcileKinesis_ActiveOwnedStream(t *testing.T) {
	srv := kinesisServer(t, "events", 24, false)
	defer srv.Close()
	d := kinesisDriver(t, srv)
	res := d.Reconcile("events", "prod", rc1Receipt("kinesis"))
	want := kinesisProviderID("eu-central-1", "000000000000", KinesisStreamName("prod", "events", 1))
	if res.Status != "succeeded" || res.ProviderID != want {
		t.Fatalf("reconcile kinesis = %+v, want succeeded + %s", res, want)
	}
}

func TestReconcileKinesis_UnreadableUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("X-Amz-Target"), "DescribeStreamSummary") {
			w.WriteHeader(http.StatusInternalServerError) // transient 5xx — unreadable, not absence
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	d := kinesisDriver(t, srv)
	res := d.Reconcile("events", "prod", rc1Receipt("kinesis"))
	if res.Status != "unknown" {
		t.Fatalf("unreadable stream read must reconcile unknown, got %+v", res)
	}
}
