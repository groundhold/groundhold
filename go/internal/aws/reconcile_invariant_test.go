package aws

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"groundhold/internal/cloudfake"
)

// reconcileDescriptor is the declarative per-service knowledge the generic invariant
// runner consumes. Adding a service is DATA + a small wire-render func — never new test
// logic (the anti-erosion rule from the review: variance lives in data, not in
// `if service == x`). A service that cannot be described by this schema is a driver
// design smell, escalated, not special-cased.
type reconcileDescriptor struct {
	service                 string
	capability, environment string
	async                   bool // has a distinct "creating" state that is NOT ready; a
	// sync service is ready the moment it exists, so the "creating" row does not apply.
	receipt    map[string]any              // the pending-create receipt to conclude
	resourceID func(account string) string // the deterministic id the driver recomputes
	ownerTags  map[string]string           // the tags that mark the resource OURS
	// render serves this service's describe/tags wire from the World (state → status,
	// tags → ownership). It must fail loud on any action it does not model.
	render    func(w *cloudfake.World, id, account string) http.Handler
	newDriver func(t *testing.T, srv *httptest.Server, account string) *Driver
}

// runReconcileInvariants drives a service through {absent, creating, available+foreign,
// available+ours} against a World-backed fake and asserts the ONE reconcile invariant:
// Reconcile concludes "succeeded" iff the live resource is found AND ready AND ours.
// The six fabricated-succeeded bugs are all violations of the "creating" or "foreign"
// row; this catches the whole class with no per-service assertion.
func runReconcileInvariants(t *testing.T, d reconcileDescriptor) {
	const account = "000000000000"
	foreign := map[string]string{"groundhold-capability": "someone-else", "groundhold-environment": "prod"}
	cases := []struct {
		name          string
		state         cloudfake.State // "" => absent (no resource seeded)
		tags          map[string]string
		wantSucceeded bool
	}{
		{"absent", "", nil, false},
		{"available+foreign", cloudfake.Available, foreign, false},
		{"available+ours", cloudfake.Available, d.ownerTags, true},
	}
	if d.async {
		// only an async service has a not-ready "creating" state; a create concluded
		// "succeeded" while still creating is the fabricated-succeeded bug.
		cases = append(cases, struct {
			name          string
			state         cloudfake.State
			tags          map[string]string
			wantSucceeded bool
		}{"creating", cloudfake.Creating, d.ownerTags, false})
	}
	for _, c := range cases {
		t.Run(d.service+"/"+c.name, func(t *testing.T) {
			w := cloudfake.New(0) // seeded states are stable (no transition)
			id := d.resourceID(account)
			if c.state != "" {
				w.Seed(&cloudfake.Resource{ID: id, State: c.state, Tags: c.tags})
			}
			srv := httptest.NewServer(d.render(w, id, account))
			defer srv.Close()
			dr := d.newDriver(t, srv, account)
			res := dr.Reconcile(d.capability, d.environment, d.receipt)
			got := res.Status == "succeeded"
			if got != c.wantSucceeded {
				t.Fatalf("invariant violated: %s → succeeded=%v, want %v "+
					"(succeeded must hold iff found∧ready∧ours) — %+v", c.name, got, c.wantSucceeded, res)
			}
		})
	}
}

// --- elasticache descriptor + wire adapter (the worked example) ---

func elastiCacheStatus(s cloudfake.State) string {
	switch s {
	case cloudfake.Available:
		return "available"
	case cloudfake.Creating:
		return "creating"
	case cloudfake.Failed:
		return "create-failed"
	}
	return "modifying"
}

func elastiCacheDescriptor() reconcileDescriptor {
	return reconcileDescriptor{
		service:     "elasticache",
		async:       true,
		capability:  "sessions",
		environment: "prod",
		receipt:     map[string]any{"target": "aws.elasticache/x", "operation": "create", "generation": 1},
		resourceID:  func(account string) string { return ecacheID(account, "prod", "sessions", 1) },
		ownerTags: map[string]string{
			"groundhold-capability":  sanitizeTag("sessions"),
			"groundhold-environment": sanitizeTag("prod"),
		},
		newDriver: func(t *testing.T, srv *httptest.Server, account string) *Driver {
			t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
			d := NewDriver("eu-central-1")
			d.ElastiCacheBaseURL = srv.URL
			d.Account = account
			return d
		},
		render: func(w *cloudfake.World, id, account string) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(body))
				switch form.Get("Action") {
				case "DescribeReplicationGroups":
					st, _, found := w.Describe(id)
					if !found {
						rw.Write([]byte(`<ErrorResponse><Error><Code>ReplicationGroupNotFoundFault</Code></Error></ErrorResponse>`))
						return
					}
					rw.Write([]byte(`<DescribeReplicationGroupsResponse><DescribeReplicationGroupsResult>` +
						`<ReplicationGroups><ReplicationGroup><Status>` + elastiCacheStatus(st) + `</Status>` +
						`</ReplicationGroup></ReplicationGroups>` +
						`</DescribeReplicationGroupsResult></DescribeReplicationGroupsResponse>`))
				case "ListTagsForResource":
					_, tags, _ := w.Describe(id)
					var b strings.Builder
					// ElastiCache returns tags as <Tag> under <TagList> (F28) — the
					// parser was fixed to that shape; this fake must match, or a merge
					// with the F28 change breaks the ownership case.
					b.WriteString(`<ListTagsForResourceResponse><ListTagsForResourceResult><TagList>`)
					for k, v := range tags {
						b.WriteString(`<Tag><Key>` + k + `</Key><Value>` + v + `</Value></Tag>`)
					}
					b.WriteString(`</TagList></ListTagsForResourceResult></ListTagsForResourceResponse>`)
					rw.Write([]byte(b.String()))
				default:
					http.Error(rw, `<ErrorResponse><Error><Code>UnmodeledOperation</Code></Error></ErrorResponse>`, 500)
				}
			})
		},
	}
}

// --- rds descriptor (a SECOND service, to prove the runner is generic) ---
//
// rds differs from elasticache in shape — tags come back IN the describe response, not
// a separate ListTagsForResource call, and the wire is DescribeDBInstances. That
// difference lives entirely in the render func; the runner and its four cases are
// untouched. That is the anti-erosion property: a new service is data + one render
// func, never new test logic.
func rdsStatus(s cloudfake.State) string {
	switch s {
	case cloudfake.Available:
		return "available"
	case cloudfake.Creating:
		return "creating"
	case cloudfake.Failed:
		return "failed"
	}
	return "modifying"
}

func rdsDescriptor() reconcileDescriptor {
	return reconcileDescriptor{
		service:     "rds",
		async:       true,
		capability:  "sessions",
		environment: "prod",
		receipt:     map[string]any{"target": "aws.rds/x", "operation": "create", "generation": 1},
		resourceID:  func(account string) string { return DBIdentifier(account, "prod", "sessions", 1) },
		ownerTags: map[string]string{
			"groundhold-capability":  sanitizeTag("sessions"),
			"groundhold-environment": sanitizeTag("prod"),
		},
		newDriver: func(t *testing.T, srv *httptest.Server, account string) *Driver {
			t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
			d := NewDriver("eu-central-1")
			d.RDSBaseURL = srv.URL
			d.Account = account
			return d
		},
		render: func(w *cloudfake.World, id, account string) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(body))
				if form.Get("Action") != "DescribeDBInstances" {
					http.Error(rw, `<ErrorResponse><Error><Code>UnmodeledOperation</Code></Error></ErrorResponse>`, 500)
					return
				}
				st, tags, found := w.Describe(id)
				if !found {
					rw.Write([]byte(`<ErrorResponse><Error><Code>DBInstanceNotFound</Code></Error></ErrorResponse>`))
					return
				}
				var tb strings.Builder
				for k, v := range tags {
					tb.WriteString(`<Tag><Key>` + k + `</Key><Value>` + v + `</Value></Tag>`)
				}
				rw.Write([]byte(`<DescribeDBInstancesResponse><DescribeDBInstancesResult><DBInstances><DBInstance>` +
					`<DBInstanceIdentifier>` + id + `</DBInstanceIdentifier><DBInstanceStatus>` + rdsStatus(st) + `</DBInstanceStatus>` +
					`<Engine>postgres</Engine>` +
					`<TagList>` + tb.String() + `</TagList>` +
					`</DBInstance></DBInstances></DescribeDBInstancesResult></DescribeDBInstancesResponse>`))
			})
		},
	}
}

// --- sns descriptor (a THIRD service — SYNCHRONOUS, to prove the sync/async axis) ---
//
// sns is ready the moment it exists (existence = ready), so it has no "creating" row
// (async:false). Ownership is a separate ListTagsForResource call, and "found" is
// derived from that same call (a NotFound means the topic does not exist). Again: the
// whole difference is data + the render func.
func snsDescriptor() reconcileDescriptor {
	return reconcileDescriptor{
		service:     "sns",
		async:       false,
		capability:  "sessions",
		environment: "prod",
		receipt:     map[string]any{"target": "aws.sns/x", "operation": "create", "generation": 1},
		resourceID:  func(account string) string { return TopicName(account, "prod", "sessions", 1) },
		ownerTags: map[string]string{
			"groundhold-capability":  sanitizeTag("sessions"),
			"groundhold-environment": sanitizeTag("prod"),
		},
		newDriver: func(t *testing.T, srv *httptest.Server, account string) *Driver {
			t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
			d := NewDriver("eu-central-1")
			d.SNSBaseURL = srv.URL
			d.Account = account
			return d
		},
		render: func(w *cloudfake.World, id, account string) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(body))
				if form.Get("Action") != "ListTagsForResource" {
					http.Error(rw, `<ErrorResponse><Error><Code>UnmodeledOperation</Code></Error></ErrorResponse>`, 500)
					return
				}
				_, tags, found := w.Describe(id)
				if !found { // no topic → snsListTags reports found=false
					rw.Write([]byte(`<ErrorResponse><Error><Code>NotFoundException</Code></Error></ErrorResponse>`))
					return
				}
				var b strings.Builder
				b.WriteString(`<ListTagsForResourceResponse><ListTagsForResourceResult><Tags>`)
				for k, v := range tags {
					b.WriteString(`<member><Key>` + k + `</Key><Value>` + v + `</Value></member>`)
				}
				b.WriteString(`</Tags></ListTagsForResourceResult></ListTagsForResourceResponse>`)
				rw.Write([]byte(b.String()))
			})
		},
	}
}

// --- lambda descriptor (a FOURTH service — async, REST-JSON GetFunction with tags
// INLINE, deterministic ECSName id) — the confirmed Acme blocker under the generic
// {absent, creating, foreign, ours} invariant. Its short poll budget bounds the
// "creating" (State=Pending) row to a fast unknown. ---
func lambdaState(s cloudfake.State) string {
	switch s {
	case cloudfake.Available:
		return "Active"
	case cloudfake.Creating:
		return "Pending"
	case cloudfake.Failed:
		return "Failed"
	}
	return "Inactive"
}

func lambdaDescriptor() reconcileDescriptor {
	return reconcileDescriptor{
		service:     "lambda",
		async:       true,
		capability:  "sessions",
		environment: "prod",
		receipt:     map[string]any{"target": "aws.lambda/x", "operation": "create", "generation": 1},
		resourceID:  func(account string) string { return ECSName(account, "prod", "sessions", 1) },
		ownerTags: map[string]string{
			"groundhold-capability":  sanitizeTag("sessions"),
			"groundhold-environment": sanitizeTag("prod"),
		},
		newDriver: func(t *testing.T, srv *httptest.Server, account string) *Driver {
			t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
			t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
			d := NewDriver("eu-central-1")
			d.LambdaBaseURL = srv.URL
			d.Account = account
			d.PollInterval = time.Millisecond
			d.PollTimeout = 20 * time.Millisecond // bound the still-Pending row
			return d
		},
		render: func(w *cloudfake.World, id, account string) http.Handler {
			return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/functions/") {
					http.Error(rw, `{"message":"UnmodeledOperation"}`, http.StatusInternalServerError)
					return
				}
				st, tags, found := w.Describe(id)
				if !found {
					rw.WriteHeader(http.StatusNotFound)
					_, _ = rw.Write([]byte(`{"message":"Function not found"}`))
					return
				}
				var tb strings.Builder
				tb.WriteString(`{`)
				first := true
				for k, v := range tags {
					if !first {
						tb.WriteString(`,`)
					}
					tb.WriteString(`"` + k + `":"` + v + `"`)
					first = false
				}
				tb.WriteString(`}`)
				_, _ = rw.Write([]byte(`{"Configuration":{"State":"` + lambdaState(st) + `","LastUpdateStatus":"Successful"},` +
					`"Tags":` + tb.String() + `}`))
			})
		},
	}
}

// TestReconcileInvariants runs the generic invariant suite. Each descriptor added here
// gets the full {absent, [creating,] foreign, ours} matrix for free — a new service is a
// descriptor, not new test logic. Four services, four shapes (async separate-tags,
// async tags-in-describe, sync separate-tags, async REST-JSON tags-inline), one runner,
// zero special-casing.
func TestReconcileInvariants(t *testing.T) {
	for _, d := range []reconcileDescriptor{
		elastiCacheDescriptor(),
		rdsDescriptor(),
		snsDescriptor(),
		lambdaDescriptor(),
	} {
		runReconcileInvariants(t, d)
	}
}
