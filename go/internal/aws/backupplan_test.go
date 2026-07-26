package aws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"groundhold/internal/certifynet"
	"groundhold/internal/provider"
)

func bkpAttrs() map[string]any {
	return map[string]any{
		"location.region":    "eu-central-1",
		"schedule.frequency": "24h",
		"retention.duration": "2160h", // 90 days
		"service.managed":    true,
	}
}

func bkpImpl() map[string]any {
	return map[string]any{
		"targetVaultName": "pv-archive-prod",
		"iamRoleArn":      "arn:aws:iam::000000000000:role/backup",
		"selectionTags":   map[string]any{"backup": "daily"},
	}
}

func TestBuildBackupPlanHonors(t *testing.T) {
	p, err := BuildBackupPlan("prod", "archive", bkpAttrs(), bkpImpl(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.Name, "pp-archive-prod-") {
		t.Fatalf("name = %q", p.Name)
	}
	if p.Cron != "cron(0 5 ? * * *)" || p.FreqStr != "24h" {
		t.Fatalf("cadence = %q / %q", p.FreqStr, p.Cron)
	}
	if p.RetentionDays != 90 {
		t.Fatalf("retention days = %d", p.RetentionDays)
	}
	body := p.createPlanBody("archive", "prod")
	if _, has := body["CreatorRequestId"]; !has {
		t.Fatal("create body must carry a CreatorRequestId (idempotency for a server-assigned id)")
	}
	sel := p.createSelectionBody()
	if bs, _ := sel["BackupSelection"].(map[string]any); bs["IamRoleArn"] != p.IamRoleArn {
		t.Fatalf("selection body = %+v", sel)
	}
}

func TestBuildBackupPlanCrossRegion(t *testing.T) {
	a := bkpAttrs()
	a["copy.crossRegion"] = true
	a["copy.destinationRegion"] = "eu-west-1"
	i := bkpImpl()
	i["copyDestinationVaultArn"] = "arn:aws:backup:eu-west-1:000000000000:backup-vault:dr"
	p, err := BuildBackupPlan("prod", "archive", a, i, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !p.CrossRegion || p.CopyDestRegion != "eu-west-1" {
		t.Fatalf("cross-region = %+v", p)
	}
	rule := p.createPlanBody("archive", "prod")["BackupPlan"].(map[string]any)["Rules"].([]any)[0].(map[string]any)
	if _, has := rule["CopyActions"]; !has {
		t.Fatal("cross-region plan must carry a CopyAction")
	}
}

func TestBuildBackupPlanRefusals(t *testing.T) {
	type mut struct {
		attrs map[string]any
		impl  map[string]any
	}
	cases := map[string]mut{
		"unknown-attr":            {attrs: map[string]any{"backup.locked": true}},
		"bad-region":              {attrs: map[string]any{"location.region": "nope"}},
		"no-frequency":            {attrs: map[string]any{"schedule.frequency": nil}},
		"sub-hour-frequency":      {attrs: map[string]any{"schedule.frequency": "30m"}},
		"non-canonical-frequency": {attrs: map[string]any{"schedule.frequency": "5h"}},
		"no-retention":            {attrs: map[string]any{"retention.duration": nil}},
		"unmanaged":               {attrs: map[string]any{"service.managed": false}},
		"crossregion-no-arn":      {attrs: map[string]any{"copy.crossRegion": true}},
		"destregion-no-cross":     {attrs: map[string]any{"copy.destinationRegion": "eu-west-1"}},
		"no-selection":            {impl: map[string]any{"selectionTags": nil}},
		"no-target-vault":         {impl: map[string]any{"targetVaultName": nil}},
		"bad-iam-role":            {impl: map[string]any{"iamRoleArn": "not-an-arn"}},
	}
	for name, m := range cases {
		a := bkpAttrs()
		for k, v := range m.attrs {
			if v == nil {
				delete(a, k)
			} else {
				a[k] = v
			}
		}
		i := bkpImpl()
		for k, v := range m.impl {
			if v == nil {
				delete(i, k)
			} else {
				i[k] = v
			}
		}
		if _, err := BuildBackupPlan("prod", "archive", a, i, 1); err == nil {
			t.Errorf("%s: expected refusal, got none", name)
		}
	}
}

func TestBuildBackupPlanNonCanonicalCronOverride(t *testing.T) {
	a := bkpAttrs()
	a["schedule.frequency"] = "5h" // non-canonical
	i := bkpImpl()
	i["scheduleExpression"] = "cron(0 */5 ? * * *)"
	p, err := BuildBackupPlan("prod", "archive", a, i, 1)
	if err != nil {
		t.Fatalf("a non-canonical cadence with an explicit cron operand must be honored: %v", err)
	}
	if p.Cron != "cron(0 */5 ? * * *)" {
		t.Fatalf("operand cron override not honored: %q", p.Cron)
	}
}

// bkpServer is a happy AWS Backup Plan REST double. It answers the create composite
// (plan + selection), the delete sequence (get / tags / list selections / deletes),
// and observe (GetBackupPlan reflects a daily cadence, 90d retention, cross-region copy).
func bkpServer(t *testing.T, capLabel string) *httptest.Server {
	t.Helper()
	const arn = "arn:aws:backup:eu-central-1:000000000000:backup-plan:plan-abc"
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			switch {
			case r.Method == "PUT" && strings.HasSuffix(p, "/selections/"):
				_, _ = w.Write([]byte(`{"SelectionId":"sel-1","BackupPlanId":"plan-abc"}`))
			case r.Method == "PUT" && strings.HasSuffix(p, "/backup/plans/"):
				_, _ = w.Write([]byte(`{"BackupPlanId":"plan-abc","BackupPlanArn":"` + arn + `","VersionId":"v1"}`))
			case r.Method == "POST" && strings.Contains(p, "/backup/plans/"):
				// UpdateBackupPlan replaces the rule set.
				_, _ = w.Write([]byte(`{"BackupPlanId":"plan-abc","BackupPlanArn":"` + arn + `","VersionId":"v2"}`))
			case r.Method == "GET" && strings.HasPrefix(p, "/tags/"):
				_, _ = w.Write([]byte(`{"Tags":{"groundhold-capability":"` + capLabel + `","groundhold-environment":"prod"}}`))
			case r.Method == "GET" && strings.HasSuffix(p, "/selections/"):
				_, _ = w.Write([]byte(`{"BackupSelectionsList":[{"SelectionId":"sel-1"}]}`))
			case r.Method == "GET" && strings.Contains(p, "/backup/plans/"):
				_, _ = w.Write([]byte(`{"BackupPlanArn":"` + arn + `","BackupPlanId":"plan-abc",` +
					`"BackupPlan":{"BackupPlanName":"pp-x","Rules":[{"RuleName":"pv-rule",` +
					`"TargetBackupVaultName":"pv-archive-prod","ScheduleExpression":"cron(0 5 ? * * *)",` +
					`"Lifecycle":{"DeleteAfterDays":90},` +
					`"CopyActions":[{"DestinationBackupVaultArn":"arn:aws:backup:us-east-1:000000000000:backup-vault:dr"}]}]}}`))
			case r.Method == "DELETE":
				_, _ = w.Write([]byte(`{}`))
			default:
				w.WriteHeader(400)
			}
		}))
}

func bkpDriver(t *testing.T, srv *httptest.Server) *Driver {
	t.Helper()
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	d := NewDriver("eu-central-1")
	d.Account = "000000000000"
	d.BackupBaseURL = srv.URL
	d.PollInterval = time.Millisecond
	d.PollTimeout = 2 * time.Second
	return d
}

func TestCreateObserveDeleteBackupPlan(t *testing.T) {
	srv := bkpServer(t, "archive")
	defer srv.Close()
	d := bkpDriver(t, srv)

	res := d.createBackupPlan("eu-central-1", "prod", "archive", bkpAttrs(), bkpImpl(), 1)
	if res.Status != "succeeded" || res.ProviderID != "backupplan:eu-central-1:plan-abc" {
		t.Fatalf("create: %+v", res)
	}

	obs, _, err := d.observeBackupPlan("archive", res.ProviderID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	if got["schedule.frequency"] != "24h" || got["retention.duration"] != "2160h" ||
		got["copy.crossRegion"] != true || got["copy.destinationRegion"] != "us-east-1" ||
		got["location.region"] != "eu-central-1" || got["service.managed"] != true {
		t.Fatalf("observe: %+v", got)
	}

	if del := d.deleteBackupPlan("archive", "prod", res.ProviderID); del.Status != "succeeded" {
		t.Fatalf("delete: %+v", del)
	}
}

func TestUpdateBackupPlan(t *testing.T) {
	srv := bkpServer(t, "archive")
	defer srv.Close()
	d := bkpDriver(t, srv)
	a := bkpAttrs()
	a["retention.duration"] = "4320h" // 180 days
	res := d.updateBackupPlan("archive", "prod", "backupplan:eu-central-1:plan-abc",
		a, bkpImpl(), []string{"retention.duration"})
	if res.Status != "succeeded" {
		t.Fatalf("update: %+v", res)
	}
}

func TestDeleteBackupPlanForeignRefused(t *testing.T) {
	srv := bkpServer(t, "someone-else")
	defer srv.Close()
	d := bkpDriver(t, srv)
	res := d.deleteBackupPlan("archive", "prod", "backupplan:eu-central-1:plan-abc")
	if res.Status != "failed" || !strings.Contains(res.Reason, "not ours") {
		t.Fatalf("foreign plan must refuse delete, got %+v", res)
	}
}

func TestClassifyBackupPlanChange(t *testing.T) {
	cases := map[string]string{
		"schedule.frequency":     "mutable",
		"retention.duration":     "mutable",
		"copy.destinationRegion": "mutable",
		"location.region":        "immutable",
		"cost.monthly":           "unsupported",
	}
	for path, want := range cases {
		if got, _ := classifyBackupPlanChange(path, nil, nil); got != want {
			t.Errorf("%s: got %q want %q", path, got, want)
		}
	}
	// enabling cross-region without the destination operand is unsupported.
	if got, _ := classifyBackupPlanChange("copy.crossRegion", true, nil); got != "unsupported" {
		t.Errorf("crossRegion enable without arn: got %q", got)
	}
	if got, _ := classifyBackupPlanChange("copy.crossRegion", true,
		map[string]any{"copyDestinationVaultArn": "arn:aws:backup:eu-west-1:0:backup-vault:dr"}); got != "mutable" {
		t.Errorf("crossRegion enable with arn: got %q", got)
	}
}

// backupPlanRole classifies the Backup Plan REST calls: GET reads; the plan create
// PUT (/backup/plans/) yields the BackupPlanId the driver consumes (parsed); the
// selection PUT and the DELETEs are status-only (opaque).
func backupPlanRole(req *http.Request, _ []byte) certifynet.Role {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		return certifynet.RoleRead
	}
	if req.Method == http.MethodPut && strings.HasSuffix(req.URL.Path, "/backup/plans/") {
		return certifynet.RoleMutateParsed // BackupPlanId becomes the providerId
	}
	return certifynet.RoleMutateOpaque
}

func TestHonestyHarnessBackupPlan(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "AKID")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	pid := "backupplan:eu-central-1:plan-abc"
	p := &certifynet.Probe{
		// AssertTransient left false — D237 TODO: this driver's create/delete ladder
		// still maps 429/503/403 to terminal failed (and drops the providerId); it must
		// route through provider.MutationResult before the transient invariant can lock.
		Name:            "aws/backupplan",
		AssertTransient: true, // D237: create/delete route through provider.MutationResult
		Classify:        backupPlanRole,
		OwnerTagValue:   "archive",
		DeterministicID: false, // the BackupPlanId is server-assigned (D29)
		New: func(happyURL string, rt http.RoundTripper) provider.Provider {
			return newHonestyDriver(happyURL, rt)
		},
		Ops: []certifynet.Op{
			{
				Name:  "create",
				Happy: func() *httptest.Server { return bkpServer(t, "archive") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.(*Driver).createBackupPlan("eu-central-1", "prod", "archive", bkpAttrs(), bkpImpl(), 1)
				},
			},
			{
				Name:  "delete",
				Happy: func() *httptest.Server { return bkpServer(t, "archive") },
				Run: func(pr provider.Provider) provider.CreateResult {
					return pr.(*Driver).deleteBackupPlan("archive", "prod", pid)
				},
			},
		},
	}
	certifynet.CertifyDriverNet(t, p)
}

// TestBackupAvailabilityClassIsInstructive: availability.class on a backup plan or
// vault is a modeling error (no cloud maps it; the vocab does not define it), so
// the refusal must TEACH where the attribute belongs (D208) — not a bare "no
// mapping".
func TestBackupAvailabilityClassIsInstructive(t *testing.T) {
	a := bkpAttrs()
	a["availability.class"] = "regional"
	_, err := BuildBackupPlan("prod", "archive", a, bkpImpl(), 1)
	if err == nil {
		t.Fatal("availability.class on a backup plan must refuse")
	}
	if !strings.Contains(err.Error(), "RESOURCE being protected") ||
		!strings.Contains(err.Error(), "no availability-zone concept") {
		t.Fatalf("refusal must teach where availability.class belongs, got: %v", err)
	}

	va := bkvAttrs()
	va["availability.class"] = "zonal"
	_, verr := BuildBackupVault("prod", "archive", va, nil, 1)
	if verr == nil || !strings.Contains(verr.Error(), "RESOURCE being protected") {
		t.Fatalf("vault refusal must teach too, got: %v", verr)
	}
}
