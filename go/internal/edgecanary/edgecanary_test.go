package edgecanary

import (
	"strings"
	"testing"

	"groundhold/internal/apireq"
)

// TestTargetsAreApireqDriven: the canary's target list is the registry's
// CloudFront-OAC invoke entry, selected from apireq.CanaryTargets() as DATA — a
// hardcoded list would drift from the registry the guard is fenced by.
func TestTargetsAreApireqDriven(t *testing.T) {
	ts := Targets()
	if len(ts) == 0 {
		t.Fatal("Targets() found no apireq entry for the AWS Function-URL/OAC edge")
	}
	var found bool
	for _, r := range ts {
		if r.GuardID == apireq.GuardCloudFrontOACDualInvoke {
			found = true
		}
		if r.Provider != "aws" || r.Service != "lambda" {
			t.Errorf("target %s is not an aws/lambda entry: %+v", r.GuardID, r)
		}
	}
	if !found {
		t.Errorf("Targets() must include %q (the D329 seed)", apireq.GuardCloudFrontOACDualInvoke)
	}
}

// TestCitationCitesGuardAndSource: the red message must carry the GuardID and a
// human-checkable source so the operator can verify the claim.
func TestCitationCitesGuardAndSource(t *testing.T) {
	c := Citation(Targets())
	if !strings.Contains(c, apireq.GuardCloudFrontOACDualInvoke) {
		t.Errorf("citation missing GuardID: %s", c)
	}
	if !strings.Contains(c, "http") {
		t.Errorf("citation missing a SourceURL: %s", c)
	}
}

func TestCitationEmpty(t *testing.T) {
	if c := Citation(nil); !strings.Contains(c, "no apireq entry") {
		t.Errorf("empty citation should say so, got: %s", c)
	}
}

// TestClassify is the verdict truth table — the whole point of a Go core.
func TestClassify(t *testing.T) {
	cases := []struct {
		name   string
		in     Outcome
		want   Class
		exit   int
		cite   bool
		msgHas string
	}{
		{"not-applied is regression", Outcome{Applied: false}, Regression, 20, false, "status != applied"},
		{"not-deployed is flake", Outcome{Applied: true, Deployed: false}, Flake, 30, false, "propagation"},
		{"transport after deployed is flake", Outcome{Applied: true, Deployed: true, Transport: true}, Flake, 30, false, "below HTTP"},
		{"200 is green", Outcome{Applied: true, Deployed: true, HTTPStatus: 200}, Green, 0, false, "intact TODAY"},
		{"301 is green", Outcome{Applied: true, Deployed: true, HTTPStatus: 301}, Green, 0, false, "intact TODAY"},
		{"403 is cited provider-drift", Outcome{Applied: true, Deployed: true, HTTPStatus: 403}, ProviderDrift, 10, true, "invoke requirement"},
		{"401 is cited provider-drift", Outcome{Applied: true, Deployed: true, HTTPStatus: 401}, ProviderDrift, 10, true, "invoke requirement"},
		{"502 is cited provider-drift", Outcome{Applied: true, Deployed: true, HTTPStatus: 502}, ProviderDrift, 10, true, "could not invoke"},
		{"503 is cited provider-drift", Outcome{Applied: true, Deployed: true, HTTPStatus: 503}, ProviderDrift, 10, true, "could not invoke"},
		{"404 is regression not drift", Outcome{Applied: true, Deployed: true, HTTPStatus: 404}, Regression, 20, false, "does not match"},
		{"500 is regression not drift", Outcome{Applied: true, Deployed: true, HTTPStatus: 500}, Regression, 20, false, "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.in)
			if got.Class != tc.want {
				t.Errorf("class = %q, want %q", got.Class, tc.want)
			}
			if got.Exit != tc.exit {
				t.Errorf("exit = %d, want %d", got.Exit, tc.exit)
			}
			if got.Cite != tc.cite {
				t.Errorf("cite = %v, want %v", got.Cite, tc.cite)
			}
			if !strings.Contains(got.Message, tc.msgHas) {
				t.Errorf("message %q missing %q", got.Message, tc.msgHas)
			}
			if tc.cite {
				if got.GuardID != apireq.GuardCloudFrontOACDualInvoke {
					t.Errorf("cited result missing GuardID, got %q", got.GuardID)
				}
				if !strings.Contains(got.Message, "apireq:") {
					t.Errorf("cited message must carry the apireq citation: %s", got.Message)
				}
			}
		})
	}
}

// TestExitCodeTaxonomy pins the shared canary exit codes.
func TestExitCodeTaxonomy(t *testing.T) {
	for c, want := range map[Class]int{Green: 0, ProviderDrift: 10, Regression: 20, Flake: 30} {
		if got := c.ExitCode(); got != want {
			t.Errorf("%s.ExitCode() = %d, want %d", c, got, want)
		}
	}
	// an unknown class fails SAFE as a retryable flake, never as green.
	if got := Class("weird").ExitCode(); got != 30 {
		t.Errorf("unknown class = %d, want 30 (fail-safe flake)", got)
	}
}

// TestClassifyGCPEdge: the D336 GCP twin. The truth table is shared with AWS, but
// a GCP drift is HONESTLY UNCITED (no apireq entry catalogues Cloud Run's public
// invoker; the edge target is the service itself), the messages name Cloud Run,
// and green stays evidence-not-proof.
func TestClassifyGCPEdge(t *testing.T) {
	cases := []struct {
		name   string
		in     Outcome
		want   Class
		exit   int
		cite   bool
		msgHas string
	}{
		{"not-applied is regression", Outcome{Applied: false}, Regression, 20, false, "status != applied"},
		{"not-ready is flake", Outcome{Applied: true, Deployed: false}, Flake, 30, false, "Cloud Run service"},
		{"transport is flake", Outcome{Applied: true, Deployed: true, Transport: true}, Flake, 30, false, "below HTTP"},
		{"200 is green", Outcome{Applied: true, Deployed: true, HTTPStatus: 200}, Green, 0, false, "intact TODAY"},
		{"302 is green", Outcome{Applied: true, Deployed: true, HTTPStatus: 302}, Green, 0, false, "public Cloud Run service"},
		{"403 is uncited provider-drift", Outcome{Applied: true, Deployed: true, HTTPStatus: 403}, ProviderDrift, 10, false, "public-invoker"},
		{"503 is uncited provider-drift", Outcome{Applied: true, Deployed: true, HTTPStatus: 503}, ProviderDrift, 10, false, "must serve"},
		{"404 is regression", Outcome{Applied: true, Deployed: true, HTTPStatus: 404}, Regression, 20, false, "does not match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyFor(GCPEdge, tc.in)
			if got.Class != tc.want {
				t.Errorf("class = %q, want %q", got.Class, tc.want)
			}
			if got.Exit != tc.exit {
				t.Errorf("exit = %d, want %d", got.Exit, tc.exit)
			}
			if got.Cite != tc.cite {
				t.Errorf("cite = %v, want %v (GCP has no apireq entry)", got.Cite, tc.cite)
			}
			if !strings.Contains(got.Message, tc.msgHas) {
				t.Errorf("message %q missing %q", got.Message, tc.msgHas)
			}
			// a GCP drift must NEVER fabricate a registry citation
			if got.Class == ProviderDrift {
				if got.GuardID != "" {
					t.Errorf("GCP drift must carry no GuardID, got %q", got.GuardID)
				}
				if strings.Contains(got.Message, "apireq:") {
					t.Errorf("GCP drift must not claim an apireq citation: %s", got.Message)
				}
				if !strings.Contains(got.Message, "no apireq entry") {
					t.Errorf("GCP drift must state it is uncited: %s", got.Message)
				}
			}
		})
	}
}

// TestGCPEdgeHasNoTargets: GCP has no apireq entry — we do not fabricate one.
func TestGCPEdgeHasNoTargets(t *testing.T) {
	if ts := GCPEdge.Targets(); len(ts) != 0 {
		t.Errorf("GCP edge must have no apireq targets (none catalogued), got %+v", ts)
	}
	if EdgeFor("gcp").Provider != "gcp" || EdgeFor("aws").Provider != "aws" || EdgeFor("").Provider != "aws" {
		t.Error("EdgeFor must select gcp for gcp and default aws otherwise")
	}
}
