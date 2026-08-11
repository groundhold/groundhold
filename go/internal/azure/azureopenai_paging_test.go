package azure

import (
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

// TestAzureOpenAIResidencyReadsEveryDeploymentPage is the sharp half of D869.
//
// `inference.destinationRegions` is MEASURED from the account's deployment skus, and the
// driver's own comment says what it is for: "a Global sku reduces to ["global"] ... NOT
// bounded EU regions, so the trap becomes a `violated` verdict DETERMINISTICALLY". The
// list it reduces is `Deployments_List`, which ARM's specification marks pageable with a
// nextLink — and the reduction ran over page one.
//
// So the deterministic trap had a page boundary in it. A GlobalStandard deployment on page
// two disappears from the union, the surface comes back as the account's own region, and a
// residency contract that says "inference must not leave the EU" is reported SATISFIED on
// an account routing inference anywhere in the world.
//
// The function above this one already refuses when the list is UNREADABLE, with a comment
// naming this exact harm ("never a fabricated absence that would understate the residency
// surface and let the trap slip through"). That is D865's triad again: the guards were
// written for "no answer" and "nothing there", and PART of an answer is what a paginated
// API returns by default.
func TestAzureOpenAIResidencyReadsEveryDeploymentPage(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap),
		deployments:      []map[string]any{aoiDeployment("d1", "Standard", "OpenAI", "gpt-4o")},
		deploymentsPage2: []map[string]any{aoiDeployment("d2", "GlobalStandard", "OpenAI", "gpt-4o")}}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	obs, _, err := d.observeAzureOpenAI(aoiCap, pid)
	if err != nil {
		t.Fatal(err)
	}
	got := obsMap(t, obs)
	dr, _ := got["inference.destinationRegions"].([]string)
	if !reflect.DeepEqual(dr, []string{"global", "swedencentral"}) {
		t.Fatalf("destinationRegions = %v, want [global swedencentral].\n\nThe GlobalStandard "+
			"deployment sat on page two of a listing ARM pages. This attribute is the one that "+
			"turns the residency trap into a deterministic `violated`, and it was measured from "+
			"the first page (D869).", dr)
	}
}

// TestAzureOpenAIResidencyRefusesAnUnfinishedDeploymentSweep: a chain that never ends must
// be an error — the same answer this code already gives for an unreadable list, and for the
// same reason. A partial union is not a smaller truth here; it is a residency claim.
func TestAzureOpenAIResidencyRefusesAnUnfinishedDeploymentSweep(t *testing.T) {
	f := &fakeAOI{location: "swedencentral", tags: aoiTags(aoiCap),
		deployments: []map[string]any{aoiDeployment("d1", "Standard", "OpenAI", "gpt-4o")},
		endlessDeps: true}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	d := aoiDriver(t, srv)
	pid := aoiProviderID(testSub, "rg1", aoiAccountName("prod", "inference", 1))
	obs, _, err := d.observeAzureOpenAI(aoiCap, pid)
	if err == nil {
		t.Fatalf("an endless deployment page chain produced observations (%v) instead of an "+
			"error — the residency surface would be a lower bound presented as measured", obs)
	}
	if !strings.Contains(err.Error(), "residency surface") {
		t.Fatalf("the refusal should name what could not be measured, got: %v", err)
	}
}
