package provider

import "testing"

// D803. A false positive costs an honest "at least N" where the count was exact; a false
// negative restores the lie. The detector is tuned to that asymmetry, so both directions
// are pinned.
func TestListingTruncatedFiresOnAContinuationToken(t *testing.T) {
	says := [][]byte{
		[]byte(`{"Functions":[],"NextToken":"eyJ2IjoxfQ=="}`),
		[]byte(`{"items":[],"nextPageToken":"CgkxMjM0NQ"}`),
		[]byte(`{"value":[],"nextLink":"https://management.azure.com/...?$skipToken=x"}`),
		[]byte(`{"Buckets":[],"IsTruncated":true}`),
		[]byte(`<ListPoliciesResult><IsTruncated>true</IsTruncated></ListPoliciesResult>`),
		[]byte(`<Result><NextMarker>abc</NextMarker></Result>`),
	}
	for _, b := range says {
		if !ListingTruncated(b) {
			t.Errorf("a response saying there is more read as complete: %s", b)
		}
	}
}

func TestListingTruncatedStaysQuietOnACompleteAnswer(t *testing.T) {
	quiet := [][]byte{
		[]byte(`{"Functions":[{"FunctionName":"a"}]}`),
		[]byte(`{"Functions":[],"NextToken":""}`),
		[]byte(`{"items":[],"nextPageToken":""}`),
		[]byte(`{"Buckets":[],"IsTruncated":false}`),
		[]byte(`<ListPoliciesResult><IsTruncated>false</IsTruncated></ListPoliciesResult>`),
		// A bare Marker/ContinuationToken is echoed back from the REQUEST by several
		// AWS APIs, so it says nothing about whether more exists.
		[]byte(`{"Contents":[],"Marker":"page-2"}`),
		[]byte(`{"Contents":[],"ContinuationToken":"page-2"}`),
		[]byte(`<Result><NextMarker></NextMarker></Result>`),
	}
	for _, b := range quiet {
		if ListingTruncated(b) {
			t.Errorf("a complete answer read as truncated: %s", b)
		}
	}
}
