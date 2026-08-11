package provider_test

import (
	"testing"

	"groundhold/internal/provider"
)

// D818. The rule the record encodes: a truncated response is evidence of an INCOMPLETE
// answer only if the continuation it handed back went unused. These pin the two ways that
// can go wrong, and the second is the one that nearly shipped.
func TestATruncationNoteStandsUntilTheContinuationIsUsed(t *testing.T) {
	var r provider.ListingRecord
	r.Note("ListTopics", []string{"tok-abc"})
	if got := r.Take(); len(got) != 1 || got[0].Call != "ListTopics" {
		t.Fatalf("an unfollowed continuation must leave a note, got %+v", got)
	}

	r.Note("ListTopics", []string{"tok-abc"})
	r.Followed(provider.RequestValues("https://sns.example/", []byte("Action=ListTopics&NextToken=tok-abc")))
	if got := r.Take(); len(got) != 0 {
		t.Fatalf("the sweep carried the continuation and the note stood anyway: %+v", got)
	}
}

// TestAContinuationIsOnlyFollowedUnderAContinuationParameter is the near-miss, kept as a
// case because the failure it prevents is silent and points the dangerous way.
//
// DynamoDB's continuation for ListTables is the NAME of the last table on the page. A sweep
// that lists one page and then DESCRIBES that table sends the identical string — so matching
// on the value alone reads "the sweep followed the listing" from a request that did nothing
// of the kind, and the tool reports a complete listing of a truncated estate.
func TestAContinuationIsOnlyFollowedUnderAContinuationParameter(t *testing.T) {
	var r provider.ListingRecord
	r.Note("ListTables", []string{"orders-prod-1a2b3c4d"})

	// The observe that follows the listing: same value, ordinary parameter.
	r.Followed(provider.RequestValues("https://dynamodb.example/",
		[]byte(`{"TableName":"orders-prod-1a2b3c4d"}`)))
	if got := r.Take(); len(got) != 1 {
		t.Fatalf("a DescribeTable carrying the same string cleared the listing's note — the "+
			"tool would report a complete listing of a truncated estate, got %+v", got)
	}

	// The real continuation: same value, continuation parameter.
	r.Note("ListTables", []string{"orders-prod-1a2b3c4d"})
	r.Followed(provider.RequestValues("https://dynamodb.example/",
		[]byte(`{"ExclusiveStartTableName":"orders-prod-1a2b3c4d"}`)))
	if got := r.Take(); len(got) != 0 {
		t.Fatalf("the sweep asked for the next page and the note stood anyway: %+v", got)
	}
}

// TestAnAzureNextLinkCountsAsFollowed: ARM's continuation is a complete URL the response
// chose, so following it means the next REQUEST is that value rather than a parameter in it.
func TestAnAzureNextLinkCountsAsFollowed(t *testing.T) {
	next := "https://management.azure.com/subscriptions/s/resources?$skiptoken=abc"
	var r provider.ListingRecord
	r.Note("GET /subscriptions/s/resources", []string{next})
	r.Followed(provider.RequestValues(next, nil))
	if got := r.Take(); len(got) != 0 {
		t.Fatalf("the sweep followed the nextLink and the note stood anyway: %+v", got)
	}
}
