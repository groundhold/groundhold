package aws

// maxAWSListPages bounds every paginated discovery sweep in this package.
//
// D817. AWS has no single paging shape — the Query-protocol services put a NextToken in
// a form field, the JSON ones put a Marker in the body, the REST ones put it in the query
// string, and three different flags (IsTruncated, Truncated, or a bare empty token) say
// "that was the last one". So there is no shared loop here the way GCP (D813) and Azure
// (D815) have one. What CAN be shared is the bound, and it is the same bound for the same
// reason: a token the endpoint keeps handing back would otherwise spin forever, and a
// sweep that never returns is indistinguishable from a hung tool.
//
// Exceeding it is an ERROR, never a truncated answer. Fifty pages is more than any of
// these services will hand back for a real estate; if one does, the honest report is that
// the sweep did not finish, not a list that looks complete and is not.
const maxAWSListPages = 50
