package aws

import (
	"net/url"
	"reflect"
	"testing"
)

// D868. The set `trust.principals` compares against. The condition rides WITH the
// principal, and these cases are the reason: D776 came from the field, where all six of
// the reporter's roles carried an `aws:SourceAccount` guard, and a set of bare principals
// would have compared them equal to an unconditioned role — recording trust WEAKER than
// the trust that stands.
func TestTrustPrincipalsCarryTheirCondition(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[
	  {"Effect":"Allow","Action":"sts:AssumeRole",
	   "Principal":{"Service":"events.amazonaws.com"},
	   "Condition":{"StringEquals":{"aws:SourceAccount":"000000000000"}}},
	  {"Effect":"Allow","Action":"sts:AssumeRole",
	   "Principal":{"Service":"vpc-flow-logs.amazonaws.com"}}]}`
	r := iamRole{AssumeRolePolicyDocument: url.QueryEscape(doc)}
	got, ok := r.trustPrincipals()
	if !ok {
		t.Fatal("a well-formed trust document did not decode")
	}
	want := []string{
		"service:events.amazonaws.com if aws:SourceAccount=000000000000",
		"service:vpc-flow-logs.amazonaws.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("trust.principals = %q, want %q", got, want)
	}

	// The heart of it: the SAME principal, guarded and unguarded, must not render alike.
	bare := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",
	  "Principal":{"Service":"events.amazonaws.com"}}]}`
	b, _ := iamRole{AssumeRolePolicyDocument: url.QueryEscape(bare)}.trustPrincipals()
	if reflect.DeepEqual(b, []string{want[0]}) {
		t.Fatal("a bare service principal rendered identically to the same principal under " +
			"aws:SourceAccount — the exact equality D776 warned about, which records trust " +
			"weaker than the trust that stands")
	}
}

// TestTrustPrincipalsSeesTheWildcard: the one element worth reading at a glance.
func TestTrustPrincipalsSeesTheWildcard(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}`
	got, ok := iamRole{AssumeRolePolicyDocument: url.QueryEscape(doc)}.trustPrincipals()
	if !ok || len(got) != 1 || got[0] != "*" {
		t.Fatalf("a role assumable by anyone rendered as %q — the wildcard must survive "+
			"verbatim into the attribute a contract constrains", got)
	}
}

// TestTrustPrincipalsIgnoresNonAssumeStatements: a trust document can also carry
// sts:TagSession and sts:SetSourceIdentity, whose presence says nothing about who may pick
// the identity up. Folding them in would report principals that cannot assume.
func TestTrustPrincipalsIgnoresNonAssumeStatements(t *testing.T) {
	doc := `{"Statement":[
	  {"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"Service":"a.amazonaws.com"}},
	  {"Effect":"Allow","Action":"sts:TagSession","Principal":{"Service":"b.amazonaws.com"}},
	  {"Effect":"Deny","Action":"sts:AssumeRole","Principal":{"Service":"c.amazonaws.com"}}]}`
	got, _ := iamRole{AssumeRolePolicyDocument: url.QueryEscape(doc)}.trustPrincipals()
	want := []string{"service:a.amazonaws.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("trust.principals = %q, want %q (a TagSession grant is not assumption, "+
			"and a Deny is not a grant)", got, want)
	}
}

// TestAnUndecodableTrustDocumentIsNotAnEmptySet is the D847 discipline in this attribute:
// "we could not tell" and "nobody may assume this" are different answers, and only one of
// them may become a measured value.
func TestAnUndecodableTrustDocumentIsNotAnEmptySet(t *testing.T) {
	for _, raw := range []string{"", "%zz-not-url-encoded", url.QueryEscape("{not json")} {
		got, ok := iamRole{AssumeRolePolicyDocument: raw}.trustPrincipals()
		if ok {
			t.Fatalf("an undecodable document (%q) reported ok=true with %q", raw, got)
		}
		if got != nil {
			t.Fatalf("an undecodable document produced a set (%q) — an empty set is the "+
				"safest-looking possible answer about who can assume a role", got)
		}
	}
}

// TestTrustPrincipalsReadsAFederatedPrincipal serves the third principal kind. A role
// assumed through OIDC or SAML — every workload-identity federation, every GitHub Actions
// deploy role — names its provider under `Federated`, and a branch no fixture reaches is a
// branch nobody has seen work (D756).
func TestTrustPrincipalsReadsAFederatedPrincipal(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity",
	  "Principal":{"Federated":"arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com"},
	  "Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:acme/app:*"}}}]}`
	got, ok := iamRole{AssumeRolePolicyDocument: url.QueryEscape(doc)}.trustPrincipals()
	if !ok {
		t.Fatal("a federated trust document did not decode")
	}
	want := []string{"federated:arn:aws:iam::000000000000:oidc-provider/token.actions.githubusercontent.com" +
		" if token.actions.githubusercontent.com:sub=repo:acme/app:*"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("trust.principals = %q, want %q — the subject condition is what bounds a "+
			"federated role to one repository, so it belongs in the element", got, want)
	}
}
