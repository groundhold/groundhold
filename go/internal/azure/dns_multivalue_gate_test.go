package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// D1237. `dns.target` is a single string, and the vocabulary says so plainly — "the
// FIRST value only; a multi-value record set is not represented (the driver reads one
// target)". That disclosure is honest and it lives in the wrong place: an IMPLEMENTER
// reads the vocabulary, an OPERATOR reads the verdict.
//
// Measured before the fix: a record answering with 10.0.0.5 AND 203.0.113.9 reported
// `dns.target: 10.0.0.5`, `measured`, with no diagnostic. So
// `dns.target equals 10.0.0.5` read SATISFIED while the name ALSO resolved to a host
// no contract approved — against a vocabulary that says the governed fact is "does the
// name resolve to where it should".
//
// The first value is still emitted, because that is what the spec decided and a spec
// decision is not mine to overturn at 3am. What changes is that the verdict now carries
// the count, so nobody reads a single-target pass as a whole-record pass. The stronger
// option — withhold on multi-value, or give the vocabulary a set-valued attribute — is
// recorded for the owner in the entry.

func azDNSMultiObserve(t *testing.T, recordType, props string) (map[string]any, []string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"www","properties":{"TTL":300,` + props + `}}`))
	}))
	defer srv.Close()
	d := azDNSDriver(t, srv)
	obs, diags, err := d.observeAzureDNSRecord(azDNSRecordCap,
		azureDNSRecordProviderID(testSub, "rg", "example.com", recordType, "www"))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	got := map[string]any{}
	for _, o := range obs {
		got[o.Path] = o.Value
	}
	return got, diags
}

func azHasDiag(diags []string, sub string) bool {
	for _, d := range diags {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}

// The case that flipped a verdict: two A records, one reported, nothing said.
func TestMultiValueRecordDisclosesTheValuesItCannotRepresent(t *testing.T) {
	got, diags := azDNSMultiObserve(t, "A",
		`"ARecords":[{"ipv4Address":"10.0.0.5"},{"ipv4Address":"203.0.113.9"}]`)
	if got["dns.target"] != "10.0.0.5" {
		t.Fatalf("the first value is still what the spec says to report, got %v", got["dns.target"])
	}
	if !azHasDiag(diags, "FIRST of 2 values") {
		t.Fatalf("the operator must be told the record holds more than the attribute can "+
			"carry — a constraint passes on one target while the name resolves to others: %v", diags)
	}
}

// A single-value record must NOT carry the caveat, or it becomes noise on every record
// and the reader stops seeing it (the D1227 lesson).
func TestSingleValueRecordCarriesNoMultiValueCaveat(t *testing.T) {
	got, diags := azDNSMultiObserve(t, "A", `"ARecords":[{"ipv4Address":"10.0.0.5"}]`)
	if got["dns.target"] != "10.0.0.5" {
		t.Fatalf("dns.target = %v, want 10.0.0.5", got["dns.target"])
	}
	if azHasDiag(diags, "FIRST of") {
		t.Fatalf("a single-value record has nothing hidden — the caveat must not fire: %v", diags)
	}
}

// The count is per record TYPE, so each branch of the switch has to carry it. MX is the
// one whose value is assembled rather than read straight through.
func TestMultiValueCountIsRightForEachRecordType(t *testing.T) {
	for name, tc := range map[string]struct {
		typ, props, want string
	}{
		"AAAA": {"AAAA", `"AAAARecords":[{"ipv6Address":"2001:db8::1"},{"ipv6Address":"2001:db8::2"}]`,
			"FIRST of 2 values"},
		"TXT": {"TXT", `"TXTRecords":[{"value":["a"]},{"value":["b"]}]`, "FIRST of 2 values"},
		"MX": {"MX", `"MXRecords":[{"preference":10,"exchange":"m1"},{"preference":20,"exchange":"m2"}]`,
			"FIRST of 2 values"},
	} {
		_, diags := azDNSMultiObserve(t, tc.typ, tc.props)
		if !azHasDiag(diags, tc.want) {
			t.Errorf("%s: want the multi-value disclosure, got %v", name, diags)
		}
	}
}
