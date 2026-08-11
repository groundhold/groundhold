package notify

import (
	"reflect"
	"sort"
	"strings"
	"testing"
)

// D596. The doorbell posts to an operator-supplied URL — it is the one path where a
// run's data leaves the machine over the network, to an address groundhold does not
// control. Its payload is deliberately narrow: a handle, two enums, a code, an exit
// code, a timestamp and a hash. Every field is an identifier or a closed value, so
// there is structurally nothing to leak. That is stronger than redaction, and the
// package earns it: the notifier "has no ledger handle — it is physically incapable
// of writing truth".
//
// Nothing held the shape. `TestBuildPayloadIsExact` pins the exact JSON bytes of one
// fully-populated payload, which catches a new REQUIRED field — and not a new
// `omitempty` one. Measured: adding
//
//	Reason string `json:"reason,omitempty"`
//
// to the outbound payload passes every test in this package. The moment any caller
// sets it, driver text goes to an external URL — and D309 established that driver
// text is exactly where credentials surface, which is why the receipt's Reason needs
// a redactor. The doorbell has no redactor because it has no free text; that is the
// invariant, and it was unguarded.
//
// So the field SET is pinned by name (D571's membership shape, D593's): adding one is
// a deliberate edit that states what it carries and why an external endpoint may see
// it.
func TestNotifyPayloadCarriesNoFreeText(t *testing.T) {
	want := []string{
		"code",          // closed error-code vocabulary (spec/errors.md)
		"concludedAt",   // RFC3339 timestamp
		"exitCode",      // integer
		"handle",        // opaque run handle
		"kind",          // apply | converge
		"lastEventHash", // content hash
		"schema",        // constant
		"state",         // done | failed | stalled | needs-reconcile
	}
	var got []string
	rt := reflect.TypeOf(Payload{})
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		if tag == "" || tag == "-" {
			t.Errorf("field %s has no json tag — it would ship under its Go name",
				rt.Field(i).Name)
			continue
		}
		got = append(got, strings.Split(tag, ",")[0])
	}
	if len(got) < 5 {
		t.Fatalf("read %d payload fields — the probe broke and this gate would pass on "+
			"anything", len(got))
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the outbound notification payload changed WITHOUT updating this test.\n"+
			"  want: %v\n  got:  %v\n"+
			"This payload is POSTed to an operator-supplied URL. If the new field can "+
			"carry free text — a reason, a diagnostic, a provider message — it carries "+
			"whatever a driver put there, off this machine, unredacted (D309).", want, got)
	}
}

// And every field must be a scalar. A map or a nested struct is a hole of its own
// shape: the name check would pass while the content is unbounded.
func TestNotifyPayloadFieldsAreScalars(t *testing.T) {
	rt := reflect.TypeOf(Payload{})
	for i := 0; i < rt.NumField(); i++ {
		switch rt.Field(i).Type.Kind() {
		case reflect.String, reflect.Int, reflect.Int64, reflect.Bool:
		default:
			t.Errorf("payload field %s is %s — a non-scalar carries unbounded content "+
				"to an external endpoint no matter what its name suggests",
				rt.Field(i).Name, rt.Field(i).Type)
		}
	}
}
