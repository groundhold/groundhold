package certifynet

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

// GoneEstate is a fake cloud in which NOTHING exists — the estate the absence
// property has to be measured against.
//
// The first version answered 404 to every request, and that was wrong for most of
// AWS (D520). "Gone" is protocol-specific: a 404 is how a REST API says it, but an
// AWS query API returns 200 with an EMPTY RESULT SET, and a JSON-target API returns
// an error code in the body. Twenty-seven probes could not be wired because the
// generic server could not speak their protocol — `observeAWSVPC` handles its real
// absence signal correctly and was still counted un-migrated, which is a gate
// failing to measure a driver rather than a driver failing.
//
// So the estate dispatches on the SHAPE OF THE REQUEST, which is what identifies
// the protocol, rather than on a per-service fixture nobody would keep current:
//
//   - `X-Amz-Target` header  -> AWS JSON (json-1.0/1.1): HTTP 400 with a
//     `__type` naming a not-found exception, which is how these APIs say it.
//   - form-encoded body with `Action=` -> AWS query: HTTP 200 with a response
//     document containing no members, so a reader unmarshalling `xxxSet>item`
//     gets an empty slice and concludes not-found.
//   - anything else (REST paths, Google, ARM, k8s) -> HTTP 404 with a small
//     error body, which is what those protocols use.
//
// A driver that reads its protocol's real signal now passes; one that does not is
// a genuine finding rather than an artefact of the fixture.
func GoneEstate() *httptest.Server { return GoneEstateCode("") }

// GoneEstateEmptyList answers every read with an EMPTY COLLECTION (D523).
func GoneEstateEmptyList() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if action, ok := queryAction(r); ok {
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<?xml version="1.0"?><` + action + `Response></` +
				action + `Response>`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
}

// GoneEstateCode is GoneEstate with the SERVICE'S OWN not-found code (D522).
//
// The protocol says HOW absence is signalled; the service says WHAT the code is,
// and a correct driver matches on its own — IAM answers `NoSuchEntity`, EFS
// `FileSystemNotFound`, SQS `NonExistentQueue`. An estate that always said
// "NotFound" failed those drivers for not recognising a code their API never
// sends, which reads exactly like a driver defect and is not one. The code is a
// per-probe fact of the same kind as OwnerTagValue.
func GoneEstateCode(code string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Per-protocol DEFAULTS, because the conventional code differs by protocol:
		// the JSON APIs overwhelmingly use ResourceNotFoundException, the others a
		// bare NotFound. GoneCode overrides both when a service has its own (D522).
		jsonCode, otherCode := "ResourceNotFoundException", "NotFound"
		if code != "" {
			jsonCode, otherCode = code, code
		}
		if target := r.Header.Get("X-Amz-Target"); target != "" {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"` + jsonCode + `","message":"does not exist"}`))
			return
		}
		if action, ok := queryAction(r); ok {
			w.Header().Set("Content-Type", "text/xml")
			// The query protocol has TWO absence idioms and the action name picks
			// between them (D521). A plural enumerator answers 200 with an empty
			// set; a singular getter answers an ERROR with a not-found code, because
			// there is no empty form of "the attributes of this one thing".
			if strings.HasPrefix(action, "Describe") || strings.HasPrefix(action, "List") {
				w.WriteHeader(http.StatusOK)
				// The envelope is named for the action, because a reader may unmarshal
				// into a struct whose root element is ${Action}Response.
				_, _ = w.Write([]byte(`<?xml version="1.0"?><` + action + `Response></` +
					action + `Response>`))
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`<ErrorResponse><Error><Code>` + otherCode + `</Code>` +
				`<Message>does not exist</Message></Error></ErrorResponse>`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		// Answer in every dialect these APIs use to NAME an error, because the
		// code's location differs per service even within one cloud: EFS reads
		// `ErrorCode`, Google and ARM read `error.code`, some AWS REST APIs read
		// `__type`. A real server sends one; this fixture stands in for all of
		// them, and a driver reads whichever field it knows. The alternative is a
		// per-service body fixture, which is what this estate exists to avoid (D522).
		_, _ = w.Write([]byte(`{"ErrorCode":"` + otherCode + `","__type":"` + otherCode +
			`","code":"` + otherCode + `","message":"resource not found",` +
			`"error":{"code":"` + otherCode + `","status":"NOT_FOUND","message":"resource not found"}}`))
	}))
}

// queryAction recognises the AWS query protocol by its wire shape — a POST
// carrying a form-encoded body with `Action=` — and returns the action name.
// Reading the body is safe here because the handler does not forward it.
func queryAction(r *http.Request) (string, bool) {
	if r.Method != http.MethodPost {
		return "", false
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return "", false
	}
	buf := make([]byte, 4096)
	n, _ := r.Body.Read(buf)
	v, err := url.ParseQuery(string(buf[:n]))
	if err != nil {
		return "", false
	}
	act := v.Get("Action")
	return act, act != ""
}
