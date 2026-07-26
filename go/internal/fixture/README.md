# Response-fixture replay harness (D234)

Catches provider API drift that hand-written httptest fakes cannot: a fake matches
the driver's own assumption; a fixture records the provider's real response shape
independently, and replay feeds those bytes to the REAL driver parser.

## Replay (offline, every `make check`, no creds)
A driver test loads a fixture, serves its bytes from a fail-closed httptest
handler, points the driver's `BaseURL` seam at it, runs the real observe/reconcile,
and asserts the expected observations. See `internal/gcp/gcs_replay_test.go`.

## Capture (canary only, has creds) — how to record a REAL fixture
The replay harness is complete; a fixture becomes drift EVIDENCE only once captured
from the live provider. Procedure (to run inside canary-gcp.yml / the AWS sandbox):

1. Wrap the driver's HTTP client in a recording `http.RoundTripper` (records the
   request the driver ACTUALLY sends + the verbatim response bytes).
2. Run the real observe/reconcile against the live resource on a dev GCP project
   or a sandbox AWS account (e.g. 123456789012). NEVER a client account.
3. Scrub account-specifics (project ids, ARNs → placeholders); keep structural
   fields (etags, selfLinks — shape matters). Record redactions in `scrubbed`.
4. Compute the shape signature; write the fixture with `provenance: live`,
   `capturedBy: canary-<provider>@<run-id>`, `capturedAt`.
5. Run the current parser to fill `expected`, then HUMAN-REVIEW it in the PR — the
   review breaks the circularity (else `expected` is just the driver's assumption).
6. The canary opens a PR with the diff; it NEVER pushes to a protected branch.

## Honesty (enforced by `TestFixtureProvenance`)
- `provenance: live` requires `capturedBy` (a canary run id) — a live claim without
  a capture source fails Load and is not evidence.
- `provenance: handwritten-pending-canary` exercises the harness and catches DRIVER
  drift, but is NOT provider-verified coverage; it must carry a `note` saying why.
- The committed `shapeHash` is recomputed on Load — a mismatch is a corrupt fixture.

## Capture is wired (D235)
`internal/gcp/gcs_capture_test.go` (`//go:build capture`) runs in `canary-gcp.yml`
under `-tags capture` with the WIF token — records the real GCS response, flips the
fixture to `provenance:live`, and the canary uploads it for a review PR (never
pushes). Excluded from `make check`. AWS sandbox capture + Azure code-path capture
are deferred (no sandbox creds on a dev host — only client prod, which is forbidden).
