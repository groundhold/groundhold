# The conformance suite

`conformance/cases/*.yaml` is the source of truth — **the suite defines
what "correct" means**, and it is run through the implementations' own
CLIs, not their internals. 514 cases, plus seeded differential fuzzing.

Of those, **232 run against BOTH implementations** — the Python reference
and the Go runtime must agree on them exactly. The rest carry `impl: go`
because they cover components that exist only in the runtime (the
executor, the porcelain, the drivers); there is no second implementation
for them to disagree with, and claiming otherwise would overstate what
dual verification actually covers.

## Why this shape

A verifier you must trust deserves better than "trust us": any
competing implementation measures itself with the same yardstick, and
the yardstick is Apache-2.0 licensed precisely so it can. The
"Groundhold Conformant" claim means: passes the unmodified suite.

## The rules

- A bug is not fixed — a feature is not done — until a case pins it.
- Existing cases' expectations are NEVER weakened to make code pass.
- Semantic changes start with the case, then the implementation.
- `impl: go` marks cases for Go-only components (executor, porcelain);
  everything else runs against both implementations.

## Running it

```sh
make conformance        # Python reference, library mode
make conformance-cli    # Python reference through its CLI
make conformance-go     # Go runtime through its binary
make check              # all of the above + vet + go test
make differential       # seeded cross-implementation fuzzing
```

## Reporting bugs

The fastest-fixed report is a failing case. You do not have to write
one — maintainers reduce real reports before fixing (label
`pending-conformance`) — but expected/actual behavior and a MINIMAL
contract are required. See CONTRIBUTING.md.
