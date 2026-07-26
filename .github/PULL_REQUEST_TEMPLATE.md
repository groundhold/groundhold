<!-- Thanks for contributing. The one rule: the conformance suite is the
source of truth — behavior is not done until a case pins it. -->

## What and why
<!-- The change in one or two sentences. Link the issue. If it changes a
design decision, link the docs/DESIGN.md entry. -->

## Checklist
- [ ] Behavior changes carry a **conformance case** (`conformance/cases/`),
      case first — no existing case's expectations were edited to pass
- [ ] `make check` passes — vet + the full suite against **both**
      implementations (Python reference and Go runtime)
- [ ] `make differential` run (after semantic changes)
- [ ] `docs/DESIGN.md` entry added if the change is significant (append-only)
- [ ] No new dependencies; no raw Terraform/HCL as a deliverable (D39)
- [ ] Invariants held: four-valued verdicts, no type coercion, provenance
      survives, closed operator set, deterministic verifier, fail-closed

**Layer**: spec | schema | conformance | runtime | driver | mcp
