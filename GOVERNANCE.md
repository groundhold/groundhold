# Governance

## The promise

The open core of Groundhold — the spec, the conformance suite, the Python
reference and the Go runtime CLI — will NEVER be relicensed away from
its current licenses (Apache 2.0 / MPL 2.0). No BSL, no SSPL, no
source-available bait-and-switch. Build on it.

## What "correct" means

The conformance suite defines correctness. Semantic changes to the
suite follow the append-only decision log (docs/DESIGN.md): a new
entry states the change and its rationale; existing cases' expectations
are never weakened to make an implementation pass.

## Decision-making (pre-1.0)

Maintainer-led. Every accepted design decision is recorded in
docs/DESIGN.md with its reasoning — disagreement is argued against the
written rationale, not against recollection. As the ecosystem grows,
the intent is to move the spec and conformance suite under a neutral
foundation.

## Name and conformance claim

"Groundhold" is a working name (pre-release; formal trademark clearance is
not yet complete). "Groundhold Conformant" is intended to mean one thing:
an implementation that passes the unmodified conformance suite. The code is
free; the claim of conformance is earned. A formal trademark and a written
usage policy will follow the name decision — until then, treat the name as
provisional.
