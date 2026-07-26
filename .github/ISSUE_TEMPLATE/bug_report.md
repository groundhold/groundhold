---
name: Bug report
about: Something behaves against the spec or the conformance suite
title: ""
labels: bug
---

<!-- Groundhold is v0.x, experimental — an RFC you can run, not a product with an
SLA (see MATURITY.md). A "bug" here means behaviour that contradicts the spec or
a conformance case. The fastest fix is a report that arrives AS a failing
conformance case — it lands already true. -->

**Expected behavior**
<!-- What the spec / a conformance case says should happen. -->

**Actual behavior**
<!-- What happened instead. Include the machine `code` and exit code. -->

**Minimal reproduction**
<!-- The SMALLEST contract + candidate (and ledger/observations, if relevant)
that reproduces it. A report that arrives as a failing conformance case gets
fixed fastest — it arrives already true. -->

```yaml
# contract.yaml + candidate.yaml
```

**Command**
```sh
bin/groundhold-go <verb> ...
```

**Environment**
- Implementation: Go runtime / Python reference / both
- Layer: spec | schema | conformance | runtime | driver | mcp
- Version / commit:
