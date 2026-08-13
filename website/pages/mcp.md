# MCP server

Agents (Claude Code, anything MCP) get the core lifecycle verbs as gated tools.

```json
{ "mcpServers": { "groundhold": { "command": "bin/groundhold-go", "args": ["mcp"] } } }
```

Tools: `groundhold_verify`, `groundhold_plan`, `groundhold_forecast`,
`groundhold_observe`, `groundhold_hash`, `groundhold_draft` — thin adapters over
the frozen CLI protocol; refusals pass through structurally, never
summarized.

## What to route on

Every tool result carries `exitCode` and `status`.

`status` is the VERB'S OWN answer whenever the verb produced one — `applied`,
`converged`, `probed`, `partial`, `unmeasured`, `adopted`, `refused` — and never a
re-derivation from the exit code (D704). `verify` reports `proven` / `not-proven`,
because a hard constraint that is violated or unknown is a VERDICT, not the tool
declining to act.

When the SERVER itself refuses — apply not enabled, a stale or reused confirmation
token, a plan or target that changed between the two steps, a missing required
argument, a path that escapes the workspace — the result is `status: "refused"` with
a machine `code` from [Errors](errors.md), never prose alone (D705/D706).

`status: "failed"` means the server's own environment failed (it could not write a
draft, could not read entropy for a token). It carries no `code`: no error code
describes the tool's environment, and inventing one to fill the field would say
something untrue.

## Apply is a structural two-step

`groundhold_apply` **does not exist** unless the server runs with
`GROUNDHOLD_MCP_ALLOW_APPLY=1`. When it does:

1. First call returns `confirmation_required` with the plan hash, the
   full plan (risk vectors, delete targets) and a single-use token
   (5-minute expiry).
2. Second call must present that token **with the same plan hash** —
   a plan changed between steps refuses.

The token pins THIS sealed decision: same plan hash, same target, single
use, five-minute expiry. It does **not** authenticate a human — it is
delivered in-band to the same MCP client, so an autonomous (or
prompt-injected) agent can complete both steps alone. Do not rely on it
as separation-of-duties or human-approval evidence. It never supplies
contract consent either: the executor's own gates (autonomy,
`--allow-data-loss`) stay authoritative and are never satisfied by the
token, and MCP client prompts are outside Groundhold's trust boundary by
design.

## Inline YAML is draft-only

Content passed inline materializes under `.groundhold/drafts/` and comes
back as `{path, hash, draft: true}`. Nothing seals or applies from
inline content.
