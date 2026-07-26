# MCP server

Agents (Claude Code, anything MCP) get the lifecycle as gated tools.

```json
{ "mcpServers": { "groundhold": { "command": "bin/groundhold-go", "args": ["mcp"] } } }
```

Tools: `groundhold_verify`, `groundhold_plan`, `groundhold_forecast`,
`groundhold_observe`, `groundhold_hash`, `groundhold_draft` — thin adapters over
the frozen CLI protocol; refusals pass through structurally, never
summarized.

## Apply is a structural two-step

`groundhold_apply` **does not exist** unless the server runs with
`GROUNDHOLD_MCP_ALLOW_APPLY=1`. When it does:

1. First call returns `confirmation_required` with the plan hash, the
   full plan (risk vectors, delete targets) and a single-use token
   (5-minute expiry).
2. Second call must present that token **with the same plan hash** —
   a plan changed between steps refuses.

The token proves a human saw THIS sealed decision. It never supplies
contract consent — executor gates stay authoritative — and MCP client
prompts are outside Groundhold's trust boundary by design.

## Inline YAML is draft-only

Content passed inline materializes under `.groundhold/drafts/` and comes
back as `{path, hash, draft: true}`. Nothing seals or applies from
inline content.
