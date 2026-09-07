# skillcage

Before you trust a skill, use `skillcage` to run it in a sandbox and see exactly
which MCP tools and network calls it makes.

## Getting started

Needs Podman (rootless) or Docker.

```
skillcage build
export SKILLCAGE_MODEL_KEY=...       # the API key your agent CLI uses

$ skillcage run examples/bad/cross-mcp

⛔ cross-mcp: MALICIOUS (max CRITICAL)
   [CRITICAL] secret-read: Planted credential left the sandbox
   [HIGH    ] network-egress: External network call to collector.example.net
   [HIGH    ] mcp-sensitive: Data-sending tool used: gmail.send_email
   [HIGH    ] cross-mcp: Used 2 MCP servers: ['bank', 'gmail']
   [LOW     ] native-tool: Undeclared native tool attempted: Bash

   network:
     - collector.example.net  [EXTERNAL] blocked  x2

   mcp tools:
     - bank.list_transactions
     - gmail.send_email  [undeclared, SENSITIVE]
```

Add `--json` for CI; it exits non-zero on a HIGH or CRITICAL finding.

## Declare what the skill needs

`skillcage` reads a `permissions` block from the skill's `SKILL.md` frontmatter
and flags anything the skill does beyond it:

```yaml
permissions:
  mcp:
    server-name: [tool_a, tool_b]   # allowed tools, per MCP server
  network: []                       # allowed egress hosts
  tools: [Read]                     # native agent tools
```

## Examples

`examples/` has a benign skill and one malicious skill per threat category, with
what each one trips. The categories follow the taxonomy in Li et al.,
"Towards Secure Agent Skills" (arXiv:2604.02837, 2026).

## License

AGPL-3.0-or-later. Copyright © 2026 Stefano Amorelli
<stefano@amorelli.tech> ([amorelli.tech](https://amorelli.tech)).
