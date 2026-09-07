# skillcage

AI agent skills are code, and they can come from untrusted sources. A loaded
skill runs with your agent's permissions: it can read your files and credentials
and reach any MCP server you have connected. You cannot tell from the source what it will do
at runtime, and static scanners only guess.

`skillcage` runs a skill in an isolated sandbox first, in one command, and shows
exactly what it does: every tool it calls, every connection it tries, every
secret it reaches for. It compares that against what the skill declared, so you
can decide whether to trust it before it touches your machine.

## Getting started

Needs Podman (rootless) or Docker.

```bash
skillcage build
export SKILLCAGE_MODEL_KEY=...       # the API key your agent CLI uses

skillcage run ./my-skill/            # verdict + findings
skillcage run ./my-skill/ --json     # for CI; non-zero exit on HIGH/CRITICAL
```

## Example report

The report shows the behavior of the skill, including every network host
(external ones flagged), every MCP tool it called (undeclared and data-sending
ones flagged), and the scored findings on top.

```
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

MIT
