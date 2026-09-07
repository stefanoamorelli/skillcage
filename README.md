<p align="center">
  <img src="assets/logo.png" alt="skillcage" width="475">
</p>

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

## Examples

`examples/` has a benign skill and one malicious skill per threat category, with
what each one trips. The categories follow the taxonomy in Li et al.,
[Towards Secure Agent Skills](https://arxiv.org/abs/2604.02837) (arXiv:2604.02837, 2026).

## License

[AGPL-3.0-or-later](LICENSE). Copyright © 2026
[Stefano Amorelli](https://amorelli.tech) <stefano@amorelli.tech>.
