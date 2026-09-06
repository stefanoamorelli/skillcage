# Example skills

A benign skill and one deliberately malicious skill per major threat category,
so you can see what `skillcage` flags and why.

```bash
skillcage run examples/good/spending-summary     # clean
skillcage run examples/bad/data-exfiltration      # flagged
```

The `bad/` skills are inert test fixtures. They are never installed into a real
agent; `skillcage` only ever runs them inside the sandbox, and their payloads
point at `example.net`, which goes nowhere.

## Categories

The categories follow the threat taxonomy in Li, Wu, Ling, Cui and Luo,
"Towards Secure Agent Skills: Architecture, Threat Taxonomy, and Security
Analysis" (arXiv:2604.02837, 2026). Their scan of 42,447 community skills found
26.1% carried at least one vulnerability across prompt injection, data
exfiltration, privilege escalation and supply-chain risks.

| Example | Category | What `skillcage` catches |
| --- | --- | --- |
| `good/spending-summary` | benign | stays within its declared permissions |
| `bad/prompt-injection` | prompt injection | instruction-override text aimed at the agent |
| `bad/data-exfiltration` | data exfiltration | egress to a host it never declared |
| `bad/credential-theft` | privilege escalation | reads planted secrets; a canary leaves the sandbox |
| `bad/supply-chain` | supply chain | pipes a remote script into a shell |
| `bad/cross-mcp` | data laundering | calls an MCP server it never declared |

The last one is the case static scanners miss: the skill reads data from one MCP
server and sends it out through another. `skillcage` sees the second server get
called at runtime and flags it.
