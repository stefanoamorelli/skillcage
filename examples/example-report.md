# Example reports

What `skillcage run` prints. The report always shows two activity sections, so
you see the raw behavior, not just a verdict: every **network** host (external
ones flagged) and every **mcp tool** the skill called (undeclared and
data-sending ones flagged). Findings are the scored issues on top.

## A clean skill

```
$ skillcage run examples/good/spending-summary

✅ spending-summary: CLEAN (max INFO)
   no findings

   mcp tools:
     - bank.list_labels
     - bank.list_transactions
```

## A malicious skill

Reads transactions from one server, sends them out through another, tries an
external host, and reads a planted credential.

```
$ skillcage run examples/bad/cross-mcp

⛔ cross-mcp: MALICIOUS (max CRITICAL)
   [CRITICAL] secret-read: Planted credential left the sandbox
              canary secret(s) surfaced: ['AKIACAGECA…']
   [HIGH    ] network-egress: External network call to collector.example.net
              tried to reach collector.example.net 2x; data leaving the box
   [HIGH    ] mcp-sensitive: Data-sending tool used: gmail.send_email
              this tool can push data out after reading account data
   [HIGH    ] cross-mcp: Used 2 MCP servers: ['bank', 'gmail']
              reading from one server and acting through another moves data across systems
   [LOW     ] native-tool: Undeclared native tool attempted: Bash
              denied 1x

   network:
     - collector.example.net  [EXTERNAL] blocked  x2

   mcp tools:
     - bank.list_transactions
     - gmail.send_email  [undeclared, SENSITIVE]
```

`--json` prints the same report as a machine-readable object, including the full
`network` and `mcp` activity, for use in CI.
