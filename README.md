# skillcage

Detonate an untrusted AI agent skill in a rootless sandbox and see what it
actually touches. One command, no added privileges, no Kubernetes, no cloud.

Static scanners read a skill's code and guess. skillcage runs the skill headless
in a sealed container and records what it really does: which MCP tools it calls,
where it tries to send data, whether it reads a planted secret. Then it diffs
that against what the skill declared it needs.

## Why it's different

- **Rootless, zero added capabilities.** The skill runs under `--cap-drop ALL`
  with a userspace egress proxy, not `NET_ADMIN`/`SYS_ADMIN` and iptables. The
  security tool is not itself a privilege risk.
- **Your model key never enters the container.** A reverse proxy injects it only
  for `POST /v1/messages`; the container holds a dummy.
- **MCP-permission aware.** Declare which MCP tools a skill may call, then catch
  the laundering path other tools miss: read from one MCP server, exfiltrate
  through another. Decoy `gmail`/`slack`/`github`/... servers make the attempt
  observable.
- **Tamper-proof evidence.** Logs are written by a separate collector container;
  the skill has no writable mount, so it cannot erase its own tracks.

## Install

```bash
uvx skillcage --help          # or: pipx install skillcage
skillcage build               # build the sandbox image from the bundled Dockerfile
export ANTHROPIC_API_KEY=sk-ant-...
```

You need **Podman (rootless) or Docker** on the host. Nothing else.

## Use

```bash
skillcage run ./my-skill/          # detonate, print a verdict
skillcage run ./my-skill/ --json   # machine-readable, for CI
```

Exit code is non-zero when the max finding is HIGH or CRITICAL, so it drops into
a CI gate directly.

## What a skill declares

skillcage reads a `permissions` block from the skill's `SKILL.md` frontmatter:

```yaml
---
name: monthly-report
description: Summarize this month's transactions.
permissions:
  mcp:
    qonto: [list_transactions, list_labels]   # allowed tools per server
  network: []          # allowed egress hostnames (empty = none)
  env: []              # allowed environment variables
  tools: [Read]        # native agent tools
---
```

Anything the skill does beyond this at runtime becomes a finding.

## How it works

```
host: skillcage
  ├─ proxy container      injects your key for POST /v1/messages, denies the rest
  ├─ collector container  owns the log dir; the skill cannot write to it
  └─ sandbox container    the skill runs here, rootless, cap-drop all, no host net
       → verdict + findings (undeclared MCP tool, cross-MCP, egress, canary leak)
```

The default driver is Claude Code; point `--agent-cmd` at another headless agent
CLI to use a different one.

## Scope

skillcage is deliberately small: it detonates one skill and reports. It does not
do static scanning, PR gating, or marketplace policy. Wrap it with your own
policy layer for that. See the design notes in `docs/` (coming soon).

## License

MIT
