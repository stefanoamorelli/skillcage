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

## License

MIT
