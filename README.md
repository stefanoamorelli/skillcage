# skillcage

`skillcage` runs an untrusted AI agent skill in an isolated sandbox, in one
command, and shows exactly what it does.

Static scanners read the code and guess. `skillcage` runs the skill headless in a
sealed container, records every tool it calls and connection it makes, and
compares that against what the skill declared.

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
