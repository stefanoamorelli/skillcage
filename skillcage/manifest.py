from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
import yaml


@dataclass
class Manifest:
    """What a skill declares it needs, from its SKILL.md frontmatter.

    permissions:
      mcp:                 # map of server name -> allowed tool names ([] = none)
        qonto: [list_transactions]
      network: []          # allowed egress hostnames ([] = none)
      env: []              # allowed environment variables
      tools: [Read, Bash]  # native agent tools
    """
    name: str = ""
    mcp: dict[str, list[str]] = field(default_factory=dict)
    network: list[str] = field(default_factory=list)
    env: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def parse_frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    lines = text.splitlines()
    end = next((i for i in range(1, len(lines)) if lines[i].strip() == "---"), None)
    if end is None:
        return {}
    data = yaml.safe_load("\n".join(lines[1:end])) or {}
    return data if isinstance(data, dict) else {}


def load_manifest(skill_dir: Path) -> Manifest:
    md = Path(skill_dir) / "SKILL.md"
    fm = parse_frontmatter(md.read_text(errors="replace")) if md.is_file() else {}
    perms = fm.get("permissions") or {}
    mcp = perms.get("mcp") or {}
    if not isinstance(mcp, dict):
        mcp = {}
    at = fm.get("allowed-tools") or perms.get("tools") or []
    if isinstance(at, str):
        at = [t.strip() for t in at.replace(",", " ").split() if t.strip()]
    return Manifest(
        name=str(fm.get("name", Path(skill_dir).name)),
        mcp={k: list(v or []) for k, v in mcp.items()},
        network=list(perms.get("network") or []),
        env=list(perms.get("env") or []),
        tools=[t for t in at if not str(t).startswith("mcp__")],
        raw=fm,
    )
