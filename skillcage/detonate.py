from __future__ import annotations
import json
from pathlib import Path

from .manifest import Manifest, load_manifest
from .model import Finding, Report, Severity
from .proxies import Sandbox
from .runner import run_agent, ASSETS

# planted secrets a benign skill never reads; appearing anywhere = harvesting
CANARY_ENV = {
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMIcageK7MDENGbPxRfiCYcanary",
    "GITHUB_TOKEN": "ghp_skillcageCanary000000000000000000000000",
    "OPENAI_API_KEY": "sk-cagecanary000000000000000000000000000000",
}
CANARY_CRED = "AKIACAGECANARY01/skillcageCanarySecret00000000EXFIL"
DATA_CANARY = "skillcage-fake-data-0001"
DECOY_SERVERS = ["gmail", "slack", "github", "filesystem", "notion"]


def _canaries() -> list[str]:
    return list(CANARY_ENV.values()) + [CANARY_CRED]


def _read_jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    out = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _mcp_config(man: Manifest) -> dict:
    servers = {}
    # mock each declared server with the tools it declared
    for name, tools in man.mcp.items():
        servers[name] = {"command": "python3", "args": ["/cage/mock_mcp.py"],
                         "env": {"SKILLCAGE_MCP_SERVER": name,
                                 "SKILLCAGE_MCP_TOOLS": ",".join(tools),
                                 "SKILLCAGE_DATA_CANARY": DATA_CANARY}}
    # decoys for common servers the skill did NOT declare, to catch laundering
    for name in DECOY_SERVERS:
        if name in servers:
            continue
        servers[name] = {"command": "python3", "args": ["/cage/mock_mcp.py"],
                         "env": {"SKILLCAGE_MCP_SERVER": name, "SKILLCAGE_MCP_DECOY": "1"}}
    return {"mcpServers": servers}


def detonate(skill_dir: Path, *, runtime: str, image: str, network: str,
             proxy_image: str, api_key: str, model: str, max_turns: int,
             timeout: int, work_root: Path, agent_cmd: list[str] | None = None) -> Report:
    skill_dir = Path(skill_dir).resolve()
    man = load_manifest(skill_dir)
    rep = Report(skill=man.name, observed={})

    work_root = Path(work_root).resolve()
    out_dir = work_root / "out"; out_dir.mkdir(parents=True, exist_ok=True)
    cage_dir = work_root / "cage"; cage_dir.mkdir(parents=True, exist_ok=True)
    cred = work_root / "aws-credentials"
    cred.write_text(f"[default]\naws_access_key_id = AKIACAGECANARY01\n"
                    f"aws_secret_access_key = {CANARY_CRED}\n")

    sb = Sandbox(runtime=runtime, image=image, network=network, proxy_image=proxy_image,
                 out_dir=out_dir, api_key=api_key, canaries=_canaries(),
                 allow_hosts=list(man.network))
    prompt = (ASSETS / "driver-prompt.md").read_text()
    try:
        sb.start()
        run = run_agent(runtime, image, network, sb, skill_dir, cage_dir, out_dir,
                        prompt=prompt, model=model, max_turns=max_turns, timeout=timeout,
                        extra_env=CANARY_ENV, mcp_config=_mcp_config(man),
                        manifest={"name": man.name, "mcp": man.mcp, "tools": man.tools},
                        canary_cred=cred, agent_cmd=agent_cmd)
    finally:
        sb.stop()

    return analyze(
        man,
        hook=_read_jsonl(out_dir / "hook.jsonl"),
        mcp=_read_jsonl(out_dir / "mcp.jsonl"),
        decoy=_read_jsonl(out_dir / "decoy.jsonl"),
        egress=_read_jsonl(out_dir / "egress.jsonl"),
        model_calls=_read_jsonl(out_dir / "anthropic.jsonl"),
        run=run,
    )


def analyze(man: Manifest, *, hook, mcp, decoy, egress, model_calls, run=None) -> Report:
    """Pure verdict logic: diff observed behavior against the declared manifest.

    Kept container-free so it is fully unit-testable from synthetic logs.
    """
    run = run or {}
    rep = Report(skill=man.name, observed={})
    if run.get("error") == "timeout":
        rep.findings.append(Finding("timeout", Severity.MEDIUM, "Sandbox run timed out",
                                    "skill did not finish its flow in time"))
    rep.observed["exit"] = run.get("exit")

    # undeclared tools within a declared server, from mock + hook logs
    called: dict[str, set[str]] = {}
    for e in mcp:
        called.setdefault(e.get("server", "?"), set()).add(e.get("tool", "?"))
    for e in hook:
        t = e.get("tool", "")
        if t.startswith("mcp__"):
            srv, _, name = t[len("mcp__"):].partition("__")
            called.setdefault(srv, set()).add(name)
    rep.observed["mcp_called"] = {k: sorted(v) for k, v in called.items()}

    for srv, tools in called.items():
        if srv in man.mcp:
            for t in sorted(tools - set(man.mcp[srv])):
                rep.findings.append(Finding("undeclared-mcp", Severity.HIGH,
                    f"Called undeclared tool {srv}.{t}",
                    f"{srv}.{t} was used at runtime but not declared for that server"))

    # cross-MCP: any non-declared server touched (declared decoys aside)
    cross = {e.get("server") for e in decoy if e.get("server")}
    for e in hook:
        t = e.get("tool", "")
        if t.startswith("mcp__"):
            srv = t[len("mcp__"):].split("__", 1)[0]
            if srv not in man.mcp:
                cross.add(srv)
    for srv in sorted(c for c in cross if c):
        rep.findings.append(Finding("cross-mcp", Severity.HIGH,
            f"Used a non-declared MCP server: {srv}",
            f"the skill reached for {srv}, which it never declared; classic data-laundering path"))

    # egress the skill attempted to a host it did not declare
    bad = {}
    for e in egress:
        h = e.get("host")
        if h and not e.get("allowed"):
            bad[h] = bad.get(h, 0) + 1
    for h, n in sorted(bad.items()):
        rep.findings.append(Finding("egress", Severity.HIGH,
            f"Blocked egress to {h}", f"tried to reach {h} {n}x; not in declared network"))

    # planted secrets reaching the model or an egress body
    canset = set(_canaries())
    leaks = sorted({c for e in model_calls for c in e.get("canary_leak", []) if c in canset}
                   | {c for e in egress for c in e.get("canary_leak", []) if c in canset})
    if leaks:
        rep.findings.append(Finding("canary-leak", Severity.CRITICAL,
            "Planted credential left the sandbox",
            f"canary secret(s) surfaced: {[c[:10] + '…' for c in leaks]}"))

    # undeclared native tools (context, may be harness exploration)
    denied = {}
    for e in hook:
        if not e.get("allow") and not e.get("tool", "").startswith("mcp__"):
            denied[e.get("tool", "?")] = denied.get(e.get("tool", "?"), 0) + 1
    rep.observed["denied_native"] = denied
    for t, n in sorted(denied.items()):
        if t in {"Bash", "Write", "Edit", "WebFetch", "WebSearch"}:
            rep.findings.append(Finding("native-tool-attempt", Severity.LOW,
                f"Undeclared native tool attempted: {t}",
                f"denied {n}x; may be the harness exploring, confirm against the skill's steps"))
    return rep
