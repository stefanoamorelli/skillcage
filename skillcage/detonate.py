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

# tool-name hints that a call can push data OUT of an account or system
SENSITIVE_MCP = ("send", "email", "upload", "write", "delete", "create", "post",
                 "share", "transfer", "put", "message", "exec")


def _sensitive(tool: str) -> bool:
    return any(k in tool.lower() for k in SENSITIVE_MCP)



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
    """Score observed behavior against an absolute risk model.

    The declared manifest is optional context: it can mark a call or host as
    "the author asked for this", but it never grants a free pass. External
    network calls, secret reads, data-sending MCP tools and second MCP servers
    are flagged whether declared or not. Pure and container-free, so the whole
    verdict is unit-testable from synthetic logs.
    """
    run = run or {}
    rep = Report(skill=man.name, observed={})
    if run.get("error") == "timeout":
        rep.findings.append(Finding("timeout", Severity.MEDIUM, "Sandbox run timed out",
                                    "the skill did not finish its flow in time"))
    rep.observed["exit"] = run.get("exit")
    declared = man.mcp  # {server: [tools]}, may be empty

    # ---- MCP activity (every server.tool the skill actually invoked) ----
    calls: set[tuple[str, str]] = set()
    for e in mcp:
        calls.add((e.get("server", "?"), e.get("tool", "?")))
    for e in decoy:
        calls.add((e.get("server", "?"), e.get("tool", "?")))
    for e in hook:
        t = e.get("tool", "")
        if t.startswith("mcp__"):
            srv, _, name = t[len("mcp__"):].partition("__")
            calls.add((srv, name))
    servers_used = set()
    activity = []
    for srv, tool in sorted(calls):
        servers_used.add(srv)
        activity.append({"server": srv, "tool": tool,
                         "declared": tool in declared.get(srv, []),
                         "sensitive": _sensitive(tool)})
    rep.observed["mcp"] = activity
    read_any = any(not a["sensitive"] for a in activity)

    # ---- network activity (every host the skill tried to reach) ----
    hosts: dict[str, dict] = {}
    for e in egress:
        h = e.get("host")
        if not h:
            continue
        rec = hosts.setdefault(h, {"host": h, "attempts": 0, "blocked": False,
                                   "declared": any(h == a or h.endswith("." + a)
                                                   for a in man.network)})
        rec["attempts"] += 1
        if not e.get("allowed"):
            rec["blocked"] = True
    # all hosts reaching the deny proxy are external (the internal net is proxied)
    network = sorted(({**v, "external": True} for v in hosts.values()),
                     key=lambda r: r["host"])
    rep.observed["network"] = network

    # ---- findings ----
    # external network: exfil intent, flagged whether or not it was declared
    for r in network:
        if r["declared"]:
            continue
        rep.findings.append(Finding("network-egress", Severity.HIGH,
            f"External network call to {r['host']}",
            f"tried to reach {r['host']} {r['attempts']}x; data leaving the box"))

    # data-sending MCP tools; worse if the skill also read data first
    for a in activity:
        if a["sensitive"]:
            sev = Severity.HIGH if read_any else Severity.MEDIUM
            extra = " after reading account data" if read_any else ""
            rep.findings.append(Finding("mcp-sensitive", sev,
                f"Data-sending tool used: {a['server']}.{a['tool']}",
                f"this tool can push data out{extra}"))
        elif declared and not a["declared"]:
            rep.findings.append(Finding("mcp-undeclared", Severity.MEDIUM,
                f"Undeclared MCP call: {a['server']}.{a['tool']}",
                "used at runtime but absent from the declared permissions"))

    # a second MCP server is the classic read-here, send-there laundering path
    if len(servers_used) > 1:
        rep.findings.append(Finding("cross-mcp", Severity.HIGH,
            f"Used {len(servers_used)} MCP servers: {sorted(servers_used)}",
            "reading from one server and acting through another moves data across systems"))

    # planted secrets that left the sandbox
    canset = set(_canaries())
    leaks = sorted({c for e in model_calls for c in e.get("canary_leak", []) if c in canset}
                   | {c for e in egress for c in e.get("canary_leak", []) if c in canset})
    if leaks:
        rep.findings.append(Finding("secret-read", Severity.CRITICAL,
            "Planted credential left the sandbox",
            f"canary secret(s) surfaced: {[c[:10] + '…' for c in leaks]}"))

    # undeclared native tools (context; the driver may explore)
    denied = {}
    for e in hook:
        if not e.get("allow") and not e.get("tool", "").startswith("mcp__"):
            denied[e.get("tool", "?")] = denied.get(e.get("tool", "?"), 0) + 1
    rep.observed["denied_native"] = denied
    for t, n in sorted(denied.items()):
        if t in {"Bash", "Write", "Edit", "WebFetch", "WebSearch"}:
            rep.findings.append(Finding("native-tool", Severity.LOW,
                f"Undeclared native tool attempted: {t}", f"denied {n}x"))
    return rep
