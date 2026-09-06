from __future__ import annotations
import json
import secrets
import subprocess
from pathlib import Path

from .proxies import Sandbox

ASSETS = Path(__file__).parent / "assets"


def run_agent(runtime: str, image: str, network: str, sandbox: Sandbox,
              skill_dir: Path, cage_dir: Path, out_dir: Path, *,
              prompt: str, model: str, max_turns: int, timeout: int,
              extra_env: dict, mcp_config: dict, manifest: dict,
              canary_cred: Path,
              agent_cmd: list[str] | None = None) -> dict:
    """Run the driver agent headless inside the sealed sandbox container.

    Network = internal only (model reachable via the injecting proxy, nothing
    else). No writable mount: logs go to the collector. Rootless, cap-drop all.
    """
    cage_dir = Path(cage_dir).resolve()
    (cage_dir / "mcp.json").write_text(json.dumps(mcp_config))
    (cage_dir / "manifest.json").write_text(json.dumps(manifest))
    (cage_dir / "settings.json").write_text(json.dumps({"hooks": {"PreToolUse": [
        {"matcher": "", "hooks": [{"type": "command",
         "command": "python3 /cage/hook.py", "timeout": 10}]}]}}))
    (cage_dir / "hook.py").write_text((ASSETS / "hook.py").read_text())
    (cage_dir / "mock_mcp.py").write_text((ASSETS / "mock_mcp.py").read_text())

    name = f"{sandbox.prefix}-run-{secrets.token_hex(2)}"
    args = [
        runtime, "run", "--rm", "--name", name,
        "--userns", "keep-id", "--network", network,
        "--memory", "3g", "--memory-swap", "3g", "--cpus", "2", "--pids-limit", "512",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-v", f"{cage_dir}:/cage:ro,z",
        "-v", f"{Path(skill_dir).resolve()}:/work/skill:ro,z",
        "-v", f"{Path(canary_cred).resolve()}:/home/sandbox/.aws/credentials:ro,z",
        "-w", "/work",
    ]
    env = dict(sandbox.sandbox_env())
    env.update({"DISABLE_TELEMETRY": "1", "DISABLE_ERROR_REPORTING": "1",
                "DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                "IS_SANDBOX": "1", "SKILLCAGE_MANIFEST": "/cage/manifest.json"})
    env.update(extra_env)
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    args.append(image)

    cli = agent_cmd or [
        "claude", "-p", prompt, "--model", model,
        "--output-format", "json", "--max-turns", str(max_turns),
        "--no-session-persistence", "--dangerously-skip-permissions",
        "--mcp-config", "/cage/mcp.json", "--strict-mcp-config",
        "--settings", "/cage/settings.json"]
    args += cli
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        subprocess.run([runtime, "rm", "-f", name], capture_output=True)
        return {"error": "timeout"}
    out = {"exit": p.returncode, "stderr": p.stderr[-1500:]}
    try:
        out["result"] = json.loads(p.stdout)
    except json.JSONDecodeError:
        out["raw"] = p.stdout[-1500:]
    return out
