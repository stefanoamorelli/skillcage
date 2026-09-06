#!/usr/bin/env python3
"""PreToolUse hook. Enforces the declared manifest inside the sandbox.

Allows read-only inspection and CLI internals always; allows + logs every MCP
call (tagged by server) so undeclared/cross-server calls are observable; denies
undeclared native tools. Fails closed. Logs to the collector (file fallback).
"""
import json, os, sys, urllib.request

MANIFEST = os.environ.get("SKILLCAGE_MANIFEST", "/cage/manifest.json")
COLLECTOR = os.environ.get("SKILLCAGE_COLLECTOR", "")
LOG = os.environ.get("SKILLCAGE_HOOK_LOG", "/tmp/hook.jsonl")
ALWAYS = {"Read", "Grep", "Glob", "TodoWrite", "NotebookRead",
          "StructuredOutput", "ExitPlanMode"}


def log(ev):
    ev["stream"] = "hook.jsonl"
    if COLLECTOR:
        try:
            urllib.request.urlopen(urllib.request.Request(
                COLLECTOR, data=json.dumps(ev).encode(),
                headers={"Content-Type": "application/json"}), timeout=5)
            return
        except Exception:  # noqa: BLE001
            pass
    try:
        with open(LOG, "a") as f:
            f.write(json.dumps(ev) + "\n")
    except OSError:
        pass


def load_manifest():
    try:
        with open(MANIFEST) as f:
            return json.load(f)
    except Exception:  # noqa: BLE001
        return {}


def decide(tool, man):
    if tool in ALWAYS:
        return True, "always"
    if tool.startswith("mcp__"):
        server, _, name = tool[len("mcp__"):].partition("__")
        declared = set((man.get("mcp") or {}).get(server, []))
        if name in declared:
            return True, f"declared-mcp:{server}"
        if server in (man.get("mcp") or {}):
            return True, f"undeclared-tool:{server}.{name}"
        return True, f"cross-mcp:{server}.{name}"
    if tool in set(man.get("tools", [])):
        return True, "declared-tool"
    return False, f"undeclared native tool: {tool}"


def deny(reason):
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny",
        "permissionDecisionReason": f"skillcage: {reason}"}}))
    sys.exit(0)


def main():
    try:
        data = json.load(sys.stdin)
    except Exception as e:  # noqa: BLE001
        deny(f"unparseable hook event ({e})")
        return
    tool = data.get("tool_name", "")
    man = load_manifest()
    try:
        allow, reason = decide(tool, man)
    except Exception as e:  # noqa: BLE001
        deny(f"hook error ({e})")
        return
    log({"tool": tool, "input": data.get("tool_input", {}), "allow": allow, "reason": reason})
    if allow:
        sys.exit(0)
    deny(reason)


if __name__ == "__main__":
    main()
