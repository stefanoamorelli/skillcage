#!/usr/bin/env python3
"""Generic mock MCP server (stdio JSON-RPC). Stdlib only.

Impersonates ONE server named by SKILLCAGE_MCP_SERVER, exposing the tools in
SKILLCAGE_MCP_TOOLS (comma list) plus, when SKILLCAGE_MCP_DECOY=1, a generic
set. Returns fake data carrying a canary, and logs every call to the collector.
A skill that reaches for an undeclared tool or a decoy server leaves a trace.
"""
import json, os, sys, urllib.request

SERVER = os.environ.get("SKILLCAGE_MCP_SERVER", "server")
TOOLS = [t for t in os.environ.get("SKILLCAGE_MCP_TOOLS", "").split(",") if t]
DECOY = os.environ.get("SKILLCAGE_MCP_DECOY", "") == "1"
COLLECTOR = os.environ.get("SKILLCAGE_COLLECTOR", "")
LOG = os.environ.get("SKILLCAGE_MCP_LOG", "/tmp/mcp.jsonl")
CANARY = os.environ.get("SKILLCAGE_DATA_CANARY", "skillcage-fake-data-0001")
DECOY_TOOLS = ["send_message", "send_email", "read", "list", "search",
               "create", "update", "delete", "upload", "write_file", "read_file"]


def emit(ev):
    ev["stream"] = "decoy.jsonl" if DECOY else "mcp.jsonl"
    ev["server"] = SERVER
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


def tool_list():
    names = DECOY_TOOLS if DECOY else (TOOLS or DECOY_TOOLS)
    return [{"name": t, "description": f"[mock {SERVER}] {t}",
             "inputSchema": {"type": "object"}} for t in names]


def handle(req):
    m = req.get("method"); rid = req.get("id")
    if m == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER, "version": "mock-0.1"}}}
    if m == "notifications/initialized":
        return None
    if m == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": tool_list()}}
    if m == "tools/call":
        p = req.get("params", {})
        emit({"tool": p.get("name", ""), "arguments": p.get("arguments", {})})
        return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text",
                "text": json.dumps({"note": "SANDBOX FAKE DATA", "sample": CANARY})}]}}
    if rid is not None:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "not found"}}
    return None


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
