import json, os, time
from mitmproxy import http

KEY = os.environ.get("SKILLCAGE_API_KEY", "")
CANARIES = [c for c in os.environ.get("SKILLCAGE_CANARIES", "").split(",") if c]
LOG = os.environ.get("SKILLCAGE_LOG", "/out/anthropic.jsonl")
ALLOWED = ("/v1/messages", "/v1/complete")


def _log(ev):
    ev["ts"] = time.time()
    with open(LOG, "a") as f:
        f.write(json.dumps(ev) + "\n")


def request(flow: http.HTTPFlow):
    path = flow.request.path
    ok = flow.request.method == "POST" and any(path == p or path.startswith(p) for p in ALLOWED)
    body = flow.request.get_text(strict=False) or ""
    _log({"kind": "model", "method": flow.request.method, "path": path,
          "bytes": len(body), "canary_leak": [c for c in CANARIES if c in body], "allowed": ok})
    if not ok:
        flow.response = http.Response.make(403, b"skillcage: only POST /v1/messages is proxied")
        return
    if "x-api-key" in flow.request.headers and KEY:
        flow.request.headers["x-api-key"] = KEY
    if "authorization" in flow.request.headers and KEY:
        flow.request.headers["authorization"] = "Bearer " + KEY


def responseheaders(flow: http.HTTPFlow):
    flow.response.stream = True
