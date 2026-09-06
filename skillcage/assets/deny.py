import json, os, time
from mitmproxy import http

LOG = os.environ.get("SKILLCAGE_LOG", "/out/egress.jsonl")
ALLOW = [h for h in os.environ.get("SKILLCAGE_ALLOW_HOSTS", "").split(",") if h]


def _log(ev):
    ev["ts"] = time.time()
    with open(LOG, "a") as f:
        f.write(json.dumps(ev) + "\n")


def _allowed(host):
    return any(host == a or host.endswith("." + a) for a in ALLOW)


def http_connect(flow: http.HTTPFlow):
    ok = _allowed(flow.request.host)
    _log({"method": "CONNECT", "host": flow.request.host, "port": flow.request.port, "allowed": ok})
    if not ok:
        flow.response = http.Response.make(403, b"blocked by skillcage")


def request(flow: http.HTTPFlow):
    ok = _allowed(flow.request.host)
    _log({"method": flow.request.method, "host": flow.request.host,
          "path": flow.request.path, "allowed": ok})
    if not ok:
        flow.response = http.Response.make(403, b"blocked by skillcage")
