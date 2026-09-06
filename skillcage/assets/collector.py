import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OUT = os.environ.get("SKILLCAGE_OUT", "/out")
ALLOWED = {"hook.jsonl", "mcp.jsonl", "decoy.jsonl", "driver.jsonl"}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            obj = json.loads(self.rfile.read(n))
            stream = obj.pop("stream", "misc.jsonl")
            if stream not in ALLOWED:
                stream = "misc.jsonl"
            with open(os.path.join(OUT, stream), "a") as f:
                f.write(json.dumps(obj) + "\n")
            self.send_response(204); self.end_headers()
        except Exception as e:  # noqa: BLE001
            self.send_response(400); self.end_headers(); self.wfile.write(str(e).encode())


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8099), H).serve_forever()
