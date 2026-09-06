from __future__ import annotations
import secrets
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

ASSETS = Path(__file__).parent / "assets"


@dataclass
class Sandbox:
    """Lifecycle for the throwaway proxy + collector containers around one run."""
    runtime: str
    image: str
    network: str
    proxy_image: str
    out_dir: Path
    api_key: str
    canaries: list[str]
    allow_hosts: list[str] = field(default_factory=list)
    prefix: str = ""

    def __post_init__(self):
        self.out_dir = Path(self.out_dir).resolve()
        self.prefix = self.prefix or f"cage-{secrets.token_hex(3)}"

    @property
    def proxy(self):
        return f"{self.prefix}-proxy"

    @property
    def egress(self):
        return f"{self.prefix}-egress"

    @property
    def collector(self):
        return f"{self.prefix}-collector"

    def _rt(self, *a):
        return subprocess.run([self.runtime, *a], capture_output=True, text=True)

    def _ensure_network(self):
        if self._rt("network", "exists", self.network).returncode != 0:
            self._rt("network", "create", "--internal", self.network)

    def start(self):
        self._ensure_network()
        self.stop()
        # reverse proxy -> api.anthropic.com : external net first, then internal;
        # its own resolv.conf so the internal net's DNS can't shadow the upstream.
        r = self._rt(
            "run", "-d", "--replace", "--name", self.proxy,
            "--userns", "keep-id", "--user", "1000:1000",
            "--entrypoint", "mitmdump", "--network", "podman"
            if self.runtime == "podman" else "bridge",
            "-v", f"{ASSETS/'resolv.conf'}:/etc/resolv.conf:ro,z",
            "-v", f"{ASSETS/'inject.py'}:/a/inject.py:ro,z",
            "-v", f"{self.out_dir}:/out:z",
            "-e", f"SKILLCAGE_API_KEY={self.api_key}",
            "-e", f"SKILLCAGE_CANARIES={','.join(self.canaries)}",
            "-e", "SKILLCAGE_LOG=/out/anthropic.jsonl",
            self.proxy_image, "-q", "--mode", "reverse:https://api.anthropic.com",
            "--listen-host", "0.0.0.0", "--listen-port", "3128", "-s", "/a/inject.py")
        if r.returncode != 0:
            raise RuntimeError(f"proxy start failed: {r.stderr[:300]}")
        self._rt("network", "connect", self.network, self.proxy)
        # egress deny/log : internal net only
        r = self._rt(
            "run", "-d", "--replace", "--name", self.egress,
            "--userns", "keep-id", "--user", "1000:1000",
            "--entrypoint", "mitmdump", "--network", self.network,
            "-v", f"{ASSETS/'deny.py'}:/a/deny.py:ro,z",
            "-v", f"{self.out_dir}:/out:z",
            "-e", "SKILLCAGE_LOG=/out/egress.jsonl",
            "-e", f"SKILLCAGE_ALLOW_HOSTS={','.join(self.allow_hosts)}",
            self.proxy_image, "-q", "--mode", "regular", "--listen-host", "0.0.0.0",
            "--listen-port", "3129", "--set", "connection_strategy=lazy", "-s", "/a/deny.py")
        if r.returncode != 0:
            raise RuntimeError(f"egress proxy start failed: {r.stderr[:300]}")
        # append-only collector : owns out_dir; the sandbox has no writable mount
        r = self._rt(
            "run", "-d", "--replace", "--name", self.collector,
            "--userns", "keep-id", "--network", self.network,
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{ASSETS/'collector.py'}:/a/collector.py:ro,z",
            "-v", f"{self.out_dir}:/out:z", "-e", "SKILLCAGE_OUT=/out",
            "--entrypoint", "python3", self.image, "/a/collector.py")
        if r.returncode != 0:
            raise RuntimeError(f"collector start failed: {r.stderr[:300]}")
        time.sleep(3)

    def stop(self):
        for n in (self.proxy, self.egress, self.collector):
            self._rt("rm", "-f", n)

    def sandbox_env(self) -> dict[str, str]:
        return {
            "ANTHROPIC_BASE_URL": f"http://{self.proxy}:3128",
            "ANTHROPIC_API_KEY": "skillcage-dummy",
            "HTTP_PROXY": f"http://{self.egress}:3129",
            "HTTPS_PROXY": f"http://{self.egress}:3129",
            "NO_PROXY": f"{self.proxy},{self.egress},{self.collector}",
            "SKILLCAGE_COLLECTOR": f"http://{self.collector}:8099",
        }
