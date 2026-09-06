from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .detonate import detonate
from .model import Severity

ASSETS = Path(__file__).parent / "assets"
DEFAULT_IMAGE = "skillcage:local"


def _runtime(pref: str | None) -> str:
    if pref:
        return pref
    for r in ("podman", "docker"):
        if shutil.which(r):
            return r
    sys.exit("skillcage: need podman or docker on PATH")


def _proxy_image(runtime: str) -> str:
    return "docker.io/mitmproxy/mitmproxy:latest"


def _has_image(runtime: str, image: str) -> bool:
    return subprocess.run([runtime, "image", "exists", image],
                          capture_output=True).returncode == 0 if runtime == "podman" \
        else subprocess.run([runtime, "image", "inspect", image],
                            capture_output=True).returncode == 0


def cmd_build(args):
    runtime = _runtime(args.runtime)
    print(f"building {args.image} with {runtime} ...", file=sys.stderr)
    r = subprocess.run([runtime, "build", "-t", args.image, "-f",
                        str(ASSETS / "Dockerfile"), str(ASSETS)])
    return r.returncode


def cmd_run(args):
    runtime = _runtime(args.runtime)
    skill = Path(args.skill).resolve()
    if not (skill / "SKILL.md").is_file():
        sys.exit(f"skillcage: {skill}/SKILL.md not found")
    if not _has_image(runtime, args.image):
        print(f"image {args.image} missing; run `skillcage build` first "
              f"(or pass --image a prebuilt tag)", file=sys.stderr)
        return 3
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        print("warning: ANTHROPIC_API_KEY not set; the driver agent will fail",
              file=sys.stderr)
    work = Path(tempfile.mkdtemp(prefix="skillcage-"))
    try:
        rep = detonate(skill, runtime=runtime, image=args.image, network=args.network,
                       proxy_image=_proxy_image(runtime), api_key=key, model=args.model,
                       max_turns=args.max_turns, timeout=args.timeout, work_root=work)
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    if args.json:
        print(json.dumps(rep.to_dict(), indent=2))
    else:
        _print_human(rep)
    return 0 if rep.max_severity < Severity.HIGH else 1


def _print_human(rep):
    icon = {"clean": "✅", "suspicious": "⚠️", "malicious": "⛔", "error": "❓"}
    print(f"\n{icon.get(rep.verdict, '?')} {rep.skill}: {rep.verdict.upper()} "
          f"(max {rep.max_severity.label})")
    if rep.error:
        print(f"   error: {rep.error}")
    for f in sorted(rep.findings, key=lambda x: -int(x.severity)):
        print(f"   [{f.severity.label:8}] {f.rule}: {f.title}")
        if f.detail:
            print(f"              {f.detail}")
    if not rep.findings:
        print("   no findings")
    obs = rep.observed.get("mcp_called")
    if obs:
        print(f"   mcp called: {obs}")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="skillcage",
        description="Detonate an untrusted agent skill in a rootless sandbox.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="detonate a skill and report what it touched")
    r.add_argument("skill", help="path to the skill directory (contains SKILL.md)")
    r.add_argument("--json", action="store_true", help="machine-readable output")
    r.add_argument("--image", default=DEFAULT_IMAGE)
    r.add_argument("--runtime", choices=["podman", "docker"])
    r.add_argument("--network", default="skillcage-net")
    r.add_argument("--model", default="claude-sonnet-5")
    r.add_argument("--max-turns", type=int, default=30)
    r.add_argument("--timeout", type=int, default=600)
    r.add_argument("--keep", action="store_true", help="keep the run's temp dir")
    r.set_defaults(func=cmd_run)

    b = sub.add_parser("build", help="build the sandbox image from the bundled Dockerfile")
    b.add_argument("--image", default=DEFAULT_IMAGE)
    b.add_argument("--runtime", choices=["podman", "docker"])
    b.set_defaults(func=cmd_build)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
