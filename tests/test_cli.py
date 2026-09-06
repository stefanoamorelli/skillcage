import subprocess
import sys


def test_help_runs():
    r = subprocess.run([sys.executable, "-m", "skillcage.cli", "--help"],
                       capture_output=True, text=True)
    assert r.returncode == 0
    assert "Detonate" in r.stdout


def test_run_missing_skill_errors(tmp_path):
    r = subprocess.run([sys.executable, "-m", "skillcage.cli", "run", str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode != 0
    assert "SKILL.md not found" in (r.stderr + r.stdout)
