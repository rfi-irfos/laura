import sys
import os
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_cli_help_exits_zero():
    r = subprocess.run(
        [sys.executable, "-m", "laura_scanner.cli", "--help"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "sweep" in r.stdout
    assert "wifi" in r.stdout
    assert "mitm" in r.stdout
    assert "relay" in r.stdout


def test_cli_sweep_runs():
    # Without network tooling this should still complete (returns benign
    # 'scan_unavailable' rather than crashing).
    r = subprocess.run(
        [sys.executable, "-m", "laura_scanner.cli", "sweep"],
        capture_output=True, text=True,
    )
    assert r.returncode == 0
    assert "Befunde" in r.stdout
