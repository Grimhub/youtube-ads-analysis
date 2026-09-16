"""Initialise a mounted token directory, then run the server without root privileges."""

import os
import json
import subprocess
import sys
from pathlib import Path


def run_auth_diagnostic() -> None:
    """Optionally inspect a saved grant without delaying server startup indefinitely."""
    if os.environ.get("AUTH_DIAGNOSTIC_ON_STARTUP") != "1":
        return
    try:
        result = subprocess.run(
            [sys.executable, "diagnose_existing_auth.py"],
            capture_output=True, text=True, timeout=20, check=False,
        )
        if result.returncode != 0:
            raise ValueError("Diagnostic did not complete")
        report = json.loads(result.stdout)
        if not isinstance(report, dict):
            raise ValueError("Invalid diagnostic result")
        print("AUTH_DIAGNOSTIC " + json.dumps(report, sort_keys=True), flush=True)
    except Exception:
        # Never forward exception text or a subprocess traceback: either could
        # contain private request details. Failure must not prevent startup.
        print('AUTH_DIAGNOSTIC {"stage":"diagnostic_unavailable"}', flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    if os.geteuid() == 0:
        location = Path(os.environ.get("TOKEN_STORE_DIR", "/data/oauth"))
        if not location.is_absolute() or location == Path("/") or location.is_symlink():
            raise ValueError("TOKEN_STORE_DIR must be an absolute, dedicated directory.")
        location.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chown(location, 10001, 10001)
        os.chmod(location, 0o700)
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    run_auth_diagnostic()
    os.execv(sys.executable, [sys.executable, "server.py"])
