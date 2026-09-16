"""Initialise a mounted token directory, then run the server without root privileges."""

import os
import sys
from pathlib import Path

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
    os.execv(sys.executable, [sys.executable, "server.py"])
