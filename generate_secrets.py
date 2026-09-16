"""Create new local server secrets without displaying them or overwriting a file."""

import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

target = Path(".secrets.env")
contents = (
    "TOKEN_ENCRYPTION_KEY=" + Fernet.generate_key().decode("ascii") + "\n"
    "JWT_SIGNING_KEY=" + secrets.token_urlsafe(48) + "\n"
)
descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    stream.write(contents)
print("Created .secrets.env with private file permissions. Copy values directly into your host's secret settings.")
