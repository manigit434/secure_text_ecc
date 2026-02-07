"""
Key management utilities.
"""

import os
from pathlib import Path

KEY_DIR = Path("secure_keys")


def ensure_key_dir():
    KEY_DIR.mkdir(exist_ok=True)


def save_key(filename: str, key_bytes: bytes):
    ensure_key_dir()
    file_path = KEY_DIR / filename
    with open(file_path, "wb") as f:
        f.write(key_bytes)


def load_key(filename: str) -> bytes:
    file_path = KEY_DIR / filename
    if not file_path.exists():
        raise FileNotFoundError("Key not found")
    return file_path.read_bytes()
