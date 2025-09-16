"""Common configuration helpers for loading environment settings.

This module loads the project ``.env`` file once and exposes helpers to
retrieve configuration values with sensible defaults. Paths returned by
``env_path`` are resolved relative to the project root so callers can keep
relative paths inside the ``.env`` file.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


# Absolute path to the repository root (two levels above this file).
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Load the .env file once so every service shares the same configuration.
load_dotenv(PROJECT_ROOT / ".env", override=False)


def env_str(key: str, default: Optional[str] = None) -> Optional[str]:
    """Return the environment variable ``key`` or ``default`` if unset."""

    return os.environ.get(key, default)


def env_path(key: str, default: Optional[str] = None) -> Optional[str]:
    """Return ``key`` as an absolute path, resolving relative paths from .env."""

    value = env_str(key, default)
    if value is None:
        return None

    path = Path(value)
    if not path.is_absolute():
        path = (PROJECT_ROOT / path).resolve()
    return str(path)


def env_int(key: str, default: Optional[int] = None) -> Optional[int]:
    """Return an integer environment variable if present."""

    value = env_str(key)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def env_bool(key: str, default: bool = False) -> bool:
    """Return a boolean flag from the environment."""

    value = env_str(key)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}

