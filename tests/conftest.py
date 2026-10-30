"""Shared pytest fixtures for CIPHER STRIKE tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from cipherstrike.crypto import KdfParams  # noqa: E402


@pytest.fixture()
def fast_params() -> KdfParams:
    """Cheap Argon2id parameters for tests only.

    Production defaults are KdfParams(3, 65536, 4).  The on-disk header records
    the parameters used, so decryption exercises the same KDF configuration.
    """
    return KdfParams(time_cost=1, memory_cost=8192, parallelism=1)
