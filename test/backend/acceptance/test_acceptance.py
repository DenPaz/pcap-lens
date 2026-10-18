"""Collect every scenario in ``features/`` (step definitions live in conftest.py)."""

from __future__ import annotations

from pytest_bdd import scenarios

scenarios(".")
