"""Verify all required API v1 route prefixes are mounted on the application."""

from __future__ import annotations

import pytest
from app.main import app

REQUIRED_PREFIXES = [
    "/api/v1/auth",
    "/api/v1/users",
    "/api/v1/audit",
    "/api/v1/dataset",
    "/api/v1/deletion",
    "/api/v1/evaluations",
    "/api/v1/liveness",
    "/api/v1/threshold",
    "/api/v1/subgroups",
    "/api/v1/policy",
    "/api/v1/reports",
]


def _get_registered_paths() -> list[str]:
    """Extract registered path strings from openapi schema and route objects."""
    paths = set(app.openapi().get("paths", {}).keys())
    for r in app.routes:
        if hasattr(r, "path"):
            paths.add(r.path)
    return list(paths)


@pytest.mark.parametrize("prefix", REQUIRED_PREFIXES)
def test_route_prefix_is_mounted(prefix: str):
    """Ensure that at least one registered route starts with the required prefix."""
    paths = _get_registered_paths()
    matching = [p for p in paths if p.startswith(prefix)]
    assert matching, f"No route found with prefix '{prefix}'. Registered paths: {sorted(paths)}"
