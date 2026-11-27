"""CLI utility to verify the tamper-evident audit log hash chain."""

from __future__ import annotations

import sys

from app.core.audit import verify_chain
from app.db.session import SessionLocal


def main() -> int:
    """Verify the audit log hash chain in the configured database."""
    db = SessionLocal()
    try:
        result = verify_chain(db)
    finally:
        db.close()

    ok = result.get("ok", False)
    count = result.get("count", 0)
    print(f"Audit chain verification: {'OK' if ok else 'FAILED'} ({count} events)")
    if not ok:
        print(f"Details: {result}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
