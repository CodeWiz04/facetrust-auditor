"""Policy / configuration management.

- Loads the versioned default config.
- Only keys in TUNABLES can be changed (allow-list = least privilege).
- Every value is type- and range-checked (NaN/inf/bool rejected).
- update_config() is a PURE function: it returns the new config plus a
  list of {key, old, new} changes. The API layer writes the CONFIG_CHANGED
  audit event; the engine never touches storage.
"""

import copy
import json
import math
from pathlib import Path

from .errors import EngineError
from .hashing import config_hash  # re-exported for callers

DEFAULTS_PATH = Path(__file__).parent / "config" / "defaults.json"

# dotted key -> (type, min, max). Anything not listed cannot be changed,
# including "limits.*" (hard safety caps) and "config_version".
TUNABLES = {
    "match_threshold": (float, -1.0, 1.0),
    "target_far": (float, 0.0001, 0.5),
    "min_group_n": (int, 5, 1000),
    "liveness.blur_min": (float, 1.0, 5000.0),
    "liveness.hf_max": (float, 0.0, 1.0),
    "liveness.glare_max": (float, 0.0, 1.0),
    "liveness.bright_min": (float, 0.0, 255.0),
    "liveness.bright_max": (float, 0.0, 255.0),
    "liveness.votes_required": (int, 1, 3),
}


def _get(config: dict, dotted: str):
    node = config
    for part in dotted.split("."):
        node = node[part]
    return node


def _set(config: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    node = config
    for part in parts[:-1]:
        node = node[part]
    node[parts[-1]] = value


def validate_value(key: str, value):
    """Return the normalized value, or raise EngineError."""
    if key not in TUNABLES:
        raise EngineError("CFG-UNKNOWN-KEY", f"key={key!r}")
    typ, lo, hi = TUNABLES[key]

    # bool is a subclass of int in Python, so reject it explicitly.
    if isinstance(value, bool):
        raise EngineError("CFG-INVALID-TYPE", f"key={key}")
    if typ is int:
        if not isinstance(value, int):
            raise EngineError("CFG-INVALID-TYPE", f"key={key}")
    else:  # float: accept int or float, store as float
        if not isinstance(value, (int, float)):
            raise EngineError("CFG-INVALID-TYPE", f"key={key}")
        value = float(value)
        if not math.isfinite(value):
            raise EngineError("CFG-OUT-OF-RANGE", f"key={key} not finite")

    if not lo <= value <= hi:
        raise EngineError("CFG-OUT-OF-RANGE", f"key={key} allowed=[{lo},{hi}]")
    return value


def _check_consistency(config: dict) -> None:
    lv = config["liveness"]
    if lv["bright_min"] >= lv["bright_max"]:
        raise EngineError("CFG-INCONSISTENT", "bright_min must be < bright_max")


def validate_config(config: dict) -> dict:
    """Validate a complete config (used when loading defaults or from storage)."""
    for key in TUNABLES:
        try:
            value = _get(config, key)
        except (KeyError, TypeError):
            raise EngineError("CFG-INCONSISTENT", f"missing key={key}")
        validate_value(key, value)
    _check_consistency(config)
    return config


def load_default_config() -> dict:
    with open(DEFAULTS_PATH, "r", encoding="utf-8") as f:
        config = json.load(f)
    return validate_config(config)


def update_config(config: dict, changes: dict):
    """Apply admin changes. Returns (new_config, change_records).

    The original config is never mutated. If nothing actually changes,
    the version is not bumped and the change list is empty.
    """
    if not isinstance(changes, dict) or not changes:
        raise EngineError("CFG-INVALID-TYPE", "changes must be a non-empty object")

    new_config = copy.deepcopy(config)
    records = []
    for key in sorted(changes):
        new_value = validate_value(key, changes[key])  # validate before applying
        old_value = _get(new_config, key)
        if new_value != old_value:
            _set(new_config, key, new_value)
            records.append({"key": key, "old": old_value, "new": new_value})

    _check_consistency(new_config)  # all-or-nothing: raises before returning

    if records:
        new_config["config_version"] = config["config_version"] + 1
    return new_config, records