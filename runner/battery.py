# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# battery.py: single source of truth for the task battery. The runner
# holds no battery copy of its own; it reads the axioma-l0 canonical
# file and verifies its git blob SHA against the pinned value at load. A
# drift refuses, exactly as the shim self-check and the CTXHASH vector
# refuse. Instances derive from a frozen pool, shapes from a frozen
# twenty, and this loader is the gate that the twenty the runner scores
# against is the twenty the design of record froze.

import hashlib
import json
import os
import pathlib

# Pinned battery blob (git hash-object of task-battery-v1.json at the
# freeze). Full SHA, exact comparison.
BATTERY_BLOB_PIN = "64f2f601d3f3e988d77e14bd6e780d402954808c"

# Pinned pool header blob, for the record; the pool constants live
# C-side and are exercised through the shim, but the pin is carried here
# so both freeze values sit together.
POOL_BLOB_PIN = "12b1478dfdafbf69eed9af669174b0d5ba767e54"


class BatteryError(RuntimeError):
    pass


def _git_blob_sha(data: bytes) -> str:
    """git hash-object: sha1('blob ' + len + '\\0' + content)."""
    h = hashlib.sha1()
    h.update(b"blob " + str(len(data)).encode() + b"\x00")
    h.update(data)
    return h.hexdigest()


def _find_battery() -> pathlib.Path:
    env = os.environ.get("EXP1_BATTERY")
    if env:
        return pathlib.Path(env)
    # Estate layout: axioma-l0 is a sibling of exp1-runner under ~/axilog.
    here = pathlib.Path(__file__).resolve().parent.parent
    cand = here.parent / "axioma-l0" / "exp1" / "battery" \
        / "task-battery-v1.json"
    if cand.exists():
        return cand
    raise BatteryError(
        "canonical battery not found; set EXP1_BATTERY to "
        "axioma-l0/exp1/battery/task-battery-v1.json"
    )


def load_battery():
    """Read the canonical battery, verify its blob SHA against the pin,
    return the parsed templates. Refuses on any drift."""
    path = _find_battery()
    data = path.read_bytes()
    got = _git_blob_sha(data)
    if got != BATTERY_BLOB_PIN:
        raise BatteryError(
            f"battery blob mismatch: {got} != pinned {BATTERY_BLOB_PIN}. "
            f"The battery at {path} is not the frozen design of record."
        )
    d = json.loads(data)
    templates = d["templates"]
    if len(templates) != 20:
        raise BatteryError(f"expected 20 templates, found {len(templates)}")
    return d


# Verify at import so any consumer of this module is guaranteed the
# battery is the frozen one.
_BATTERY = load_battery()


def templates():
    return _BATTERY["templates"]


def meta():
    return _BATTERY["_meta"]
