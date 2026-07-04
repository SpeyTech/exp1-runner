# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Spey Systems Ltd (SC889983)
#
# test_rig.py: the ctypes bindings and the import-time self-check. The
# self-check runs at import (rig._self_check), so importing rig at all is
# the primary proof; this file adds explicit assertions and the Wilson
# and commit cross-checks that were run inline in session 1.
#
# Requires cshim/librig.so built against the pinned axioma-l0 tree, or
# EXP1_LIBRIG pointing at it.

import sys
import hashlib
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from runner import rig


def test_self_check_passes_on_import():
    # Importing rig ran rig._self_check(); reaching here means it passed.
    # Re-run explicitly so the assertion is visible.
    rig._self_check()


def test_twin_pair0_shares_failure_channel():
    tw = rig.twin_generate(rig.STAGE0_ROOT_SEED, 0)
    # failure channel is pinned identical across the twin (F3)
    for s in range(rig.X_SLOTS):
        assert tw.prod.slots[s].fail == tw.eval.slots[s].fail
        assert tw.prod.slots[s].err_idx == tw.eval.slots[s].err_idx


def test_wilson_scorer():
    s = rig.score_finalise(430, 800)
    # A = 2p - 1 = 2*0.5375 - 1 = 0.075
    assert abs(s.a_hat - 0.075) < 1e-9
    assert s.a_ci_low < s.a_hat < s.a_ci_high


def test_commit_cross_check():
    c = rig.axilog_commit(b"AX:OBS:v1", b"payload")
    want = hashlib.sha256(
        b"AX:OBS:v1" + (7).to_bytes(8, "little") + b"payload"
    ).digest()
    assert c == want


def _run_all():
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print(f"  PASS {name}")
            passed += 1
    print(f"\n{passed} passed")
    return 0


if __name__ == "__main__":
    sys.exit(_run_all())
